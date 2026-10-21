"""
Wiz API client + normalizers — stdlib only (urllib), so it runs in Lambda with
no extra packages. Requirements 1.1-1.5 (ingest), 9.2 (scan-now).

Two sources of findings, both normalized to the platform's finding schema
(the shape core.enrich / store.upsert_finding expect):

  * Wiz GraphQL `vulnerabilityFindings` — what Wiz already knows about an image
    (continuous ECR scanning, ~1 day lag). Used by ingest + per-image refresh.
  * wizcli JSON output — a fresh on-demand scan run in CodeBuild ("Scan now"),
    also used to re-verify an image after a fix.

The HTTP layer is an injectable `transport` callable so tests and MOCK mode
(wiz_mock.MockTransport) never touch the network.

CONFIRM AGAINST THE TENANT: the GraphQL field names below follow the public
Wiz schema as we understand it; Wiz schemas are tenant-versioned, so check
FINDINGS_QUERY and image_filter() in the Wiz API Explorer before go-live.
Everything schema-specific is kept in this file.
"""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
PAGE_SIZE = 500
MAX_RETRIES = 4
MUTABLE_TAGS = {"latest", "main", "master", "dev", "develop", "stable", "prod", "production"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

FINDINGS_QUERY = """
query ImageVulnerabilityFindings($filterBy: VulnerabilityFindingFilters, $first: Int, $after: String) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      severity
      status
      firstDetectedAt
      lastDetectedAt
      detailedName
      version
      fixedVersion
      hasExploit
      hasCisaKevExploit
      epssProbability
      layerMetadata { id details isBaseLayer }
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          type
          name
          providerUniqueId
          subscriptionExternalId
          tags
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class WizError(Exception):
    """Wiz API / auth failure (non-retryable, or retries exhausted)."""


# ---------------------------------------------------------------- transport
def urllib_transport(method, url, headers, body, timeout=30):
    """Default HTTP transport. Returns (status, body_bytes); never raises on HTTP errors."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---------------------------------------------------------------- client
class WizClient:
    def __init__(self, client_id, client_secret, api_endpoint,
                 auth_url=DEFAULT_AUTH_URL, transport=None, sleep=time.sleep, clock=time.time):
        if not (client_id and client_secret and api_endpoint):
            raise WizError("Wiz client_id, client_secret and endpoint are required")
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_endpoint = api_endpoint
        self.auth_url = auth_url
        self._transport = transport or urllib_transport
        self._sleep = sleep
        self._clock = clock
        self._token = None
        self._token_expiry = 0

    @classmethod
    def from_secret(cls, secret, **kwargs):
        """Build from the Secrets Manager JSON: {endpoint, client_id, client_secret, auth_url?}."""
        return cls(secret.get("client_id"), secret.get("client_secret"), secret.get("endpoint"),
                   auth_url=secret.get("auth_url") or DEFAULT_AUTH_URL, **kwargs)

    # -- auth (OAuth2 client credentials, audience wiz-api) --
    def _access_token(self):
        if self._token and self._clock() < self._token_expiry - 60:
            return self._token
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "audience": "wiz-api",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }).encode()
        status, raw = self._transport(
            "POST", self.auth_url,
            {"Content-Type": "application/x-www-form-urlencoded"}, body)
        if status != 200:
            # never echo the response body: it can contain credential details
            raise WizError(f"Wiz authentication failed (HTTP {status})")
        data = json.loads(raw)
        self._token = data["access_token"]
        self._token_expiry = self._clock() + int(data.get("expires_in", 3600))
        return self._token

    # -- GraphQL with retry on throttling / 5xx --
    def graphql(self, query, variables=None):
        payload = json.dumps({"query": query, "variables": variables or {}}).encode()
        for attempt in range(MAX_RETRIES + 1):
            headers = {"Content-Type": "application/json",
                       "Authorization": f"Bearer {self._access_token()}"}
            status, raw = self._transport("POST", self.api_endpoint, headers, payload)
            if status == 401 and attempt == 0:
                self._token = None  # token revoked/expired early: re-auth once
                continue
            if status == 429 or status >= 500:
                if attempt == MAX_RETRIES:
                    raise WizError(f"Wiz API unavailable after retries (HTTP {status})")
                self._sleep(min(2 ** attempt, 30))
                continue
            if status != 200:
                raise WizError(f"Wiz API error (HTTP {status})")
            data = json.loads(raw)
            if data.get("errors"):
                msgs = "; ".join(e.get("message", "?") for e in data["errors"])
                raise WizError(f"Wiz GraphQL error: {msgs}")
            return data["data"]
        raise WizError("Wiz API retries exhausted")

    def iter_findings(self, filter_by):
        """Yield raw vulnerabilityFindings nodes across all pages."""
        after = None
        while True:
            data = self.graphql(FINDINGS_QUERY, {"filterBy": filter_by, "first": PAGE_SIZE,
                                                 "after": after})
            conn = data["vulnerabilityFindings"]
            yield from conn.get("nodes") or []
            page = conn.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                return
            after = page["endCursor"]

    def fetch_findings(self, base_image_names=(), image=None):
        """All open container-image findings (or just one image's), normalized."""
        filter_by = image_filter(image)
        out = []
        for node in self.iter_findings(filter_by):
            f = normalize_finding(node, base_image_names)
            if f and (image is None or f"{f['repo']}:{f['imageTag']}" == image):
                out.append(f)
        return out


def image_filter(image=None):
    """GraphQL filter: open findings on container images, optionally one image (repo:tag).
    The server-side name search narrows the page set; fetch_findings re-checks exactly."""
    flt = {"assetType": ["CONTAINER_IMAGE"], "status": ["OPEN", "IN_PROGRESS"]}
    if image:
        flt["search"] = image
    return flt


# ---------------------------------------------------------------- normalizers
def finding_key(repo, tag, cve, package):
    """Stable finding id shared by the Wiz API and wizcli paths, so a fresh scan
    updates the same row (and keeps the earliest firstSeen) instead of duplicating."""
    return f"{repo}:{tag}:{cve}:{package or '-'}"


def split_image_name(name):
    """'123.dkr.ecr.us-east-1.amazonaws.com/team/app:1.2' -> ('team/app', '1.2').
    Digest refs (repo@sha256:...) keep the digest as the tag."""
    if not name:
        return "", ""
    ref = name.strip()
    if "@" in ref:
        repo, tag = ref.split("@", 1)
    else:
        last = ref.rsplit("/", 1)[-1]
        if ":" in last:
            repo, tag = ref.rsplit(":", 1)
        else:
            repo, tag = ref, "latest"
    parts = repo.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        repo = "/".join(parts[1:])  # strip registry host
    return repo, tag


def _severity(value):
    sev = (value or "").upper()
    if sev in ("NONE", "INFORMATIONAL"):
        return "INFO"
    return sev if sev in SEVERITIES else "INFO"


def resolve_base_image(layer_details, base_image_names):
    """Map a base-layer's details to a governed base image name.
    Prefers a known shared-base-images name; falls back to the FROM reference."""
    details = layer_details or ""
    for name in sorted(base_image_names, key=len, reverse=True):
        if name and name in details:
            return name
    m = re.search(r"FROM\s+(\S+)", details, re.IGNORECASE)
    if m:
        return split_image_name(m.group(1))[0]
    return None


def _tags_dict(tags):
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):  # [{"key":..,"value":..}]
        return {t.get("key"): t.get("value") for t in tags if isinstance(t, dict)}
    return {}


def normalize_finding(node, base_image_names=()):
    """Wiz vulnerabilityFindings node -> platform finding dict (None if unusable)."""
    asset = node.get("vulnerableAsset") or {}
    repo, tag = split_image_name(asset.get("name") or asset.get("providerUniqueId"))
    cve = node.get("name")
    if not (repo and cve and node.get("firstDetectedAt")):
        return None
    layer = node.get("layerMetadata") or {}
    is_base = bool(layer.get("isBaseLayer"))
    tags = _tags_dict(asset.get("tags"))
    env_tag = (tags.get("Environment") or tags.get("env") or "").lower()
    return {
        "id": finding_key(repo, tag, cve, node.get("detailedName")),
        "wizId": node["id"],
        "source": "wiz-api",
        "cve": cve,
        "severity": _severity(node.get("severity")),
        "status": node.get("status", "OPEN"),
        "repo": repo,
        "imageTag": tag,
        "account": asset.get("subscriptionExternalId"),
        "businessUnit": tags.get("BusinessUnit") or tags.get("bu"),
        "package": node.get("detailedName"),
        "installedVersion": node.get("version"),
        "fixedVersion": node.get("fixedVersion"),
        "layerType": "base" if is_base else "app",
        "baseImage": resolve_base_image(layer.get("details"), base_image_names) if is_base else None,
        "kev": bool(node.get("hasCisaKevExploit")),
        "hasExploit": bool(node.get("hasExploit")),
        "epss": float(node.get("epssProbability") or 0.0),
        "firstSeen": node["firstDetectedAt"],
        "lastSeen": node.get("lastDetectedAt"),
        "mutableTag": tag.lower() in MUTABLE_TAGS,
        "runningInProd": env_tag in ("prod", "production"),
    }


def normalize_wizcli_result(result, image, base_image_names=(), scanned_at=None):
    """wizcli JSON scan output -> platform findings for `image` (repo:tag).

    wizcli groups vulnerabilities under OS packages and libraries. When a package
    carries layerMetadata.isBaseLayer we use it; otherwise OS packages are treated
    as base-layer and libraries as app-layer (heuristic, flagged layerSource)."""
    repo, tag = split_image_name(image)
    scanned_at = scanned_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    body = result.get("result", result)
    out = []
    for group, default_base in (("osPackages", True), ("libraries", False)):
        for pkg in body.get(group) or []:
            layer = pkg.get("layerMetadata") or {}
            if "isBaseLayer" in layer:
                is_base, layer_source = bool(layer["isBaseLayer"]), "wiz"
            else:
                is_base, layer_source = default_base, "heuristic"
            for v in pkg.get("vulnerabilities") or []:
                cve = v.get("name")
                if not cve:
                    continue
                out.append({
                    "id": finding_key(repo, tag, cve, pkg.get("name")),
                    "source": "wizcli",
                    "cve": cve,
                    "severity": _severity(v.get("severity")),
                    "status": "OPEN",
                    "repo": repo,
                    "imageTag": tag,
                    "package": pkg.get("name"),
                    "installedVersion": pkg.get("version"),
                    "fixedVersion": v.get("fixedVersion"),
                    "layerType": "base" if is_base else "app",
                    "layerSource": layer_source,
                    "baseImage": (resolve_base_image(layer.get("details"), base_image_names)
                                  if is_base else None),
                    "kev": bool(v.get("hasCisaKevExploit")),
                    "hasExploit": bool(v.get("hasExploit")),
                    "epss": float(v.get("epssProbability") or 0.0),
                    "firstSeen": scanned_at,
                    "lastSeen": scanned_at,
                    "mutableTag": tag.lower() in MUTABLE_TAGS,
                })
    return out


def resolved_ids(previous, current):
    """Ids of `previous` open findings for an image that a fresh scan no longer reports."""
    now = {f["id"] for f in current}
    return sorted(f["id"] for f in previous if f["id"] not in now)


def scan_summary(findings):
    """Counts for the scan record / report header."""
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "kev": sum(1 for f in findings if f.get("kev")),
        "base_layer": sum(1 for f in findings if f.get("layerType") == "base"),
        "fixable": sum(1 for f in findings if f.get("fixedVersion")),
    }
