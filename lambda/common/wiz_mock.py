"""
Mock Wiz — stands in for the Wiz API and wizcli until real credentials exist.

  * MockTransport: a WizClient transport that answers the OAuth token call and
    the vulnerabilityFindings GraphQL query (with real paging + image search),
    so the client code paths are exercised end to end.
  * mock_wizcli_result(): a wizcli-shaped JSON result for on-demand scans.
  * mock_sbom(): a minimal CycloneDX document for the SBOM export path.

Fixture images match the web UI's MOCK data (web/app.js) so the console looks
the same in MOCK and in deployed-with-mock-Wiz mode.
"""

import json
import urllib.parse

MOCK_ENDPOINT = "https://api.mock.app.wiz.io/graphql"
MOCK_REGISTRY = "111122223333.dkr.ecr.us-east-1.amazonaws.com"
MOCK_SECRET = {"client_id": "mock-client", "client_secret": "mock-secret",
               "endpoint": MOCK_ENDPOINT}

_BASE = {
    "python": "FROM shared-base-images/al2023-python:2026.02.1",
    "dotnet": "FROM shared-base-images/dotnet-aspnet:8.0.2",
    "java": "FROM shared-base-images/al2023-java:2026.02.1",
}


def _asset(image, account, bu, env="prod"):
    return {
        "id": f"asset-{image}", "type": "CONTAINER_IMAGE",
        "name": f"{MOCK_REGISTRY}/{image}", "providerUniqueId": f"{MOCK_REGISTRY}/{image}",
        "subscriptionExternalId": account,
        "tags": {"BusinessUnit": bu, "Environment": env},
    }


def _node(nid, cve, sev, pkg, ver, fixed, first, asset, base=None, kev=False, epss=0.0):
    return {
        "id": nid, "name": cve, "severity": sev, "status": "OPEN",
        "firstDetectedAt": first, "lastDetectedAt": "2026-10-18T06:00:00Z",
        "detailedName": pkg, "version": ver, "fixedVersion": fixed,
        "hasExploit": kev, "hasCisaKevExploit": kev, "epssProbability": epss,
        "layerMetadata": ({"id": f"layer-{nid}", "details": _BASE[base], "isBaseLayer": True}
                          if base else {"id": f"layer-{nid}", "details": "RUN pip install -r requirements.txt",
                                        "isBaseLayer": False}),
        "vulnerableAsset": asset,
    }


_RWD = _asset("clarivate-rwd/ingest-api:latest", "prod-rwd-1", "Clarivate-RWD")
_MMIT = _asset("mmit-access/claims-processor:8.0.2", "prod-access-2", "MMIT-Access")
_PAN = _asset("panalgo-analytics/query-engine:v3.2.0", "prod-analytics-1", "Panalgo")

FINDING_NODES = [
    _node("f-001", "CVE-2024-21626", "CRITICAL", "runc", "1.1.4", "1.1.12",
          "2026-09-10T08:00:00Z", _RWD, base="python", kev=True, epss=0.92),
    _node("f-002", "CVE-2024-2961", "HIGH", "glibc", "2.34-52", "2.34-100",
          "2026-10-02T08:00:00Z", _RWD, base="python", epss=0.31),
    _node("f-003", "CVE-2023-50782", "HIGH", "cryptography", "41.0.4", "42.0.0",
          "2026-10-12T08:00:00Z", _RWD, epss=0.04),
    _node("f-004", "CVE-2023-45853", "CRITICAL", "zlib", "1.2.13", "1.3",
          "2026-10-03T08:00:00Z", _MMIT, base="dotnet", epss=0.12),
    _node("f-005", "CVE-2024-3094", "CRITICAL", "xz-libs", "5.6.0", "5.6.2",
          "2026-10-13T08:00:00Z", _PAN, base="java", kev=True, epss=0.86),
]


class MockTransport:
    """Callable transport: (method, url, headers, body) -> (status, bytes).
    `fail_next` lets tests inject HTTP statuses (e.g. [429, 500]) before success."""

    def __init__(self, nodes=None, fail_next=None, token_status=200):
        self.nodes = list(FINDING_NODES if nodes is None else nodes)
        self.fail_next = list(fail_next or [])
        self.token_status = token_status
        self.calls = []

    def __call__(self, method, url, headers, body, timeout=30):
        self.calls.append((method, url))
        if "oauth/token" in url:
            form = urllib.parse.parse_qs((body or b"").decode())
            if self.token_status != 200 or form.get("audience") != ["wiz-api"]:
                return self.token_status if self.token_status != 200 else 400, b'{"error":"denied"}'
            return 200, json.dumps({"access_token": "mock-token", "expires_in": 3600}).encode()
        if self.fail_next:
            return self.fail_next.pop(0), b'{"error":"injected"}'
        if headers.get("Authorization") != "Bearer mock-token":
            return 401, b'{"error":"unauthorized"}'
        req = json.loads(body)
        v = req.get("variables") or {}
        search = (v.get("filterBy") or {}).get("search")
        nodes = [n for n in self.nodes
                 if not search or search in n["vulnerableAsset"]["name"]]
        start = int(v.get("after") or 0)
        first = int(v.get("first") or 500)
        page = nodes[start:start + first]
        more = start + first < len(nodes)
        return 200, json.dumps({"data": {"vulnerabilityFindings": {
            "nodes": page,
            "pageInfo": {"hasNextPage": more, "endCursor": str(start + first) if more else None},
        }}}).encode()


def _fixed_by(node, fixed_base, fix_spec):
    """True when the simulated rebuild removed this vulnerability."""
    layer = node["layerMetadata"]
    if layer["isBaseLayer"]:
        if fixed_base:
            return True
        return any(c["base_image"] in layer["details"]
                   for c in (fix_spec or {}).get("base_changes", []))
    return any(c["package"] == node["detailedName"] and c["to_version"] == node["fixedVersion"]
               for c in (fix_spec or {}).get("dependency_changes", []))


def _image_nodes(image):
    return [n for n in FINDING_NODES if n["vulnerableAsset"]["name"].endswith("/" + image)]


def mock_wizcli_result(image, fixed_base=False, fix_spec=None):
    """wizcli-shaped JSON for an on-demand scan of `image` (repo:tag).
    fixed_base=True / a fix spec simulate a re-scan after the rebuild: the
    vulnerabilities the fix addressed are gone."""
    pkgs_os, libs = [], []
    for n in _image_nodes(image):
        if _fixed_by(n, fixed_base, fix_spec):
            continue
        vuln = {"name": n["name"], "severity": n["severity"].capitalize(),
                "fixedVersion": n["fixedVersion"], "hasExploit": n["hasExploit"],
                "hasCisaKevExploit": n["hasCisaKevExploit"], "epssProbability": n["epssProbability"]}
        pkg = {"name": n["detailedName"], "version": n["version"],
               "layerMetadata": n["layerMetadata"], "vulnerabilities": [vuln]}
        (pkgs_os if n["layerMetadata"]["isBaseLayer"] else libs).append(pkg)
    return {"id": f"mock-scan-{image}", "status": {"state": "SUCCESS"},
            "result": {"osPackages": pkgs_os, "libraries": libs}}


def mock_sbom(image, fix_spec=None):
    """Minimal CycloneDX 1.5 SBOM listing the fixture packages for `image`
    (fixed versions when a fix spec was applied)."""
    comps = [{"type": "library", "name": n["detailedName"],
              "version": n["fixedVersion"] if _fixed_by(n, False, fix_spec) else n["version"]}
             for n in _image_nodes(image)]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "container", "name": image}},
            "components": comps}
