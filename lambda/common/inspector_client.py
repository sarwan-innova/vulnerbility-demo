"""
Amazon Inspector (ECR enhanced scanning) as the scanner until Wiz credentials
exist. Requirement 9.2 / scanner switch SCANNER=inspector.

Inspector scans every image pushed to ECR (scan on push) and emits an
"Inspector2 Scan" event when done. fetch_result() pulls the ACTIVE package
findings for one image and converts them to the wizcli result shape, so the
rest of the platform (scanner.finalize -> normalize -> gate/report) is the same
for Inspector, wizcli and Trivy.

Layer attribution: Inspector reports each vulnerable package's sourceLayerHash.
A package whose layer is one of the image's BASE layers (first N manifest
layers, N recorded at build time — see ecr_meta.py) is a base-layer finding.
Unlike Trivy, Inspector gives EPSS and exploit data: exploitAvailable ->
hasExploit, exploitabilityDetails.lastKnownExploitAt -> known exploited (KEV-like).
"""

SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low",
            "INFORMATIONAL": "Low", "UNTRIAGED": "Low"}
OS_PACKAGE_MANAGERS = {"OS", "APK", "DPKG", "RPM", "DEB"}


def list_image_findings(inspector, repository, digest):
    """All ACTIVE package-vulnerability findings for one ECR image (paged)."""
    criteria = {
        "ecrImageRepositoryName": [{"comparison": "EQUALS", "value": repository}],
        "ecrImageHash": [{"comparison": "EQUALS", "value": digest}],
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
    }
    out, token = [], None
    while True:
        kwargs = {"filterCriteria": criteria, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = inspector.list_findings(**kwargs)
        out.extend(resp.get("findings", []))
        token = resp.get("nextToken")
        if not token:
            return out


def _version(pkg):
    v = pkg.get("version") or ""
    return f"{v}-{pkg['release']}" if pkg.get("release") else v


def _fixed(pkg):
    fixed = pkg.get("fixedInVersion")
    return None if not fixed or fixed in ("NotAvailable", "None") else fixed


def to_wizcli(findings, base_layers=None, base_ref=None):
    """Inspector findings -> {"result": {"osPackages": [...], "libraries": [...]}}"""
    base_layers = set(base_layers or [])
    details = f"FROM {base_ref}" if base_ref else ""
    groups = {}
    for f in findings:
        d = f.get("packageVulnerabilityDetails") or {}
        cve = d.get("vulnerabilityId")
        exploit = f.get("exploitabilityDetails") or {}
        for pkg in d.get("vulnerablePackages") or []:
            is_os = (pkg.get("packageManager") or "").upper() in OS_PACKAGE_MANAGERS
            layer = pkg.get("sourceLayerHash")
            is_base = (layer in base_layers) if (base_layers and layer) else is_os
            key = (pkg.get("name"), _version(pkg), is_base, is_os)
            entry = groups.setdefault(key, {
                "name": pkg.get("name"), "version": _version(pkg),
                "layerMetadata": {"id": layer or "", "isBaseLayer": is_base,
                                  "details": details if is_base else (pkg.get("filePath") or "")},
                "vulnerabilities": [], "_os": is_os,
            })
            if any(v["name"] == cve for v in entry["vulnerabilities"]):
                continue
            entry["vulnerabilities"].append({
                "name": cve,
                "severity": SEVERITY.get(f.get("severity", "LOW"), "Low"),
                "fixedVersion": _fixed(pkg),
                "hasExploit": f.get("exploitAvailable") == "YES",
                "hasCisaKevExploit": bool(exploit.get("lastKnownExploitAt")),
                "epssProbability": float((f.get("epss") or {}).get("score") or 0.0),
                "title": f.get("title"),
            })
    os_pkgs, libs = [], []
    for p in groups.values():
        (os_pkgs if p.pop("_os") else libs).append(p)
    return {"scanner": "inspector", "baseImage": base_ref,
            "result": {"osPackages": os_pkgs, "libraries": libs}}
