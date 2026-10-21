"""
Trivy -> wizcli adapter (local real scanning, until Wiz credentials exist).

Converts `trivy image --format json` output into the wizcli result shape that
wiz_client.normalize_wizcli_result() already consumes, so the platform code
path is identical to a real wizcli scan.

Layer attribution works like Wiz's: a vulnerability whose layer DiffID belongs
to the BASE image (from the OCI label org.opencontainers.image.base.name) is a
base-layer finding; everything added on top is app-layer. Without base layer
info it falls back to OS packages = base, language packages = app.
Trivy has no KEV/EPSS data, so those are left false/0.

Besides vulnerabilities, the scan reports
  secrets            credentials/keys baked into a layer (`--scanners secret`):
                     rule, file, line and layer, never the matched value
  misconfigurations  failed image-config checks (`--image-config-scanners misconfig`),
                     e.g. DS002 "image runs as root"
"""

import fix_engine

BASE_LABEL = "org.opencontainers.image.base.name"
SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low",
            "UNKNOWN": "Low"}


def base_image_ref(trivy_json):
    labels = (((trivy_json.get("Metadata") or {}).get("ImageConfig") or {})
              .get("config") or {}).get("Labels") or {}
    return labels.get(BASE_LABEL)


def to_wizcli(trivy_json, base_layers=None, base_ref=None):
    """trivy JSON -> {"result": {"osPackages": [...], "libraries": [...]}}"""
    base_ref = base_ref or base_image_ref(trivy_json)
    base_layers = set(base_layers or [])
    details = f"FROM {base_ref}" if base_ref else ""
    groups = {}
    for res in trivy_json.get("Results") or []:
        is_os = res.get("Class") == "os-pkgs"
        for v in res.get("Vulnerabilities") or []:
            diff_id = (v.get("Layer") or {}).get("DiffID")
            is_base = (diff_id in base_layers) if (base_layers and diff_id) else is_os
            key = (v.get("PkgName"), v.get("InstalledVersion"), is_base, is_os)
            pkg = groups.setdefault(key, {
                "name": v.get("PkgName"), "version": v.get("InstalledVersion"),
                "layerMetadata": {"id": diff_id or "", "isBaseLayer": is_base,
                                  "details": details if is_base else res.get("Target", "")},
                "vulnerabilities": [], "_os": is_os,
            })
            if any(x["name"] == v.get("VulnerabilityID") for x in pkg["vulnerabilities"]):
                continue  # trivy repeats a CVE per target path
            pkg["vulnerabilities"].append({
                "name": v.get("VulnerabilityID"),
                "severity": SEVERITY.get(v.get("Severity", "UNKNOWN"), "Low"),
                "fixedVersion": fix_engine.pick_fixed_version(v.get("InstalledVersion"),
                                                              v.get("FixedVersion")),
                "hasExploit": False, "hasCisaKevExploit": False, "epssProbability": 0.0,
                "title": v.get("Title"),
            })
    os_pkgs, libs = [], []
    for p in groups.values():
        (os_pkgs if p.pop("_os") else libs).append(p)
    return {"id": trivy_json.get("ArtifactName"), "scanner": "trivy",
            "baseImage": base_ref, "result": {
                "osPackages": os_pkgs, "libraries": libs,
                "secrets": _secrets(trivy_json, base_layers, details),
                "misconfigurations": _misconfigurations(trivy_json)}}


def _secrets(trivy_json, base_layers, details):
    out, seen = [], set()
    for res in trivy_json.get("Results") or []:
        for s in res.get("Secrets") or []:
            path = "/" + (res.get("Target") or "").lstrip("/")
            key = (s.get("RuleID"), path, s.get("StartLine"))
            if key in seen:
                continue
            seen.add(key)
            diff_id = (s.get("Layer") or {}).get("DiffID")
            is_base = bool(base_layers and diff_id in base_layers)
            out.append({   # Trivy's Match (the secret itself, partly masked) is dropped
                "rule": s.get("RuleID"), "category": s.get("Category"),
                "title": s.get("Title"),
                "severity": SEVERITY.get(s.get("Severity", "UNKNOWN"), "Low"),
                "path": path, "line": s.get("StartLine"),
                "layerMetadata": {"id": diff_id or "", "isBaseLayer": is_base,
                                  "details": details if is_base else ""},
            })
    return out


def _misconfigurations(trivy_json):
    out, seen = [], set()
    for res in trivy_json.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            if (m.get("Status") or "FAIL") != "FAIL":
                continue
            rule = m.get("ID") or m.get("AVDID")
            if (rule, res.get("Target")) in seen:
                continue
            seen.add((rule, res.get("Target")))
            out.append({
                "rule": rule, "title": m.get("Title"),
                "severity": SEVERITY.get(m.get("Severity", "UNKNOWN"), "Low"),
                "target": res.get("Target") or "image config",
                "message": m.get("Message"), "resolution": m.get("Resolution"),
            })
    return out
