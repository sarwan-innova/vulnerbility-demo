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
            "baseImage": base_ref, "result": {"osPackages": os_pkgs, "libraries": libs}}
