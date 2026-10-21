"""
Repo-aware mock scanner + mock CodeBuild for the local push -> build -> scan loop.

The "image" of a commit is its files: the Dockerfile's FROM decides the base
layer's vulnerabilities, requirements.txt pins decide the app layer's. So an
AI fix that changes those files really changes the next scan — the loop
behaves like the real one without Docker, ECR or a scanner account.

VULN_DB is small local DEMO DATA modelled on real advisories (base-image rows
come from a real Trivy scan of the same tags). It is not authoritative.
"""

import re
import uuid

import fix_engine

BASE_DB = {
    "public.ecr.aws/docker/library/python:3.9-alpine3.16": [
        ("CVE-2023-52425", "HIGH", "expat", "2.5.0-r0", "2.6.0-r0"),
        ("CVE-2024-28757", "HIGH", "expat", "2.5.0-r0", "2.6.2-r0"),
        ("CVE-2025-26519", "HIGH", "musl", "1.2.3-r2", "1.2.3-r4"),
        ("CVE-2023-29491", "HIGH", "ncurses-libs", "6.3_p20220521-r0", "6.3_p20220521-r1"),
        ("CVE-2023-7104", "HIGH", "sqlite-libs", "3.40.1-r0", "3.40.1-r1"),
        ("CVE-2022-40897", "HIGH", "setuptools", "58.1.0", "65.5.1"),
        ("CVE-2023-5678", "MEDIUM", "libssl1.1", "1.1.1u-r1", "1.1.1w-r1"),
    ],
    "public.ecr.aws/docker/library/python:3.12-alpine": [
        ("CVE-2025-8869", "MEDIUM", "pip", "25.0.1", "25.3"),
        ("CVE-2026-85091", "MEDIUM", "zlib", "1.3.2-r0", "1.3.2-r1"),
    ],
}
PKG_DB = {
    "cryptography": [("CVE-2023-50782", "HIGH", "42.0.0", 0.02), ("CVE-2024-26130", "HIGH", "42.0.4", 0.01),
                     ("CVE-2024-12797", "MEDIUM", "44.0.1", 0.0)],
    "jinja2": [("CVE-2024-22195", "MEDIUM", "3.1.3", 0.0), ("CVE-2024-56201", "MEDIUM", "3.1.5", 0.0),
               ("CVE-2025-27516", "MEDIUM", "3.1.6", 0.0)],
    "requests": [("CVE-2023-32681", "MEDIUM", "2.31.0", 0.06), ("CVE-2024-35195", "MEDIUM", "2.32.0", 0.0),
                 ("CVE-2024-47081", "MEDIUM", "2.32.4", 0.0)],
    "urllib3": [("CVE-2023-43804", "MEDIUM", "1.26.17", 0.01), ("CVE-2023-45803", "MEDIUM", "1.26.18", 0.0),
                ("CVE-2024-37891", "MEDIUM", "1.26.19", 0.0), ("CVE-2025-50181", "MEDIUM", "2.5.0", 0.0)],
    "idna": [("CVE-2024-3651", "MEDIUM", "3.7", 0.0)],
    "certifi": [("CVE-2023-37920", "HIGH", "2023.7.22", 0.0), ("CVE-2024-39689", "LOW", "2024.7.4", 0.0)],
}


SECRET_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")   # demo: AWS access key ids only


def base_ref(files):
    froms = re.findall(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", files.get("Dockerfile", ""), re.I | re.M)
    return froms[-1] if froms else None


def scan_files(files):
    """Commit files -> wizcli-shaped result."""
    ref = base_ref(files)
    os_pkgs, libs = {}, {}
    for cve, sev, name, ver, fixed in BASE_DB.get(ref, []):
        p = os_pkgs.setdefault((name, ver), {"name": name, "version": ver, "vulnerabilities": [],
                                              "layerMetadata": {"isBaseLayer": True, "details": f"FROM {ref}"}})
        p["vulnerabilities"].append({"name": cve, "severity": sev.capitalize(), "fixedVersion": fixed,
                                     "hasExploit": False, "hasCisaKevExploit": False, "epssProbability": 0.0})
    for path, text in files.items():
        if fix_engine.patcher_for(path) != "requirements":
            continue
        for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", text, re.M):
            name, ver = m.group(1).lower(), m.group(2)
            for cve, sev, fixed, epss in PKG_DB.get(name, []):
                if fix_engine.version_key(ver) < fix_engine.version_key(fixed):
                    p = libs.setdefault((name, ver), {"name": name, "version": ver, "vulnerabilities": [],
                                                      "layerMetadata": {"isBaseLayer": False, "details": path}})
                    p["vulnerabilities"].append({"name": cve, "severity": sev.capitalize(),
                                                 "fixedVersion": fixed, "hasExploit": False,
                                                 "hasCisaKevExploit": False, "epssProbability": epss})
    secrets = [{"rule": "aws-access-key-id", "title": "AWS Access Key ID", "severity": "Critical",
                "path": "/app/" + path, "line": text[:m.start()].count("\n") + 1,
                "layerMetadata": {"isBaseLayer": False}}
               for path, text in files.items() for m in SECRET_RE.finditer(text)]
    misconfig = [] if re.search(r"^\s*HEALTHCHECK\s", files.get("Dockerfile", ""), re.I | re.M) else [
        {"rule": "DS026", "title": "No HEALTHCHECK defined", "severity": "Low",
         "target": "Dockerfile", "resolution": "Add a HEALTHCHECK instruction to the Dockerfile"}]
    return {"scanner": "mock-repo-scanner", "baseImage": ref,
            "result": {"osPackages": list(os_pkgs.values()), "libraries": list(libs.values()),
                       "secrets": secrets, "misconfigurations": misconfig}}


def sbom_files(files):
    comps = [{"type": "library", "name": m.group(1), "version": m.group(2)}
             for path, text in files.items() if fix_engine.patcher_for(path) == "requirements"
             for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", text, re.M)]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "container", "name": base_ref(files)}},
            "components": comps}


class MockCodeBuild:
    """The wizscan project, locally: scans the commit snapshot registered for an image."""

    def __init__(self, store):
        self.store = store
        self.snapshots = {}      # "localhost/<repo>:<tag>" -> files
        self.builds = {}

    def register(self, image_uri, files):
        self.snapshots[image_uri] = files

    def start_build(self, projectName, environmentVariablesOverride=(), **_):
        env = {e["name"]: e["value"] for e in environmentVariablesOverride}
        build_id = f"{projectName}:{uuid.uuid4().hex[:8]}"
        files = self.snapshots.get(env.get("IMAGE_URI"))
        if files is None:
            self.builds[build_id] = {"id": build_id, "buildStatus": "FAILED",
                                     "error": f"no image {env.get('IMAGE_URI')}"}
        else:
            prefix = env["OUTPUT_PREFIX"].split("://", 1)[-1].split("/", 1)[1]
            self.store.put_json_report(f"{prefix}/results.json", scan_files(files))
            self.store.put_json_report(f"{prefix}/sbom.cdx.json", sbom_files(files))
            self.builds[build_id] = {"id": build_id, "buildStatus": "SUCCEEDED"}
        return {"build": dict(self.builds[build_id])}

    def batch_get_builds(self, ids):
        return {"builds": [self.builds[i] for i in ids if i in self.builds]}
