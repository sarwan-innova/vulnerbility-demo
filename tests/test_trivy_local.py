"""
Tests for local REAL-scan mode: version picking, merged dependency bumps, the
Trivy -> wizcli adapter, and the full real-mode workflow wiring
(scan Lambda LIVE path, apply_fix build_env, fix build, verify prepare/finalize)
driven through a fake LocalCodeBuild — so no Podman or Trivy is needed here.
"""

import copy
import os
import sys
import time

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "lambda", "common"))
sys.path.insert(0, os.path.join(ROOT, "local"))

import fix_engine  # noqa: E402
import promotion  # noqa: E402
import trivy_adapter  # noqa: E402
import wiz_client  # noqa: E402
from local_codebuild import LocalCodeBuild  # noqa: E402

BASE_REF = "docker.io/library/python:3.9-alpine3.16"
TRIVY = {
    "ArtifactName": "localhost/demo/vuln-api:1.0",
    "Metadata": {"ImageConfig": {"config": {"Labels": {trivy_adapter.BASE_LABEL: BASE_REF}}}},
    "Results": [
        {"Target": "python:3.9-alpine3.16 (alpine 3.16.7)", "Class": "os-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-5363", "PkgName": "libssl1.1", "InstalledVersion": "1.1.1u-r1",
             "FixedVersion": "1.1.1w-r1", "Severity": "HIGH", "Layer": {"DiffID": "sha256:base1"}}]},
        {"Target": "Python", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-6345", "PkgName": "setuptools", "InstalledVersion": "58.1.0",
             "FixedVersion": "70.0.0", "Severity": "HIGH", "Layer": {"DiffID": "sha256:base1"}},
            {"VulnerabilityID": "CVE-2023-50782", "PkgName": "cryptography", "InstalledVersion": "41.0.4",
             "FixedVersion": "42.0.0", "Severity": "HIGH", "Layer": {"DiffID": "sha256:app1"}},
            {"VulnerabilityID": "CVE-2024-26130", "PkgName": "cryptography", "InstalledVersion": "41.0.4",
             "FixedVersion": "42.0.4", "Severity": "HIGH", "Layer": {"DiffID": "sha256:app1"}},
            {"VulnerabilityID": "CVE-2023-32681", "PkgName": "requests", "InstalledVersion": "2.25.1",
             "FixedVersion": "2.31.0, 2.3.0", "Severity": "MEDIUM", "Layer": {"DiffID": "sha256:app1"}}]},
        {"Target": "usr/local/lib/python3.9/site-packages/other", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-50782", "PkgName": "cryptography", "InstalledVersion": "41.0.4",
             "FixedVersion": "42.0.0", "Severity": "HIGH", "Layer": {"DiffID": "sha256:app1"}}]},
    ],
}


# ---------------------------------------------------------------- versions + plan merge
@pytest.mark.parametrize("installed,cands,expected", [
    ("2.2.2", "2.2.5, 2.3.2", "2.2.5"),
    ("2.25.1", "2.31.0, 2.3.0", "2.31.0"),
    ("1.1.1u-r1", "1.1.1w-r1", "1.1.1w-r1"),
    ("9.0", "1.0", "1.0"),        # nothing above installed: largest listed
    ("1.0", "", None),
])
def test_pick_fixed_version(installed, cands, expected):
    assert fix_engine.pick_fixed_version(installed, cands) == expected


def test_version_key_orders_numerically():
    assert fix_engine.version_key("42.0.4") > fix_engine.version_key("42.0.0")
    assert fix_engine.version_key("2.34-100") > fix_engine.version_key("2.34-52")
    assert fix_engine.version_key("1.26.18") > fix_engine.version_key("1.26.5")


def test_plan_merges_bumps_per_package_to_highest_fix():
    findings = [
        {"cve": "A", "severity": "HIGH", "layerType": "app", "package": "cryptography",
         "installedVersion": "41.0.4", "fixedVersion": "42.0.0"},
        {"cve": "B", "severity": "HIGH", "layerType": "app", "package": "cryptography",
         "installedVersion": "41.0.4", "fixedVersion": "42.0.4"},
        {"cve": "C", "severity": "LOW", "layerType": "app", "package": "cryptography",
         "installedVersion": "41.0.4", "fixedVersion": None},
    ]
    plan = promotion.plan_remediation("a/b:1", findings, {})
    bumps = plan["actions"]
    assert bumps[0] == {"type": "app-dependency-bump", "package": "cryptography",
                        "from_version": "41.0.4", "to_version": "42.0.4", "fixes": ["A", "B"]}
    assert bumps[1]["to_version"] is None and bumps[1]["fixes"] == ["C"]
    spec = fix_engine.build_fix_spec("a/b:1", "w", plan)
    assert fix_engine.validate_fix_spec(spec, findings) == []
    assert spec["unsupported"][0]["reason"] == "no fixed version available"
    spec["dependency_changes"][0]["to_version"] = "42.0.0"   # would leave CVE B open
    assert "does not reach every fixed version" in " ".join(fix_engine.validate_fix_spec(spec, findings))


# ---------------------------------------------------------------- trivy adapter
def _findings(result, base_names=("library/python",)):
    return {(f["cve"], f["package"]): f for f in
            wiz_client.normalize_wizcli_result(result, "demo/vuln-api:1.0", list(base_names))}


def test_adapter_splits_layers_by_base_diff_ids():
    fs = _findings(trivy_adapter.to_wizcli(TRIVY, base_layers=["sha256:base1"]))
    assert len(fs) == 5                                     # duplicate target row collapsed
    assert fs[("CVE-2023-5363", "libssl1.1")]["layerType"] == "base"
    assert fs[("CVE-2024-6345", "setuptools")]["layerType"] == "base"   # pip pkg in base layer
    assert fs[("CVE-2024-6345", "setuptools")]["baseImage"] == "library/python"
    assert fs[("CVE-2023-50782", "cryptography")]["layerType"] == "app"
    assert fs[("CVE-2023-32681", "requests")]["fixedVersion"] == "2.31.0"
    assert fs[("CVE-2023-32681", "requests")]["severity"] == "MEDIUM"
    assert all(f["kev"] is False and f["epss"] == 0.0 for f in fs.values())


def test_adapter_falls_back_to_package_class_without_layers():
    fs = _findings(trivy_adapter.to_wizcli(TRIVY))
    assert fs[("CVE-2023-5363", "libssl1.1")]["layerType"] == "base"
    assert fs[("CVE-2024-6345", "setuptools")]["layerType"] == "app"   # lang pkg -> app


# ---------------------------------------------------------------- real-mode workflow (fake engine)
class FakeEngine(LocalCodeBuild):
    """LocalCodeBuild with the podman/trivy calls replaced: the original image has
    TRIVY's findings; a fix-* image drops what the applied fix spec fixed."""

    def __init__(self):
        super().__init__(None, log=lambda *a: None)
        self.built, self.specs = [], []

    def image_exists(self, ref):
        return True

    def build(self, context, ref):
        self.built.append(ref)
        return BASE_REF

    def scan(self, image_uri, output_prefix):
        raw = copy.deepcopy(TRIVY)
        if ":fix-" in image_uri:
            spec = self.specs[-1]
            bumped = {c["package"]: c["to_version"] for c in spec["dependency_changes"]}
            for res in raw["Results"]:
                res["Vulnerabilities"] = [
                    v for v in res["Vulnerabilities"]
                    if not (v["Layer"]["DiffID"] == "sha256:base1" and spec["base_changes"])
                    and not (v["PkgName"] in bumped and fix_engine.version_key(bumped[v["PkgName"]])
                             >= fix_engine.version_key(fix_engine.pick_fixed_version(
                                 v["InstalledVersion"], v["FixedVersion"])))]
        prefix = self._key(output_prefix)
        self.store.put_json_report(f"{prefix}/results.json",
                                   trivy_adapter.to_wizcli(raw, base_layers=["sha256:base1"]))
        self.store.put_json_report(f"{prefix}/sbom.cdx.json", {"bomFormat": "CycloneDX"})

    def fix_build(self, env):
        self.specs.append(self.store.get_json_report(self._key(env["FIX_SPEC_S3"])))
        assert env["SOURCE_REPO_URL"].endswith("demo-app") and env["ECR_REGISTRY"] == "localhost"
        self.built.append(f"{env['ECR_REGISTRY']}/{env['TARGET_REPO']}:{env['TARGET_TAG']}")


@pytest.fixture
def real_app(tmp_path, monkeypatch):
    from app import LocalApp
    engine = FakeEngine()
    a = LocalApp(step_delay=0, codebuild=engine)
    engine.store = a.store
    monkeypatch.setattr(a.store, "S3_DIR", str(tmp_path / "s3"))
    yield a, engine
    os.environ["WIZ_MOCK"] = "true"   # leave the mock default for other test modules


def _wait(app, wf, states):
    for _ in range(500):
        s = app.call("GET /workflow/{id}", {"id": wf})[1]
        if s["state"] in states:
            return s
        time.sleep(0.02)
    raise AssertionError(s["state"])


def test_real_mode_scan_fix_verify_promote(real_app):
    app, engine = real_app
    seeded = app.seed()
    assert seeded == {"ingested": 5, "source": "trivy", "image": "demo/vuln-api:1.0"}
    imgs = {i["image"]: i for i in app.call("GET /images")[1]["images"]}
    assert set(imgs) == {"demo/vuln-api:1.0"} and imgs["demo/vuln-api:1.0"]["base_layer"]

    body = app.call("GET /image-findings", query={"image": "demo/vuln-api:1.0"})[1]
    plan = body["plan"]
    assert plan["actions"][0]["base_image"] == "library/python"
    assert plan["actions"][0]["fixed_tag"] == "3.12-alpine"
    crypto = next(a for a in plan["actions"] if a.get("package") == "cryptography")
    assert crypto["to_version"] == "42.0.4" and crypto["fixes"] == ["CVE-2023-50782", "CVE-2024-26130"]

    wf = app.call("POST /remediate", body={"image": "demo/vuln-api:1.0"})[1]["workflowId"]
    s = _wait(app, wf, {"AWAIT_APPROVAL", "FAILED"})
    assert s["state"] == "AWAIT_APPROVAL", s.get("failure")
    assert engine.built == [f"localhost/demo/vuln-api:fix-{wf}"]
    spec = engine.specs[-1]
    assert spec["base_changes"][0]["to_tag"] == "3.12-alpine"
    assert {c["package"]: c["to_version"] for c in spec["dependency_changes"]} == \
        {"cryptography": "42.0.4", "requests": "2.31.0"}
    assert s["verify_result"] == "PASS" and s["verify_summary"]["total"] == 0

    app.call("POST /approve", body={"workflowId": wf, "decision": "approve"})
    assert _wait(app, wf, {"DONE", "FAILED"})["state"] == "DONE"
    assert app.call("GET /images")[1]["images"] == []


def test_real_mode_fix_build_failure_marks_workflow_failed(real_app):
    app, engine = real_app
    app.seed()

    def boom(env):
        raise RuntimeError("pip could not resolve cryptography==42.0.4")
    engine.fix_build = boom
    wf = app.call("POST /remediate", body={"image": "demo/vuln-api:1.0"})[1]["workflowId"]
    s = _wait(app, wf, {"FAILED", "AWAIT_APPROVAL"})
    assert s["state"] == "FAILED" and s["failed_stage"] == "APPLY_FIX"
    assert "pip could not resolve" in s["failure"]
