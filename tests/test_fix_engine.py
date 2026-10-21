"""
Unit tests for the deterministic fix engine and the CodeBuild fixer script
(Phase 3: fully automated fixes). No AWS, no network.
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "lambda", "common"))

import fix_engine  # noqa: E402
import promotion  # noqa: E402

BASE = "shared-base-images/al2023-python"
FINDINGS = [
    {"cve": "CVE-2024-21626", "severity": "CRITICAL", "layerType": "base", "baseImage": BASE,
     "package": "runc", "fixedVersion": "1.1.12"},
    {"cve": "CVE-2024-2961", "severity": "HIGH", "layerType": "base", "baseImage": BASE,
     "package": "glibc", "fixedVersion": "2.34-100"},
    {"cve": "CVE-2023-50782", "severity": "HIGH", "layerType": "app", "package": "cryptography",
     "installedVersion": "41.0.4", "fixedVersion": "42.0.0"},
]
BASE_IMAGES = {BASE: {"fixed_tag_available": "2026.02.4", "downstream_image_count": 142}}


def spec_for(findings=FINDINGS, base_images=BASE_IMAGES):
    plan = promotion.plan_remediation("team/app:latest", findings, base_images)
    return fix_engine.build_fix_spec("team/app:latest", "wf1", plan)


# ---------------------------------------------------------------- spec + validation
def test_spec_from_plan():
    spec = spec_for()
    assert spec["target_image"] == "team/app:fix-wf1"
    assert spec["base_changes"] == [{"base_image": BASE, "to_tag": "2026.02.4",
                                     "cves": ["CVE-2024-21626", "CVE-2024-2961"]}]
    assert spec["dependency_changes"][0]["package"] == "cryptography"
    assert spec["dependency_changes"][0]["to_version"] == "42.0.0"
    assert fix_engine.validate_fix_spec(spec, FINDINGS) == []
    assert fix_engine.fixed_cves(spec) == {"CVE-2024-21626", "CVE-2024-2961", "CVE-2023-50782"}


def test_missing_fixed_tag_or_version_is_unsupported():
    spec = spec_for(findings=FINDINGS[:1] + [dict(FINDINGS[2], fixedVersion=None)], base_images={})
    assert spec["base_changes"] == [] and spec["dependency_changes"] == []
    reasons = {u["reason"] for u in spec["unsupported"]}
    assert reasons == {"no fixed base tag published yet", "no fixed version available"}


def test_validation_rejects_changes_without_backing_findings():
    spec = spec_for()
    spec["dependency_changes"].append({"package": "requests", "to_version": "9.9.9",
                                       "cves": ["CVE-2023-50782"]})
    spec["dependency_changes"][0]["to_version"] = "43.0.0"
    spec["base_changes"].append({"base_image": "evil/base", "to_tag": "1", "cves": ["CVE-2024-21626"]})
    problems = fix_engine.validate_fix_spec(spec, FINDINGS)
    assert any("requests" in p for p in problems)
    assert any("cryptography" in p and "not the Wiz fixed version" in p for p in problems)
    assert any("evil/base" in p for p in problems)


def test_validation_rejects_overwriting_source_image():
    spec = spec_for()
    spec["target_image"] = spec["source_image"]
    assert "target image must differ" in " ".join(fix_engine.validate_fix_spec(spec, FINDINGS))


# ---------------------------------------------------------------- patchers
@pytest.mark.parametrize("line,expected", [
    (f"FROM {BASE}:2026.02.1", f"FROM {BASE}:2026.02.4"),
    (f"FROM 111.dkr.ecr.us-east-1.amazonaws.com/{BASE}:2026.02.1 AS build",
     f"FROM 111.dkr.ecr.us-east-1.amazonaws.com/{BASE}:2026.02.4 AS build"),
    (f"FROM --platform=linux/amd64 {BASE}", f"FROM --platform=linux/amd64 {BASE}:2026.02.4"),
    (f"FROM {BASE}:old@sha256:abc", f"FROM {BASE}:2026.02.4"),
])
def test_patch_dockerfile(line, expected):
    new, changed = fix_engine.patch_dockerfile(line + "\nRUN echo hi\n", BASE, "2026.02.4")
    assert changed and new.splitlines()[0] == expected and "RUN echo hi" in new


def test_patch_dockerfile_leaves_other_bases_alone():
    content = "FROM shared-base-images/al2023-node:1\n"
    assert fix_engine.patch_dockerfile(content, BASE, "2")[1] is False


def test_patch_requirements():
    content = ("flask==3.0.0\ncryptography==41.0.4  # pinned\ncryptography-extra==1.0\n"
               "Cryptography[ssh]>=41,<42 ; python_version>'3.8'\n")
    new, changed = fix_engine.patch_requirements(content, "cryptography", "42.0.0")
    lines = new.splitlines()
    assert changed
    assert lines[1] == "cryptography==42.0.0  # pinned"
    assert lines[2] == "cryptography-extra==1.0"              # different package untouched
    assert lines[3].startswith("Cryptography[ssh]==42.0.0")   # extras kept, case-insensitive
    assert lines[0] == "flask==3.0.0"


def test_patch_package_json_keeps_range_prefix():
    content = json.dumps({"dependencies": {"lodash": "^4.17.0", "x": "1"},
                          "devDependencies": {"lodash-es": "4.0.0"}}, indent=2) + "\n"
    new, changed = fix_engine.patch_package_json(content, "lodash", "4.17.21")
    data = json.loads(new)
    assert changed and data["dependencies"]["lodash"] == "^4.17.21"
    assert data["devDependencies"]["lodash-es"] == "4.0.0" and new.endswith("\n")
    assert fix_engine.patch_package_json(new, "lodash", "4.17.21")[1] is False  # idempotent


def test_patch_csproj():
    content = '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
    new, changed = fix_engine.patch_csproj(content, "Newtonsoft.Json", "13.0.1")
    assert changed and 'Version="13.0.1"' in new


@pytest.mark.parametrize("name,kind", [
    ("Dockerfile", "dockerfile"), ("svc/api.Dockerfile", "dockerfile"),
    ("requirements-prod.txt", "requirements"), ("web/package.json", "package_json"),
    ("src/App.csproj", "csproj"), ("README.md", None), ("package-lock.json", None),
])
def test_patcher_for(name, kind):
    assert fix_engine.patcher_for(name) == kind


# ---------------------------------------------------------------- fixer script (CodeBuild)
def test_fixer_script_applies_spec_to_a_checkout(tmp_path):
    repo = tmp_path / "app"
    (repo / "src").mkdir(parents=True)
    (repo / "Dockerfile").write_text(f"FROM {BASE}:2026.02.1\nCOPY . /app\n")
    (repo / "src" / "requirements.txt").write_text("cryptography==41.0.4\n")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "requirements.txt").write_text("cryptography==1\n")  # skipped dir
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec_for()))

    proc = subprocess.run([sys.executable, os.path.join(ROOT, "fixer", "apply_fix_spec.py"),
                           str(spec_file), str(repo)], cwd=tmp_path, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert (repo / "Dockerfile").read_text().startswith(f"FROM {BASE}:2026.02.4")
    assert (repo / "src" / "requirements.txt").read_text() == "cryptography==42.0.0\n"
    assert (repo / "node_modules" / "requirements.txt").read_text() == "cryptography==1\n"
    assert json.loads((tmp_path / "fix-result.json").read_text())["missing"] == []


def test_fixer_script_fails_when_a_change_lands_nowhere(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "Dockerfile").write_text(f"FROM {BASE}:2026.02.1\n")  # no requirements file
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec_for()))
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "fixer", "apply_fix_spec.py"),
                           str(spec_file), str(repo)], cwd=tmp_path, capture_output=True, text=True)
    assert proc.returncode != 0 and "package cryptography" in proc.stderr
