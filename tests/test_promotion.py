"""
Unit tests for the pure promotion state logic — no AWS, no network.
Requirements: 9.2-9.7, 9.10.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "common"))

import promotion  # noqa: E402

POLICY = {"gate": {"block_on": ["CRITICAL", "HIGH"]}}

BASE_IMAGES = {
    "shared-base-images/al2023-python": {"fixed_tag_available": "2026.02.4", "downstream_image_count": 142},
}

FINDINGS = [
    {"cve": "CVE-2024-21626", "severity": "CRITICAL", "layerType": "base",
     "baseImage": "shared-base-images/al2023-python"},
    {"cve": "CVE-2024-2961", "severity": "HIGH", "layerType": "base",
     "baseImage": "shared-base-images/al2023-python"},
    {"cve": "CVE-2023-50782", "severity": "HIGH", "layerType": "app",
     "package": "cryptography", "installedVersion": "41.0.4", "fixedVersion": "42.0.0"},
]


def test_plan_groups_base_rebuild_and_app_bump():
    plan = promotion.plan_remediation("rwd/ingest:latest", FINDINGS, BASE_IMAGES)
    assert plan["primary_path"] == "base-image-rebuild"
    base_actions = [a for a in plan["actions"] if a["type"] == "base-image-rebuild"]
    app_actions = [a for a in plan["actions"] if a["type"] == "app-dependency-bump"]
    assert len(base_actions) == 1
    assert base_actions[0]["fixed_tag"] == "2026.02.4"
    assert base_actions[0]["downstream_image_count"] == 142
    assert set(base_actions[0]["fixes"]) == {"CVE-2024-21626", "CVE-2024-2961"}
    assert len(app_actions) == 1
    assert app_actions[0]["to_version"] == "42.0.0"


def test_verify_pass_after_full_fix():
    plan = promotion.plan_remediation("img", FINDINGS, BASE_IMAGES)
    remaining = promotion.simulate_fixed_findings(FINDINGS, plan)
    result, blocking = promotion.verify_result(remaining, POLICY)
    assert remaining == []
    assert result == "PASS"
    assert blocking == []


def test_verify_fail_when_blocking_remains():
    # a residual HIGH not covered by the plan
    after = [{"cve": "CVE-9999-0001", "severity": "HIGH", "layerType": "app"}]
    result, blocking = promotion.verify_result(after, POLICY)
    assert result == "FAIL"
    assert len(blocking) == 1


def test_happy_path_transitions():
    s = promotion.initial_state()
    assert s == "SCAN"
    for expected in ["APPLY_FIX", "DEPLOY_DEV", "VERIFY", "AWAIT_APPROVAL"]:
        s = promotion.advance(s, "ok")
        assert s == expected
    s = promotion.advance(s, "approve")
    assert s == "PROMOTE_PROD"
    s = promotion.advance(s, "ok")
    assert s == "DONE"


def test_verify_fail_stops_before_approval():
    s = "VERIFY"
    s = promotion.advance(s, "verify_fail")
    assert s == "FAILED"
    # terminal: no further movement
    assert promotion.advance(s, "ok") == "FAILED"


def test_reject_stops_at_approval():
    s = "AWAIT_APPROVAL"
    s = promotion.advance(s, "reject")
    assert s == "REJECTED"
    assert promotion.advance(s, "approve") == "REJECTED"


def test_stage_index_monotonic():
    idxs = [promotion.stage_index(s) for s in
            ["SCAN", "APPLY_FIX", "DEPLOY_DEV", "VERIFY", "AWAIT_APPROVAL", "PROMOTE_PROD", "DONE"]]
    assert idxs == sorted(idxs)
    assert idxs[0] == 0
