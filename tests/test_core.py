"""
Unit tests for the ported core logic — no AWS, no network.
Validates attribution, SLA, KEV/EPSS fast-track, unit grouping, gate + waivers.
Requirements: 2, 3, 4, 5, 8.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "common"))

import core  # noqa: E402

POLICY = {
    "today": "2026-02-20",
    "sla": {"target_days": 15, "breach_days": 30, "measure_from": "firstSeen"},
    "gate": {"block_on": ["CRITICAL", "HIGH"], "exception_requires_approval": True},
    "fast_track": {"kev": True, "epss_threshold": 0.5},
    "fast_track_days": 7,
    "staleness": {"mutable_tag_prod_warn_days": 14},
}

BASE_IMAGES = {
    "shared-base-images/al2023-python": {"fixed_tag_available": "2026.02.4", "downstream_image_count": 142},
    "shared-base-images/al2023-node": {"fixed_tag_available": "2026.02.4", "downstream_image_count": 118},
    "shared-base-images/dotnet-aspnet": {"fixed_tag_available": "8.0.3", "downstream_image_count": 86},
}

FINDINGS = [
    {  # base, KEV, old -> OVERDUE, fast-tracked
        "id": "f1", "cve": "CVE-2024-21626", "severity": "CRITICAL", "epss": 0.78, "kev": True,
        "package": "runc", "installedVersion": "1.1.4", "fixedVersion": "1.1.12",
        "layerType": "base", "baseImage": "shared-base-images/al2023-python",
        "repo": "rwd/ingest", "account": "a1", "imageTag": "latest", "mutableTag": True,
        "firstSeen": "2026-02-02", "businessUnit": "RWD", "runningInProd": True,
    },
    {  # app, HIGH, recent -> ON_TRACK
        "id": "f2", "cve": "CVE-2023-50782", "severity": "HIGH", "epss": 0.12, "kev": False,
        "package": "cryptography", "installedVersion": "41.0.4", "fixedVersion": "42.0.0",
        "layerType": "app", "baseImage": "shared-base-images/al2023-python",
        "repo": "rwd/cohort", "account": "a1", "imageTag": "sha-9f2c", "mutableTag": False,
        "firstSeen": "2026-02-18", "businessUnit": "RWD", "runningInProd": True,
    },
    {  # base, MEDIUM -> PASS at gate (not blocked)
        "id": "f3", "cve": "CVE-2022-40897", "severity": "MEDIUM", "epss": 0.02, "kev": False,
        "package": "setuptools", "installedVersion": "65.5.0", "fixedVersion": "65.5.1",
        "layerType": "base", "baseImage": "shared-base-images/al2023-node",
        "repo": "cite/trials", "account": "a2", "imageTag": "2026.02", "mutableTag": False,
        "firstSeen": "2026-02-17", "businessUnit": "Citeline", "runningInProd": False,
    },
    {  # base, HIGH, waived in test
        "id": "f4", "cve": "CVE-2023-39325", "severity": "HIGH", "epss": 0.55, "kev": False,
        "package": "golang", "installedVersion": "1.21.1", "fixedVersion": "1.21.3",
        "layerType": "base", "baseImage": "shared-base-images/dotnet-aspnet",
        "repo": "cite/search", "account": "a2", "imageTag": "8.0.2", "mutableTag": False,
        "firstSeen": "2026-02-10", "businessUnit": "Citeline", "runningInProd": True,
    },
]

WAIVERS = [
    {"cve": "CVE-2023-39325", "repo": "cite/search", "approved_by": "InfoSec: a.rao",
     "approved_on": "2026-02-18", "expires_on": "2026-03-20", "justification": "not reachable"},
]


def test_attribution_and_base_pct():
    enriched = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    s = core.summarize(enriched, core.build_units(enriched, BASE_IMAGES))
    assert s["base_layer_findings"] == 3
    assert s["app_layer_findings"] == 1
    assert s["base_layer_pct"] == 75


def test_sla_status_and_fast_track():
    enriched = {f["id"]: f for f in core.enrich(FINDINGS, POLICY, BASE_IMAGES)}
    # f1: KEV -> 7-day SLA, firstSeen 2026-02-02, age 18 -> OVERDUE, fast_tracked
    assert enriched["f1"]["fast_tracked"] is True
    assert enriched["f1"]["sla_status"] == "OVERDUE"
    # f2: HIGH non-KEV low EPSS -> 15-day, age 2 -> ON_TRACK, not fast-tracked
    assert enriched["f2"]["fast_tracked"] is False
    assert enriched["f2"]["sla_status"] == "ON_TRACK"


def test_stale_mutable_prod_flag():
    enriched = {f["id"]: f for f in core.enrich(FINDINGS, POLICY, BASE_IMAGES)}
    # f1: mutable + prod + age 18 >= 14 -> stale
    assert enriched["f1"]["stale_mutable_prod"] is True
    # f2: not mutable -> not stale
    assert enriched["f2"]["stale_mutable_prod"] is False


def test_priority_orders_kev_first():
    enriched = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    assert enriched[0]["id"] == "f1"  # KEV + OVERDUE + prod -> top


def test_units_group_base_by_image():
    enriched = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    units = core.build_units(enriched, BASE_IMAGES)
    base_units = [u for u in units if u["type"] == "base"]
    # f1 (python) + f3 (node) + f4 (dotnet) -> 3 base units; f2 -> 1 app unit
    assert len(base_units) == 3
    py = next(u for u in base_units if u["target"] == "shared-base-images/al2023-python")
    assert py["downstream_image_count"] == 142
    assert py["fixed_tag"] == "2026.02.4"


def test_gate_block_waive_pass():
    enriched = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    decisions = core.gate_decisions(enriched, POLICY, WAIVERS)
    by_id = {d["finding_id"]: d for d in decisions}
    assert by_id["f1"]["decision"] == "BLOCK"    # CRITICAL, no waiver
    assert by_id["f2"]["decision"] == "BLOCK"    # HIGH, no waiver
    assert by_id["f3"]["decision"] == "PASS"     # MEDIUM, not in block list
    assert by_id["f4"]["decision"] == "WAIVED"   # HIGH but waived
    assert core.gate_verdict(decisions) == "BLOCKED"


def test_waiver_reason_has_approver_and_expiry():
    enriched = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    decisions = core.gate_decisions(enriched, POLICY, WAIVERS)
    waived = next(d for d in decisions if d["decision"] == "WAIVED")
    assert "a.rao" in waived["reason"]
    assert "2026-03-20" in waived["reason"]


def test_deterministic_repeatable():
    a = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    b = core.enrich(FINDINGS, POLICY, BASE_IMAGES)
    assert [x["id"] for x in a] == [x["id"] for x in b]
    assert [x["priority_score"] for x in a] == [x["priority_score"] for x in b]
