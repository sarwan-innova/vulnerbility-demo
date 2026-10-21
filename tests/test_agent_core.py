"""
Unit tests for the agent core — no AWS, no network (AGENTIC unset => stub path).
Requirements: 10.1-10.3, 10.5, 10.7, 10.8.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "common"))

import agent_core  # noqa: E402
import core  # noqa: E402


def test_triage_stub_is_grounded_and_offline():
    ctx = {"findings": [
        {"cve": "CVE-1", "severity": "CRITICAL", "kev": True},
        {"cve": "CVE-2", "severity": "HIGH", "kev": False},
    ]}
    r = agent_core.invoke_agent("triage", ctx)
    assert r["mode"] == "deterministic"          # no Bedrock configured (Req 10.8)
    assert r["model_id"] == "deterministic-stub"
    assert "KEV" in r["recommendation"] or "CRITICAL" in r["recommendation"]
    assert r["summary"]


def test_planner_stub_reports_base_leverage():
    ctx = {"plan": {"actions": [
        {"type": "base-image-rebuild", "base_image": "shared-base-images/al2023-python",
         "fixed_tag": "2026.02.4", "downstream_image_count": 142, "fixes": ["CVE-1"]},
        {"type": "app-dependency-bump", "package": "cryptography", "to_version": "42.0.0", "fixes": ["CVE-2"]},
    ]}}
    r = agent_core.invoke_agent("planner", ctx)
    assert "142" in r["summary"]
    assert "rebuild" in r["recommendation"]


def test_verifier_never_passes_with_blocking_remaining():
    # Req 10.5: an agent must not recommend promotion while blocking findings remain.
    r = agent_core.invoke_agent("verifier", {"remaining_blocking": ["CVE-9"]})
    assert "NOT PROMOTE" in r["recommendation"].upper() or "DO NOT" in r["recommendation"].upper()


def test_verifier_clean_allows_promotion_pending_approval():
    r = agent_core.invoke_agent("verifier", {"remaining_blocking": []})
    assert "promote" in r["recommendation"].lower()
    assert "approval" in r["rationale"].lower() or "approval" in r["recommendation"].lower()


def test_gate_remains_authority_regardless_of_agent():
    # Even with a (stub) agent recommendation, the deterministic gate decides.
    policy = {"gate": {"block_on": ["CRITICAL", "HIGH"]}, "today": "2026-02-20",
              "sla": {"target_days": 15, "breach_days": 30, "measure_from": "firstSeen"},
              "fast_track": {"kev": True, "epss_threshold": 0.5}, "fast_track_days": 7,
              "staleness": {"mutable_tag_prod_warn_days": 14}}
    findings = [{"id": "f", "cve": "CVE-X", "severity": "CRITICAL", "repo": "r",
                 "firstSeen": "2026-02-10", "layerType": "app", "epss": 0.1, "kev": False}]
    enriched = core.enrich(findings, policy, {})
    decisions = core.gate_decisions(enriched, policy, [])
    # agent might "recommend" promotion, but the gate still BLOCKs the critical
    agent = agent_core.invoke_agent("verifier", {"remaining_blocking": []})
    assert decisions[0]["decision"] == "BLOCK"   # gate authority preserved
    assert core.gate_verdict(decisions) == "BLOCKED"


def test_audit_record_is_safe():
    r = agent_core.invoke_agent("triage", {"findings": [{"cve": "CVE-1", "severity": "HIGH"}]})
    rec = agent_core.audit_record("triage", {"findings": [{"cve": "CVE-1"}]}, r)
    assert rec["agent_role"] == "triage"
    assert "model_id" in rec and "recommendation" in rec
