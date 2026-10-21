"""
End-to-end tests: the REAL Lambda handlers driven through the local platform
(local/app.py) — in-memory store, mock Wiz, local copy of the state machine.
Covers Phase 2 (report/scan/SBOM API), Phase 3 (automated fix), Phase 4
(verify re-scan, gate, approval, promotion) and the failure paths.
"""

import importlib.util
import inspect
import os
import sys
import time

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "local"))

from app import LocalApp  # noqa: E402

RWD = "clarivate-rwd/ingest-api:latest"
MMIT = "mmit-access/claims-processor:8.0.2"


@pytest.fixture
def app(tmp_path, monkeypatch):
    a = LocalApp(step_delay=0)
    monkeypatch.setattr(a.store, "S3_DIR", str(tmp_path / "s3"))
    a.seed()
    return a


def wait_for(app, wf_id, states, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        _, s = app.call("GET /workflow/{id}", {"id": wf_id})
        if s["state"] in states:
            return s
        time.sleep(0.02)
    raise AssertionError(f"workflow stuck in {s['state']}")


def images(app):
    return {i["image"]: i for i in app.call("GET /images")[1]["images"]}


# ---------------------------------------------------------------- store parity
def test_memstore_implements_every_store_function():
    import memstore  # sets a default AWS region so the real module can build its clients
    spec = importlib.util.spec_from_file_location("real_store_parity",
                                                  os.path.join(ROOT, "lambda", "common", "store.py"))
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    public = {n for n, f in inspect.getmembers(real, inspect.isfunction)
              if not n.startswith("_") and f.__module__ == real.__name__}
    assert public - set(dir(memstore)) == set()


# ---------------------------------------------------------------- Phase 2: report API
def test_images_and_report_for_one_image(app):
    imgs = images(app)
    assert set(imgs) == {RWD, MMIT, "panalgo-analytics/query-engine:v3.2.0"}
    assert imgs[RWD]["kev"] and imgs[RWD]["finding_count"] == 3

    code, body = app.call("GET /image-findings", query={"image": RWD})
    assert code == 200
    assert body["gate"] == {"block_on": ["CRITICAL", "HIGH"], "verdict": "BLOCKED", "blocking": 3}
    runc = next(f for f in body["findings"] if f["cve"] == "CVE-2024-21626")
    assert runc["kev"] and runc["fast_tracked"] and runc["epss"] == pytest.approx(0.92)
    assert body["advice"]["mode"] == "deterministic" and "KEV" in body["advice"]["recommendation"]
    assert body["latest_scan"] is None
    assert [a["type"] for a in body["plan"]["actions"]] == ["base-image-rebuild", "app-dependency-bump"]


def test_scan_now_report_and_sbom(app):
    code, body = app.call("POST /scan", body={"image": RWD})
    assert code == 200 and body["scan"]["status"] == "SUCCEEDED"
    assert body["scan"]["summary"]["total"] == 3
    sid = body["scan"]["id"]
    assert app.call("GET /scan/{id}", {"id": sid})[1]["scan"]["status"] == "SUCCEEDED"

    code, rep = app.call("GET /report", query={"image": RWD})
    assert code == 200 and rep["url"] == f"/api/files/reports/scans/{sid}.json"
    report = app.store.get_json_report(f"reports/scans/{sid}.json")
    assert len(report["findings"]) == 3
    code, sbom = app.call("GET /sbom", query={"image": RWD})
    assert code == 200
    assert app.store.get_json_report(sbom["url"][len("/api/files/"):])["bomFormat"] == "CycloneDX"
    # a scan reuses the Wiz finding ids: still 3 open findings, not 6
    assert images(app)[RWD]["finding_count"] == 3
    assert app.call("GET /image-findings", query={"image": RWD})[1]["latest_scan"]["id"] == sid


@pytest.mark.parametrize("bad", [None, "no-tag", "UPPER/x:1", "a:b;rm -rf /"])
def test_scan_rejects_bad_image(app, bad):
    assert app.call("POST /scan", body={"image": bad} if bad else {})[0] == 400


def test_report_and_sbom_404_before_any_scan(app):
    assert app.call("GET /report", query={"image": RWD})[0] == 404
    assert app.call("GET /sbom", query={"image": RWD})[0] == 404
    assert app.call("GET /scan/{id}", {"id": "missing"})[0] == 404


# ---------------------------------------------------------------- Phases 3-4: fix -> verify -> promote
def test_full_flow_fix_verify_approve_promote(app):
    code, body = app.call("POST /remediate", body={"image": RWD})
    assert code == 200
    wf = body["workflowId"]
    s = wait_for(app, wf, {"AWAIT_APPROVAL", "FAILED"})
    assert s["state"] == "AWAIT_APPROVAL" and s["verify_result"] == "PASS"
    assert s["mode"] == "deterministic" and s["agents"] == {}
    assert s["target_image"] == f"clarivate-rwd/ingest-api:fix-{wf}"
    assert any("cryptography 41.0.4 -> 42.0.0" in a for a in s["applied"])
    assert any("al2023-python:2026.02.4" in a for a in s["applied"])
    assert s["verify_summary"]["total"] == 0

    code, body = app.call("POST /approve", body={"workflowId": wf, "decision": "approve"},
                          claims={"email": "infosec@example.com"})
    assert code == 200
    s = wait_for(app, wf, {"DONE", "FAILED"})
    assert s["state"] == "DONE" and s["approver"] == "infosec@example.com"
    stages = [(e["stage"], e["status"]) for e in s["events"]]
    assert stages == [("SCAN", "started"), ("APPLY_FIX", "done"), ("DEPLOY_DEV", "done"),
                      ("VERIFY", "PASS"), ("AWAIT_APPROVAL", "waiting"),
                      ("AWAIT_APPROVAL", "approve"), ("PROMOTE_PROD", "done")]
    assert RWD not in images(app)              # original image's findings closed
    # the verify gate decisions were recorded for audit
    assert app.store.list_gate_decisions() == []  # nothing remained to decide on


def test_reject_stops_before_prod(app):
    wf = app.call("POST /remediate", body={"image": MMIT})[1]["workflowId"]
    wait_for(app, wf, {"AWAIT_APPROVAL"})
    assert app.call("POST /approve", body={"workflowId": wf, "decision": "reject"})[0] == 200
    s = wait_for(app, wf, {"REJECTED"})
    assert s["failed_stage"] == "AWAIT_APPROVAL" and "prod" not in str(s["events"][-1].get("env"))
    assert MMIT in images(app)


def test_verify_fails_when_fix_cannot_clear_blocking_findings(app):
    # no fixed base tag published -> base CVEs cannot be fixed -> re-scan still blocked
    bi = app.store.list_base_images()["shared-base-images/al2023-python"]
    app.store.put_base_image({**bi, "fixed_tag_available": "<fixed>"})
    wf = app.call("POST /remediate", body={"image": RWD})[1]["workflowId"]
    s = wait_for(app, wf, {"FAILED", "AWAIT_APPROVAL"})
    assert s["state"] == "FAILED" and s["failed_stage"] == "VERIFY"
    assert s["remaining_blocking"] == ["CVE-2024-21626", "CVE-2024-2961"]
    assert s["jira"].startswith("MOCK-")
    assert any("needs a human" in a for a in s["applied"])
    decisions = app.store.list_gate_decisions()
    assert {d["decision"] for d in decisions} == {"BLOCK"} and decisions[0]["workflow_id"] == wf
    # a failed workflow can never be approved into prod
    assert app.call("POST /approve", body={"workflowId": wf, "decision": "approve"})[0] == 409
    assert RWD in images(app)


def test_agentic_pipeline_records_agent_outputs(app):
    wf = app.call("POST /remediate", body={"image": RWD, "agentic": True})[1]["workflowId"]
    s = wait_for(app, wf, {"AWAIT_APPROVAL", "FAILED"})
    assert s["state"] == "AWAIT_APPROVAL" and s["mode"] == "agentic"
    assert set(s["agents"]) == {"agent_triage", "agent_plan", "agent_verify"}
    assert s["agents"]["agent_verify"]["recommendation"].startswith("Safe to promote")


def test_remediate_unknown_image_is_404(app):
    assert app.call("POST /remediate", body={"image": "nope/x:1"})[0] == 404
