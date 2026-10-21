"""
wfStatusFn — HTTP API: return the live stage/status of a workflow (Req 9.8),
with the fix spec, verify scan, agent outputs and the event timeline.
Path: GET /workflow/{id}
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import promotion  # noqa: E402
import store  # noqa: E402

AGENT_KEYS = ("agent_triage", "agent_plan", "agent_verify")


def handler(event, context):
    wf_id = (event.get("pathParameters") or {}).get("id")
    if not wf_id:
        return _resp(400, {"error": "workflow id required"})
    wf = store.get_workflow(wf_id)
    if not wf:
        return _resp(404, {"error": "not found"})

    state = wf.get("state", "SCAN")
    failed_stage = None
    if state == "FAILED":
        failed_stage = wf.get("failed_stage") or "APPLY_FIX"
    elif state == "REJECTED":
        failed_stage = "AWAIT_APPROVAL"
    events = sorted(store.list_workflow_events(wf_id), key=lambda e: e.get("SK", ""))
    return _resp(200, {
        "workflowId": wf_id,
        "image": wf.get("image"),
        "target_image": wf.get("target_image"),
        "mode": wf.get("mode", "deterministic"),
        "state": state,
        "stage_index": promotion.stage_index(state),
        "failed_stage": failed_stage,
        "stages": promotion.STAGES,
        "terminal": state in promotion.TERMINAL,
        "plan": wf.get("plan"),
        "fix_spec": wf.get("fix_spec"),
        "applied": wf.get("applied", []),
        "verify_result": wf.get("verify_result"),
        "verify_summary": wf.get("verify_summary"),
        "remaining_blocking": wf.get("remaining_blocking", []),
        "failure": wf.get("failure"),
        "jira": wf.get("jira"),
        "approver": wf.get("approver"),
        "agents": {k: wf[k] for k in AGENT_KEYS if wf.get(k)},
        "events": [{k: v for k, v in e.items() if k not in ("PK", "SK", "entity")}
                   for e in events],
    })


def _resp(code, body):
    return {"statusCode": code,
            "headers": {"content-type": "application/json",
                        "access-control-allow-origin": "*"},
            "body": json.dumps(body, default=str)}
