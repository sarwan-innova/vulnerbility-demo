"""
wfFailFn — Step Functions catch handler: a task or CodeBuild step failed, so
mark the workflow FAILED (the UI stops polling and shows why) instead of
leaving it stuck in its last stage.
Input: {"workflowId": ..., "error": {"Error": ..., "Cause": ...}}
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import store  # noqa: E402


def handler(event, context):
    wf_id = event["workflowId"]
    err = event.get("error") or {}
    wf = store.get_workflow(wf_id) or {"id": wf_id}
    stage = wf.get("state", "UNKNOWN")
    wf["state"] = "FAILED"
    wf["failed_stage"] = stage if stage in ("APPLY_FIX", "DEPLOY_DEV", "VERIFY", "PROMOTE_PROD") else "APPLY_FIX"
    wf["failure"] = f"{stage} failed: {err.get('Error', 'error')} {str(err.get('Cause', ''))[:300]}".strip()
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": stage, "status": "failed", "detail": wf["failure"]})
    return {"workflowId": wf_id, "state": "FAILED"}
