"""
approvalFn — HTTP API: approve or reject a workflow paused at AWAIT_APPROVAL.
Resolves the stored Step Functions task token (Req 9.6, 9.7).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import store  # noqa: E402

_sfn = None


def _stepfunctions():
    global _sfn
    if _sfn is None:
        import boto3
        _sfn = boto3.client("stepfunctions")
    return _sfn


def handler(event, context):
    body = event.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body or "{}")
        except ValueError:
            return _resp(400, {"error": "invalid JSON body"})
    body = body or {}
    wf_id = body.get("workflowId")
    decision = (body.get("decision") or "").lower()
    approver = body.get("approver", "unknown")
    if decision not in ("approve", "reject"):
        return _resp(400, {"error": "decision must be approve or reject"})

    # Prefer the authenticated identity from the API Gateway JWT authorizer
    # (set when EdgeStack/Cognito is in front) over any client-supplied value.
    claims = (((event.get("requestContext") or {}).get("authorizer") or {})
              .get("jwt") or {}).get("claims") or {}
    jwt_user = claims.get("email") or claims.get("cognito:username") or claims.get("sub")
    if jwt_user:
        approver = jwt_user

    wf = store.get_workflow(wf_id)
    if not wf:
        return _resp(404, {"error": "workflow not found"})
    if wf.get("state") != "AWAIT_APPROVAL":
        # e.g. a FAILED verify can never be approved into prod
        return _resp(409, {"error": f"workflow is {wf.get('state')}, not awaiting approval"})
    token = wf.get("task_token")

    if decision == "approve":
        if token:
            _stepfunctions().send_task_success(taskToken=token,
                                   output=json.dumps({"approved": True, "approver": approver}))
        wf["state"] = "PROMOTE_PROD"
    else:
        if token:
            _stepfunctions().send_task_failure(taskToken=token, error="Rejected",
                                   cause=f"Rejected by {approver}")
        wf["state"] = "REJECTED"

    wf["approver"] = approver
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": "AWAIT_APPROVAL",
                                        "status": decision, "approver": approver})
    return _resp(200, {"workflowId": wf_id, "decision": decision, "state": wf["state"]})


def _resp(code, body):
    return {"statusCode": code,
            "headers": {"content-type": "application/json",
                        "access-control-allow-origin": "*"},
            "body": json.dumps(body)}
