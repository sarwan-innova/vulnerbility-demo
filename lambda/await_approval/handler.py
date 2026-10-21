"""
awaitApprovalFn — Step Functions task (waitForTaskToken): persist the task token
and pause until a human approves/rejects via the /approve API (Req 9.6).

Invoked with the task token in the state input; stores it on the workflow record
and returns nothing (the state machine waits). The approval API later calls
SendTaskSuccess / SendTaskFailure with this token.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import store  # noqa: E402


def handler(event, context):
    wf_id = event["workflowId"]
    token = event.get("taskToken", "")
    wf = store.get_workflow(wf_id) or {}
    wf["state"] = "AWAIT_APPROVAL"
    wf["task_token"] = token
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": "AWAIT_APPROVAL", "status": "waiting"})
    # No return value needed; the state machine is paused on the token.
    return {"workflowId": wf_id, "stage": "AWAIT_APPROVAL"}
