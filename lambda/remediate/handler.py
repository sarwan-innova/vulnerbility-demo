"""
remediateFn — HTTP API: start a promotion workflow for a selected image.
Starts the Step Functions execution and records the workflow record.
Requirement 9.2.
"""
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import core  # noqa: E402
import promotion  # noqa: E402
import store  # noqa: E402

SFN_ARN = os.environ.get("PROMOTION_SFN_ARN", "")
AGENTIC_SFN_ARN = os.environ.get("AGENTIC_SFN_ARN", "")
_sfn = None


def _stepfunctions():
    global _sfn
    if _sfn is None:
        import boto3
        _sfn = boto3.client("stepfunctions")
    return _sfn


def handler(event, context):
    body = json.loads(event.get("body") or "{}") if isinstance(event.get("body"), str) else (event.get("body") or {})
    image = body.get("image")
    if not image:
        return _resp(400, {"error": "image is required"})

    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    all_findings = core.enrich(store.list_findings(), policy, base_images)
    findings = store.findings_for_image(all_findings, image)
    if not findings:
        return _resp(404, {"error": f"no findings for image {image}"})

    plan = promotion.plan_remediation(image, findings, base_images)
    wf_id = uuid.uuid4().hex[:12]
    wf = {
        "id": wf_id, "image": image, "state": promotion.initial_state(),
        "plan": plan, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cve_count": len(plan["total_cves"]),
    }
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": "SCAN", "status": "started", "image": image})

    # select agentic vs deterministic pipeline per request (Req 10.9)
    use_agentic = bool(body.get("agentic")) and bool(AGENTIC_SFN_ARN)
    target_arn = AGENTIC_SFN_ARN if use_agentic else SFN_ARN
    wf["mode"] = "agentic" if use_agentic else "deterministic"
    store.put_workflow(wf)

    sfn_input = {"workflowId": wf_id, "image": image}
    execution_arn = ""
    if target_arn:
        resp = _stepfunctions().start_execution(stateMachineArn=target_arn,
                                    name=f"wf-{wf_id}",
                                    input=json.dumps(sfn_input))
        execution_arn = resp["executionArn"]
        wf["execution_arn"] = execution_arn
        store.put_workflow(wf)

    return _resp(200, {"workflowId": wf_id, "image": image, "plan": plan,
                       "mode": wf["mode"], "executionArn": execution_arn,
                       "state": wf["state"]})


def _resp(code, body):
    return {"statusCode": code,
            "headers": {"content-type": "application/json",
                        "access-control-allow-origin": "*"},
            "body": json.dumps(body)}
