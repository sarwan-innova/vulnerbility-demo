"""
agentPlannerFn — Step Functions task: Planner Agent (Req 10.2).
Proposes the concrete fix plan for the image (grounded in promotion.plan_remediation).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import agent_core  # noqa: E402
import core  # noqa: E402
import promotion  # noqa: E402
import store  # noqa: E402


def handler(event, context):
    wf_id = event["workflowId"]
    image = event["image"]
    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    enriched = core.enrich(store.list_findings(), policy, base_images)
    findings = store.findings_for_image(enriched, image)

    plan = promotion.plan_remediation(image, findings, base_images)
    result = agent_core.invoke_agent("planner", {"image": image, "plan": plan})

    wf = store.get_workflow(wf_id) or {}
    wf["plan"] = plan              # the authoritative plan the next steps execute
    wf["agent_plan"] = result
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": "AGENT_PLAN", "status": "done",
                                        **agent_core.audit_record("planner", {"findings": findings}, result)})
    return {**event, "plan": plan, "plan_recommendation": result}
