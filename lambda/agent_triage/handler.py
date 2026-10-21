"""
agentTriageFn — Step Functions task: Triage Agent (Req 10.1).
Reasons over the image's findings, records a recommendation + rationale.
Grounded in deterministic facts; gate authority unchanged.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import agent_core  # noqa: E402
import core  # noqa: E402
import store  # noqa: E402


def handler(event, context):
    wf_id = event["workflowId"]
    image = event["image"]
    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    enriched = core.enrich(store.list_findings(), policy, base_images)
    findings = store.findings_for_image(enriched, image)

    result = agent_core.invoke_agent("triage", {"image": image, "findings": findings})
    store.append_workflow_event(wf_id, {"stage": "AGENT_TRIAGE", "status": "done",
                                        **agent_core.audit_record("triage", {"findings": findings}, result)})
    wf = store.get_workflow(wf_id) or {}
    wf["agent_triage"] = result
    store.put_workflow(wf)
    return {**event, "triage": result}
