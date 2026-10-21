"""
agentVerifierFn — Step Functions task: Verifier Agent (Req 10.3).
After the re-scan, explains residual risk and recommends promote/stop.
The recommendation is advisory ONLY — the deterministic gate (verify step) decides.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import agent_core  # noqa: E402
import store  # noqa: E402


def handler(event, context):
    wf_id = event["workflowId"]
    # the deterministic verify step already set verify + remaining_blocking
    remaining = event.get("remaining_blocking", [])
    verify = event.get("verify", "UNKNOWN")

    result = agent_core.invoke_agent("verifier", {
        "verify_gate_result": verify,            # deterministic result (authority)
        "remaining_blocking": remaining,
    })
    wf = store.get_workflow(wf_id) or {}
    wf["agent_verify"] = result
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": "AGENT_VERIFY", "status": verify,
                                        **agent_core.audit_record("verifier", {}, result)})
    # pass the deterministic verify result through unchanged so the Choice branches on it
    return {**event, "verify": verify, "verify_explanation": result}
