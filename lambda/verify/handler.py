"""
verifyFn — Step Functions task: re-scan the REBUILT image and gate it
(Req 9.4, 9.5; Phase 4). PASS only when no blocking findings remain; FAIL
stops the workflow before approval/prod and opens a Jira ticket.

The re-scan is a real scan of <repo>:fix-<workflow id> through scanner.py:
  WIZ_MOCK=true : scanner.run_mock (results honour the applied fix spec)
  WIZ_MOCK=false: two calls around the state machine's synchronous wizscan
                  CodeBuild step —
                    {"verify_phase": "prepare"} -> create scan, return scan_env
                    (CodeBuild runs wizcli, writes results to S3)
                    {"verify_phase": "finalize"} -> ingest results + gate
Every gate decision is appended to the audit log (auditors asked for gate
decision records). Returns {"verify": "PASS"|"FAIL"} for the Choice state.
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import core  # noqa: E402
import jira_client  # noqa: E402
import promotion  # noqa: E402
import scanner  # noqa: E402
import store  # noqa: E402
import wiz_source  # noqa: E402

JIRA_SECRET_ARN = os.environ.get("JIRA_SECRET_ARN", "")


def handler(event, context):
    wf_id = event["workflowId"]
    image = event["image"]
    wf = store.get_workflow(wf_id) or {}
    target = wf.get("target_image") or event.get("target_image") or image
    phase = event.get("verify_phase")

    if phase == "prepare":
        scan = scanner.new_scan(target, purpose="verify", workflow_id=wf_id,
                                account=_account(image))
        scan["mode"] = "wizcli"
        store.put_scan(scan)
        wf["state"] = "VERIFY"
        wf["verify_scan_id"] = scan["id"]
        store.put_workflow(wf)
        return {**event, "scan_id": scan["id"], "scan_env": scanner.live_env(scan)}

    if phase == "finalize":
        scan = scanner.finalize(store.get_scan(event["scan_id"]))
    else:  # mock re-scan
        scan = scanner.new_scan(target, purpose="verify", workflow_id=wf_id,
                                account=_account(image))
        scan = scanner.run_mock(scan, source_image=image, fix_spec=wf.get("fix_spec"))

    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    enriched = core.enrich(store.list_findings(), policy, base_images)
    before = store.findings_for_image(enriched, image)
    after = store.findings_for_image(enriched, target)

    # audit trail: the deterministic gate decision for every remaining finding
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    for d in core.gate_decisions(after, policy, store.list_waivers()):
        store.append_gate_decision({**d, "workflow_id": wf_id, "phase": "verify"},
                                   policy["today"], ts)

    result, blocking = promotion.verify_result(after, policy)
    wf.update({
        "verify_result": result,
        "verify_scan_id": scan["id"],
        "verify_summary": scan.get("summary"),
        "remaining_blocking": sorted({b["cve"] for b in blocking}),
        "state": "VERIFY" if result == "PASS" else "FAILED",
    })
    if result == "FAIL":
        wf["failure"] = "blocking findings remain after the fix"
        wf["failed_stage"] = "VERIFY"
        wf["jira"] = _open_ticket(wf, target, blocking)
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {
        "stage": "VERIFY", "status": result, "scan_id": scan["id"],
        "remaining_blocking": wf["remaining_blocking"],
        "fixed_count": len({f["cve"] for f in before} - {f["cve"] for f in after}),
        "jira": wf.get("jira")})
    return {**event, "verify": result, "remaining_blocking": wf["remaining_blocking"]}


def _account(image):
    return next((f["account"] for f in store.findings_for_image(store.list_findings(), image)
                 if f.get("account")), None)


def _open_ticket(wf, target, blocking):
    try:
        creds = wiz_source.load_secret(JIRA_SECRET_ARN)
        lines = [f"Automated fix for {wf.get('image')} did not clear blocking findings.",
                 f"Rebuilt image: {target}", f"Workflow: {wf.get('id')}"]
        lines += [f"{b['cve']} {b['severity']} {b.get('package') or ''} "
                  f"{b.get('installedVersion') or ''} -> {b.get('fixedVersion') or 'no fix'}"
                  for b in blocking]
        return jira_client.create_issue(
            creds, f"[VERIFY FAILED] {wf.get('image')}: {len(blocking)} blocking finding(s)",
            "\n".join(lines),
            priority="Highest" if any(b.get("kev") for b in blocking) else "High")
    except Exception as e:  # a ticketing outage must not hide the verify result
        return f"ticket-failed: {str(e)[:120]}"
