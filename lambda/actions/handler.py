"""
ActionsFn — create Jira tickets per remediation unit, SNS alert on FAIL,
write the S3 report + summary. Skips fully-waived units; partial-failure tolerant.
Requirements: 4.2-4.5, 6.1.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import core  # noqa: E402
import jira_client  # noqa: E402
import store  # noqa: E402
import wiz_source  # noqa: E402

JIRA_SECRET_ARN = os.environ.get("JIRA_SECRET_ARN", "")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
_sns = None


def _publish(**kwargs):
    global _sns
    if _sns is None:
        import boto3
        _sns = boto3.client("sns")
    _sns.publish(**kwargs)


def create_jira_issue(creds, title, description, priority):
    """Real Jira REST create-issue when the secret is filled in; MOCK-#### otherwise."""
    return jira_client.create_issue(creds, title, description, priority)


def handler(event, context):
    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    waivers = store.list_waivers()
    today = policy["today"]

    enriched = core.enrich(store.list_findings(), policy, base_images)
    units = core.build_units(enriched, base_images)
    decisions = core.gate_decisions(enriched, policy, waivers)
    verdict = core.gate_verdict(decisions)
    summary = core.summarize(enriched, units)

    creds = wiz_source.load_secret(JIRA_SECRET_ARN)
    tickets, failures = [], []
    for u in units:
        active = [f for f in u["findings"] if not core.is_waived(f, waivers, today)]
        if not active:
            continue  # fully waived (Req 4.4)
        try:
            title = (f"[{u['max_severity']}] Rebuild base image {u['target']} -> {u.get('fixed_tag','')}"
                     if u["type"] == "base"
                     else f"[{u['max_severity']}] Patch app dependencies in {u['target']}")
            desc = f"{u['leverage']}. {u['action']}. Repos: {', '.join(u['repos'])}."
            prio = "Highest" if u["kev"] else ("High" if u["max_severity"] == "CRITICAL" else "Medium")
            tid = create_jira_issue(creds, title, desc, prio)
            tickets.append({"ticket": tid, "title": title, "unit": u["target"],
                            "downstream_images": u["downstream_image_count"]})
        except Exception as e:  # partial-failure tolerance (Req 4.5)
            failures.append({"unit": u["target"], "error": str(e)})

    # persist report artifacts (Req 6.1/6.2)
    report = {"generated_at": today, "summary": summary, "verdict": verdict,
              "tickets": tickets, "decision_counts": _counts(decisions)}
    store.put_summary({**summary, "verdict": verdict, "tickets": len(tickets)})
    store.put_json_report(f"reports/{today}/summary.json", report)
    store.put_json_report("reports/latest/summary.json", report)

    # alert on FAIL (Req 5/6)
    if verdict == "BLOCKED" and ALERT_TOPIC_ARN:
        _publish(
            TopicArn=ALERT_TOPIC_ARN,
            Subject="[VULN GATE] Promotion BLOCKED",
            Message=(f"Gate verdict BLOCKED on {today}.\n"
                     f"Severity: {json.dumps(summary['by_severity'])}\n"
                     f"Base-layer: {summary['base_layer_pct']}% -> "
                     f"{summary['downstream_images_reachable']} images reachable via "
                     f"{summary['base_rebuild_units']} base rebuilds.\n"
                     f"Tickets created: {len(tickets)}."),
        )

    return {"tickets": len(tickets), "failures": len(failures), "verdict": verdict}


def _counts(decisions):
    c = {}
    for d in decisions:
        c[d["decision"]] = c.get(d["decision"], 0) + 1
    return c
