"""
imageFindingsFn — HTTP API: the findings report for one image — findings with
SLA/KEV/EPSS, the remediation plan, the AI triage advice and the latest
on-demand scan (Req 9.1/9.3, Phase 2).
Path: GET /image-findings?image=<repo:tag>
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import agent_core  # noqa: E402
import ai_fixer  # noqa: E402
import core  # noqa: E402
import promotion  # noqa: E402
import store  # noqa: E402

FIELDS = ("cve", "severity", "layerType", "baseImage", "package", "installedVersion",
          "fixedVersion", "kev", "epss", "sla_status", "sla_remaining_days", "age_days",
          "fast_tracked", "priority_score", "fix_hint", "source")


SOURCE_FIELDS = ("commit", "branch", "github", "pushedAt", "scanner", "scan_status", "scan_error",
                 "fix_id", "source_image", "last_fix_id")


def handler(event, context):
    params = (event.get("queryStringParameters") or {})
    image = params.get("image")
    if not image:
        return _resp(400, {"error": "image query param required"})

    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    enriched = core.enrich(store.list_findings(), policy, base_images)
    findings = store.findings_for_image(enriched, image)
    plan = promotion.plan_remediation(image, findings, base_images)

    advice = agent_core.invoke_agent("triage", {"image": image, "findings": [
        {k: f.get(k) for k in ("cve", "severity", "kev", "epss", "layerType", "sla_status")}
        for f in findings]}) if findings else None
    blocking = [f for f in findings if f["severity"] in policy["gate"]["block_on"]]
    scan = store.get_latest_scan(image)
    record = store.get_image(image)

    return _resp(200, {
        "image": image,
        "findings": [{k: f.get(k) for k in FIELDS} for f in findings],
        "plan": plan,
        "advice": advice,
        "gate": {"block_on": policy["gate"]["block_on"],
                 "verdict": "BLOCKED" if blocking else "CLEAR",
                 "blocking": len(blocking)},
        "latest_scan": ({k: scan.get(k) for k in ("id", "status", "finishedAt", "summary", "mode")}
                        if scan else None),
        "source": ({k: record.get(k) for k in SOURCE_FIELDS} if record else None),
        "ai": {"model": ai_fixer.MODEL_ID or None,
               "enabled": bool(store.get_settings().get(
                   "fix_with_ai", os.environ.get("FIX_WITH_AI_DEFAULT", "true").lower() == "true"))},
    })


def _resp(code, body):
    return {"statusCode": code,
            "headers": {"content-type": "application/json",
                        "access-control-allow-origin": "*"},
            "body": json.dumps(body, default=str)}
