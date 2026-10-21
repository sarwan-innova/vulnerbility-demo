"""
imagesFn — HTTP API: images for the console (Req 9.1).

Merges two sources:
  * CI image records (pushed by the app build): commit, branch, scan state,
    and — for images built from an AI fix branch — which image they fix
  * the open-findings roll-up (worst severity, SLA, KEV, finding count)
A CI image with a clean scan is listed too (0 findings), so a fixed rebuild
shows up next to the image it replaced.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import store  # noqa: E402

RECORD_FIELDS = ("commit", "branch", "github", "pushedAt", "scan_status", "scan_summary",
                 "scanner", "fix_id", "source_image", "digest", "gate_verdict", "approved_tag",
                 "scanned_at")


def handler(event, context):
    rollup = {i["image"]: i for i in store.images_with_findings(store.list_findings())}
    images = []
    for rec in store.list_image_records():
        row = rollup.pop(rec["image"], None) or {
            "image": rec["image"], "repo": rec.get("repo"), "imageTag": rec.get("tag"),
            "worst_severity": None, "worst_sla": None, "finding_count": 0,
            "base_layer": False, "kev": False, "remediation_path": None}
        row.update({k: rec.get(k) for k in RECORD_FIELDS})
        row["ci"] = True
        images.append(row)
    images.extend(rollup.values())  # images known only from Wiz findings
    images.sort(key=lambda r: r.get("pushedAt") or "", reverse=True)
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json",
                    "access-control-allow-origin": "*"},
        "body": json.dumps({"images": images}, default=str),
    }
