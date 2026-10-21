"""
scanFn — on-demand Wiz scan ("Scan now"), scan report + SBOM export. Req 9.2.

HTTP API routes (one Lambda, dispatched on routeKey):
  POST /scan         {"image": "repo:tag"}  -> start a wizcli scan, returns {scan}
  GET  /scan/{id}                            -> status; on success ingests the results
  GET  /report?image=repo:tag                -> presigned URL to the latest scan report (JSON)
  GET  /sbom?image=repo:tag                  -> presigned URL to the latest scan's SBOM

LIVE: starts the `*-wizscan` CodeBuild project (pull from ECR, run wizcli,
write results.json + sbom.cdx.json to S3); status polling finalizes the scan.
MOCK (WIZ_MOCK=true): scanner.run_mock writes wizcli-shaped results and
finalizes immediately — the same finalize path either way.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import ci  # noqa: E402
import scanner  # noqa: E402
import store  # noqa: E402
import wiz_source  # noqa: E402

SCAN_PROJECT = os.environ.get("WIZ_SCAN_PROJECT", "")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,254}:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
FAILED_BUILD = {"FAILED", "FAULT", "STOPPED", "TIMED_OUT"}

_cb = None


def _codebuild():
    global _cb
    if _cb is None:
        import boto3
        _cb = boto3.client("codebuild")
    return _cb


def valid_image(image):
    return bool(image and IMAGE_RE.match(image))


def _image_account(image):
    for f in store.findings_for_image(store.list_findings(), image):
        if f.get("account"):
            return f["account"]
    return None


# ---------------------------------------------------------------- routes
def start_scan(image):
    if not valid_image(image):
        return _resp(400, {"error": "image must look like 'repo/name:tag'"})
    record = store.get_image(image)
    if record and ci.SCANNER == "inspector":   # CI image: re-pull Inspector's findings now
        record = ci.inspector_scan(record)
        return _resp(200, {"scan": store.get_scan(record["scan_id"])})
    scan = scanner.new_scan(image, account=_image_account(image))
    if wiz_source.WIZ_MOCK:
        scan = scanner.run_mock(scan)
    else:
        scan["mode"] = ci.SCANNER if ci.SCANNER in ci.CODEBUILD_SCANNERS else "wizcli"
        env = scanner.live_env(scan)
        build = _codebuild().start_build(
            projectName=SCAN_PROJECT,
            environmentVariablesOverride=[{"name": k, "value": v, "type": "PLAINTEXT"}
                                          for k, v in env.items()])
        scan["buildId"] = build["build"]["id"]
        store.put_scan(scan)
    return _resp(202 if scan["status"] == "RUNNING" else 200, {"scan": scan})


def scan_status(scan_id):
    scan = store.get_scan(scan_id)
    if not scan:
        return _resp(404, {"error": "scan not found"})
    if scan["status"] == "RUNNING" and scan.get("buildId"):
        builds = _codebuild().batch_get_builds(ids=[scan["buildId"]]).get("builds") or []
        state = builds[0]["buildStatus"] if builds else "FAILED"
        if state == "SUCCEEDED":
            scan = scanner.finalize(scan)
        elif state in FAILED_BUILD:
            scan = scanner.fail(scan, f"wizcli build {state}")
        record = store.get_image(scan["image"])
        if record and scan["status"] != "RUNNING":
            ci.finish_scan(record, scan)
    return _resp(200, {"scan": scan})


def latest_artifact(image, key_field, label):
    scan = store.get_latest_scan(image) if valid_image(image) else None
    if not scan:
        return _resp(404, {"error": "no completed scan for this image; run Scan now first"})
    return _resp(200, {"image": image, "scan_id": scan["id"], "artifact": label,
                       "url": store.presigned_report_url(scan[key_field])})


# ---------------------------------------------------------------- dispatch
def handler(event, context):
    route = event.get("routeKey", "")
    query = event.get("queryStringParameters") or {}
    if route == "POST /scan":
        try:
            body = json.loads(event.get("body") or "{}")
        except ValueError:
            return _resp(400, {"error": "invalid JSON body"})
        return start_scan(body.get("image"))
    if route == "GET /scan/{id}":
        return scan_status((event.get("pathParameters") or {}).get("id"))
    if route == "GET /sbom":
        return latest_artifact(query.get("image"), "sbomKey", "sbom-cyclonedx")
    if route == "GET /report":
        return latest_artifact(query.get("image"), "reportKey", "scan-report")
    return _resp(404, {"error": f"unknown route {route}"})


def _resp(code, body):
    return {"statusCode": code,
            "headers": {"content-type": "application/json",
                        "access-control-allow-origin": "*"},
            "body": json.dumps(body, default=str)}
