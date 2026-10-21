"""
Scanner — one scan lifecycle shared by "Scan now" (scan Lambda) and post-fix
verification (verify Lambda). Requirements 9.2, 9.4.

  new_scan()      create the scan record + S3 keys
  run_mock()      MOCK: write wizcli-shaped results (honouring an applied fix
                  spec) and finalize immediately
  live_env()      LIVE: env overrides for the `*-wizscan` CodeBuild project
  finalize()      normalize results -> upsert findings -> resolve what is gone
                  -> write report -> mark SUCCEEDED

Cross-account (Phase 5): images live in many accounts. registry_for() maps a
finding's 12-digit account id to that account's ECR registry; the scan/fix
builds pull cross-account, which needs an org-wide ECR repository policy
granting the platform account's CodeBuild roles pull access (see README).
"""

import os
import re
import time
import uuid

import store
import wiz_client
import wiz_mock

REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
DEFAULT_REGISTRY = os.environ.get("ECR_REGISTRY", "")
ACCOUNT_RE = re.compile(r"^\d{12}$")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def registry_for(account=None, default=None, region=None):
    """ECR registry host for an image's account (falls back to the platform registry)."""
    if account and ACCOUNT_RE.match(str(account)):
        return f"{account}.dkr.ecr.{region or REGION}.amazonaws.com"
    return default if default is not None else DEFAULT_REGISTRY


def new_scan(image, purpose="scan-now", workflow_id=None, account=None):
    scan_id = uuid.uuid4().hex[:12]
    prefix = f"scans/{scan_id}"
    return {
        "id": scan_id, "image": image, "purpose": purpose, "workflowId": workflow_id,
        "status": "RUNNING", "startedAt": now(), "account": account,
        "prefix": prefix, "resultsKey": f"{prefix}/results.json",
        "sbomKey": f"{prefix}/sbom.cdx.json", "reportKey": f"reports/scans/{scan_id}.json",
    }


def live_env(scan, registry=None):
    """CodeBuild env overrides for the wizscan project."""
    reg = registry or registry_for(scan.get("account"))
    return {
        "IMAGE_URI": f"{reg}/{scan['image']}",
        "OUTPUT_PREFIX": f"s3://{store.BUCKET}/{scan['prefix']}",
    }


def run_mock(scan, source_image=None, fix_spec=None):
    """MOCK scan. For a rebuilt image, results come from the source image's
    fixtures minus whatever the fix spec fixed."""
    scan["mode"] = "mock"
    src = source_image or scan["image"]
    store.put_json_report(scan["resultsKey"], wiz_mock.mock_wizcli_result(src, fix_spec=fix_spec))
    store.put_json_report(scan["sbomKey"], wiz_mock.mock_sbom(src, fix_spec=fix_spec))
    return finalize(scan)


def finalize(scan):
    raw = store.get_json_report(scan["resultsKey"])
    base_names = list(store.list_base_images().keys())
    findings = wiz_client.normalize_wizcli_result(raw, scan["image"], base_names,
                                                  scanned_at=scan["startedAt"])
    for f in findings:
        if scan.get("account"):
            f.setdefault("account", scan["account"])
    previous = store.findings_for_image(store.list_findings(), scan["image"])
    gone = wiz_client.resolved_ids(previous, findings)
    for f in findings:
        store.upsert_finding(f)
    store.resolve_findings(gone, now(), scan["id"])

    scan.update({"status": "SUCCEEDED", "finishedAt": now(),
                 "summary": wiz_client.scan_summary(findings), "resolved": gone})
    store.put_json_report(scan["reportKey"], {"scan": scan, "findings": findings})
    store.put_scan(scan)
    return scan


def fail(scan, error):
    scan.update({"status": "FAILED", "finishedAt": now(), "error": error})
    store.put_scan(scan)
    return scan
