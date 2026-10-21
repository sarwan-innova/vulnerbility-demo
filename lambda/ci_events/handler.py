"""
ciEventsFn — EventBridge target for the push -> build -> scan loop.

  aws.ecr        "ECR Image Action" (PUSH, SUCCESS)      -> register image + start scan
  aws.inspector2 "Inspector2 Scan"                       -> pull findings, finalize scan
  aws.codebuild  "CodeBuild Build State Change" (wizscan) -> finalize/fail the wizcli scan
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import ci  # noqa: E402
import ecr_meta  # noqa: E402
import scanner  # noqa: E402
import store  # noqa: E402


def describe_image(repository, digest):
    """Labels written by the app build (commit, branch, source, base layers)."""
    try:
        return ecr_meta.describe_image(ci.client("ecr"), repository, digest)
    except Exception as e:  # still register + scan an image built outside the CI build
        print(f"could not read image labels for {repository}@{digest}: {e}")
        return {}


def on_push(detail, account=None):
    if detail.get("action-type") != "PUSH" or detail.get("result") != "SUCCESS":
        return {"skipped": "not a successful push"}
    tag = detail.get("image-tag")
    if not tag:
        return {"skipped": "untagged image"}
    repository, digest = detail["repository-name"], detail["image-digest"]
    record = ci.register_push(repository, tag, digest, describe_image(repository, digest),
                              account=account)
    return {"image": record["image"], "scan_status": record["scan_status"]}


def _repo_name(value):
    """Inspector sends the repository as an ARN (…:repository/<name>) or a plain name."""
    return value.split(":repository/", 1)[1] if value and ":repository/" in value else value


def on_inspector_scan(detail):
    repository = _repo_name(detail.get("repository-name"))
    digest = detail.get("image-digest")
    record = ci.image_for_digest(repository, digest, detail.get("image-tags") or [])
    if not record:
        return {"skipped": f"no CI image record for {repository}@{digest}"}
    record = ci.inspector_scan(record)
    return {"image": record["image"], "scan_status": record["scan_status"],
            "summary": record.get("scan_summary")}


def on_build_state(detail):
    status = detail.get("build-status")
    if status in ("IN_PROGRESS", None):
        return {"skipped": "build still running"}
    scan = store.find_scan_by_build(detail.get("build-id"))
    if not scan or scan.get("status") != "RUNNING":
        return {"skipped": "no running scan for this build"}
    scan = scanner.finalize(scan) if status == "SUCCEEDED" else scanner.fail(scan, f"wizcli build {status}")
    record = store.get_image(scan["image"])
    if record:
        ci.finish_scan(record, scan)
    return {"scan": scan["id"], "status": scan["status"]}


def handler(event, context):
    source, kind = event.get("source"), event.get("detail-type")
    detail = event.get("detail") or {}
    if source == "aws.ecr" and kind == "ECR Image Action":
        return on_push(detail, account=event.get("account"))
    if source == "aws.inspector2" and kind == "Inspector2 Scan":
        return on_inspector_scan(detail)
    if source == "aws.codebuild" and kind == "CodeBuild Build State Change":
        return on_build_state(detail)
    return {"skipped": f"unhandled event {source}/{kind}"}
