"""
IngestFn — pull vulnerability findings from Wiz and upsert into DynamoDB.
Requirements: 1.1-1.5.

Event shapes:
  {}                                  full pull (hourly schedule / resync rule)
  {"image": "repo:tag"}               refresh one image from Wiz
  {"findings": [...]}                 on-demand payload, already normalized (Req 1.3)

The Wiz backend is the real GraphQL API when the secret is filled in and
WIZ_MOCK=false; otherwise the mock (wiz_mock) so the pipeline runs end to end
before credentials exist.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")  # Lambda layer path (common/)

import store  # noqa: E402
import wiz_source  # noqa: E402

WIZ_SECRET_ARN = os.environ.get("WIZ_SECRET_ARN", "")


def fetch_wiz_findings(secret, image=None):
    """Normalized findings from Wiz (all open container-image findings, or one image)."""
    base_names = list(store.list_base_images().keys())
    return wiz_source.client(secret).fetch_findings(base_names, image=image)


def handler(event, context):
    event = event or {}
    findings = event.get("findings")
    if findings is None:
        secret = wiz_source.load_secret(WIZ_SECRET_ARN)
        findings = fetch_wiz_findings(secret, image=event.get("image"))
        source = "wiz-mock" if wiz_source.is_mock(secret) else "wiz"
    else:
        source = "payload"

    count = 0
    for f in findings:
        if "id" not in f or "firstSeen" not in f:
            continue
        store.upsert_finding(f)
        count += 1

    return {"ingested": count, "source": source, "image": event.get("image")}
