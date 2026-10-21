"""
EnrichFn — attribute base/app, compute SLA + KEV/EPSS score, persist.
Requirements: 2, 3.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import core  # noqa: E402
import store  # noqa: E402


def handler(event, context):
    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    findings = store.list_findings()

    enriched = core.enrich(findings, policy, base_images)
    for f in enriched:
        store.upsert_finding(f)

    return {"enriched": len(enriched)}
