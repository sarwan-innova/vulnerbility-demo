"""
GateFn — deterministic PASS/BLOCK/WAIVED decisions, appended to the audit log.
Requirements: 5.
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import core  # noqa: E402
import store  # noqa: E402


def handler(event, context):
    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    waivers = store.list_waivers()

    enriched = core.enrich(store.list_findings(), policy, base_images)
    decisions = core.gate_decisions(enriched, policy, waivers)

    run_date = policy["today"]
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    for d in decisions:
        store.append_gate_decision(d, run_date, ts)

    counts = {}
    for d in decisions:
        counts[d["decision"]] = counts.get(d["decision"], 0) + 1

    return {
        "decision_counts": counts,
        "verdict": core.gate_verdict(decisions),
    }
