"""
UnitsFn — group enriched findings into remediation units, persist.
Requirements: 4.1.
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
    enriched = core.enrich(store.list_findings(), policy, base_images)
    units = core.build_units(enriched, base_images)
    for u in units:
        store.put_unit(u)
    return {"units": len(units),
            "base_rebuild_units": sum(1 for u in units if u["type"] == "base")}
