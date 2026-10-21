"""
ReportFn — HTTP API handler returning the latest posture summary (JSON).
Requirements: 6.2, 6.3.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import store  # noqa: E402


def handler(event, context):
    summary = store.get_summary()
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json",
                    "cache-control": "no-store"},
        "body": json.dumps(summary or {"message": "no summary yet; run the pipeline"}),
    }
