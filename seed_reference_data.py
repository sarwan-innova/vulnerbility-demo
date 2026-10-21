"""
Seed reference data into the DynamoDB table (Task 8 / Req 2.2, 2.3, 3.1):
  * shared-base-images + downstream counts
  * the active policy
  * (optional) demo waivers and a sample Wiz findings payload for a first run

Run AFTER `cdk deploy` with AWS credentials:
    python seed_reference_data.py --table vuln-remediation-dev [--demo-findings]

Uses the same store.py helpers the Lambdas use.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lambda", "common"))

BASE_IMAGES = [
    {"name": "shared-base-images/al2023-python", "current_tag": "2026.02.1", "os": "Amazon Linux 2023",
     "runtime": "python3.12", "rebuild_cadence": "daily", "fixed_tag_available": "2026.02.4",
     "downstream_image_count": 142},
    {"name": "shared-base-images/al2023-node", "current_tag": "2026.02.1", "os": "Amazon Linux 2023",
     "runtime": "node20", "rebuild_cadence": "daily", "fixed_tag_available": "2026.02.4",
     "downstream_image_count": 118},
    {"name": "shared-base-images/dotnet-aspnet", "current_tag": "8.0.2", "os": "Amazon Linux 2023",
     "runtime": "dotnet8", "rebuild_cadence": "weekly", "fixed_tag_available": "8.0.3",
     "downstream_image_count": 86},
    {"name": "shared-base-images/windows-ltsc2022", "current_tag": "2026.01", "os": "Windows Server 2022",
     "runtime": "dotnet-framework", "rebuild_cadence": "weekly", "fixed_tag_available": "2026.02",
     "downstream_image_count": 54},
    {"name": "shared-base-images/al2023-java", "current_tag": "2026.02.1", "os": "Amazon Linux 2023",
     "runtime": "corretto21", "rebuild_cadence": "daily", "fixed_tag_available": "2026.02.4",
     "downstream_image_count": 97},
]

# Public official images the demo + test apps build FROM (via the ECR Public
# mirror). fixed_tag_available = the current upstream tag the AI fix moves to.
PUBLIC_BASE_IMAGES = [
    {"name": "library/python", "current_tag": "3.9-alpine3.16", "os": "Alpine Linux",
     "runtime": "python", "rebuild_cadence": "upstream", "fixed_tag_available": "3.12-alpine",
     "downstream_image_count": 3},
    {"name": "library/node", "current_tag": "16-alpine3.16", "os": "Alpine Linux",
     "runtime": "node", "rebuild_cadence": "upstream", "fixed_tag_available": "22-alpine",
     "downstream_image_count": 2},
]

# NOTE: "today" freezes the SLA clock. Only written with --with-policy; without a
# stored policy the platform uses core.default_policy() (today's date).
POLICY = {
    "today": "2026-02-20",
    "sla": {"target_days": 15, "breach_days": 30, "measure_from": "firstSeen"},
    "gate": {"block_on": ["CRITICAL", "HIGH"], "exception_requires_approval": True},
    "fast_track": {"kev": True, "epss_threshold": 0.5},
    "fast_track_days": 7,
    "staleness": {"mutable_tag_prod_warn_days": 14},
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", required=True)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--demo-findings", action="store_true",
                    help="also load the demo Wiz findings for a first run")
    ap.add_argument("--with-policy", action="store_true",
                    help="also store the fixed-date demo POLICY (freezes the SLA clock)")
    ap.add_argument("--profile", default=None, help="AWS profile (e.g. sandbox)")
    args = ap.parse_args()

    os.environ["TABLE_NAME"] = args.table
    os.environ.setdefault("AWS_DEFAULT_REGION", args.region)
    if args.profile:
        os.environ["AWS_PROFILE"] = args.profile
    import store  # imported after env is set

    for bi in BASE_IMAGES + PUBLIC_BASE_IMAGES:
        store.put_base_image(bi)
    if args.with_policy:
        store.put_policy(POLICY)
    print(f"Seeded {len(BASE_IMAGES) + len(PUBLIC_BASE_IMAGES)} base images"
          + (" + policy" if args.with_policy else "") + f" into {args.table}")

    if args.demo_findings:
        path = os.path.join(os.path.dirname(__file__), "..", "demo-norstella", "data", "wiz_findings.json")
        if os.path.exists(path):
            data = json.load(open(path, encoding="utf-8"))
            n = 0
            for f in data["vulnerabilityFindings"]:
                store.upsert_finding(f)
                n += 1
            print(f"Seeded {n} demo findings")
        else:
            print("demo findings file not found; skipping")


if __name__ == "__main__":
    main()
