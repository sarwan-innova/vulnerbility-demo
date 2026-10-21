#!/usr/bin/env python3
"""
Delete the mock-Wiz sample findings (clarivate-rwd/..., mmit-access/...,
panalgo-analytics/...) from a deployed table. They are loaded by the hourly
ingest when Wiz runs in mock mode and only clutter the console.

    .venv\\Scripts\\python.exe scripts\\remove_mock_findings.py --table vuln-remediation-sarwan --profile sandbox
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "common"))

import wiz_client  # noqa: E402
import wiz_mock  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    import boto3
    table = boto3.Session(profile_name=args.profile, region_name=args.region) \
        .resource("dynamodb").Table(args.table)
    mock_repos = {wiz_client.split_image_name(n["vulnerableAsset"]["name"])[0]
                  for n in wiz_mock.FINDING_NODES}
    kwargs = {"FilterExpression": "entity = :e", "ExpressionAttributeValues": {":e": "finding"},
              "ProjectionExpression": "PK, SK, repo"}
    removed = 0
    while True:
        page = table.scan(**kwargs)
        for item in page.get("Items", []):
            if item.get("repo") in mock_repos:
                if not args.dry_run:
                    table.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
                removed += 1
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    print(f"{'would remove' if args.dry_run else 'removed'} {removed} mock finding(s) "
          f"for {sorted(mock_repos)}")


if __name__ == "__main__":
    main()
