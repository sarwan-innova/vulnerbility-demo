"""
Data access layer — DynamoDB (single table) + S3 report bucket.

Entity key design (see design.md):
  Finding      PK=FINDING#<id>            SK=META
  Unit         PK=UNIT#<type>#<target>    SK=META
  Gate record  PK=AUDIT#<date>            SK=DEC#<findingId>#<ts>   (append-only)
  Waiver       PK=WAIVER#<cve>#<repo>     SK=META
  Summary      PK=SUMMARY                 SK=LATEST
Reference:
  BaseImage    PK=BASEIMAGE#<name>        SK=META
  Policy       PK=POLICY                  SK=ACTIVE

Table/bucket names come from environment variables set by the ComputeStack.
"""

import json
import os
from decimal import Decimal

import boto3

TABLE = os.environ.get("TABLE_NAME", "")
BUCKET = os.environ.get("REPORT_BUCKET", "")

_ddb = boto3.resource("dynamodb")
_s3 = boto3.client("s3")


def _table():
    return _ddb.Table(TABLE)


def _clean(obj):
    """Floats -> Decimal for DynamoDB; recurse."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, list):
        return [_clean(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    return obj


def _undecimal(obj):
    if isinstance(obj, Decimal):
        return float(obj) if obj % 1 else int(obj)
    if isinstance(obj, list):
        return [_undecimal(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _undecimal(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------- findings
def upsert_finding(finding):
    """Insert/update a finding, preserving the earliest firstSeen (Req 1.4)."""
    t = _table()
    pk = f"FINDING#{finding['id']}"
    existing = t.get_item(Key={"PK": pk, "SK": "META"}).get("Item")
    first_seen = finding["firstSeen"]
    if existing and existing.get("firstSeen"):
        first_seen = min(first_seen, existing["firstSeen"])
    item = _clean({
        **finding, "PK": pk, "SK": "META", "entity": "finding",
        "firstSeen": first_seen,
        "gsi1pk": f"SLA#{finding.get('sla_status', 'UNKNOWN')}",
        "gsi1sk": Decimal(str(finding.get("priority_score", 0))),
    })
    t.put_item(Item=item)


def list_findings():
    """Open findings only — rows a re-scan marked RESOLVED are excluded."""
    t = _table()
    items, kwargs = [], {
        "FilterExpression": "entity = :e AND (attribute_not_exists(#s) OR #s <> :r)",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":e": "finding", ":r": "RESOLVED"},
    }
    while True:
        resp = t.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return [_undecimal(i) for i in items]


def resolve_findings(finding_ids, resolved_at, scan_id):
    """Mark findings a fresh scan no longer reports as RESOLVED (kept for audit)."""
    t = _table()
    for fid in finding_ids:
        t.update_item(
            Key={"PK": f"FINDING#{fid}", "SK": "META"},
            UpdateExpression="SET #s = :r, resolvedAt = :at, resolvedByScan = :sid",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":r": "RESOLVED", ":at": resolved_at, ":sid": scan_id},
        )


# ---------------------------------------------------------------- units
def put_unit(unit):
    t = _table()
    t.put_item(Item=_clean({
        **unit, "PK": f"UNIT#{unit['type']}#{unit['target']}", "SK": "META",
        "entity": "unit",
        # store finding ids only (keep item small)
        "findings": [f.get("id") for f in unit.get("findings", [])],
    }))


# ---------------------------------------------------------------- gate audit (append-only)
def append_gate_decision(decision, run_date, ts):
    t = _table()
    t.put_item(Item=_clean({
        **decision, "PK": f"AUDIT#{run_date}",
        "SK": f"DEC#{decision['finding_id']}#{ts}", "entity": "gate_decision",
    }))


# ---------------------------------------------------------------- waivers
def list_waivers():
    t = _table()
    resp = t.scan(FilterExpression="entity = :e",
                  ExpressionAttributeValues={":e": "waiver"})
    return [_undecimal(i) for i in resp.get("Items", [])]


def put_waiver(w):
    t = _table()
    t.put_item(Item=_clean({
        **w, "PK": f"WAIVER#{w['cve']}#{w['repo']}", "SK": "META", "entity": "waiver",
    }))


# ---------------------------------------------------------------- reference data
def list_base_images():
    t = _table()
    resp = t.scan(FilterExpression="entity = :e",
                  ExpressionAttributeValues={":e": "base_image"})
    return {i["name"]: _undecimal(i) for i in resp.get("Items", [])}


def put_base_image(bi):
    t = _table()
    t.put_item(Item=_clean({**bi, "PK": f"BASEIMAGE#{bi['name']}", "SK": "META",
                            "entity": "base_image"}))


def get_policy(default):
    t = _table()
    item = t.get_item(Key={"PK": "POLICY", "SK": "ACTIVE"}).get("Item")
    return _undecimal(item["policy"]) if item and "policy" in item else default


def put_policy(policy):
    t = _table()
    t.put_item(Item=_clean({"PK": "POLICY", "SK": "ACTIVE", "entity": "policy",
                            "policy": policy}))


# ---------------------------------------------------------------- summary
def put_summary(summary):
    t = _table()
    t.put_item(Item=_clean({"PK": "SUMMARY", "SK": "LATEST", "entity": "summary",
                            **summary}))


def get_summary():
    t = _table()
    item = t.get_item(Key={"PK": "SUMMARY", "SK": "LATEST"}).get("Item")
    return _undecimal(item) if item else {}


# ---------------------------------------------------------------- S3 reports
def put_report(key, body, content_type="application/json"):
    _s3.put_object(Bucket=BUCKET, Key=key,
                   Body=body.encode() if isinstance(body, str) else body,
                   ContentType=content_type)


def put_json_report(key, obj):
    put_report(key, json.dumps(obj, indent=2, default=str))


def get_json_report(key):
    resp = _s3.get_object(Bucket=BUCKET, Key=key)
    return json.loads(resp["Body"].read())


def presigned_report_url(key, expires=900):
    return _s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": key},
                                      ExpiresIn=expires)


# ---------------------------------------------------------------- on-demand scans (wizcli)
def put_scan(scan):
    """Scan record  PK=SCAN#<id> SK=META; also points IMAGESCAN#<image> at the latest scan."""
    t = _table()
    t.put_item(Item=_clean({**scan, "PK": f"SCAN#{scan['id']}", "SK": "META", "entity": "scan"}))
    if scan.get("status") == "SUCCEEDED":
        t.put_item(Item={"PK": f"IMAGESCAN#{scan['image']}", "SK": "LATEST",
                         "entity": "image_scan", "scan_id": scan["id"]})


def get_scan(scan_id):
    item = _table().get_item(Key={"PK": f"SCAN#{scan_id}", "SK": "META"}).get("Item")
    return _undecimal(item) if item else None


def find_scan_by_build(build_id):
    resp = _table().scan(FilterExpression="entity = :e AND buildId = :b",
                         ExpressionAttributeValues={":e": "scan", ":b": build_id})
    items = resp.get("Items", [])
    return _undecimal(items[0]) if items else None


# ---------------------------------------------------------------- CI images + AI fixes
def put_image(record):
    """Image built by CI   PK=IMAGE#<repo:tag>  (commit, branch, GitHub repo, base layers, scan state)."""
    _table().put_item(Item=_clean({**record, "PK": f"IMAGE#{record['image']}", "SK": "META",
                                   "entity": "image"}))


def get_image(image):
    item = _table().get_item(Key={"PK": f"IMAGE#{image}", "SK": "META"}).get("Item")
    return _undecimal(item) if item else None


def list_image_records():
    t = _table()
    items, kwargs = [], {"FilterExpression": "entity = :e",
                         "ExpressionAttributeValues": {":e": "image"}}
    while True:
        resp = t.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return [_undecimal(i) for i in items]


def put_fix(fix):
    """AI fix proposal  PK=FIX#<id> (file contents live in S3: fixes/<id>/proposal.json)."""
    _table().put_item(Item=_clean({**fix, "PK": f"FIX#{fix['id']}", "SK": "META", "entity": "fix"}))


def get_fix(fix_id):
    item = _table().get_item(Key={"PK": f"FIX#{fix_id}", "SK": "META"}).get("Item")
    return _undecimal(item) if item else None


def get_latest_scan(image):
    ptr = _table().get_item(Key={"PK": f"IMAGESCAN#{image}", "SK": "LATEST"}).get("Item")
    return get_scan(ptr["scan_id"]) if ptr else None


# ---------------------------------------------------------------- promotion workflow
def images_with_findings(findings):
    """Roll findings up into an image list for the UI (Req 9.1)."""
    by_image = {}
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for f in findings:
        img = f.get("repo", "") + ":" + str(f.get("imageTag", ""))
        g = by_image.setdefault(img, {
            "image": img, "repo": f.get("repo"), "imageTag": f.get("imageTag"),
            "account": f.get("account"), "businessUnit": f.get("businessUnit"),
            "worst_severity": "INFO", "worst_sla": "ON_TRACK",
            "finding_count": 0, "base_layer": False, "kev": False,
        })
        g["finding_count"] += 1
        if sev_rank.get(f.get("severity", "INFO"), 0) > sev_rank.get(g["worst_severity"], 0):
            g["worst_severity"] = f.get("severity")
        order = ["BREACHED", "OVERDUE", "AT_RISK", "ON_TRACK"]
        if f.get("sla_status") in order and order.index(f["sla_status"]) < order.index(g["worst_sla"]):
            g["worst_sla"] = f["sla_status"]
        if f.get("layerType") == "base":
            g["base_layer"] = True
        if f.get("kev"):
            g["kev"] = True
    for g in by_image.values():
        g["remediation_path"] = "base-image-rebuild" if g["base_layer"] else "app-dependency-bump"
    return sorted(by_image.values(),
                  key=lambda x: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                                 .get(x["worst_severity"], 9)))


def put_workflow(wf):
    _table().put_item(Item=_clean({**wf, "PK": f"WORKFLOW#{wf['id']}", "SK": "META",
                                   "entity": "workflow"}))


def get_workflow(wf_id):
    item = _table().get_item(Key={"PK": f"WORKFLOW#{wf_id}", "SK": "META"}).get("Item")
    return _undecimal(item) if item else None


def append_workflow_event(wf_id, event):
    """Append-only audit of each stage transition (Req 9.10)."""
    import time
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    _table().put_item(Item=_clean({
        "PK": f"WORKFLOW#{wf_id}", "SK": f"EVENT#{ts}#{event.get('stage','')}",
        "entity": "workflow_event", **event,
    }))


def list_workflow_events(wf_id):
    from boto3.dynamodb.conditions import Key
    resp = _table().query(KeyConditionExpression=Key("PK").eq(f"WORKFLOW#{wf_id}")
                          & Key("SK").begins_with("EVENT#"))
    return [_undecimal(i) for i in resp.get("Items", [])]


def findings_for_image(findings, image):
    return [f for f in findings
            if (f.get("repo", "") + ":" + str(f.get("imageTag", ""))) == image]
