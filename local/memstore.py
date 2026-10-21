"""
In-memory drop-in for lambda/common/store.py, used by the local dev server and
the end-to-end tests. Registered as sys.modules["store"] BEFORE any handler is
imported, so the real Lambda handler code runs unchanged against it.

Same public functions as store.py (tests/test_local_e2e.py checks the parity);
the pure roll-up helpers are reused from store.py itself. "S3" objects are
written under .local/s3/ so reports and SBOMs can be downloaded.
"""

import copy
import importlib.util
import json
import os
import threading

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

# reuse the pure helpers from the real store module (no AWS calls at import)
_spec = importlib.util.spec_from_file_location(
    "_real_store", os.path.join(ROOT, "lambda", "common", "store.py"))
_real = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_real)
images_with_findings = _real.images_with_findings
findings_for_image = _real.findings_for_image

TABLE = "local"
BUCKET = "local-reports"
S3_DIR = os.environ.get("LOCAL_S3_DIR", os.path.join(ROOT, ".local", "s3"))
FILES_URL_PREFIX = "/api/files/"

_lock = threading.RLock()
_db = {}


def reset():
    with _lock:
        _db.clear()
        _db.update({"findings": {}, "units": {}, "audit": [], "waivers": {}, "base_images": {},
                    "policy": None, "summary": {}, "scans": {}, "latest_scan": {},
                    "workflows": {}, "events": {}, "images": {}, "fixes": {}})


reset()


def _copy(x):
    return copy.deepcopy(x)


# ---------------------------------------------------------------- findings
def upsert_finding(finding):
    with _lock:
        existing = _db["findings"].get(finding["id"])
        item = _copy(finding)
        if existing and existing.get("firstSeen"):
            item["firstSeen"] = min(item["firstSeen"], existing["firstSeen"])
        _db["findings"][finding["id"]] = item


def list_findings():
    with _lock:
        return [_copy(f) for f in _db["findings"].values() if f.get("status") != "RESOLVED"]


def resolve_findings(finding_ids, resolved_at, scan_id):
    with _lock:
        for fid in finding_ids:
            if fid in _db["findings"]:
                _db["findings"][fid].update(status="RESOLVED", resolvedAt=resolved_at,
                                            resolvedByScan=scan_id)


# ---------------------------------------------------------------- units / audit / waivers
def put_unit(unit):
    with _lock:
        _db["units"][f"{unit['type']}#{unit['target']}"] = _copy(unit)


def append_gate_decision(decision, run_date, ts):
    with _lock:
        _db["audit"].append({**_copy(decision), "run_date": run_date, "ts": ts})


def list_gate_decisions():
    with _lock:
        return _copy(_db["audit"])


def list_waivers():
    with _lock:
        return [_copy(w) for w in _db["waivers"].values()]


def put_waiver(w):
    with _lock:
        _db["waivers"][f"{w['cve']}#{w['repo']}"] = _copy(w)


# ---------------------------------------------------------------- reference data
def list_base_images():
    with _lock:
        return _copy(_db["base_images"])


def put_base_image(bi):
    with _lock:
        _db["base_images"][bi["name"]] = _copy(bi)


def get_policy(default):
    with _lock:
        return _copy(_db["policy"]) if _db["policy"] else default


def put_policy(policy):
    with _lock:
        _db["policy"] = _copy(policy)


def put_summary(summary):
    with _lock:
        _db["summary"] = _copy(summary)


def get_summary():
    with _lock:
        return _copy(_db["summary"])


# ---------------------------------------------------------------- "S3"
def _path(key):
    path = os.path.abspath(os.path.join(S3_DIR, key))
    if not path.startswith(os.path.abspath(S3_DIR) + os.sep):
        raise ValueError("invalid object key")
    return path


def put_report(key, body, content_type="application/json"):
    path = _path(key)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(body.encode() if isinstance(body, str) else body)


def put_json_report(key, obj):
    put_report(key, json.dumps(obj, indent=2, default=str))


def get_json_report(key):
    with open(_path(key), encoding="utf-8") as fh:
        return json.load(fh)


def read_object(key):
    with open(_path(key), "rb") as fh:
        return fh.read()


def presigned_report_url(key, expires=900):
    return FILES_URL_PREFIX + key


# ---------------------------------------------------------------- scans
def put_scan(scan):
    with _lock:
        _db["scans"][scan["id"]] = _copy(scan)
        if scan.get("status") == "SUCCEEDED":
            _db["latest_scan"][scan["image"]] = scan["id"]


def get_scan(scan_id):
    with _lock:
        s = _db["scans"].get(scan_id)
        return _copy(s) if s else None


def get_latest_scan(image):
    with _lock:
        sid = _db["latest_scan"].get(image)
        return _copy(_db["scans"][sid]) if sid else None


def find_scan_by_build(build_id):
    with _lock:
        return next((_copy(s) for s in _db["scans"].values() if s.get("buildId") == build_id), None)


# ---------------------------------------------------------------- CI images + AI fixes
def put_image(record):
    with _lock:
        _db["images"][record["image"]] = _copy(record)


def get_image(image):
    with _lock:
        r = _db["images"].get(image)
        return _copy(r) if r else None


def list_image_records():
    with _lock:
        return [_copy(r) for r in _db["images"].values()]


def put_fix(fix):
    with _lock:
        _db["fixes"][fix["id"]] = _copy(fix)


def get_fix(fix_id):
    with _lock:
        f = _db["fixes"].get(fix_id)
        return _copy(f) if f else None


# ---------------------------------------------------------------- workflows
def put_workflow(wf):
    with _lock:
        _db["workflows"][wf["id"]] = _copy(wf)


def get_workflow(wf_id):
    with _lock:
        w = _db["workflows"].get(wf_id)
        return _copy(w) if w else None


def append_workflow_event(wf_id, event):
    import time
    with _lock:
        evs = _db["events"].setdefault(wf_id, [])
        ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        evs.append({**_copy(event), "SK": f"EVENT#{ts}#{len(evs):04d}#{event.get('stage', '')}",
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})


def list_workflow_events(wf_id):
    with _lock:
        return _copy(_db["events"].get(wf_id, []))
