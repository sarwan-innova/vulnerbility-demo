"""
CI loop shared logic: an image pushed by the app build -> registered -> scanned.

  register_push()     ECR push event -> image record (commit, branch, GitHub repo,
                      base layers from the image's labels) -> start its scan
  inspector_scan()    pull Amazon Inspector's findings for the image and finalize
  finish_scan()       copy a finished scan's status/summary onto the image record,
                      then enforce the gate (GitHub status check + ECR approved- tag)
  rescan_latest()     the daily schedule: re-scan the newest image of every repo,
                      so a CVE published after the push still flips the gate

SCANNER selects how images are scanned:
  inspector  Amazon Inspector ECR scan-on-push (an "Inspector2 Scan" event follows)
  wizcli     the `*-wizscan` CodeBuild project running wizcli (a CodeBuild state-change event follows)
  trivy      the same project running Trivy (no account-wide scanning change; until Wiz)
  mock       the mock Wiz (local runs / tests)
A push from a fix/<...>-<fixid> branch is linked to that AI fix, so the console
can show before/after.
"""

import os
import time

import gate
import inspector_client
import scanner
import store

SCANNER = os.environ.get("SCANNER") or (
    "mock" if os.environ.get("WIZ_MOCK", "true").lower() == "true" else "wizcli")
SCAN_PROJECT = os.environ.get("WIZ_SCAN_PROJECT", "")
FIX_BRANCH_PREFIX = "fix/"
CODEBUILD_SCANNERS = ("wizcli", "trivy")   # both run in the `*-wizscan` CodeBuild project
GITHUB_SECRET_ARN = os.environ.get("GITHUB_SECRET_ARN", "")
# post the gate to GitHub + ECR after each scan (on in AWS; local runs inject mocks)
GATE_ENFORCE = os.environ.get("GATE_ENFORCE", "false").lower() == "true"

_clients = {}
_github = None


def github():
    """GitHub client for commit statuses (local runs inject a mock)."""
    global _github
    if _github is None and GITHUB_SECRET_ARN:
        import github_client
        import wiz_source
        _github = github_client.GitHubClient(wiz_source.load_secret(GITHUB_SECRET_ARN).get("token"))
    return _github


def client(name):
    """Lazy boto3 client (tests/local replace entries in _clients)."""
    if name not in _clients:
        import boto3
        _clients[name] = boto3.client(name)
    return _clients[name]


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fix_id_from_branch(branch):
    if branch and branch.startswith(FIX_BRANCH_PREFIX) and "-" in branch:
        return branch.rsplit("-", 1)[-1]
    return None


def register_push(repository, tag, digest, meta, account=None):
    """Create the image record for a CI push and start its scan. Returns the record."""
    from github_client import repo_from_source_url
    image = f"{repository}:{tag}"
    record = {
        "image": image, "repo": repository, "tag": tag, "digest": digest,
        "pushedAt": now(), "account": account,
        "commit": meta.get("commit"), "branch": meta.get("branch"),
        "github": repo_from_source_url(meta.get("source")),
        "base_ref": meta.get("base_ref"), "base_layers": meta.get("base_layers") or [],
        "context": meta.get("context"),
        "scanner": SCANNER, "scan_status": "SCANNING",
    }
    fix_id = fix_id_from_branch(record["branch"])
    fix = store.get_fix(fix_id) if fix_id else None
    if fix:
        record["fix_id"] = fix_id
        record["source_image"] = fix["image"]
        fix["rebuilt_image"] = image
        store.put_fix(fix)

    store.put_image(record)
    return start_scan(record)


def start_scan(record, purpose="ci"):
    """Scan an image record with the configured scanner. Returns the updated record."""
    if SCANNER == "inspector" and purpose != "ci":
        return inspector_scan(record)        # Inspector keeps its findings current itself
    scan = scanner.new_scan(record["image"], purpose=purpose, account=record.get("account"))
    scan["digest"] = record.get("digest")
    record = {**record, "scan_id": scan["id"], "scan_status": "SCANNING"}
    if SCANNER in CODEBUILD_SCANNERS:
        scan["mode"] = SCANNER
        env = scanner.live_env(scan)
        build = client("codebuild").start_build(
            projectName=SCAN_PROJECT,
            environmentVariablesOverride=[{"name": k, "value": v, "type": "PLAINTEXT"}
                                          for k, v in env.items()])
        scan["buildId"] = build["build"]["id"]
        store.put_scan(scan)
    elif SCANNER == "inspector":
        scan["mode"] = "inspector"   # Inspector scans on push; its event completes this
        store.put_scan(scan)
    else:
        scan = scanner.run_mock(scan)
    store.put_image(record)
    if scan["status"] != "RUNNING":
        record = finish_scan(record, scan)
    return record


def inspector_scan(record):
    """Fetch Inspector's findings for the image now and finalize a scan of them."""
    scan = store.get_scan(record.get("scan_id")) if record.get("scan_id") else None
    if not scan or scan.get("status") != "RUNNING":
        scan = scanner.new_scan(record["image"], purpose="ci", account=record.get("account"))
        scan["mode"] = "inspector"
    findings = inspector_client.list_image_findings(client("inspector2"), record["repo"],
                                                    record["digest"])
    store.put_json_report(scan["resultsKey"], inspector_client.to_wizcli(
        findings, base_layers=record.get("base_layers"), base_ref=record.get("base_ref")))
    store.put_json_report(scan["sbomKey"], {"note": "Inspector: export the SBOM with "
                                                   "inspector2:CreateSbomExport"})
    scan = scanner.finalize(scan)
    record["scan_id"] = scan["id"]
    return finish_scan(record, scan)


def finish_scan(record, scan):
    record = {**record, "scan_id": scan["id"],
              "scan_status": "DONE" if scan["status"] == "SUCCEEDED" else "FAILED",
              "scan_summary": scan.get("summary"), "scanned_at": scan.get("finishedAt"),
              "scan_error": scan.get("error")}
    if scan["status"] == "SUCCEEDED":
        record = enforce_gate(record)
    store.put_image(record)
    return record


def enforce_gate(record):
    """Recompute the image's gate verdict and make it bind (see gate.py)."""
    verdict = gate.evaluate(record["image"])
    if not GATE_ENFORCE:
        return {**record, "gate_verdict": verdict["verdict"], "gate_blocking": verdict["blocking"]}
    try:
        gh = github()
    except Exception as e:      # no token: still tag ECR, report the GitHub problem
        gh, record = None, {**record, "gate_error": f"GitHub: {e}"}
    return gate.enforce(record, verdict, github=gh, ecr=client("ecr"))


def rescan_latest(repos=None):
    """Daily re-scan: the newest image of each repo (fix-branch images included)."""
    latest = {}
    for r in store.list_image_records():
        if not r.get("repo") or (repos and r["repo"] not in repos):
            continue
        if r["repo"] not in latest or (r.get("pushedAt") or "") > (latest[r["repo"]].get("pushedAt") or ""):
            latest[r["repo"]] = r
    started = []
    for r in latest.values():
        if r.get("scan_status") == "SCANNING" or not r.get("digest"):
            continue
        try:
            start_scan(r, purpose="scheduled")
            started.append(r["image"])
        except Exception as e:
            print(f"scheduled re-scan of {r['image']} failed to start: {e}")
    return started


def image_for_digest(repository, digest, tags=()):
    for tag in tags or ():
        rec = store.get_image(f"{repository}:{tag}")
        if rec:
            return rec
    return next((r for r in store.list_image_records()
                 if r.get("repo") == repository and r.get("digest") == digest), None)

