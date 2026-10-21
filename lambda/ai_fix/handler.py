"""
aiFixFn — "Fix with AI" and "Push fix" for a CI-built image.

HTTP API (dispatched on routeKey):
  POST /fix             {"image": "repo:tag"} -> start a fix proposal (async), 202 {fix}
  GET  /fix/{id}                              -> status, proposal, validation, diffs,
                                                 and the rebuilt image's re-scan (before/after)
  POST /fix/{id}/push                         -> commit to fix/<repo>-<id>, open a PR
Async worker (Lambda invokes itself with {"fix_worker": id}):
  read the commit from GitHub -> ai_fixer.propose (Claude on Bedrock) -> validate -> store

Nothing reaches the base branch: the push creates a new fix/ branch and a pull
request; the branch push triggers the normal build -> ECR -> scan loop.
"""
import json
import os
import re
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import ai_fixer  # noqa: E402
import core  # noqa: E402
import github_client  # noqa: E402
import store  # noqa: E402
import wiz_source  # noqa: E402

GITHUB_SECRET_ARN = os.environ.get("GITHUB_SECRET_ARN", "")
BUILD_CONTEXT = os.environ.get("BUILD_CONTEXT", "")   # app folder inside a bigger repo
CONSOLE_URL = os.environ.get("CONSOLE_URL", "")

_github = None          # local runs inject a mock here
_invoke_async = None    # local runs inject a thread runner here


def github():
    global _github
    if _github is None:
        _github = github_client.GitHubClient(wiz_source.load_secret(GITHUB_SECRET_ARN).get("token"))
    return _github


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _findings(image):
    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    enriched = core.enrich(store.list_findings(), policy, base_images)
    return store.findings_for_image(enriched, image), base_images, policy


def _counts(findings, policy):
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    blocking = sum(1 for f in findings if f["severity"] in policy["gate"]["block_on"])
    return {"total": len(findings), "by_severity": by, "blocking": blocking,
            "verdict": "BLOCKED" if blocking else "CLEAR"}


def _proposal_key(fix_id):
    return f"fixes/{fix_id}/proposal.json"


# ---------------------------------------------------------------- routes
def start(image, context, user=None):
    record = store.get_image(image) if image else None
    if not record or not record.get("commit") or not record.get("github"):
        return _resp(400, {"error": "this image was not built by the CI pipeline from a "
                                    "GitHub commit, so there is no source to fix"})
    findings, _, policy = _findings(image)
    if not findings:
        return _resp(400, {"error": "no open findings for this image"})
    fix = {"id": uuid.uuid4().hex[:8], "image": image, "status": "RUNNING",
           "createdAt": _now(), "requestedBy": user,
           "github": record["github"], "commit": record["commit"],
           "base_branch": record.get("branch") or "main",
           "mode": "bedrock" if ai_fixer.model_configured() else "rule-based",
           "model": ai_fixer.MODEL_ID or None,
           "before": _counts(findings, policy)}
    store.put_fix(fix)
    store.put_image({**record, "last_fix_id": fix["id"]})
    payload = {"fix_worker": fix["id"]}
    if _invoke_async:
        _invoke_async(payload)
    else:
        import boto3
        boto3.client("lambda").invoke(FunctionName=context.invoked_function_arn,
                                      InvocationType="Event", Payload=json.dumps(payload))
    return _resp(202, {"fix": fix})


def work(fix_id):
    fix = store.get_fix(fix_id)
    if not fix or fix["status"] != "RUNNING":
        return {"skipped": fix_id}
    try:
        findings, base_images, _ = _findings(fix["image"])
        gh = github()
        listing = gh.list_files(fix["github"], fix["commit"])
        files, notes = ai_fixer.select_context(
            listing, lambda p: gh.read_file(fix["github"], p, fix["commit"]), findings,
            root=BUILD_CONTEXT)
        proposal = ai_fixer.propose(fix["image"], findings, base_images, files)
        validation = ai_fixer.validate(proposal, files, findings, base_images)
        store.put_json_report(_proposal_key(fix_id), {
            "proposal": proposal, "files_sent": sorted(files), "notes": notes,
            "diffs": ai_fixer.diffs(files, proposal), "validation": validation})
        fix.update(status="READY", finishedAt=_now(), summary=proposal.get("summary"),
                   mode=proposal.get("mode"), model=proposal.get("model"),
                   changed_files=[c["path"] for c in proposal.get("changes") or []],
                   addressed=[a["cve"] for a in proposal.get("addressed") or []],
                   errors=validation["errors"], warnings=validation["warnings"])
    except Exception as e:  # surface model/GitHub failures in the console
        fix.update(status="FAILED", finishedAt=_now(), error=f"{type(e).__name__}: {str(e)[:500]}")
    store.put_fix(fix)
    return {"fix": fix_id, "status": fix["status"]}


def status(fix_id):
    fix = store.get_fix(fix_id)
    if not fix:
        return _resp(404, {"error": "fix not found"})
    body = {"fix": fix}
    if fix["status"] in ("READY", "PUSHED"):
        doc = store.get_json_report(_proposal_key(fix_id))
        p = doc["proposal"]
        body.update(diffs=doc["diffs"], validation=doc["validation"], files_sent=doc["files_sent"],
                    proposal={k: p.get(k) for k in ("summary", "addressed", "not_addressed",
                                                    "risks", "mode", "model", "usage")})
    rebuilt = store.get_image(fix["rebuilt_image"]) if fix.get("rebuilt_image") else next(
        (r for r in store.list_image_records() if r.get("fix_id") == fix_id), None)
    if rebuilt:
        after = None
        if rebuilt.get("scan_status") == "DONE":
            findings, _, policy = _findings(rebuilt["image"])
            after = _counts(findings, policy)
        body["rebuilt"] = {"image": rebuilt["image"], "scan_status": rebuilt.get("scan_status"),
                           "after": after}
    return _resp(200, body)


def push(fix_id, user=None):
    fix = store.get_fix(fix_id)
    if not fix:
        return _resp(404, {"error": "fix not found"})
    if fix["status"] != "READY":
        return _resp(409, {"error": f"fix is {fix['status']}, not ready to push"})
    if fix.get("errors"):
        return _resp(409, {"error": "validation errors block this push", "errors": fix["errors"]})
    doc = store.get_json_report(_proposal_key(fix_id))
    p = doc["proposal"]
    files = {c["path"]: c["content"] for c in p["changes"]}
    slug = re.sub(r"[^a-z0-9]+", "-", fix["image"].split(":")[0].lower()).strip("-")[:40]
    branch = f"fix/{slug}-{fix_id}"
    message = (f"fix(security): remediate {len(p.get('addressed') or [])} CVE(s) in {fix['image']}\n\n"
               f"{p.get('summary', '')}\n\nCVEs: "
               + ", ".join(a["cve"] for a in p.get("addressed") or []))
    gh = github()
    commit = gh.commit_to_new_branch(fix["github"], fix["commit"], branch, files, message)
    pr = gh.open_pull_request(fix["github"], branch, fix["base_branch"],
                              f"Security fix for {fix['image']} ({len(files)} file(s))",
                              pr_body(fix, p, doc["validation"]))
    # re-read: the branch push may already have triggered a build that linked
    # its image to this fix (rebuilt_image) while we were talking to GitHub
    fix = store.get_fix(fix_id)
    fix.update(status="PUSHED", pushedAt=_now(), pushedBy=user, branch=branch,
               fix_commit=commit, pr=pr)
    store.put_fix(fix)
    return _resp(200, {"fix": fix})


def pr_body(fix, p, validation):
    lines = [f"Automated security fix for `{fix['image']}` (commit `{fix['commit'][:7]}`).", "",
             p.get("summary", ""), "", "**Addressed**"]
    lines += [f"- {a['cve']}: {a['how']}" for a in p.get("addressed") or []] or ["- none"]
    if p.get("not_addressed"):
        lines += ["", "**Not addressed**"] + [f"- {a['cve']}: {a['reason']}" for a in p["not_addressed"]]
    if p.get("risks"):
        lines += ["", "**Risks to review**"] + [f"- {r}" for r in p["risks"]]
    if validation.get("warnings"):
        lines += ["", "**Validation warnings**"] + [f"- {w}" for w in validation["warnings"]]
    lines += ["", f"Proposed by: {p.get('model') or 'rule-based fix engine'}",
              "Pushing this branch triggers the build; the console shows the re-scan before you merge."]
    if CONSOLE_URL:
        lines.append(f"Console: {CONSOLE_URL}")
    return "\n".join(lines)


# ---------------------------------------------------------------- dispatch
def _user(event):
    claims = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or {}
    return claims.get("email") or claims.get("cognito:username")


def handler(event, context):
    if "fix_worker" in event:
        return work(event["fix_worker"])
    route = event.get("routeKey", "")
    fix_id = (event.get("pathParameters") or {}).get("id")
    if route == "POST /fix":
        try:
            body = json.loads(event.get("body") or "{}")
        except ValueError:
            return _resp(400, {"error": "invalid JSON body"})
        return start(body.get("image"), context, _user(event))
    if route == "GET /fix/{id}":
        return status(fix_id)
    if route == "POST /fix/{id}/push":
        return push(fix_id, _user(event))
    return _resp(404, {"error": f"unknown route {route}"})


def _resp(code, body):
    return {"statusCode": code,
            "headers": {"content-type": "application/json",
                        "access-control-allow-origin": "*"},
            "body": json.dumps(body, default=str)}
