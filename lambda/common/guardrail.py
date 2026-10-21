"""
Amazon Bedrock Guardrail around Fix with AI, applied with the standalone
ApplyGuardrail API (independent of the model endpoint, so it works the same
for the Mantle Messages API):

  screen_files()   INPUT: every repo file before it is shown to the model.
                   A file the guardrail flags (prompt-injection text, an AWS
                   access key, a private key, a token) is withheld from the model
                   (so the model cannot edit it either) and listed in the notes.
  screen_output()  OUTPUT: the lines the model adds + its summary. Any
                   intervention becomes a validation error, which blocks Push.

Without GUARDRAIL_ID (local runs, tests) both are no-ops. With it, a failed
ApplyGuardrail call fails the fix (closed), it never skips the check.
"""

import os

GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
CHUNK = 20_000        # characters per content block

_client = None        # tests inject a fake


def enabled():
    return bool(GUARDRAIL_ID) or _client is not None


def client():
    global _client
    if _client is None:
        import boto3
        from botocore.config import Config
        _client = boto3.client("bedrock-runtime", config=Config(
            retries={"mode": "adaptive", "max_attempts": 8}))   # text-unit quotas are per second
    return _client


def _reasons(resp):
    out = []
    for a in resp.get("assessments") or []:
        for f in (a.get("contentPolicy") or {}).get("filters") or []:
            if f.get("action") == "BLOCKED":
                out.append(f"{f.get('type')} ({f.get('confidence', '').lower()} confidence)")
        sens = a.get("sensitiveInformationPolicy") or {}
        for e in sens.get("piiEntities") or []:
            if e.get("action") in ("BLOCKED", "ANONYMIZED"):
                out.append(e.get("type"))
        for r in sens.get("regexes") or []:
            if r.get("action") in ("BLOCKED", "ANONYMIZED"):
                out.append(r.get("name"))
        for t in (a.get("topicPolicy") or {}).get("topics") or []:
            if t.get("action") == "BLOCKED":
                out.append(f"topic {t.get('name')}")
    return sorted(set(out)) or ["guardrail intervened"]


def check(text, source):
    """-> {"intervened": bool, "reasons": [...], "units": usage} for one text."""
    chunks = [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)] or [""]
    resp = client().apply_guardrail(
        guardrailIdentifier=GUARDRAIL_ID, guardrailVersion=GUARDRAIL_VERSION, source=source,
        content=[{"text": {"text": c}} for c in chunks])
    hit = resp.get("action") == "GUARDRAIL_INTERVENED"
    return {"intervened": hit, "reasons": _reasons(resp) if hit else [],
            "usage": resp.get("usage") or {}}


def screen_files(files):
    """-> (files the model may see, notes, log entries)."""
    if not enabled():
        return files, [], []
    kept, notes, log = {}, [], []
    for path in sorted(files):
        r = check(files[path], "INPUT")
        log.append({"path": path, "source": "INPUT", **r})
        if r["intervened"]:
            notes.append(f"guardrail withheld {path} from the model: {', '.join(r['reasons'])}")
        else:
            kept[path] = files[path]
    return kept, notes, log


def screen_output(proposal, files):
    """-> (errors, log entries) for the model's proposal."""
    if not enabled():
        return [], []
    errors, log = [], []
    for c in proposal.get("changes") or []:
        before = set((files.get(c.get("path")) or "").splitlines())
        added = "\n".join(l for l in (c.get("content") or "").splitlines() if l not in before)
        if not added.strip():
            continue
        r = check(added, "OUTPUT")
        log.append({"path": c.get("path"), "source": "OUTPUT", **r})
        if r["intervened"]:
            errors.append(f"{c.get('path')}: guardrail blocked the change ({', '.join(r['reasons'])})")
    text = "\n".join([proposal.get("summary") or ""] + [str(x) for x in proposal.get("risks") or []])
    if text.strip():
        r = check(text, "OUTPUT")
        log.append({"path": None, "source": "OUTPUT", **r})
        if r["intervened"]:
            errors.append(f"summary: guardrail blocked it ({', '.join(r['reasons'])})")
    return errors, log
