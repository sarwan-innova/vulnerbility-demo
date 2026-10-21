"""
Jira client — stdlib only (Phase 5 / Req 4.2). Creates issues via
POST /rest/api/3/issue with basic auth (user + API token from Secrets Manager).

With no credentials configured it returns a deterministic MOCK-#### key, so
the pipeline and tests run without Jira. Transport is injectable like the Wiz
client.
"""

import base64
import hashlib
import json

PRIORITIES = {"Highest", "High", "Medium", "Low", "Lowest"}


class JiraError(Exception):
    pass


def _adf(text):
    """Plain text -> minimal Atlassian Document Format (one paragraph per line)."""
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in (text or "-").splitlines() if line.strip()] or
        [{"type": "paragraph", "content": [{"type": "text", "text": "-"}]}]}


def mock_key(summary):
    h = int(hashlib.sha1(summary.encode()).hexdigest()[:4], 16)
    return f"MOCK-{h % 9000 + 1000}"


def configured(creds):
    return bool(creds and creds.get("base_url") and creds.get("user") and creds.get("token"))


def create_issue(creds, summary, description, priority="Medium", labels=None, transport=None):
    """Create a Jira issue; returns the issue key (MOCK-#### when not configured)."""
    if not configured(creds):
        return mock_key(summary)
    if transport is None:
        from wiz_client import urllib_transport as transport
    project = creds.get("project_key", "VULN")
    body = {"fields": {
        "project": {"key": project},
        "issuetype": {"name": creds.get("issue_type", "Bug")},
        "summary": summary[:250],
        "description": _adf(description),
        "priority": {"name": priority if priority in PRIORITIES else "Medium"},
        "labels": labels or ["vuln-remediation"],
    }}
    auth = base64.b64encode(f"{creds['user']}:{creds['token']}".encode()).decode()
    status, raw = transport(
        "POST", creds["base_url"].rstrip("/") + "/rest/api/3/issue",
        {"Content-Type": "application/json", "Accept": "application/json",
         "Authorization": f"Basic {auth}"},
        json.dumps(body).encode())
    if status not in (200, 201):
        raise JiraError(f"Jira create issue failed (HTTP {status})")
    return json.loads(raw)["key"]
