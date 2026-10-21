"""Unit tests for the Jira client (Phase 5). No network: injected transport."""

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "common"))

import jira_client  # noqa: E402

CREDS = {"base_url": "https://example.atlassian.net/", "user": "svc@example.com",
         "token": "t0ken", "project_key": "SEC"}


def test_unconfigured_returns_stable_mock_key():
    k1 = jira_client.create_issue({}, "Fix image", "desc")
    assert k1.startswith("MOCK-") and k1 == jira_client.create_issue(None, "Fix image", "x")


def test_creates_issue_with_basic_auth_and_adf():
    seen = {}

    def transport(method, url, headers, body, timeout=30):
        seen.update(method=method, url=url, headers=headers, body=json.loads(body))
        return 201, b'{"key": "SEC-42"}'

    key = jira_client.create_issue(CREDS, "Summary", "line one\nline two", "Highest",
                                   transport=transport)
    assert key == "SEC-42"
    assert seen["method"] == "POST"
    assert seen["url"] == "https://example.atlassian.net/rest/api/3/issue"
    assert base64.b64decode(seen["headers"]["Authorization"].split()[1]) == b"svc@example.com:t0ken"
    fields = seen["body"]["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["priority"] == {"name": "Highest"}
    assert [p["content"][0]["text"] for p in fields["description"]["content"]] == ["line one", "line two"]


def test_unknown_priority_falls_back_to_medium():
    seen = {}

    def transport(method, url, headers, body, timeout=30):
        seen["body"] = json.loads(body)
        return 201, b'{"key": "SEC-1"}'

    jira_client.create_issue(CREDS, "s", "d", "P0", transport=transport)
    assert seen["body"]["fields"]["priority"] == {"name": "Medium"}


def test_http_error_raises_without_body():
    def transport(method, url, headers, body, timeout=30):
        return 400, b'{"errors": {"secret": "leak"}}'

    with pytest.raises(jira_client.JiraError) as e:
        jira_client.create_issue(CREDS, "s", "d", transport=transport)
    assert "400" in str(e.value) and "leak" not in str(e.value)
