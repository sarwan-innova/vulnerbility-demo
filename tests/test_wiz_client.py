"""
Unit tests for the Wiz client and normalizers — all against the mock Wiz
(no AWS, no network). Requirements 1.1-1.5, 9.2. The scan Lambda itself is
covered end to end in test_local_e2e.py.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda", "common"))

import core  # noqa: E402
import wiz_client  # noqa: E402
import wiz_mock  # noqa: E402

BASE_NAMES = ["shared-base-images/al2023-python", "shared-base-images/dotnet-aspnet",
              "shared-base-images/al2023-java"]


def make_client(transport=None, sleeps=None):
    return wiz_client.WizClient.from_secret(
        wiz_mock.MOCK_SECRET, transport=transport or wiz_mock.MockTransport(),
        sleep=(sleeps.append if sleeps is not None else (lambda s: None)))


# ---------------------------------------------------------------- auth + transport
def test_token_is_fetched_once_and_reused():
    t = wiz_mock.MockTransport()
    c = make_client(t)
    c.fetch_findings(BASE_NAMES)
    c.fetch_findings(BASE_NAMES)
    assert sum(1 for _, url in t.calls if "oauth/token" in url) == 1


def test_auth_failure_raises_without_leaking_body():
    c = make_client(wiz_mock.MockTransport(token_status=401))
    with pytest.raises(wiz_client.WizError) as e:
        c.fetch_findings(BASE_NAMES)
    assert "401" in str(e.value) and "denied" not in str(e.value)


def test_missing_credentials_rejected():
    with pytest.raises(wiz_client.WizError):
        wiz_client.WizClient.from_secret({"endpoint": "https://x"})


def test_retries_on_throttle_and_5xx_then_succeeds():
    sleeps = []
    c = make_client(wiz_mock.MockTransport(fail_next=[429, 503]), sleeps)
    assert len(c.fetch_findings(BASE_NAMES)) == 5
    assert sleeps == [1, 2]


def test_retries_exhausted_raises():
    fails = [500] * (wiz_client.MAX_RETRIES + 1)
    with pytest.raises(wiz_client.WizError):
        make_client(wiz_mock.MockTransport(fail_next=fails)).fetch_findings(BASE_NAMES)


def test_401_on_query_reauthenticates_once():
    t = wiz_mock.MockTransport(fail_next=[401])
    assert len(make_client(t).fetch_findings(BASE_NAMES)) == 5
    assert sum(1 for _, url in t.calls if "oauth/token" in url) == 2


def test_graphql_errors_raise():
    def transport(method, url, headers, body, timeout=30):
        if "oauth" in url:
            return 200, b'{"access_token":"t","expires_in":3600}'
        return 200, json.dumps({"errors": [{"message": "Cannot query field x"}]}).encode()
    with pytest.raises(wiz_client.WizError, match="Cannot query field x"):
        make_client(transport).fetch_findings(BASE_NAMES)


def test_paging_collects_every_page(monkeypatch):
    monkeypatch.setattr(wiz_client, "PAGE_SIZE", 2)
    t = wiz_mock.MockTransport()
    assert len(make_client(t).fetch_findings(BASE_NAMES)) == 5
    assert sum(1 for _, url in t.calls if url == wiz_mock.MOCK_ENDPOINT) == 3


# ---------------------------------------------------------------- per-image + normalization
def test_findings_for_one_image_only():
    fs = make_client().fetch_findings(BASE_NAMES, image="clarivate-rwd/ingest-api:latest")
    assert {f["cve"] for f in fs} == {"CVE-2024-21626", "CVE-2024-2961", "CVE-2023-50782"}
    assert all(f["repo"] == "clarivate-rwd/ingest-api" for f in fs)


def test_normalized_fields():
    fs = {f["cve"]: f for f in make_client().fetch_findings(BASE_NAMES)}
    runc = fs["CVE-2024-21626"]
    assert runc["repo"] == "clarivate-rwd/ingest-api" and runc["imageTag"] == "latest"
    assert runc["layerType"] == "base"
    assert runc["baseImage"] == "shared-base-images/al2023-python"
    assert runc["kev"] is True and runc["epss"] == pytest.approx(0.92)
    assert runc["mutableTag"] is True and runc["runningInProd"] is True
    assert runc["businessUnit"] == "Clarivate-RWD" and runc["account"] == "prod-rwd-1"
    app = fs["CVE-2023-50782"]
    assert app["layerType"] == "app" and app["baseImage"] is None
    assert app["package"] == "cryptography" and app["fixedVersion"] == "42.0.0"
    assert fs["CVE-2024-3094"]["mutableTag"] is False  # v3.2.0 is immutable


@pytest.mark.parametrize("name,expected", [
    ("111.dkr.ecr.us-east-1.amazonaws.com/team/app:1.2", ("team/app", "1.2")),
    ("registry.local:5000/app:dev", ("app", "dev")),
    ("team/app", ("team/app", "latest")),
    ("111.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc", ("app", "sha256:abc")),
    ("", ("", "")),
])
def test_split_image_name(name, expected):
    assert wiz_client.split_image_name(name) == expected


def test_severity_mapping():
    assert wiz_client._severity("Critical") == "CRITICAL"
    assert wiz_client._severity("NONE") == "INFO"
    assert wiz_client._severity("weird") == "INFO"


def test_base_image_falls_back_to_from_line():
    assert wiz_client.resolve_base_image("FROM public.ecr.aws/docker/library/alpine:3.19", []) \
        == "docker/library/alpine"


def test_normalized_findings_feed_enrich_with_kev_fast_track():
    policy = core.default_policy()
    policy["today"] = "2026-10-19"
    enriched = core.enrich(make_client().fetch_findings(BASE_NAMES), policy, {})
    runc = next(f for f in enriched if f["cve"] == "CVE-2024-21626")
    assert runc["fast_tracked"] is True and runc["sla_days"] == 7
    assert runc["sla_status"] == "BREACHED"  # first seen 2026-09-10, 39 days > 30


# ---------------------------------------------------------------- wizcli (scan now)
def test_wizcli_ids_match_api_ids():
    image = "clarivate-rwd/ingest-api:latest"
    api_ids = {f["id"] for f in make_client().fetch_findings(BASE_NAMES, image=image)}
    cli = wiz_client.normalize_wizcli_result(wiz_mock.mock_wizcli_result(image), image, BASE_NAMES)
    assert {f["id"] for f in cli} == api_ids
    assert {f["baseImage"] for f in cli if f["layerType"] == "base"} == \
        {"shared-base-images/al2023-python"}


def test_rescan_after_base_fix_resolves_base_findings():
    image = "clarivate-rwd/ingest-api:latest"
    before = wiz_client.normalize_wizcli_result(wiz_mock.mock_wizcli_result(image), image, BASE_NAMES)
    after = wiz_client.normalize_wizcli_result(
        wiz_mock.mock_wizcli_result(image, fixed_base=True), image, BASE_NAMES)
    gone = wiz_client.resolved_ids(before, after)
    by_id = {f["id"]: f["cve"] for f in before}
    assert {by_id[g] for g in gone} == {"CVE-2024-21626", "CVE-2024-2961"}
    assert wiz_client.scan_summary(after)["total"] == 1


def test_wizcli_layer_heuristic_when_metadata_missing():
    raw = {"result": {
        "osPackages": [{"name": "openssl", "version": "3.0.1",
                        "vulnerabilities": [{"name": "CVE-1", "severity": "High"}]}],
        "libraries": [{"name": "lodash", "version": "4.17.0",
                       "vulnerabilities": [{"name": "CVE-2", "severity": "Medium",
                                            "fixedVersion": "4.17.21"}]}]}}
    fs = {f["cve"]: f for f in wiz_client.normalize_wizcli_result(raw, "a/b:1", [])}
    assert fs["CVE-1"]["layerType"] == "base" and fs["CVE-1"]["layerSource"] == "heuristic"
    assert fs["CVE-2"]["layerType"] == "app"
    assert wiz_client.scan_summary(list(fs.values()))["fixable"] == 1
