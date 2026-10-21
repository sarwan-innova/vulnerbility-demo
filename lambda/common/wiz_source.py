"""
Picks the Wiz backend for a Lambda: the real API (credentials from Secrets
Manager) or the mock (WIZ_MOCK=true, or the secret not filled in yet).
Keeps handlers free of mock/live branching for the API client itself.
"""

import json
import os

import wiz_client
import wiz_mock

WIZ_MOCK = os.environ.get("WIZ_MOCK", "true").lower() == "true"


def load_secret(secret_arn, sm_client=None):
    if not secret_arn:
        return {}
    if sm_client is None:
        import boto3
        sm_client = boto3.client("secretsmanager")
    try:
        resp = sm_client.get_secret_value(SecretId=secret_arn)
    except Exception as e:  # secret created empty by the stack -> no value yet
        if type(e).__name__ == "ResourceNotFoundException" or "ResourceNotFound" in str(e):
            return {}
        raise
    # CDK seeds new secrets with a random non-JSON string: treat as "not filled in"
    try:
        data = json.loads(resp.get("SecretString") or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def is_mock(secret):
    return WIZ_MOCK or not (secret.get("client_id") and secret.get("client_secret"))


def client(secret):
    """WizClient for the configured backend."""
    if is_mock(secret):
        return wiz_client.WizClient.from_secret(wiz_mock.MOCK_SECRET,
                                                transport=wiz_mock.MockTransport())
    return wiz_client.WizClient.from_secret(secret)
