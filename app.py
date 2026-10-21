#!/usr/bin/env python3
"""
CDK app entry point for the Image Vulnerability Remediation Orchestration
platform. Deploys:

  * DataStack      - DynamoDB table, S3 report bucket, SNS topic, Secrets.
  * ComputeStack   - ingest/enrich/gate pipeline, hourly Wiz pull, /summary API.
  * PromotionStack - console API, scan/fix CodeBuild, promotion state machines, UI.
  * EdgeStack      - (secure=true) CloudFront + Cognito in front of the console.

Config via CDK context:  cdk deploy -c env=prod -c region=us-east-1
"""

import json
import os

import aws_cdk as cdk

from stacks.data_stack import DataStack
from stacks.compute_stack import ComputeStack
from stacks.promotion_stack import PromotionStack
from stacks.edge_stack import EdgeStack

app = cdk.App(outdir="cdk.out")

def _flag(name, default="false"):
    """Read a toggle from CDK context (-c name=value) or an env var fallback.
    Env fallback lets a bare `python app.py` run enable features without the CDK CLI."""
    ctx = app.node.try_get_context(name)
    if ctx is not None:
        return str(ctx)
    return os.environ.get(name.upper(), default)


env_name = app.node.try_get_context("env") or os.environ.get("ENV", "dev")
region = app.node.try_get_context("region") or os.environ.get("CDK_DEFAULT_REGION", "us-east-1")
account = os.environ.get("CDK_DEFAULT_ACCOUNT")

env = cdk.Environment(account=account, region=region)

# Wiz backend: mock until real credentials exist; -c wiz_mock=false for the live API/wizcli.
wiz_mock = _flag("wiz_mock", "true") != "false"
prefix = f"vuln-remediation-{env_name}"

def _json_ctx(name):
    """JSON-valued context (-c repo_map='{"team/app":"https://..."}') or env var."""
    raw = app.node.try_get_context(name) or os.environ.get(name.upper(), "")
    if isinstance(raw, dict):
        return raw
    return json.loads(raw) if raw else {}


# ECR repo -> git clone URL for the automated fix build; env -> ECS service mapping.
repo_map = _json_ctx("repo_map")
env_map = _json_ctx("env_map")

# prod keeps its data (table, reports) when a stack is deleted
data = DataStack(app, f"{prefix}-data", prefix=prefix, retain=(env_name == "prod"), env=env)

ComputeStack(
    app,
    f"{prefix}-compute",
    prefix=prefix,
    table=data.table,
    report_bucket=data.report_bucket,
    alert_topic=data.alert_topic,
    wiz_secret=data.wiz_secret,
    jira_secret=data.jira_secret,
    wiz_mock=wiz_mock,
    env=env,
)

# Guided end-to-end remediation UX (select -> scan -> fix -> verify -> approve -> prod).
# mock=True keeps side effects (rebuild/deploy/re-scan) simulated so the UX runs
# without live ECR/EKS/Wiz; flip via context: -c mock=false
mock = _flag("mock", "true") != "false"
# Agentic AI orchestration (Bedrock). Off unless agentic=true and a model id.
agentic = _flag("agentic", "false") == "true"
bedrock_model_id = app.node.try_get_context("bedrock_model_id") or os.environ.get("BEDROCK_MODEL_ID", "")
bedrock_guardrail_id = app.node.try_get_context("bedrock_guardrail_id") or os.environ.get("BEDROCK_GUARDRAIL_ID", "")

# Secure delivery (CloudFront + Cognito). Opt-in: secure=true. The Cognito pool +
# JWT authorizer live in PromotionStack (so the API enforces auth); EdgeStack
# fronts it with CloudFront and patches the client callback to the CF domain.
secure = _flag("secure", "false") == "true"

# Developer loop (git push -> CodeBuild -> ECR -> scan -> Fix with AI -> push fix PR).
# Opt-in: -c github_repo=<owner>/<name>. The GitHub token secret must exist first.
github_repo = _flag("github_repo", "")
ci_loop = None
if github_repo:
    ci_loop = {
        "github_repo": github_repo,
        "github_secret": _flag("github_secret", f"{prefix}/github"),
        "ecr_repo": _flag("app_ecr_repo", "demo/vuln-api"),
        "dockerfile": _flag("dockerfile", "Dockerfile"),
        "context": _flag("build_context", "."),
        # trivy (in CodeBuild) until Wiz credentials exist; then -c scanner=wizcli.
        # inspector also works but changes the ACCOUNT-WIDE ECR scanning config.
        "scanner": _flag("scanner", "trivy"),
        "bedrock_model_id": _flag("fix_model_id", "anthropic.claude-opus-5-5"),
        "bedrock_region": _flag("fix_model_region", ""),
    }

promo = PromotionStack(
    app,
    f"{prefix}-promotion",
    prefix=prefix,
    table=data.table,
    report_bucket=data.report_bucket,
    wiz_secret=data.wiz_secret,
    jira_secret=data.jira_secret,
    wiz_mock=wiz_mock,
    repo_map=repo_map,
    env_map=env_map,
    mock=mock,
    agentic=agentic,
    bedrock_model_id=bedrock_model_id,
    bedrock_guardrail_id=bedrock_guardrail_id,
    secure=secure,
    ci_loop=ci_loop,
    env=env,
)

if secure:
    EdgeStack(
        app,
        f"{prefix}-edge",
        prefix=prefix,
        api_url=promo.api_url,
        user_pool=promo.user_pool,
        cognito_domain_prefix=promo.cognito_domain_prefix,
        http_api_id=promo.http_api_id,
        jwt_authorizer_id=promo.jwt_authorizer_id,
        env=env,
    )

cdk.Tags.of(app).add("project", "image-vuln-remediation")
cdk.Tags.of(app).add("owner", "cloudops-infosec")

app.synth()
