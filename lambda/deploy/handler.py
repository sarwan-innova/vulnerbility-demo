"""
deployFn — Step Functions task: deploy the REBUILT image to an environment.
Used for DEPLOY_DEV and PROMOTE_PROD (env passed in the state input). Req 9.2/9.7.

MOCK mode records "deployed <image> to <env>".
LIVE mode: retags <repo>:fix-<workflow id> as <env>-current in ECR and forces a
new ECS deployment on that env's service (ENV_MAP, populated from config).

After a successful PROMOTE_PROD the workflow is DONE and the original image's
findings that the promoted image no longer has are marked RESOLVED.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import promotion  # noqa: E402
import store  # noqa: E402

MOCK = os.environ.get("MOCK", "true").lower() == "true"
ENV_MAP = json.loads(os.environ.get("ENV_MAP", "{}") or "{}")

_clients = {}


def _client(name):
    if name not in _clients:
        import boto3
        _clients[name] = boto3.client(name)
    return _clients[name]


def _retag_in_ecr(repo, source_tag, dest_tag):
    """LIVE: copy the rebuilt image manifest to the env-specific tag."""
    ecr = _client("ecr")
    img = ecr.batch_get_image(repositoryName=repo, imageIds=[{"imageTag": source_tag}])
    manifest = img["images"][0]["imageManifest"]
    try:
        ecr.put_image(repositoryName=repo, imageTag=dest_tag, imageManifest=manifest)
    except ecr.exceptions.ImageAlreadyExistsException:
        pass


def handler(event, context):
    wf_id = event["workflowId"]
    env_name = event.get("env", "dev")
    image = event["image"]
    wf = store.get_workflow(wf_id) or {}
    target = wf.get("target_image") or image
    stage = "DEPLOY_DEV" if env_name == "dev" else "PROMOTE_PROD"

    detail = f"deployed {target} to {env_name}"
    if not MOCK:
        cfg = ENV_MAP.get(env_name, {})
        repo, _, tag = target.rpartition(":")
        repo = cfg.get("ecr_repo") or repo
        _retag_in_ecr(repo, tag, f"{env_name}-current")
        detail = f"retagged {repo}:{tag} as {env_name}-current"
        if cfg.get("ecs_cluster") and cfg.get("ecs_service"):
            _client("ecs").update_service(cluster=cfg["ecs_cluster"], service=cfg["ecs_service"],
                                          forceNewDeployment=True)
            detail += f" and forced ECS deploy on {cfg['ecs_cluster']}/{cfg['ecs_service']}"

    wf.setdefault("deployed", []).append(env_name)
    wf["state"] = stage
    if env_name == "prod":
        open_findings = store.list_findings()
        gone = promotion.superseded(store.findings_for_image(open_findings, image),
                                    store.findings_for_image(open_findings, target))
        store.resolve_findings(gone, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               f"promoted:{wf_id}")
        wf["state"] = "DONE"
        wf["resolved_on_promote"] = len(gone)
        detail += f"; {len(gone)} finding(s) on {image} resolved"
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": stage, "status": "done",
                                        "env": env_name, "detail": detail, "mock": MOCK})
    return {**event, "stage": stage, "env": env_name}
