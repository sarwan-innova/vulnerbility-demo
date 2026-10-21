"""
apply_fixFn — Step Functions task: turn the plan into a validated FIX SPEC and
apply it (Req 9.3, Phase 3 — fully automated fixes up to dev).

  * base-image-rebuild  -> FROM <base>:<fixed_tag>
  * app-dependency-bump -> manifest bump (pip / npm / NuGet) to the Wiz fixed version

fix_engine.validate_fix_spec() must pass: every change is backed by a finding
for this image and targets exactly the fixed version. An invalid spec stops the
workflow (FAILED) before anything is built.

MOCK=true : records the spec; the mock scanner honours it at VERIFY.
MOCK=false: writes the spec to S3 and returns `build_env` for the `*-fixbuild`
            CodeBuild step (run synchronously by the state machine), which
            clones the app repo (REPO_MAP), applies the spec with
            fixer/apply_fix_spec.py, builds and pushes <repo>:fix-<workflow id>.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, "/opt/python")

import core  # noqa: E402
import fix_engine  # noqa: E402
import scanner  # noqa: E402
import store  # noqa: E402

MOCK = os.environ.get("MOCK", "true").lower() == "true"
REPO_MAP = json.loads(os.environ.get("REPO_MAP", "{}") or "{}")  # ecr repo -> git clone URL


def handler(event, context):
    wf_id = event["workflowId"]
    image = event["image"]
    wf = store.get_workflow(wf_id) or {}
    plan = wf.get("plan", {})

    policy = store.get_policy(core.default_policy())
    base_images = store.list_base_images()
    findings = store.findings_for_image(
        core.enrich(store.list_findings(), policy, base_images), image)

    spec = fix_engine.build_fix_spec(image, wf_id, plan)
    problems = fix_engine.validate_fix_spec(spec, findings)
    wf["fix_spec"] = spec
    wf["target_image"] = spec["target_image"]

    if problems:
        wf["state"] = "FAILED"
        wf["failed_stage"] = "APPLY_FIX"
        wf["failure"] = "fix spec rejected: " + "; ".join(problems)
        store.put_workflow(wf)
        store.append_workflow_event(wf_id, {"stage": "APPLY_FIX", "status": "rejected",
                                            "detail": wf["failure"]})
        return {**event, "fix": "INVALID", "problems": problems}

    applied = [f"rebuild FROM {c['base_image']}:{c['to_tag']} (fixes {', '.join(c['cves'])})"
               for c in spec["base_changes"]]
    applied += [f"bump {c['package']} {c.get('from_version') or '?'} -> {c['to_version']} "
                f"(fixes {', '.join(c['cves'])})" for c in spec["dependency_changes"]]
    applied += [f"needs a human: {u.get('package') or u.get('base_image')} — {u['reason']}"
                for u in spec["unsupported"]]

    result = {**event, "fix": "READY", "target_image": spec["target_image"]}
    if not MOCK:
        spec_key = f"fixes/{wf_id}/fix-spec.json"
        store.put_json_report(spec_key, spec)
        repo, _, tag = spec["target_image"].rpartition(":")
        result["build_env"] = {
            "FIX_SPEC_S3": f"s3://{store.BUCKET}/{spec_key}",
            "SOURCE_REPO_URL": REPO_MAP.get(repo, ""),
            "SOURCE_IMAGE": image,
            "TARGET_REPO": repo,
            "TARGET_TAG": tag,
            "ECR_REGISTRY": scanner.registry_for(_account(findings)),
        }

    wf["state"] = "APPLY_FIX"
    wf["applied"] = applied
    store.put_workflow(wf)
    store.append_workflow_event(wf_id, {"stage": "APPLY_FIX", "status": "done",
                                        "detail": "; ".join(applied), "mock": MOCK,
                                        "target_image": spec["target_image"]})
    return result


def _account(findings):
    return next((f["account"] for f in findings if f.get("account")), None)
