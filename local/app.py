"""
Local platform: the REAL Lambda handlers wired to an in-memory store, a local
copy of the Step Functions promotion pipelines, and either
  * the mock Wiz (default), or
  * REAL scanning + building (real=RealTools(...)): Trivy stands in for wizcli and
    Podman/Docker for CodeBuild, through local_codebuild.LocalCodeBuild — the
    handlers run their LIVE (wiz_mock=false, mock=false) code paths unchanged.
Used by local_server.py (browser) and tests/test_local_e2e.py.

    app = LocalApp(); app.seed()
    status, body = app.call("GET /images")
"""

import importlib.util
import json
import os
import sys
import threading
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COMMON = os.path.join(ROOT, "lambda", "common")

# API routes -> handler directory (mirrors PromotionStack's HTTP API)
ROUTES = {
    "GET /images": "images",
    "GET /image-findings": "image_findings",
    "POST /scan": "scan",
    "GET /scan/{id}": "scan",
    "GET /report": "scan",
    "GET /sbom": "scan",
    "POST /remediate": "remediate",
    "GET /workflow/{id}": "wf_status",
    "POST /approve": "approval",
    "POST /fix": "ai_fix",
    "GET /fix/{id}": "ai_fix",
    "POST /fix/{id}/push": "ai_fix",
    "GET /settings": "ai_fix",
    "POST /settings": "ai_fix",
}
LOCAL_SFN = "arn:local:states:::stateMachine:promotion"
LOCAL_AGENTIC_SFN = "arn:local:states:::stateMachine:promotion-agentic"
# the demo service in demo-app/ (built + scanned at startup in real mode)
DEMO_IMAGE = {"repo": "demo/vuln-api", "tag": "1.0", "source": os.path.join(ROOT, "demo-app")}
TASKS = ("apply_fix", "deploy", "verify", "await_approval", "agent_triage",
         "agent_planner", "agent_verifier", "ingest", "ci_events")
# the demo service as a GitHub repo for the push -> build -> scan -> AI fix loop
DEMO_GITHUB_REPO = "innova-demo/vuln-api"


class LocalApp:
    def __init__(self, step_delay=1.0, agentic=False, codebuild=None, ci_loop=False):
        """codebuild: a local_codebuild.LocalCodeBuild for real scans/builds (None = mock).
        ci_loop: the git push -> build -> scan -> AI fix -> push loop with a mock GitHub."""
        self.real = codebuild is not None
        self.ci_loop = ci_loop
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
        os.environ["MOCK"] = "true"            # deploy stays simulated (no ECS locally)
        os.environ["WIZ_MOCK"] = "false" if (self.real or ci_loop) else "true"
        os.environ["SCANNER"] = "wizcli" if (self.real or ci_loop) else "mock"
        os.environ["ECR_REGISTRY"] = "localhost"   # local images: localhost/<repo>:<tag>
        os.environ["REPO_MAP"] = json.dumps({DEMO_IMAGE["repo"]: DEMO_IMAGE["source"]})
        os.environ["WIZ_SCAN_PROJECT"] = "local-wizscan"
        os.environ["AGENTIC"] = "true" if agentic else "false"
        os.environ["PROMOTION_SFN_ARN"] = LOCAL_SFN
        os.environ["AGENTIC_SFN_ARN"] = LOCAL_AGENTIC_SFN
        for p in (COMMON, os.path.dirname(__file__)):
            if p not in sys.path:
                sys.path.insert(0, p)
        import memstore
        sys.modules["store"] = memstore
        # common modules hold `import store` references: reload them on top of memstore
        for name in ("scanner", "wiz_source", "agent_core", "ci", "ai_fixer", "gate"):
            sys.modules.pop(name, None)
        self.store = memstore
        self.step_delay = step_delay
        self.handlers = {name: self._load(name) for name in set(ROUTES.values()) | set(TASKS)}
        self.threads = {}
        # remediate's Step Functions client -> local runner (it picks the pipeline as in AWS)
        self.handlers["remediate"]._sfn = _LocalStepFunctions(self)
        self.codebuild = codebuild
        if self.real and not ci_loop:
            self.handlers["scan"]._cb = codebuild       # Scan now -> local wizscan job
            self.handlers["apply_fix"].MOCK = False     # emit build_env for the fix build
        if ci_loop:
            self._setup_ci_loop()

    # ------------------------------------------------------------ CI loop (mock GitHub + local builds)
    def _setup_ci_loop(self):
        import ci
        from mock_github import MockGitHub
        from mock_scanner import MockCodeBuild
        self.github = MockGitHub(on_push=self._on_git_push)
        self.cb = self.codebuild if self.real else MockCodeBuild(self.store)
        ci._clients["codebuild"] = self.cb                  # wizscan project
        from mock_ecr import MockEcr
        self.ecr = MockEcr()                                # approved-<tag> tags
        ci._clients["ecr"] = self.ecr
        ci._github = self.github                            # gate status checks
        ci.GATE_ENFORCE = True
        self.handlers["scan"]._cb = self.cb
        self.handlers["ci_events"].describe_image = self._describe_image
        fixer = self.handlers["ai_fix"]
        fixer._github = self.github
        fixer._invoke_async = lambda payload: threading.Thread(
            target=fixer.handler, args=(payload, None), daemon=True).start()
        self.image_meta = {}                                # (ecr repo, digest) -> labels
        self.builds = []                                    # build threads (tests join them)

    def _describe_image(self, repository, digest):
        return self.image_meta.get((repository, digest), {})

    def _on_git_push(self, repo, branch, sha):
        """The CodeBuild webhook: build the pushed commit, 'push to ECR', scan."""
        t = threading.Thread(target=self._build_and_scan, args=(repo, branch, sha), daemon=True)
        self.builds.append(t)
        t.start()

    def _build_and_scan(self, repo, branch, sha):
        import tempfile
        from mock_scanner import base_ref
        ecr_repo, tag = DEMO_IMAGE["repo"], sha[:7]
        image_uri, digest = f"localhost/{ecr_repo}:{tag}", f"sha256:{sha}"
        files = self.github.snapshot(sha)
        try:
            time.sleep(self.step_delay)                     # "building"
            if self.real:
                with tempfile.TemporaryDirectory() as tmp:
                    for path, text in files.items():
                        full = os.path.join(tmp, *path.split("/"))
                        os.makedirs(os.path.dirname(full), exist_ok=True)
                        with open(full, "w", encoding="utf-8") as fh:
                            fh.write(text)
                    self.codebuild.build(tmp, image_uri)
            else:
                self.cb.register(image_uri, files)
            self.ecr.push(ecr_repo, tag, digest)
            self.image_meta[(ecr_repo, digest)] = {
                "commit": sha, "branch": branch, "source": f"https://github.com/{repo}",
                "base_ref": base_ref(files), "base_layers": [], "context": "."}
            ev = self.handlers["ci_events"]
            ev.handler({"source": "aws.ecr", "detail-type": "ECR Image Action", "account": "local",
                        "detail": {"action-type": "PUSH", "result": "SUCCESS",
                                   "repository-name": ecr_repo, "image-tag": tag,
                                   "image-digest": digest}}, None)
            record = self.store.get_image(f"{ecr_repo}:{tag}")
            scan = self.store.get_scan(record["scan_id"])
            if scan.get("buildId"):                         # wizscan finished -> state-change event
                build = self.cb.batch_get_builds([scan["buildId"]])["builds"][0]
                ev.handler({"source": "aws.codebuild", "detail-type": "CodeBuild Build State Change",
                            "detail": {"build-status": build["buildStatus"],
                                       # the real event carries the build ARN
                                       "build-id": "arn:aws:codebuild:us-east-1:000000000000:build/"
                                                   + scan["buildId"]}}, None)
        except Exception as e:                              # show build failures in the console
            self.store.put_image({"image": f"{ecr_repo}:{tag}", "repo": ecr_repo, "tag": tag,
                                  "commit": sha, "branch": branch, "github": repo,
                                  "pushedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                  "scan_status": "BUILD_FAILED", "scan_error": str(e)[-800:]})

    def wait_for_builds(self, timeout=600):
        for t in list(self.builds):
            t.join(timeout)

    @staticmethod
    def _load(name):
        spec = importlib.util.spec_from_file_location(
            f"local_handler_{name}", os.path.join(ROOT, "lambda", name, "handler.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    # ------------------------------------------------------------ data
    def seed(self):
        """Fresh state: base images + policy, then a full pull from (mock) Wiz —
        or, in real mode, build the demo image if needed and scan it for real."""
        import core
        sys.path.insert(0, ROOT)
        from seed_reference_data import BASE_IMAGES, PUBLIC_BASE_IMAGES
        self.store.reset()
        for bi in BASE_IMAGES + PUBLIC_BASE_IMAGES:
            self.store.put_base_image(bi)
        self.store.put_policy(core.default_policy())  # today's date drives SLA
        if self.ci_loop:                                  # developer pushes demo-app to main
            sha = self.github.seed_from_dir(DEMO_GITHUB_REPO, DEMO_IMAGE["source"],
                                            message="vuln-api: initial version")
            self.wait_for_builds()
            rec = self.store.get_image(f"{DEMO_IMAGE['repo']}:{sha[:7]}") or {}
            if rec.get("scan_status") != "DONE":
                raise RuntimeError(f"initial build/scan failed: {rec.get('scan_error') or rec}")
            return {"ingested": (rec.get("scan_summary") or {}).get("total", 0),
                    "source": "trivy" if self.real else "mock repo scanner", "image": rec["image"]}
        if not self.real:
            return self.handlers["ingest"].handler({}, None)
        image = f"{DEMO_IMAGE['repo']}:{DEMO_IMAGE['tag']}"
        ref = f"localhost/{image}"
        if not self.codebuild.image_exists(ref):
            self.codebuild.build(DEMO_IMAGE["source"], ref)
        code, body = self.call("POST /scan", body={"image": image})
        scan = body.get("scan") or {}
        if scan.get("status") == "RUNNING":  # build already ran; status call ingests it
            code, body = self.call("GET /scan/{id}", {"id": scan["id"]})
            scan = body.get("scan") or {}
        if code >= 300 or scan.get("status") != "SUCCEEDED":
            raise RuntimeError(f"initial scan of {image} failed: {body}")
        return {"ingested": scan["summary"]["total"], "source": "trivy", "image": image}

    # ------------------------------------------------------------ HTTP API
    def call(self, route, path_params=None, query=None, body=None, claims=None):
        """Invoke the handler behind an API route with an API Gateway v2 event."""
        handler = self.handlers[ROUTES[route]]
        event = {
            "routeKey": route,
            "pathParameters": path_params or {},
            "queryStringParameters": query or {},
            "body": json.dumps(body) if body is not None else None,
            "requestContext": {"authorizer": {"jwt": {"claims": claims or {}}}},
        }
        resp = handler.handler(event, None)
        payload = json.loads(resp["body"]) if resp.get("body") else {}
        return resp["statusCode"], payload

    # ------------------------------------------------------------ Step Functions stand-in
    def start_workflow(self, wf_id, image, agentic=False):
        t = threading.Thread(target=self._run, args=(wf_id, image, agentic), daemon=True)
        self.threads[wf_id] = t
        t.start()
        return t

    def _task(self, name, event):
        time.sleep(self.step_delay)
        return self.handlers[name].handler(event, None)

    def _run(self, wf_id, image, agentic):
        """Same order as PromotionStack's (agentic) state machine."""
        ev = {"workflowId": wf_id, "image": image}
        try:
            if agentic:
                ev = self._task("agent_triage", ev)
                ev = self._task("agent_planner", ev)
            ev = self._task("apply_fix", ev)
            if ev.get("fix") == "INVALID":
                return
            if ev.get("build_env"):          # FixBuild (CodeBuild RUN_JOB in AWS)
                self.codebuild.run_job("local-fixbuild", ev["build_env"])
            ev = self._task("deploy", {"workflowId": wf_id, "image": image, "env": "dev"})
            if self.real:                    # VerifyPrepare -> VerifyScan -> Verify
                ids = {"workflowId": wf_id, "image": image}
                prep = self._task("verify", {**ids, "verify_phase": "prepare"})
                self.codebuild.run_job("local-wizscan", prep["scan_env"])
                ev = self._task("verify", {**ids, "verify_phase": "finalize",
                                           "scan_id": prep["scan_id"]})
            else:
                ev = self._task("verify", ev)
            if agentic:
                ev = self._task("agent_verifier", ev)
            if ev.get("verify") != "PASS":
                return
            self._task("await_approval", {"workflowId": wf_id, "image": image, "taskToken": ""})
            if self._wait_for_decision(wf_id) == "PROMOTE_PROD":
                self._task("deploy", {"workflowId": wf_id, "image": image, "env": "prod"})
        except Exception as e:  # surface failures like a failed execution would
            wf = self.store.get_workflow(wf_id) or {"id": wf_id}
            stage = wf.get("state") if wf.get("state") in ("APPLY_FIX", "DEPLOY_DEV", "VERIFY") else "APPLY_FIX"
            wf.update(state="FAILED", failed_stage=stage, failure=f"{type(e).__name__}: {e}")
            self.store.put_workflow(wf)
            self.store.append_workflow_event(wf_id, {"stage": "ERROR", "status": "failed",
                                                     "detail": traceback.format_exc(limit=3)})

    def _wait_for_decision(self, wf_id, timeout=3600):
        """waitForTaskToken stand-in: the approval handler moves the state on."""
        end = time.time() + timeout
        while time.time() < end:
            state = (self.store.get_workflow(wf_id) or {}).get("state")
            if state != "AWAIT_APPROVAL":
                return state
            time.sleep(0.2)
        return "TIMEOUT"


class _LocalStepFunctions:
    """Just enough of the boto3 Step Functions client for remediate's start_execution."""

    def __init__(self, app):
        self.app = app

    def start_execution(self, stateMachineArn, name, input):
        data = json.loads(input)
        self.app.start_workflow(data["workflowId"], data["image"],
                                agentic=stateMachineArn == LOCAL_AGENTIC_SFN)
        return {"executionArn": f"{stateMachineArn}:{name}"}
