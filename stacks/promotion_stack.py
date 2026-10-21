"""
PromotionStack — the guided end-to-end remediation UX (Requirements 9-11):
  select image -> scan -> AI fix -> deploy dev -> verify re-scan -> approve -> prod.

Resources:
  * Lambdas (images, image_findings, scan, remediate, apply_fix, deploy, verify,
    await_approval, approval, wf_status, wf_fail, agent_*) on the common layer.
  * CodeBuild `*-wizscan`  — wizcli scan of one image (Scan now + verify re-scan).
  * CodeBuild `*-fixbuild` — clone the app repo, apply the fix spec
    (fixer/apply_fix_spec.py + fix_engine.py), build + push <repo>:fix-<wf id>.
  * Step Functions pipelines (deterministic + agentic) with a manual approval
    gate (task token). LIVE build/scan steps run synchronously (RUN_JOB) and
    only exist when mock=false / wiz_mock=false; every step's failure marks the
    workflow FAILED via wf_fail.
  * HTTP API: GET /images, GET /image-findings, POST /scan, GET /scan/{id},
    GET /report, GET /sbom, POST /remediate, GET /workflow/{id}, POST /approve.
  * S3 website bucket hosting the static web UI.
"""

import json
import os

from aws_cdk import (
    Stack, Duration, RemovalPolicy, CfnOutput,
    aws_lambda as lambda_,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_apigatewayv2 as apigw,
    aws_apigatewayv2_integrations as apigw_int,
    aws_apigatewayv2_authorizers as apigw_auth,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_logs as logs,
    aws_iam as iam,
    aws_codebuild as codebuild,
    aws_cognito as cognito,
    aws_secretsmanager as secrets,
)
from constructs import Construct
from stacks._layer import common_layer_code, deps_layer_code
from stacks.ci_loop import add_ci_loop

COMMON_PATH = "lambda/common"
WIZCLI_URL = "https://downloads.wiz.io/wizcli/latest/wizcli-linux-amd64"
ECR_LOGIN = ('aws ecr get-login-password --region "$AWS_REGION" | '
             'docker login --username AWS --password-stdin "$REGISTRY"')


def _wizscan_buildspec():
    """wizcli scan of IMAGE_URI -> results.json + sbom.cdx.json in OUTPUT_PREFIX.
    wizcli exits non-zero when the Wiz policy fails; that is a scan RESULT, not a
    build failure, so the scan step tolerates it and the results file decides.
    CONFIRM: wizcli flags against the version your Wiz tenant ships."""
    return {
        "version": "0.2",
        "phases": {
            "install": {"commands": [
                f'curl -fsSL -o /usr/local/bin/wizcli "{WIZCLI_URL}"',
                "chmod +x /usr/local/bin/wizcli",
            ]},
            "build": {"commands": [
                'REGISTRY="${IMAGE_URI%%/*}"',
                ECR_LOGIN,
                'docker pull "$IMAGE_URI"',
                'wizcli auth --id "$WIZ_CLIENT_ID" --secret "$WIZ_CLIENT_SECRET"',
                'wizcli docker scan --image "$IMAGE_URI" --output results.json,json '
                '--sbom-format cyclonedx-json --sbom-output-file sbom.cdx.json '
                '|| echo "wizcli reported policy failures (results still captured)"',
                "test -s results.json",
                'aws s3 cp results.json "$OUTPUT_PREFIX/results.json"',
                'if [ -s sbom.cdx.json ]; then aws s3 cp sbom.cdx.json "$OUTPUT_PREFIX/sbom.cdx.json"; fi',
            ]},
        },
    }


TRIVY_VERSION = "0.76.0"
TRIVY_TGZ = f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz"
TRIVY_RELEASE = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}"


def _trivyscan_buildspec():
    """scanner=trivy: same contract as the wizcli scan (IMAGE_URI in, results.json
    + sbom.cdx.json out) with no account-wide scanning change. Pinned Trivy
    release, verified against its published checksums; base-image layers split
    base vs app findings; fixer/convert_trivy.py writes the wizcli shape."""
    return {
        "version": "0.2",
        "phases": {
            "install": {"commands": [
                f'curl -fsSLO "{TRIVY_RELEASE}/{TRIVY_TGZ}"',
                f'curl -fsSLO "{TRIVY_RELEASE}/trivy_{TRIVY_VERSION}_checksums.txt"',
                f'grep " {TRIVY_TGZ}$" trivy_{TRIVY_VERSION}_checksums.txt | sha256sum -c -',
                f'tar -xzf {TRIVY_TGZ} -C /usr/local/bin trivy',
            ]},
            "build": {"commands": [
                'REGISTRY="${IMAGE_URI%%/*}"',
                ECR_LOGIN,
                'docker pull "$IMAGE_URI"',
                'BASE="$(docker image inspect "$IMAGE_URI" --format '
                '\'{{ index .Config.Labels "org.opencontainers.image.base.name" }}\')"',
                'if [ -n "$BASE" ] && [ "$BASE" != "<no value>" ] && docker pull "$BASE"; then '
                'docker image inspect "$BASE" --format \'{{json .RootFS.Layers}}\' > base_layers.json; '
                'else echo "[]" > base_layers.json; fi',
                'aws s3 cp "$TOOLING_S3" tooling/ --recursive',
                'trivy image --quiet --scanners vuln --ignore-unfixed --format json '
                '--output trivy.json "$IMAGE_URI"',
                'trivy image --quiet --format cyclonedx --output sbom.cdx.json "$IMAGE_URI"',
                'python3 tooling/convert_trivy.py trivy.json base_layers.json "$BASE" results.json',
                'aws s3 cp results.json "$OUTPUT_PREFIX/results.json"',
                'aws s3 cp sbom.cdx.json "$OUTPUT_PREFIX/sbom.cdx.json"',
            ]},
        },
    }


def _fixbuild_buildspec():
    """Clone the app repo, apply the fix spec, build + push the fixed image.
    Everything is in one phase so a failed step never reaches `docker push`."""
    git_token = (
        'GIT_TOKEN=$(aws secretsmanager get-secret-value --secret-id "$GIT_SECRET_ARN" '
        '--query SecretString --output text 2>/dev/null | python3 -c '
        '"import sys,json; d=sys.stdin.read().strip(); '
        'print(json.loads(d).get(\'token\',\'\') if d.startswith(\'{\') else \'\')" || true)')
    return {
        "version": "0.2",
        "phases": {
            "build": {"commands": [
                'test -n "$SOURCE_REPO_URL" || { echo "No source repo mapped for $TARGET_REPO '
                '(add it to the repo_map context)"; exit 1; }',
                'aws s3 cp "$TOOLING_S3" tooling/ --recursive',
                'aws s3 cp "$FIX_SPEC_S3" fix-spec.json',
                git_token,
                'if [ -n "$GIT_TOKEN" ]; then '
                'AUTH=$(printf "x-access-token:%s" "$GIT_TOKEN" | base64 -w0); '
                'git -c http.extraHeader="Authorization: Basic $AUTH" clone --depth 1 "$SOURCE_REPO_URL" app; '
                'else git clone --depth 1 "$SOURCE_REPO_URL" app; fi',
                "python3 tooling/apply_fix_spec.py fix-spec.json app",
                'REGISTRY="$ECR_REGISTRY"',
                ECR_LOGIN,
                'docker build -t "$ECR_REGISTRY/$TARGET_REPO:$TARGET_TAG" '
                '--label "remediation.source=$SOURCE_IMAGE" app',
                'docker push "$ECR_REGISTRY/$TARGET_REPO:$TARGET_TAG"',
            ]},
        },
    }


class PromotionStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, prefix: str,
                 table, report_bucket=None, wiz_secret=None, jira_secret=None,
                 wiz_mock: bool = True, mock: bool = True, agentic: bool = False,
                 bedrock_model_id: str = "", bedrock_guardrail_id: str = "",
                 repo_map: dict = None, env_map: dict = None,
                 secure: bool = False, ci_loop: dict = None,
                 fix_with_ai_default: bool = True, **kwargs):
        super().__init__(scope, cid, **kwargs)
        self.user_pool = None
        self.user_pool_client = None
        ecr_registry = f"{self.account}.dkr.ecr.{self.region}.amazonaws.com"

        common_layer = lambda_.LayerVersion(
            self, "PromoCommonLayer",
            code=common_layer_code(),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            description="Shared core + promotion + store + Wiz + fix engine logic",
        )

        env = {
            "TABLE_NAME": table.table_name,
            "MOCK": "true" if mock else "false",
            "WIZ_MOCK": "true" if wiz_mock else "false",
            "ECR_REGISTRY": ecr_registry,
            "AGENTIC": "true" if agentic else "false",
            "BEDROCK_MODEL_ID": bedrock_model_id or "",
            "BEDROCK_GUARDRAIL_ID": bedrock_guardrail_id or "",
            # starting state of the console's Fix with AI switch (until someone flips it)
            "FIX_WITH_AI_DEFAULT": "true" if fix_with_ai_default else "false",
        }
        if report_bucket is not None:
            env["REPORT_BUCKET"] = report_bucket.bucket_name
        if jira_secret is not None:
            env["JIRA_SECRET_ARN"] = jira_secret.secret_arn

        def fn(name, src, timeout=60, memory=256, extra_layers=()):
            lg = logs.LogGroup(self, f"{name}Logs",
                               log_group_name=f"/aws/lambda/{prefix}-{src}",
                               retention=logs.RetentionDays.ONE_MONTH,
                               removal_policy=RemovalPolicy.DESTROY)
            f = lambda_.Function(
                self, name,
                function_name=f"{prefix}-{src}",
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler="handler.handler",
                code=lambda_.Code.from_asset(f"lambda/{src}"),
                layers=[common_layer, *extra_layers],
                timeout=Duration.seconds(timeout),
                memory_size=memory,
                environment=dict(env),
                log_group=lg,
            )
            table.grant_read_write_data(f)
            return f

        # ---------- CodeBuild: image scan (Scan now + verify re-scan + CI) ----------
        # wizcli by default; Trivy when the CI loop runs with scanner=trivy
        use_trivy = (ci_loop or {}).get("scanner") == "trivy"
        tooling_s3 = (f"s3://{report_bucket.bucket_name}/tooling/" if report_bucket is not None else "")
        wizscan_env = {"AWS_REGION": codebuild.BuildEnvironmentVariable(value=self.region),
                       "TOOLING_S3": codebuild.BuildEnvironmentVariable(value=tooling_s3)}
        if wiz_secret is not None and not wiz_mock and not use_trivy:
            for var, field in (("WIZ_CLIENT_ID", "client_id"), ("WIZ_CLIENT_SECRET", "client_secret")):
                wizscan_env[var] = codebuild.BuildEnvironmentVariable(
                    type=codebuild.BuildEnvironmentVariableType.SECRETS_MANAGER,
                    value=f"{wiz_secret.secret_arn}:{field}")
        wizscan_project = codebuild.Project(
            self, "WizScanProject",
            project_name=f"{prefix}-wizscan",
            build_spec=codebuild.BuildSpec.from_object(
                _trivyscan_buildspec() if use_trivy else _wizscan_buildspec()),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,  # docker pull for wizcli docker scan
                compute_type=codebuild.ComputeType.SMALL),
            environment_variables=wizscan_env,
            timeout=Duration.minutes(20),
        )

        # ---------- CodeBuild: apply the fix spec + build the fixed image ----------
        git_secret = secrets.Secret(self, "GitSecret", secret_name=f"{prefix}/git",
                                    description='{"token": "<PAT>"} for cloning app repos')
        fixbuild_project = codebuild.Project(
            self, "FixBuildProject",
            project_name=f"{prefix}-fixbuild",
            build_spec=codebuild.BuildSpec.from_object(_fixbuild_buildspec()),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,  # docker build
                compute_type=codebuild.ComputeType.MEDIUM),
            environment_variables={
                "AWS_REGION": codebuild.BuildEnvironmentVariable(value=self.region),
                "TOOLING_S3": codebuild.BuildEnvironmentVariable(value=tooling_s3),
                "GIT_SECRET_ARN": codebuild.BuildEnvironmentVariable(value=git_secret.secret_arn),
            },
            timeout=Duration.minutes(45),
        )
        git_secret.grant_read(fixbuild_project)

        # ECR: pull from any account's repos (cross-account needs the org repo
        # policy, see README), push only to this account's repos.
        for project in (wizscan_project, fixbuild_project):
            project.add_to_role_policy(iam.PolicyStatement(
                actions=["ecr:GetAuthorizationToken"], resources=["*"]))
            project.add_to_role_policy(iam.PolicyStatement(
                actions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
                         "ecr:BatchCheckLayerAvailability"],
                resources=["arn:aws:ecr:*:*:repository/*"]))
        fixbuild_project.add_to_role_policy(iam.PolicyStatement(
            actions=["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
                     "ecr:CompleteLayerUpload"],
            resources=[f"arn:aws:ecr:{self.region}:{self.account}:repository/*"]))
        if wiz_secret is not None:
            wiz_secret.grant_read(wizscan_project)
        if report_bucket is not None:
            report_bucket.grant_put(wizscan_project)
            report_bucket.grant_read(wizscan_project)     # tooling/ (Trivy converter)
            report_bucket.grant_read(fixbuild_project)
            # ship the fixer, fix engine and Trivy converter the builds run
            # (the same code the tests cover)
            shared = []
            for name in ("fix_engine.py", "trivy_adapter.py"):
                with open(os.path.join(COMMON_PATH, name), encoding="utf-8") as fh:
                    shared.append(s3deploy.Source.data(name, fh.read()))
            s3deploy.BucketDeployment(
                self, "DeployFixerTooling",
                sources=[s3deploy.Source.asset("fixer"), *shared],
                destination_bucket=report_bucket,
                destination_key_prefix="tooling/",
                prune=False,
            )

        # ---------- Lambdas ----------
        # ---------- CI loop: push -> build -> ECR -> scan -> AI fix -> push (opt-in) ----------
        ai_fix_fn = None
        if ci_loop and report_bucket is not None:
            deps_layer = lambda_.LayerVersion(
                self, "DepsLayer", code=deps_layer_code(),
                compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
                description="Third-party packages (Anthropic SDK)")
            ai_fix_fn, built = add_ci_loop(
                self, prefix=prefix, fn=fn, deps_layer=deps_layer, report_bucket=report_bucket,
                wizscan_project=wizscan_project, cfg=ci_loop)
            CfnOutput(self, "AppBuildProject", value=built[0][1].project_name)
            CfnOutput(self, "AppEcrRepo", value=built[0][2].repository_uri)
            CfnOutput(self, "AppBuildProjects",
                      value=",".join(b.project_name for _, b, _ in built))

        images_fn = fn("ImagesFn", "images", timeout=15)
        image_findings_fn = fn("ImageFindingsFn", "image_findings", timeout=30)
        if ci_loop:  # so the console labels the fix with the real model, not "rule-based"
            image_findings_fn.add_environment("FIX_MODEL_ID", ci_loop.get("bedrock_model_id", ""))
        scan_fn = fn("ScanFn", "scan", timeout=60)
        remediate_fn = fn("RemediateFn", "remediate")
        apply_fix_fn = fn("ApplyFixFn", "apply_fix", timeout=60)
        deploy_fn = fn("DeployFn", "deploy", timeout=120)
        verify_fn = fn("VerifyFn", "verify", timeout=120)
        await_fn = fn("AwaitApprovalFn", "await_approval")
        approval_fn = fn("ApprovalFn", "approval", timeout=15)
        status_fn = fn("WfStatusFn", "wf_status", timeout=15)
        wf_fail_fn = fn("WfFailFn", "wf_fail", timeout=15)
        agent_triage_fn = fn("AgentTriageFn", "agent_triage")
        agent_planner_fn = fn("AgentPlannerFn", "agent_planner")
        agent_verifier_fn = fn("AgentVerifierFn", "agent_verifier")

        scan_fn.add_environment("WIZ_SCAN_PROJECT", wizscan_project.project_name)
        if ci_loop:  # re-scan of a CI image uses the same scanner as the push-triggered scan
            scan_fn.add_environment("SCANNER", ci_loop["scanner"])
            scan_fn.add_to_role_policy(iam.PolicyStatement(
                actions=["inspector2:ListFindings"], resources=["*"]))
        scan_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
            resources=[wizscan_project.project_arn]))
        apply_fix_fn.add_environment("REPO_MAP", json.dumps(repo_map or {}))
        deploy_fn.add_environment("ENV_MAP", json.dumps(env_map or {}))
        deploy_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["ecr:BatchGetImage", "ecr:PutImage", "ecr:GetDownloadUrlForLayer",
                     "ecs:UpdateService", "ecs:DescribeServices"],
            resources=["*"]))
        if report_bucket is not None:
            for f in (scan_fn, verify_fn):
                report_bucket.grant_read_write(f)
            report_bucket.grant_put(apply_fix_fn)
        if jira_secret is not None:
            jira_secret.grant_read(verify_fn)
        if agentic and bedrock_model_id:
            for af in (agent_triage_fn, agent_planner_fn, agent_verifier_fn, image_findings_fn):
                af.add_to_role_policy(iam.PolicyStatement(
                    actions=["bedrock:InvokeModel", "bedrock:Converse", "bedrock:ApplyGuardrail"],
                    resources=["*"]))

        # ---------- Step Functions ----------
        def task(fnc, name, payload=None):
            return tasks.LambdaInvoke(
                self, name, lambda_function=fnc,
                payload=sfn.TaskInput.from_object(payload) if payload else None,
                output_path="$.Payload",
            ).add_retry(errors=["Lambda.ServiceException", "Lambda.TooManyRequestsException",
                                "Lambda.SdkClientException"],
                        max_attempts=2, interval=Duration.seconds(3), backoff_rate=2.0)

        def env_from(path, names):
            return {n: codebuild.BuildEnvironmentVariable(value=sfn.JsonPath.string_at(f"{path}.{n}"))
                    for n in names}

        wf_ids = {"workflowId.$": "$.workflowId", "image.$": "$.image"}

        def pipeline(p, agentic_mode):
            """Build one state machine definition; `p` prefixes construct ids."""
            mark_failed = tasks.LambdaInvoke(
                self, f"{p}MarkFailed", lambda_function=wf_fail_fn,
                payload=sfn.TaskInput.from_object({"workflowId.$": "$.workflowId",
                                                   "error.$": "$.error"}),
                output_path="$.Payload")
            mark_failed.next(sfn.Fail(self, f"{p}WorkflowFailed", error="WorkflowFailed",
                                      cause="A step failed; see the workflow record"))

            def guard(state):
                return state.add_catch(mark_failed, errors=["States.ALL"], result_path="$.error")

            states = []
            if agentic_mode:
                states += [guard(task(agent_triage_fn, f"{p}AgentTriage")),
                           guard(task(agent_planner_fn, f"{p}AgentPlan"))]
            apply_fix = guard(task(apply_fix_fn, f"{p}ApplyFix"))
            states.append(apply_fix)

            after_fix = []
            if not mock:
                after_fix.append(guard(tasks.CodeBuildStartBuild(
                    self, f"{p}FixBuild", project=fixbuild_project,
                    integration_pattern=sfn.IntegrationPattern.RUN_JOB,
                    environment_variables_override=env_from(
                        "$.build_env", ["FIX_SPEC_S3", "SOURCE_REPO_URL", "SOURCE_IMAGE",
                                        "TARGET_REPO", "TARGET_TAG", "ECR_REGISTRY"]),
                    result_path=sfn.JsonPath.DISCARD)))
            after_fix.append(guard(task(deploy_fn, f"{p}DeployDev", {**wf_ids, "env": "dev"})))
            if wiz_mock:
                after_fix.append(guard(task(verify_fn, f"{p}Verify", wf_ids)))
            else:
                after_fix += [
                    guard(task(verify_fn, f"{p}VerifyPrepare", {**wf_ids, "verify_phase": "prepare"})),
                    guard(tasks.CodeBuildStartBuild(
                        self, f"{p}VerifyScan", project=wizscan_project,
                        integration_pattern=sfn.IntegrationPattern.RUN_JOB,
                        environment_variables_override=env_from("$.scan_env", ["IMAGE_URI", "OUTPUT_PREFIX"]),
                        result_path=sfn.JsonPath.DISCARD)),
                    guard(task(verify_fn, f"{p}Verify",
                               {**wf_ids, "verify_phase": "finalize", "scan_id.$": "$.scan_id"})),
                ]
            if agentic_mode:
                after_fix.append(guard(task(agent_verifier_fn, f"{p}AgentVerifyExplain")))

            await_approval = tasks.LambdaInvoke(
                self, f"{p}AwaitApproval", lambda_function=await_fn,
                integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
                payload=sfn.TaskInput.from_object({**wf_ids, "taskToken": sfn.JsonPath.task_token}),
                task_timeout=sfn.Timeout.duration(Duration.hours(24)),
                result_path=sfn.JsonPath.DISCARD)
            # a rejection arrives as SendTaskFailure: stop cleanly (state already REJECTED)
            await_approval.add_catch(sfn.Fail(self, f"{p}Rejected", error="Rejected",
                                              cause="Promotion rejected by approver"),
                                     errors=["Rejected"])
            guard(await_approval)
            promote = guard(task(deploy_fn, f"{p}PromoteProd", {**wf_ids, "env": "prod"}))

            verify_choice = sfn.Choice(self, f"{p}VerifyPassed?") \
                .when(sfn.Condition.string_equals("$.verify", "PASS"),
                      await_approval.next(promote).next(sfn.Succeed(self, f"{p}Done"))) \
                .otherwise(sfn.Fail(self, f"{p}VerifyFailed", error="VerifyFailed",
                                    cause="Blocking findings remain after the fix"))

            for a, b in zip(after_fix, after_fix[1:]):
                a.next(b)
            after_fix[-1].next(verify_choice)
            fix_choice = sfn.Choice(self, f"{p}FixValid?") \
                .when(sfn.Condition.string_equals("$.fix", "INVALID"),
                      sfn.Fail(self, f"{p}FixRejected", error="FixRejected",
                               cause="Fix spec failed validation"))\
                .otherwise(after_fix[0])
            for a, b in zip(states, states[1:]):
                a.next(b)
            apply_fix.next(fix_choice)
            return states[0]

        pipeline_sm = sfn.StateMachine(
            self, "PromotionPipeline",
            state_machine_name=f"{prefix}-promotion",
            definition_body=sfn.DefinitionBody.from_chainable(pipeline("", False)),
            timeout=Duration.hours(26),
        )
        agentic_sm = sfn.StateMachine(
            self, "AgenticPromotionPipeline",
            state_machine_name=f"{prefix}-promotion-agentic",
            definition_body=sfn.DefinitionBody.from_chainable(pipeline("Agent", True)),
            timeout=Duration.hours(26),
        )
        for sm in (pipeline_sm, agentic_sm):
            sm.grant_start_execution(remediate_fn)
        remediate_fn.add_environment("PROMOTION_SFN_ARN", pipeline_sm.state_machine_arn)
        remediate_fn.add_environment("AGENTIC_SFN_ARN", agentic_sm.state_machine_arn)

        # approval Lambda resolves the task token of either pipeline
        approval_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["states:SendTaskSuccess", "states:SendTaskFailure"],
            resources=[pipeline_sm.state_machine_arn, agentic_sm.state_machine_arn]))

        # ---------- Cognito (owned here so the API can enforce it) ----------
        # Created in this stack (not EdgeStack) so the HTTP API JWT authorizer can
        # reference the user pool without a circular stack dependency.
        jwt_authorizer = None
        if secure:
            self.user_pool = cognito.UserPool(
                self, "UserPool",
                user_pool_name=f"{prefix}-users",
                self_sign_up_enabled=False,
                sign_in_aliases=cognito.SignInAliases(email=True),
                removal_policy=RemovalPolicy.DESTROY,
            )
            self.user_pool_domain = self.user_pool.add_domain(
                "HostedDomain",
                cognito_domain=cognito.CognitoDomainOptions(
                    domain_prefix=f"{prefix}-{self.account}"[:63].replace("_", "-")),
            )
            # The web app CLIENT is created in EdgeStack (it needs the CloudFront
            # callback URL). The authorizer validates tokens from the POOL (Req 11.4).
            jwt_authorizer = apigw_auth.HttpUserPoolAuthorizer(
                "JwtAuthorizer", self.user_pool,
                identity_source=["$request.header.Authorization"],
            )

        # ---------- HTTP API ----------
        # CORS: list explicit headers (never mix "*" with named headers). The
        # auto-generated OPTIONS preflight route is NOT subject to the JWT authorizer.
        http_api = apigw.HttpApi(
            self, "PromotionApi", api_name=f"{prefix}-promotion-api",
            cors_preflight=apigw.CorsPreflightOptions(
                allow_origins=["*"],
                allow_methods=[apigw.CorsHttpMethod.GET, apigw.CorsHttpMethod.POST,
                               apigw.CorsHttpMethod.OPTIONS],
                allow_headers=["authorization", "content-type", "x-amz-date",
                               "x-amz-security-token", "x-api-key"],
                max_age=Duration.days(1)),
        )

        def route(path, method, fnc, rid, authorizer=None):
            http_api.add_routes(
                path=path, methods=[method],
                integration=apigw_int.HttpLambdaIntegration(rid, fnc),
                authorizer=authorizer)

        # read routes stay open; MUTATING routes require a valid JWT (Req 11.4)
        route("/images", apigw.HttpMethod.GET, images_fn, "ImagesInt")
        route("/image-findings", apigw.HttpMethod.GET, image_findings_fn, "ImageFindingsInt")
        route("/scan", apigw.HttpMethod.POST, scan_fn, "ScanInt", authorizer=jwt_authorizer)
        route("/scan/{id}", apigw.HttpMethod.GET, scan_fn, "ScanStatusInt")
        route("/report", apigw.HttpMethod.GET, scan_fn, "ReportInt")
        route("/sbom", apigw.HttpMethod.GET, scan_fn, "SbomInt")
        route("/remediate", apigw.HttpMethod.POST, remediate_fn, "RemediateInt",
              authorizer=jwt_authorizer)
        route("/workflow/{id}", apigw.HttpMethod.GET, status_fn, "StatusInt")
        if ai_fix_fn is not None:
            route("/fix", apigw.HttpMethod.POST, ai_fix_fn, "FixInt", authorizer=jwt_authorizer)
            route("/fix/{id}", apigw.HttpMethod.GET, ai_fix_fn, "FixStatusInt")
            route("/fix/{id}/push", apigw.HttpMethod.POST, ai_fix_fn, "FixPushInt",
                  authorizer=jwt_authorizer)
            route("/settings", apigw.HttpMethod.GET, ai_fix_fn, "SettingsInt")
            route("/settings", apigw.HttpMethod.POST, ai_fix_fn, "SettingsSetInt",
                  authorizer=jwt_authorizer)
        route("/approve", apigw.HttpMethod.POST, approval_fn, "ApproveInt",
              authorizer=jwt_authorizer)

        # ---------- Static web UI (S3 website) ----------
        ui_bucket = s3.Bucket(
            self, "UiBucket",
            bucket_name=f"{prefix}-ui-{self.account}",
            website_index_document="index.html",
            public_read_access=True,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=False, block_public_policy=False,
                ignore_public_acls=False, restrict_public_buckets=False),
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        s3deploy.BucketDeployment(
            self, "DeployUi",
            sources=[s3deploy.Source.asset("web")],
            destination_bucket=ui_bucket,
        )

        self.api_url = http_api.url or ""   # consumed by EdgeStack (CloudFront origin)
        # EdgeStack adds its console login client to this authorizer's audience
        self.http_api_id = http_api.api_id
        self.jwt_authorizer_id = jwt_authorizer.authorizer_id if jwt_authorizer else ""
        self.cognito_domain_prefix = (f"{prefix}-{self.account}"[:63].replace("_", "-")
                                      if secure else "")

        CfnOutput(self, "PromotionApiUrl", value=http_api.url or "")
        CfnOutput(self, "PromotionPipelineArn", value=pipeline_sm.state_machine_arn)
        CfnOutput(self, "AgenticPipelineArn", value=agentic_sm.state_machine_arn)
        CfnOutput(self, "UiUrl", value=ui_bucket.bucket_website_url)
        CfnOutput(self, "GitSecretName", value=git_secret.secret_name)
        if self.user_pool is not None:
            CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
