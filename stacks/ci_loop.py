"""
CI loop resources (git push -> CodeBuild -> ECR -> scan -> AI fix -> push), added
to PromotionStack when apps are configured (`-c github_repo=owner/name` for one
app, or `-c apps_file=ci-apps.json` for several). PER APP:

  * CodeBuild build: GitHub webhook on push; builds the image, labels it
    (commit, branch, source, build folder, base image + base layer count) and
    pushes <ecr repo>:<short sha>
  * an ECR repository
Shared: ECR enhanced scanning / Amazon Inspector when scanner=inspector,
  * EventBridge -> ciEventsFn: ECR push, Inspector scan done, wizscan finished
  * aiFixFn: Fix with AI (Claude in Amazon Bedrock) + Push fix (GitHub branch + PR)

Before deploying, create the GitHub token secret (CodeBuild's webhook needs it
at deploy time):  {"token": "<fine-grained PAT>"}  — see README "Deploy the loop".
"""

import re

from aws_cdk import (
    Duration, RemovalPolicy, SecretValue,
    aws_codebuild as codebuild,
    aws_ecr as ecr,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_secretsmanager as secrets,
    custom_resources as cr,
)

LABEL_ARGS = (
    '--label "com.innova.build.context=$CONTEXT" '
    '--label "org.opencontainers.image.revision=$COMMIT" '
    '--label "org.opencontainers.image.source=$SOURCE_URL" '
    '--label "org.opencontainers.image.base.name=$BASE" '
    '--label "com.innova.git.branch=$BRANCH" '
    '--label "com.innova.base.layers=$BASE_LAYERS"'
)


def _app_buildspec():
    """One phase so a failed step never pushes. Labels let the platform map the
    image back to its commit and split base-layer from app-layer findings."""
    return {
        "version": "0.2",
        "phases": {"build": {"commands": [
            'COMMIT="$CODEBUILD_RESOLVED_SOURCE_VERSION"; TAG="$(echo "$COMMIT" | cut -c1-7)"',
            'BRANCH="${CODEBUILD_WEBHOOK_HEAD_REF#refs/heads/}"; '
            '[ -n "$BRANCH" ] || BRANCH="${CODEBUILD_SOURCE_VERSION:-unknown}"',
            'BASE="$(grep -iE \'^[[:space:]]*FROM[[:space:]]\' "$CONTEXT/$DOCKERFILE" | tail -1 | '
            'awk \'{for(i=2;i<=NF;i++) if ($i !~ /^--/) {print $i; exit}}\')"',
            'echo "commit=$COMMIT branch=$BRANCH base=$BASE"',
            'docker pull "$BASE"',
            'BASE_LAYERS="$(docker image inspect "$BASE" --format \'{{len .RootFS.Layers}}\')"',
            'REGISTRY="${ECR_REPO_URI%%/*}"',
            'aws ecr get-login-password --region "$AWS_REGION" | '
            'docker login --username AWS --password-stdin "$REGISTRY"',
            f'docker build -f "$CONTEXT/$DOCKERFILE" -t "$ECR_REPO_URI:$TAG" {LABEL_ARGS} "$CONTEXT"',
            'docker push "$ECR_REPO_URI:$TAG"',
        ]}},
    }


def _ids(app, first):
    """Construct-id suffix + CodeBuild project name. The FIRST app keeps the
    original ids so an existing single-app deployment is updated, not replaced."""
    slug = re.sub(r"[^a-z0-9]+", "-", app["ecr_repo"].lower()).strip("-")
    suffix = "" if first else "".join(p.capitalize() for p in slug.split("-"))
    return suffix, (None if first else slug[:60])


def add_ci_loop(stack, *, prefix, fn, deps_layer, report_bucket, wizscan_project, cfg):
    """Returns (AI-fix Lambda, [(app, build project, ECR repo)])."""
    gh_secret = secrets.Secret.from_secret_name_v2(stack, "GitHubSecret", cfg["github_secret"])
    creds = codebuild.GitHubSourceCredentials(
        stack, "GitHubCreds",
        access_token=SecretValue.secrets_manager(cfg["github_secret"], json_field="token"))

    built = []
    for i, app in enumerate(cfg["apps"]):
        suffix, slug = _ids(app, i == 0)
        owner, name = app["github_repo"].split("/", 1)
        # ---------- ECR repo + push-triggered build ----------
        repo = ecr.Repository(
            stack, f"AppRepo{suffix}", repository_name=app["ecr_repo"],
            removal_policy=RemovalPolicy.DESTROY, empty_on_delete=True,
            lifecycle_rules=[ecr.LifecycleRule(max_image_count=100)],
        )
        # build on every push — or, when the app lives in a subfolder of a bigger
        # repo, only on pushes that change that subfolder
        push = codebuild.FilterGroup.in_event_of(codebuild.EventAction.PUSH)
        context = app.get("context", ".").strip("./")
        if context:
            push = push.and_file_path_is(f"^{context}/")
        build = codebuild.Project(
            stack, f"AppBuild{suffix}",
            project_name=f"{prefix}-app-build" if slug is None else f"{prefix}-build-{slug}",
            source=codebuild.Source.git_hub(
                owner=owner, repo=name, webhook=True, webhook_filters=[push]),
            build_spec=codebuild.BuildSpec.from_object(_app_buildspec()),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True, compute_type=codebuild.ComputeType.SMALL),
            environment_variables={
                "ECR_REPO_URI": codebuild.BuildEnvironmentVariable(value=repo.repository_uri),
                "AWS_REGION": codebuild.BuildEnvironmentVariable(value=stack.region),
                "DOCKERFILE": codebuild.BuildEnvironmentVariable(value=app.get("dockerfile", "Dockerfile")),
                "CONTEXT": codebuild.BuildEnvironmentVariable(value=context or "."),
                "SOURCE_URL": codebuild.BuildEnvironmentVariable(value=f"https://github.com/{owner}/{name}"),
            },
            timeout=Duration.minutes(30),
        )
        build.node.add_dependency(creds)
        repo.grant_pull_push(build)
        built.append((app, build, repo))
    ecr_names = [a["ecr_repo"] for a in cfg["apps"]]

    # ---------- scanner ----------
    if cfg["scanner"] == "inspector":
        ecr.CfnRegistryScanningConfiguration(
            stack, "EnhancedScanning", scan_type="ENHANCED",
            rules=[ecr.CfnRegistryScanningConfiguration.ScanningRuleProperty(
                scan_frequency="SCAN_ON_PUSH",
                repository_filters=[ecr.CfnRegistryScanningConfiguration.RepositoryFilterProperty(
                    filter=n, filter_type="WILDCARD") for n in ecr_names])])
        cr.AwsCustomResource(
            stack, "EnableInspectorForEcr",
            on_create=cr.AwsSdkCall(
                service="Inspector2", action="enable",
                parameters={"resourceTypes": ["ECR"]},
                physical_resource_id=cr.PhysicalResourceId.of("inspector2-ecr")),
            policy=cr.AwsCustomResourcePolicy.from_statements([iam.PolicyStatement(
                actions=["inspector2:Enable", "iam:CreateServiceLinkedRole"], resources=["*"])]),
        )

    # ---------- CI events: push -> register + scan; scan done -> findings ----------
    ci_fn = fn("CiEventsFn", "ci_events", timeout=300)
    ci_fn.add_environment("SCANNER", cfg["scanner"])
    ci_fn.add_environment("WIZ_SCAN_PROJECT", wizscan_project.project_name)
    for _, _, repo in built:
        repo.grant_pull(ci_fn)
    ci_fn.add_to_role_policy(iam.PolicyStatement(
        actions=["inspector2:ListFindings"], resources=["*"]))
    ci_fn.add_to_role_policy(iam.PolicyStatement(
        actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
        resources=[wizscan_project.project_arn]))
    report_bucket.grant_read_write(ci_fn)

    events.Rule(stack, "EcrPushRule", rule_name=f"{prefix}-ecr-push",
                event_pattern=events.EventPattern(
                    source=["aws.ecr"], detail_type=["ECR Image Action"],
                    detail={"action-type": ["PUSH"], "result": ["SUCCESS"],
                            "repository-name": ecr_names}),
                targets=[targets.LambdaFunction(ci_fn)])
    events.Rule(stack, "InspectorScanRule", rule_name=f"{prefix}-inspector-scan",
                event_pattern=events.EventPattern(
                    source=["aws.inspector2"], detail_type=["Inspector2 Scan"]),
                targets=[targets.LambdaFunction(ci_fn)])
    events.Rule(stack, "WizScanDoneRule", rule_name=f"{prefix}-wizscan-done",
                event_pattern=events.EventPattern(
                    source=["aws.codebuild"], detail_type=["CodeBuild Build State Change"],
                    detail={"project-name": [wizscan_project.project_name],
                            "build-status": ["SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"]}),
                targets=[targets.LambdaFunction(ci_fn)])

    # ---------- AI fix + push ----------
    ai_fn = fn("AiFixFn", "ai_fix", timeout=900, memory=1024, extra_layers=[deps_layer])
    ai_fn.add_environment("GITHUB_SECRET_ARN", gh_secret.secret_arn)
    # images carry their build folder as a label; this is the fallback for
    # images built before that label existed (the first app's folder)
    ai_fn.add_environment("BUILD_CONTEXT", cfg["apps"][0].get("context", ".").strip("./"))
    ai_fn.add_environment("BEDROCK_MODEL_ID", cfg.get("bedrock_model_id", ""))
    ai_fn.add_environment("BEDROCK_REGION", cfg.get("bedrock_region") or stack.region)
    gh_secret.grant_read(ai_fn)
    report_bucket.grant_read_write(ai_fn)
    ai_fn.add_to_role_policy(iam.PolicyStatement(
        actions=["bedrock-mantle:CreateInference"], resources=["*"]))
    ai_fn.add_to_role_policy(iam.PolicyStatement(          # async self-invoke for the worker
        actions=["lambda:InvokeFunction"],
        resources=[f"arn:aws:lambda:{stack.region}:{stack.account}:function:{prefix}-ai_fix"]))
    return ai_fn, built
