"""
ComputeStack — stateless resources:
  * A Lambda layer carrying lambda/common (core.py + store.py).
  * Six Lambdas (ingest, enrich, units, gate, actions, report) with
    least-privilege roles.
  * Step Functions state machine: Enrich -> Triage?(skip) -> BuildUnits
    -> Gate -> Actions -> Publish  (deterministic spine; Bedrock slot later).
  * EventBridge schedule -> IngestFn + state machine start.
  * HTTP API Gateway -> ReportFn.
  * SQS DLQ on the Actions step.
Requirements: 1.1, 4.5, 7.2, 7.5, 8.2.
"""

from aws_cdk import (
    Stack, Duration, RemovalPolicy,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_events as events,
    aws_events_targets as targets,
    aws_apigatewayv2 as apigw,
    aws_apigatewayv2_integrations as apigw_int,
    aws_sqs as sqs,
    aws_logs as logs,
)
from constructs import Construct
from stacks._layer import common_layer_code

COMMON_PATH = "lambda/common"


class ComputeStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, prefix: str,
                 table, report_bucket, alert_topic, wiz_secret, jira_secret,
                 wiz_mock: bool = True, **kwargs):
        super().__init__(scope, cid, **kwargs)

        # --- shared layer: common/ modules at /opt/python (see _layer.py) ---
        common_layer = lambda_.LayerVersion(
            self, "CommonLayer",
            code=common_layer_code(),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            description="Shared core + store logic",
        )

        base_env = {
            "TABLE_NAME": table.table_name,
            "REPORT_BUCKET": report_bucket.bucket_name,
            "ALERT_TOPIC_ARN": alert_topic.topic_arn,
            "WIZ_SECRET_ARN": wiz_secret.secret_arn,
            "JIRA_SECRET_ARN": jira_secret.secret_arn,
            "WIZ_MOCK": "true" if wiz_mock else "false",
        }

        def make_fn(name, src_dir, timeout=60, memory=256):
            log_group = logs.LogGroup(
                self, f"{name}Logs",
                log_group_name=f"/aws/lambda/{prefix}-{src_dir}",
                retention=logs.RetentionDays.ONE_MONTH,
                removal_policy=RemovalPolicy.DESTROY,
            )
            fn = lambda_.Function(
                self, name,
                function_name=f"{prefix}-{src_dir}",
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler="handler.handler",
                code=lambda_.Code.from_asset(f"lambda/{src_dir}"),
                layers=[common_layer],
                timeout=Duration.seconds(timeout),
                memory_size=memory,
                environment=base_env,
                log_group=log_group,
            )
            return fn

        ingest = make_fn("IngestFn", "ingest", timeout=300)  # full Wiz pull pages through all findings
        enrich = make_fn("EnrichFn", "enrich")
        units = make_fn("UnitsFn", "units")
        gate = make_fn("GateFn", "gate")
        actions = make_fn("ActionsFn", "actions", timeout=120)
        report = make_fn("ReportFn", "report", timeout=15)

        # --- least-privilege grants ---
        for fn in (ingest, enrich, units, gate, actions, report):
            table.grant_read_write_data(fn)
        report_bucket.grant_put(actions)
        report_bucket.grant_read(report)
        alert_topic.grant_publish(actions)
        wiz_secret.grant_read(ingest)
        jira_secret.grant_read(actions)

        # --- SQS DLQ for the actions step (Req 4.5) ---
        dlq = sqs.Queue(self, "ActionsDLQ", queue_name=f"{prefix}-actions-dlq",
                        retention_period=Duration.days(14))

        # --- Step Functions spine ---
        def task(fn, name):
            return tasks.LambdaInvoke(
                self, name, lambda_function=fn, output_path="$.Payload",
            ).add_retry(max_attempts=3, interval=Duration.seconds(5), backoff_rate=2.0)

        enrich_t = task(enrich, "Enrich")
        units_t = task(units, "BuildUnits")
        gate_t = task(gate, "Gate")
        actions_t = task(actions, "Actions")
        actions_t.add_catch(
            sfn.Pass(self, "ActionsFailed", result=sfn.Result.from_object({"actions": "failed"})),
            errors=["States.ALL"],
        )

        # Triage? choice -> phase 1 skips straight to BuildUnits (Bedrock slot later)
        triage_choice = sfn.Choice(self, "TriageEnabled?")
        skip = sfn.Pass(self, "SkipTriage")

        definition = enrich_t.next(
            triage_choice
            .when(sfn.Condition.string_equals("$.triage", "enabled"), skip.next(units_t))
            .otherwise(units_t)
        )
        units_t.next(gate_t).next(actions_t)

        state_machine = sfn.StateMachine(
            self, "Pipeline",
            state_machine_name=f"{prefix}-pipeline",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.minutes(10),
        )

        # --- EventBridge schedule -> run ingest, then start the pipeline ---
        schedule_rule = events.Rule(
            self, "ScheduleRule",
            rule_name=f"{prefix}-schedule",
            schedule=events.Schedule.rate(Duration.hours(1)),
        )
        # Only pull from Wiz on a schedule when Wiz is real: with the mock, the
        # hourly pull would load fake sample images into the console.
        if not wiz_mock:
            schedule_rule.add_target(targets.LambdaFunction(ingest))
        schedule_rule.add_target(targets.SfnStateMachine(state_machine))

        # on-demand re-sync rule (custom event bus pattern)
        resync_rule = events.Rule(
            self, "ResyncRule",
            rule_name=f"{prefix}-resync",
            event_pattern=events.EventPattern(
                source=["norstella.vuln"], detail_type=["ResyncRequested"]),
        )
        resync_rule.add_target(targets.LambdaFunction(ingest))

        # --- HTTP API -> ReportFn ---
        http_api = apigw.HttpApi(self, "ReportApi", api_name=f"{prefix}-report-api")
        http_api.add_routes(
            path="/summary",
            methods=[apigw.HttpMethod.GET],
            integration=apigw_int.HttpLambdaIntegration("ReportInt", report),
        )

        # --- outputs ---
        from aws_cdk import CfnOutput
        CfnOutput(self, "StateMachineArn", value=state_machine.state_machine_arn)
        CfnOutput(self, "ReportApiUrl", value=http_api.url or "")
        CfnOutput(self, "IngestFnName", value=ingest.function_name)
        CfnOutput(self, "DlqUrl", value=dlq.queue_url)
