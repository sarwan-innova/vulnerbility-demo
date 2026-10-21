"""
DataStack — stateful resources:
  * DynamoDB single table (PK/SK + GSI1 for SLA/priority queries), SSE + PITR.
  * S3 report bucket (SSE, Block Public Access, TLS-only).
  * SNS alert topic.
  * Secrets Manager secrets for Wiz and Jira credentials (created empty).
Requirements: 1.1, 5.4, 6.2, 7.3, 7.4.
"""

from aws_cdk import (
    Stack, RemovalPolicy, Duration,
    aws_dynamodb as ddb,
    aws_s3 as s3,
    aws_sns as sns,
    aws_secretsmanager as secrets,
    aws_iam as iam,
)
from constructs import Construct


class DataStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, prefix: str, retain: bool = False, **kwargs):
        super().__init__(scope, cid, **kwargs)
        # demo/dev tear down cleanly; prod (retain=True) keeps the audit data
        removal = RemovalPolicy.RETAIN if retain else RemovalPolicy.DESTROY

        # --- DynamoDB single table ---
        self.table = ddb.Table(
            self, "Table",
            table_name=f"{prefix}",
            partition_key=ddb.Attribute(name="PK", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="SK", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True),
            removal_policy=removal,
        )
        # GSI1: SLA status + priority score queue
        self.table.add_global_secondary_index(
            index_name="gsi1",
            partition_key=ddb.Attribute(name="gsi1pk", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="gsi1sk", type=ddb.AttributeType.NUMBER),
            projection_type=ddb.ProjectionType.ALL,
        )

        # --- S3 report bucket ---
        self.report_bucket = s3.Bucket(
            self, "ReportBucket",
            bucket_name=f"{prefix}-reports-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=removal,
            auto_delete_objects=not retain,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(365))],
        )

        # --- SNS alert topic ---
        self.alert_topic = sns.Topic(
            self, "AlertTopic",
            topic_name=f"{prefix}-alerts",
            display_name="Image Vuln Remediation Alerts",
        )

        # --- Secrets (empty; populated out of band) ---
        self.wiz_secret = secrets.Secret(
            self, "WizSecret",
            secret_name=f"{prefix}/wiz",
            description="Wiz API client id/secret + endpoint",
        )
        self.jira_secret = secrets.Secret(
            self, "JiraSecret",
            secret_name=f"{prefix}/jira",
            description="Jira base URL + user + API token",
        )

        # enforce TLS on the table via resource policy is implicit; export names
        self.table.apply_removal_policy(removal)
