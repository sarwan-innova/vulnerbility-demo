"""
Architecture diagram for the Image Vulnerability Remediation Orchestration
platform (4 CDK stacks). Real AWS icons via the `diagrams` library.

Requires: diagrams + Graphviz `dot` on PATH.
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import Lambda, Fargate, EC2ContainerRegistry
from diagrams.aws.ml import Bedrock
from diagrams.aws.security import Cognito, SecretsManager, IAM
from diagrams.aws.integration import Eventbridge, StepFunctions, SNS, SQS
from diagrams.aws.devtools import Codebuild
from diagrams.aws.storage import S3
from diagrams.aws.database import Dynamodb
from diagrams.aws.network import CloudFront, APIGateway
from diagrams.aws.management import Cloudwatch
from diagrams.aws.general import Users, TraditionalServer

graph_attr = {
    "fontsize": "30", "fontname": "Segoe UI", "labelloc": "t",
    "pad": "0.8", "nodesep": "0.7", "ranksep": "1.4", "bgcolor": "white",
    "splines": "spline", "compound": "true",
}
node_attr = {"fontsize": "12", "fontname": "Segoe UI"}
edge_attr = {"fontsize": "11", "fontname": "Segoe UI", "color": "#5A6B7B", "penwidth": "1.7"}

ORANGE = "#FF9900"; RED = "#D13212"; GREEN = "#3DAE2B"; BLUE = "#2E73B8"
PURPLE = "#7B4FB5"; DARK = "#232F3E"

C_EDGE = "#F3ECFB"; C_PROMO = "#FFF3E0"; C_AGENT = "#FDECEA"
C_COMPUTE = "#EAF7EE"; C_DATA = "#EAF3FC"; C_LIVE = "#F4F5F6"


def cl(color, bg):
    return {"bgcolor": bg, "fontcolor": color, "fontsize": "15",
            "style": "rounded", "penwidth": "2", "pencolor": color, "margin": "16"}


with Diagram(
    "Image Vulnerability Remediation Orchestration — AWS CDK (4 stacks)",
    filename="cdk-architecture", show=False, direction="TB",
    graph_attr=graph_attr, node_attr=node_attr, edge_attr=edge_attr, outformat="png",
):
    users = Users("InfoSec / CloudOps\n(console users)")

    # ---------------- EdgeStack (secure delivery) ----------------
    with Cluster("EdgeStack — secure delivery (secure=true)", graph_attr=cl(PURPLE, C_EDGE)):
        cognito = Cognito("Cognito\nuser pool + hosted UI")
        cdn = CloudFront("CloudFront\n(private S3 UI via OAC)")
        ui = S3("UI bucket\n(config.js injected)")
        cdn >> Edge(color=PURPLE) >> ui

    # ---------------- PromotionStack (API + workflows) ----------------
    with Cluster("PromotionStack — guided remediation UX + API", graph_attr=cl(ORANGE, C_PROMO)):
        api = APIGateway("HTTP API\nJWT auth on /remediate,/approve")

        with Cluster("Deterministic pipeline", graph_attr=cl(BLUE, C_DATA)):
            sfn_det = StepFunctions("Promotion SFN\nApplyFix→DeployDev→Verify→\nApprove→PromoteProd")

        with Cluster("Agentic pipeline (agentic=true)", graph_attr=cl(RED, C_AGENT)):
            orch = Bedrock("Bedrock agents\nTriage · Plan · Verify")
            sfn_ag = StepFunctions("Agentic SFN\n(agents + same gate)")
            orch >> Edge(color=RED, style="dashed", label="advise\n(gate stays authority)") >> sfn_ag

        with Cluster("LIVE build/deploy (mock=false)", graph_attr=cl(DARK, C_LIVE)):
            build = Codebuild("CodeBuild\nrebuild on fixed base")
            fargate = Fargate("ECS\nredeploy dev→prod")
            ecr = EC2ContainerRegistry("ECR\nretag fixed image")
            build >> Edge(color=DARK) >> ecr >> Edge(color=DARK) >> fargate

        api >> Edge(color=ORANGE, label="start") >> sfn_det
        api >> Edge(color=RED, label="start (agentic)") >> sfn_ag
        sfn_det >> Edge(color=DARK) >> build

    # ---------------- ComputeStack (ingest/enrich/gate pipeline) ----------------
    with Cluster("ComputeStack — scan ingest & deterministic gate", graph_attr=cl(GREEN, C_COMPUTE)):
        sched = Eventbridge("EventBridge\nhourly + resync")
        pipe = StepFunctions("Pipeline SFN\nIngest→Enrich→Gate→Actions")
        ingest = Lambda("ingest / enrich /\ngate / actions")
        queue = SQS("DLQ")
        sched >> Edge(color=GREEN) >> pipe >> Edge(color=GREEN) >> ingest

    # ---------------- DataStack (state + secrets) ----------------
    with Cluster("DataStack — state, reports, secrets", graph_attr=cl(BLUE, C_DATA)):
        ddb = Dynamodb("DynamoDB\nfindings · units · audit · workflows")
        reports = S3("S3\nreports / SBOM")
        secrets = SecretsManager("Secrets Manager\nWiz · Jira creds")
        sns = SNS("SNS\ngate-fail alerts")
        logs = Cloudwatch("CloudWatch\nlogs & metrics")

    wiz = TraditionalServer("Wiz\n(findings source of truth)")

    # ---------------- flows ----------------
    users >> Edge(color=PURPLE, label="sign in (JWT)") >> cognito
    users >> Edge(color=PURPLE) >> cdn
    cdn >> Edge(color=ORANGE, label="/remediate, /approve\n(Bearer token)") >> api
    cognito >> Edge(color=PURPLE, style="dashed", label="validate JWT") >> api

    wiz >> Edge(color=GREEN, label="findings") >> ingest
    ingest >> Edge(color=BLUE) >> ddb
    api >> Edge(color=BLUE) >> ddb
    sfn_det >> Edge(color=BLUE) >> ddb
    sfn_ag >> Edge(color=BLUE) >> ddb
    ingest >> Edge(color=BLUE) >> reports
    ingest >> Edge(color=RED, style="dashed") >> sns
    ingest >> Edge(color=DARK, style="dashed") >> secrets

print("done")
