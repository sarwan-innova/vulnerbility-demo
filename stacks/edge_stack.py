"""
EdgeStack — secure delivery (Requirement 11):
  * CloudFront distribution serving the web UI from a PRIVATE S3 bucket
    (Origin Access Control; bucket is NOT public), with the HTTP API as a
    second origin behind /api/*.
  * Injects a runtime config.js (API_BASE + Cognito details) into the UI bucket.

Cognito (user pool, client, hosted domain) and the JWT authorizer live in
PromotionStack so the API can ENFORCE auth without a circular dependency.
EdgeStack consumes those references and patches the client's callback/logout
URLs to the real CloudFront domain via a CloudFormation escape hatch.
"""

from aws_cdk import (
    Stack, RemovalPolicy, CfnOutput, Fn,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_cloudfront as cf,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
)
from constructs import Construct


class EdgeStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, prefix: str,
                 api_url: str = "",
                 user_pool=None,
                 cognito_domain_prefix: str = "", **kwargs):
        super().__init__(scope, cid, **kwargs)

        # --- private UI bucket (no public access) ---
        ui_bucket = s3.Bucket(
            self, "SecureUiBucket",
            bucket_name=f"{prefix}-ui-secure-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # --- CloudFront distribution with OAC to the private bucket ---
        distribution = cf.Distribution(
            self, "Distribution",
            comment=f"{prefix} remediation console",
            default_root_object="index.html",
            default_behavior=cf.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(ui_bucket),
                viewer_protocol_policy=cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cf.CachePolicy.CACHING_OPTIMIZED,
            ),
            error_responses=[
                cf.ErrorResponse(http_status=403, response_http_status=200,
                                 response_page_path="/index.html"),
                cf.ErrorResponse(http_status=404, response_http_status=200,
                                 response_page_path="/index.html"),
            ],
        )

        # Note: the SPA calls the HTTP API directly using its URL (set in
        # config.js as API_BASE). We intentionally do NOT proxy /api/* through
        # CloudFront here, to keep a single clean dependency direction and avoid
        # a Promotion<->Edge cycle. CORS on the API already allows the browser.

        cf_url = f"https://{distribution.distribution_domain_name}"
        callback = cf_url + "/"

        # --- create the web app client in the pool via the LOW-LEVEL Cfn resource ---
        # Using CfnUserPoolClient with the pool *id string* (not the L2 object)
        # avoids CDK's automatic cross-stack wiring that would otherwise pull the
        # CloudFront domain into PromotionStack and create a dependency cycle.
        client_id = ""
        if user_pool is not None:
            cfn_client = cognito.CfnUserPoolClient(
                self, "EdgeWebClient",
                user_pool_id=user_pool.user_pool_id,
                allowed_o_auth_flows=["implicit", "code"],
                allowed_o_auth_scopes=["openid", "email", "profile"],
                allowed_o_auth_flows_user_pool_client=True,
                supported_identity_providers=["COGNITO"],
                callback_ur_ls=[callback],
                logout_ur_ls=[callback],
                generate_secret=False,
            )
            client_id = cfn_client.ref

        # --- runtime config.js injected into the UI bucket ---
        api_base = (api_url or "").rstrip("/")
        config_js = Fn.sub(
            'window.APP_CONFIG = {'
            '"API_BASE":"${ApiBase}",'
            '"COGNITO":{'
            '"domain":"${Domain}",'
            '"region":"${Region}",'
            '"clientId":"${ClientId}",'
            '"redirectUri":"${Redirect}"'
            '}};',
            {
                "ApiBase": api_base,
                "Domain": cognito_domain_prefix or "",
                "Region": self.region,
                "ClientId": client_id or "",
                "Redirect": callback,
            },
        )

        s3deploy.BucketDeployment(
            self, "DeploySecureUi",
            sources=[s3deploy.Source.asset("web")],
            destination_bucket=ui_bucket,
            distribution=distribution,
            distribution_paths=["/*"],
            prune=False,
        )
        s3deploy.BucketDeployment(
            self, "DeployRuntimeConfig",
            sources=[s3deploy.Source.data("config.js", config_js)],
            destination_bucket=ui_bucket,
            distribution=distribution,
            distribution_paths=["/config.js"],
            prune=False,
        )

        CfnOutput(self, "ConsoleUrl", value=cf_url)
        if cognito_domain_prefix:
            CfnOutput(self, "CognitoHostedUi",
                      value=f"https://{cognito_domain_prefix}.auth.{self.region}.amazoncognito.com/login"
                            f"?client_id={client_id}&response_type=token"
                            f"&scope=openid+email+profile&redirect_uri={callback}")
        CfnOutput(self, "DistributionId", value=distribution.distribution_id)
