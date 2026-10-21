# Image Vulnerability Remediation — AWS CDK

A developer loop for container-image vulnerabilities, sitting **on top of the
scanner** (Wiz; Amazon Inspector until Wiz credentials exist):

```
git push ─► CodeBuild builds the image ─► ECR ─► scan ─► console: findings + gate
                                                              │
   ┌────────────────────────── ✨ Fix with AI ◄──────────────────┘
   ▼
 Claude in Amazon Bedrock reads the repo + findings ─► proposes file changes
   ─► validated (only files it was shown, fixed versions, no secrets) ─► diff in the console
   ─► ⬆ Push fix ─► commit on a new fix/<image>-<id> branch + pull request (never main)
   ─► webhook ─► CodeBuild ─► ECR ─► re-scan ─► console: BEFORE vs AFTER
```

Built from the Innova "Automated Image Vulnerability Management" proposal and
the completed discovery questionnaire:
- **ECR is the source of truth** (there is no Nexus).
- **Wiz is the scanner.**
- **68% of findings are base-layer**, so moving `FROM` to a fixed base tag is the main fix.
- SLA is 15 days, with a 30-day breach threshold.
- KEV/EPSS findings get a fast track.

## Run the loop locally (no AWS, no GitHub, no Wiz)

```powershell
python -m venv .venv ; .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python local_server.py            # http://localhost:8080
python -m pytest tests/ -q        # 110 tests
```

**What the local server does.** It "pushes" `demo-app/` to a mock GitHub repo, then for each commit:
1. "Builds" it.
2. Scans it with a repo-aware mock scanner. The Dockerfile `FROM` and the `requirements.txt` pins decide the findings, so fixes really change the next scan.
3. Shows the result in the console.

**In the console:**
1. Open the image. You'll see 23 findings, 9 of them HIGH, and the gate says **BLOCKED**.
2. Click **Fix with AI** and review the summary, validation result and diffs.
3. Click **Push fix**. That creates a branch and PR, triggers a rebuild and re-scan, and shows **BEFORE 23 / BLOCKED → AFTER 2 / CLEAR**.

All of this runs the real Lambda handler code (`local/app.py`).

| Flag | Effect |
|---|---|
| *(none)* | rule-based fix engine stands in for the model |
| `--bedrock-model anthropic.claude-opus-5-5 --region us-east-1` | the fix comes from **Claude in Amazon Bedrock** using your local AWS credentials |
| `--trivy` | real Podman builds + real Trivy scans (needs `podman` and `trivy` on PATH) |
| `--legacy` | the earlier mock-Wiz sample images (promotion pipeline via API) |

## Deploy the loop to your AWS sandbox

Use a **sandbox account**, not a client account; their SCPs may block parts of this.

**1. Tools (one time).** You need:
- AWS CLI v2 (the installer needs admin);
- the CDK CLI: `npm i -g aws-cdk`;
- this repo's venv (above).

Sign in and confirm the account:
```powershell
aws configure sso                       # or: aws configure (access keys)
$env:AWS_PROFILE = "<your profile>"
aws sts get-caller-identity             # confirm it is the sandbox account
```

**2. Bedrock model access.** In the AWS console, go to **Amazon Bedrock → Model access** and make sure **Claude Opus 5.5** is enabled in your region. Any listed Claude model works; pass its id with `-c fix_model_id=...`.

**3. GitHub repo for the app.** Create an empty repo, e.g. `<you>/vuln-api`, then push the demo app:
```powershell
cd demo-app
git init ; git add . ; git commit -m "vuln-api: initial version"
git branch -M main
git remote add origin https://github.com/<you>/vuln-api.git
git push -u origin main
cd ..
```

**4. GitHub token → Secrets Manager.**
1. Create a fine-grained token for that one repo with these permissions:
   - Contents: read & write
   - Pull requests: read & write
   - Webhooks: read & write
   - Metadata: read
2. Write `{"token": "github_pat_..."}` to a file, e.g. `gh.json`.
3. Store it, then delete the file:
```powershell
aws secretsmanager create-secret --name vuln-remediation-dev/github --secret-string file://gh.json
Remove-Item gh.json
```

**5. Deploy.**
```powershell
cdk bootstrap
cdk deploy --all -c github_repo=<you>/vuln-api -c secure=true
```
- `secure=true` puts the console behind CloudFront + Cognito sign-in, and the POST routes (Fix, Push, Re-scan) require a signed-in user.
- Create your user:
  ```powershell
  aws cognito-idp admin-create-user --user-pool-id <UserPoolId> --username <you@innovasolutions.com>
  ```
- Open the `ConsoleUrl` output.

**6. Trigger the first build.** Push any commit to `main`, or run:
```powershell
aws codebuild start-build --project-name vuln-remediation-dev-app-build --source-version main
```
- The image appears in the console with "scanning…".
- Amazon Inspector usually finishes within a few minutes.

**What the deploy turns on in the account:**
- ECR **enhanced scanning (scan on push)** for the app repo;
- **Amazon Inspector for ECR** (about $0.09 per image scan);
- a CodeBuild **GitHub webhook**;
- a **Bedrock** call per Fix click.

**Teardown:**
```powershell
cdk destroy --all
aws inspector2 disable --resource-types ECR
```
Delete the GitHub secret if you no longer need it.

| Context flag | Default | Meaning |
|---|---|---|
| `github_repo` | — | `owner/name`; enables the loop |
| `github_secret` | `vuln-remediation-<env>/github` | Secrets Manager name holding `{"token": ...}` |
| `app_ecr_repo` | `demo/vuln-api` | ECR repository the build pushes to |
| `dockerfile` / `build_context` | `Dockerfile` / `.` | where the app's Dockerfile is |
| `scanner` | `inspector` | `inspector` (Amazon Inspector) or `wizcli` (Wiz, once the Wiz secret is filled) |
| `fix_model_id` | `anthropic.claude-opus-5-5` | Bedrock model for Fix with AI |
| `fix_model_region` | stack region | Bedrock region |

### How the loop is built

| Piece | Where |
|---|---|
| Webhook build, image labels (commit, branch, base image, base layer count) | `stacks/ci_loop.py` |
| Push / Inspector / wizscan events → image record + scan | `lambda/ci_events`, `lambda/common/ci.py` |
| Image labels from ECR (manifest + config) | `lambda/common/ecr_meta.py` |
| Inspector findings → common format (base vs app layer, EPSS, exploits) | `lambda/common/inspector_client.py` |
| Fix with AI: repo context, Claude call (`submit_fix` tool), validation, diffs | `lambda/common/ai_fixer.py` |
| Fix / status / push routes, async worker, PR body | `lambda/ai_fix` |
| GitHub: read commit, commit to new branch, open PR | `lambda/common/github_client.py` |
| Console | `web/` |

**How the Claude call is made.**
- It goes through the Anthropic SDK's Bedrock client (`AnthropicBedrockMantle`), with effort `high`, streaming, and a `submit_fix` tool. Claude in Amazon Bedrock has no structured outputs, so the tool input is shape-checked in code.
- The model sees findings and file contents as data only. It cannot run anything.
- Nothing is pushed until a person clicks **Push fix**, and then only to a `fix/` branch.

**What validation blocks or flags.**
- It **blocks** the push if the model changes a file it wasn't given or adds anything that looks like a secret.
- It **warns** when a package is still pinned below its fixed version, or when the base image hasn't moved to the fixed tag.

## Earlier design: Wiz-scan + promotion pipeline (still deployed)

The sections below describe the first version (scan → automated fix build →
verify → approval → promote). Its API and state machines are still deployed.
The console now shows the developer loop above.

### How it works

```
 Wiz (GraphQL API, hourly) ──► ingest ──► findings (DynamoDB) ──► console / report
 "Scan now" ──► wizcli in CodeBuild ──► results + SBOM (S3) ──► same findings rows

 Fix this image ─► Step Functions
   [AI triage ─► AI plan]─► ApplyFix (validated fix spec)
     ─► FixBuild (CodeBuild: clone repo, rewrite FROM + manifests, build, push repo:fix-<id>)
     ─► DeployDev ─► Verify (wizcli re-scan of the rebuilt image + deterministic gate)
     ─► [AI explain] ─► PASS? ─► AwaitApproval (task token) ─► PromoteProd ─► DONE
                         FAIL ─► Jira ticket, stop (never reaches prod)
```

| Piece | Where |
|---|---|
| Wiz API client (OAuth, paged GraphQL, retries), wizcli parser | `lambda/common/wiz_client.py` |
| Mock Wiz (API + wizcli + SBOM) | `lambda/common/wiz_mock.py` |
| Scan lifecycle (Scan now + verify re-scan) | `lambda/common/scanner.py`, `lambda/scan/` |
| Fix engine: fix spec, validation, Dockerfile/pip/npm/NuGet patchers | `lambda/common/fix_engine.py` |
| Script the fix build runs | `fixer/apply_fix_spec.py` |
| Workflow steps | `lambda/apply_fix`, `deploy`, `verify`, `await_approval`, `approval`, `wf_fail` |
| AI agents (Bedrock Converse + Guardrail; rule-based stub when off) | `lambda/common/agent_core.py`, `lambda/agent_*` |
| SLA, scoring, units, gate, waivers | `lambda/common/core.py` |
| Jira client | `lambda/common/jira_client.py` |
| Stacks | `stacks/` (Data, Compute, Promotion, Edge) |

**Safety rails**
- **The gate is deterministic.** AI agents advise and explain; they never override a BLOCK.
- **Every fix is validated.** `validate_fix_spec` allows only changes backed by a finding for that image, and only to the exact version or tag Wiz says fixes it.
- **A failed re-scan never reaches prod.** It stops the workflow and opens a Jira ticket. `/approve` only accepts workflows that are waiting for approval.
- **Gate decisions are kept for audit.** Every verify-gate decision is appended to the audit log, along with the approver.

### Deploy

```powershell
npm i -g aws-cdk
aws sts get-caller-identity          # make sure this is the sandbox account
cdk bootstrap
cdk deploy --all -c env=dev          # mock Wiz + simulated build/deploy
```

### Going live (flags + one-time setup)

| Flag | Default | Effect |
|------|---------|--------|
| `wiz_mock` | `true` | `false` = real Wiz API + wizcli (fill the Wiz secret first) |
| `mock` | `true` | `false` = real fix build (CodeBuild) + ECR retag + ECS deploy |
| `agentic` | `false` | Bedrock agents (also set `bedrock_model_id`, `bedrock_guardrail_id`) |
| `secure` | `false` | CloudFront + Cognito sign-in; JWT required on POST routes |
| `repo_map` | `{}` | JSON: ECR repo → git clone URL used by the fix build |
| `env_map` | `{}` | JSON: `{"dev": {"ecs_cluster":..,"ecs_service":..}, "prod": {...}}` |
| `env` | `dev` | `prod` also keeps (RETAINs) the table and reports bucket |

```powershell
cdk deploy --all -c env=dev -c wiz_mock=false -c mock=false -c secure=true `
  -c repo_map='{"clarivate-rwd/ingest-api":"https://dev.azure.com/org/proj/_git/ingest-api"}'
```

After deploying:
1. **Wiz secret** `vuln-remediation-<env>/wiz`:
   `{"endpoint":"https://api.<region>.app.wiz.io/graphql","client_id":"...","client_secret":"..."}`
2. **Jira secret** `vuln-remediation-<env>/jira`:
   `{"base_url":"https://<org>.atlassian.net","user":"svc@...","token":"...","project_key":"SEC"}`.
   Until it's filled in, tickets come back as `MOCK-####`.
3. **Git secret** `vuln-remediation-<env>/git`: `{"token":"<PAT with read access>"}`.
4. Seed the reference data:
   ```powershell
   python seed_reference_data.py --table vuln-remediation-<env>
   ```
5. **Cross-account images** (Control Tower, 179 accounts): add an org-wide ECR repository policy that lets this account's `*-wizscan` and `*-fixbuild` CodeBuild roles pull. Findings carry the 12-digit account id, and the platform resolves each image's registry from it.

### Honest status (earlier design)

**Verified here**
- **80 unit and end-to-end tests pass.** They cover the Wiz client (auth, paging, retries, normalization), the fix engine and fixer script, the Jira client, and the full workflow through the real handlers: scan, report/SBOM, fix → verify → approve/reject → promote, verify failure → Jira, agentic mode.
- **The console was clicked through in a browser against `local_server.py`.**
- **Synth is clean** for the default config and for the fully live `env=prod` config (all 4 stacks).

**Not verified (needs real systems)**
- **`cdk deploy` was not run.**
- **Real Wiz is untested.** The Wiz GraphQL field names (`FINDINGS_QUERY`, `image_filter`) and the wizcli flags are marked `CONFIRM`; check them in your Wiz tenant's API Explorer and wizcli version.
- **The live fix build is untested.** It assumes a Dockerfile at the repo root.
- **ECS deploy, Bedrock and Jira have not been run against real services.**

**Known limits**
- **Some fixes need a human.** App-dependency bumps cover pip, npm and NuGet manifests. A fix with no Wiz fixed version, no published base tag, or an unmapped repo is reported as "needs a human" and verify fails.
- **Infrastructure-as-code.** The client standard is Terraform; this MVP uses CDK by agreement.
