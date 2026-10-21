#!/usr/bin/env python3
"""
Store the GitHub token the platform needs in AWS Secrets Manager — safely.

    .venv\\Scripts\\python.exe scripts\\set_github_token.py --repo owner/name

* asks for the token with hidden input (nothing echoed, nothing written to disk)
* checks with GitHub that the token can read the repo and push to it
* creates (or updates) the secret <prefix>/github as {"token": "..."}
"""

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.request


def github_repo_access(token, repo):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "User-Agent": "innova-vuln-remediation"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/name of the GitHub repo")
    ap.add_argument("--secret", default="vuln-remediation-dev/github")
    ap.add_argument("--profile", default="sandbox")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    token = getpass.getpass("Paste the GitHub token (input is hidden), then press Enter: ").strip()
    if not token.startswith(("github_pat_", "ghp_")):
        sys.exit("That doesn't look like a GitHub token (expected github_pat_... or ghp_...).")

    status, repo = github_repo_access(token, args.repo)
    if status != 200:
        sys.exit(f"GitHub says HTTP {status} for {args.repo}: the token can't see this repo. "
                 "Check 'Repository access' includes it (and approve it for the org if asked).")
    perms = repo.get("permissions") or {}
    if perms and not perms.get("push"):
        sys.exit("The token can read the repo but not push: give it Contents = Read and write.")
    hooks_status, _ = github_repo_access(token, f"{args.repo}/hooks")
    if hooks_status != 200:
        sys.exit(f"GitHub says HTTP {hooks_status} for webhooks: CodeBuild needs the token's "
                 "'Webhooks' permission set to Read and write.")
    print(f"GitHub: token can access {args.repo} and manage its webhooks "
          f"(private={repo.get('private')}).")

    import boto3
    sm = boto3.Session(profile_name=args.profile, region_name=args.region).client("secretsmanager")
    value = json.dumps({"token": token})
    try:
        sm.create_secret(Name=args.secret, SecretString=value,
                         Description="GitHub token for the image remediation platform")
        print(f"Created secret {args.secret}.")
    except sm.exceptions.ResourceExistsException:
        sm.put_secret_value(SecretId=args.secret, SecretString=value)
        print(f"Updated secret {args.secret}.")


if __name__ == "__main__":
    main()
