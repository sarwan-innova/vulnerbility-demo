"""
GitHub REST client — stdlib only, injectable transport (like wiz_client).

What the AI-fix loop needs:
  * read a commit's tree and file contents (context for the model)
  * write the fix as ONE commit on a new fix/ branch (Git Data API:
    blobs -> tree -> commit -> ref), never touching the base branch
  * open a pull request back to the branch the image was built from

Token: a fine-grained PAT (Contents RW, Pull requests RW) from Secrets Manager
`<prefix>/github` as {"token": "..."}. Repos are "owner/name" strings.
"""

import base64
import json
import urllib.parse

API = "https://api.github.com"


class GitHubError(Exception):
    pass


class GitHubClient:
    def __init__(self, token, api=API, transport=None):
        if not token:
            raise GitHubError("GitHub token is required")
        self.token = token
        self.api = api.rstrip("/")
        if transport is None:
            from wiz_client import urllib_transport as transport
        self._transport = transport

    def _req(self, method, path, body=None, ok=(200, 201)):
        headers = {"Authorization": f"Bearer {self.token}",
                   "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "innova-vuln-remediation"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        status, raw = self._transport(method, self.api + path, headers, data)
        if status not in ok:
            msg = ""
            try:
                msg = json.loads(raw).get("message", "")
            except ValueError:
                pass
            raise GitHubError(f"GitHub {method} {path.split('?')[0]} failed (HTTP {status}) {msg[:200]}")
        return json.loads(raw) if raw else {}

    # ------------------------------------------------------------ read
    def branch_sha(self, repo, branch):
        ref = urllib.parse.quote(f"heads/{branch}", safe="/")
        return self._req("GET", f"/repos/{repo}/git/ref/{ref}")["object"]["sha"]

    def list_files(self, repo, sha):
        """[{path, size}] for every blob in the commit's tree."""
        commit = self._req("GET", f"/repos/{repo}/git/commits/{sha}")
        tree = self._req("GET", f"/repos/{repo}/git/trees/{commit['tree']['sha']}?recursive=1")
        if tree.get("truncated"):
            raise GitHubError("repository tree too large to read in one call")
        return [{"path": t["path"], "size": t.get("size", 0)}
                for t in tree.get("tree", []) if t.get("type") == "blob"]

    def read_file(self, repo, path, sha):
        q = urllib.parse.quote(path)
        data = self._req("GET", f"/repos/{repo}/contents/{q}?ref={sha}")
        return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")

    # ------------------------------------------------------------ write
    def commit_to_new_branch(self, repo, base_sha, branch, files, message):
        """Create `branch` at a new commit (parent base_sha) with `files` {path: content}."""
        base = self._req("GET", f"/repos/{repo}/git/commits/{base_sha}")
        tree = [{"path": p, "mode": "100644", "type": "blob",
                 "sha": self._req("POST", f"/repos/{repo}/git/blobs",
                                  {"content": c, "encoding": "utf-8"})["sha"]}
                for p, c in sorted(files.items())]
        new_tree = self._req("POST", f"/repos/{repo}/git/trees",
                             {"base_tree": base["tree"]["sha"], "tree": tree})
        commit = self._req("POST", f"/repos/{repo}/git/commits",
                           {"message": message, "tree": new_tree["sha"], "parents": [base_sha]})
        self._req("POST", f"/repos/{repo}/git/refs",
                  {"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
        return commit["sha"]

    def open_pull_request(self, repo, head, base, title, body):
        pr = self._req("POST", f"/repos/{repo}/pulls",
                       {"title": title, "head": head, "base": base, "body": body})
        return {"number": pr["number"], "url": pr["html_url"]}


def repo_from_source_url(url):
    """'https://github.com/owner/name(.git)' -> 'owner/name' (None if not GitHub)."""
    if not url:
        return None
    u = url.strip().removesuffix(".git").rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if u.startswith(prefix):
            parts = u[len(prefix):].split("/")
            return "/".join(parts[:2]) if len(parts) >= 2 else None
    return None
