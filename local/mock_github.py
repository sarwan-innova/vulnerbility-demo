"""
In-memory GitHub with the same methods as github_client.GitHubClient, plus a
webhook hook: every new branch commit calls on_push(repo, branch, sha) — the
local stand-in for the CodeBuild GitHub webhook.
"""

import hashlib
import os
import threading


class MockGitHub:
    def __init__(self, on_push=None):
        self.on_push = on_push
        self.commits = {}        # sha -> {"files": {path: text}, "parent", "message", "repo"}
        self.branches = {}       # (repo, branch) -> sha
        self.pulls = []
        self.statuses = {}       # (repo, sha, context) -> {"state", "description", "target_url"}
        self._lock = threading.RLock()

    # ------------------------------------------------------------ helpers
    def _new_commit(self, repo, files, parent, message):
        sha = hashlib.sha1(f"{repo}{parent}{message}{sorted(files.items())}".encode()).hexdigest()
        self.commits[sha] = {"files": dict(files), "parent": parent, "message": message, "repo": repo}
        return sha

    def seed_from_dir(self, repo, path, branch="main", message="initial commit"):
        """Create `repo` with one commit holding the files under `path`."""
        files = {}
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for n in names:
                full = os.path.join(root, n)
                with open(full, encoding="utf-8") as fh:
                    files[os.path.relpath(full, path).replace("\\", "/")] = fh.read()
        return self.push(repo, branch, files, message)

    def push(self, repo, branch, files, message):
        """A developer `git push`: new commit on `branch`, then the webhook fires."""
        with self._lock:
            parent = self.branches.get((repo, branch))
            sha = self._new_commit(repo, files, parent, message)
            self.branches[(repo, branch)] = sha
        if self.on_push:
            self.on_push(repo, branch, sha)
        return sha

    def snapshot(self, sha):
        return dict(self.commits[sha]["files"])

    # ------------------------------------------------------------ GitHubClient surface
    def branch_sha(self, repo, branch):
        return self.branches[(repo, branch)]

    def list_files(self, repo, sha):
        return [{"path": p, "size": len(c)} for p, c in sorted(self.commits[sha]["files"].items())]

    def read_file(self, repo, path, sha):
        return self.commits[sha]["files"][path]

    def commit_to_new_branch(self, repo, base_sha, branch, files, message):
        with self._lock:
            if (repo, branch) in self.branches:
                raise RuntimeError(f"branch {branch} already exists")
            merged = {**self.commits[base_sha]["files"], **files}
            sha = self._new_commit(repo, merged, base_sha, message)
            self.branches[(repo, branch)] = sha
        if self.on_push:
            self.on_push(repo, branch, sha)
        return sha

    def set_commit_status(self, repo, sha, state, context, description, target_url=None):
        with self._lock:
            self.statuses[(repo, sha, context)] = {"state": state, "description": description,
                                                   "target_url": target_url}
        return {"state": state}

    def open_pull_request(self, repo, head, base, title, body):
        with self._lock:
            number = len(self.pulls) + 1
            self.pulls.append({"repo": repo, "number": number, "head": head, "base": base,
                               "title": title, "body": body})
        return {"number": number, "url": f"https://github.com/{repo}/pull/{number} (local mock)"}
