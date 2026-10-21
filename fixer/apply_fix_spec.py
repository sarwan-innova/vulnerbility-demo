#!/usr/bin/env python3
"""
Apply a fix spec to an application checkout — runs inside the `*-fixbuild`
CodeBuild project (LIVE mode) right before `docker build`.

    python3 apply_fix_spec.py fix-spec.json <repo_dir>

Uses the same fix_engine.py as the Lambdas (shipped next to this script), so
the rewrite rules that are unit-tested locally are exactly what runs in the
build. Exits non-zero when a requested change could not be applied anywhere,
so a silent no-op never reaches VERIFY.
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lambda", "common"))  # repo checkout
sys.path.insert(0, _HERE)  # CodeBuild: fix_engine.py is shipped next to this script

import fix_engine  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "bin", "obj", "dist", "build", "__pycache__"}


def apply(spec, repo_dir):
    applied = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if not fix_engine.patcher_for(name):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, repo_dir)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            new, changes = fix_engine.apply_to_file(rel, content, spec)
            if changes:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new)
                applied.extend(changes)
    return applied


def missing(spec, applied):
    """Requested changes that touched no file."""
    text = "\n".join(applied)
    out = [f"base {c['base_image']}" for c in spec.get("base_changes", [])
           if f"FROM {c['base_image']}:{c['to_tag']}" not in text]
    out += [f"package {c['package']}" for c in spec.get("dependency_changes", [])
            if f": {c['package']} -> {c['to_version']}" not in text]
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: apply_fix_spec.py <fix-spec.json> <repo_dir>")
    with open(sys.argv[1], encoding="utf-8") as fh:
        spec = json.load(fh)
    applied = apply(spec, sys.argv[2])
    for line in applied:
        print("applied:", line)
    gaps = missing(spec, applied)
    with open("fix-result.json", "w", encoding="utf-8") as fh:
        json.dump({"applied": applied, "missing": gaps}, fh, indent=2)
    if gaps:
        sys.exit("could not apply: " + ", ".join(gaps))


if __name__ == "__main__":
    main()
