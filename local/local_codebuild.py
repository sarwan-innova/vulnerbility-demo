"""
LocalCodeBuild — a stand-in for the two CodeBuild projects, run on your machine
with Podman (or Docker) and Trivy. Same env contract as the AWS buildspecs:

  *-wizscan  : IMAGE_URI, OUTPUT_PREFIX
               -> save image, trivy scan (+ CycloneDX SBOM), convert to wizcli
                  JSON, write results.json + sbom.cdx.json to the (local) bucket
  *-fixbuild : FIX_SPEC_S3, SOURCE_REPO_URL (a local folder), TARGET_REPO,
               TARGET_TAG, ECR_REGISTRY
               -> copy the source to a temp dir, apply the fix spec with
                  fixer/apply_fix_spec.py, build + tag the fixed image

Exposes the boto3 calls the handlers make (start_build, batch_get_builds);
builds run synchronously, so a build is finished when start_build returns.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

import trivy_adapter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASE_LABEL = trivy_adapter.BASE_LABEL


class BuildError(RuntimeError):
    pass


class LocalCodeBuild:
    def __init__(self, store, engine="podman", trivy="trivy", ignore_unfixed=True, log=print):
        self.store = store
        self.engine = engine
        self.trivy = trivy
        self.ignore_unfixed = ignore_unfixed
        self.log = log
        self.builds = {}

    # ------------------------------------------------------------ boto3 surface
    def start_build(self, projectName, environmentVariablesOverride=(), **_):
        env = {e["name"]: e["value"] for e in environmentVariablesOverride}
        build_id = f"{projectName}:{uuid.uuid4().hex[:8]}"
        try:
            if projectName.endswith("wizscan"):
                self.scan(env["IMAGE_URI"], env["OUTPUT_PREFIX"])
            elif projectName.endswith("fixbuild"):
                self.fix_build(env)
            else:
                raise BuildError(f"unknown project {projectName}")
            self.builds[build_id] = {"id": build_id, "buildStatus": "SUCCEEDED"}
        except Exception as e:
            self.builds[build_id] = {"id": build_id, "buildStatus": "FAILED", "error": str(e)[-2000:]}
        return {"build": dict(self.builds[build_id])}

    def batch_get_builds(self, ids):
        return {"builds": [self.builds[i] for i in ids if i in self.builds]}

    def run_job(self, project, env):
        """Run a build and raise when it fails (the RUN_JOB integration in Step Functions)."""
        b = self.start_build(project, [{"name": k, "value": v} for k, v in env.items()])["build"]
        if b["buildStatus"] != "SUCCEEDED":
            raise BuildError(b.get("error") or "build failed")
        return b

    # ------------------------------------------------------------ helpers
    def _run(self, *cmd, cwd=None):
        self.log("  $ " + " ".join(cmd))
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            raise BuildError(f"{cmd[0]} {cmd[1] if len(cmd) > 1 else ''} failed:\n"
                             + (proc.stderr or proc.stdout)[-1500:])
        return proc.stdout

    def image_exists(self, ref):
        return subprocess.run([self.engine, "image", "inspect", ref], capture_output=True).returncode == 0

    def inspect(self, ref):
        data = json.loads(self._run(self.engine, "image", "inspect", ref))
        return data[0] if isinstance(data, list) else data

    def build(self, context, ref):
        """Build `context` as `ref`, labelling it with its base image (OCI annotation)
        so scans can split base-layer from app-layer findings."""
        with open(os.path.join(context, "Dockerfile"), encoding="utf-8") as fh:
            froms = re.findall(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", fh.read(), re.I | re.M)
        if not froms:
            raise BuildError("Dockerfile has no FROM line")
        self._run(self.engine, "build", "-t", ref, "--label", f"{BASE_LABEL}={froms[-1]}", context)
        return froms[-1]

    @staticmethod
    def _key(s3_uri):
        """s3://bucket/key -> key (the local bucket ignores the bucket name)."""
        return s3_uri.split("://", 1)[-1].split("/", 1)[1]

    # ------------------------------------------------------------ jobs
    def scan(self, image_uri, output_prefix):
        info = self.inspect(image_uri)
        labels = info.get("Labels") or (info.get("Config") or {}).get("Labels") or {}
        base_ref = labels.get(BASE_LABEL)
        base_layers = []
        if base_ref and self.image_exists(base_ref):
            base_layers = (self.inspect(base_ref).get("RootFS") or {}).get("Layers") or []

        prefix = self._key(output_prefix)
        with tempfile.TemporaryDirectory() as tmp:
            tar = os.path.join(tmp, "image.tar")
            self._run(self.engine, "save", "-o", tar, image_uri)
            args = [self.trivy, "image", "--input", tar, "--scanners", "vuln,secret",
                    "--image-config-scanners", "misconfig", "--quiet"]
            if self.ignore_unfixed:
                args.append("--ignore-unfixed")
            out = os.path.join(tmp, "trivy.json")
            self._run(*args, "--format", "json", "--output", out)
            with open(out, encoding="utf-8") as fh:
                raw = json.load(fh)
            sbom = os.path.join(tmp, "sbom.json")
            self._run(self.trivy, "image", "--input", tar, "--quiet", "--format", "cyclonedx",
                      "--output", sbom)
            with open(sbom, encoding="utf-8") as fh:
                sbom_doc = json.load(fh)
        result = trivy_adapter.to_wizcli(raw, base_layers=base_layers, base_ref=base_ref)
        self.store.put_json_report(f"{prefix}/results.json", result)
        self.store.put_json_report(f"{prefix}/sbom.cdx.json", sbom_doc)
        n = sum(len(p["vulnerabilities"]) for g in result["result"].values() for p in g)
        self.log(f"  scanned {image_uri}: {n} fixable vulnerabilities (base: {base_ref})")

    def fix_build(self, env):
        source = env.get("SOURCE_REPO_URL")
        if not source or not os.path.isdir(source):
            raise BuildError(f"No local source folder mapped for {env.get('TARGET_REPO')}")
        spec = self.store.get_json_report(self._key(env["FIX_SPEC_S3"]))
        target = f"{env['ECR_REGISTRY']}/{env['TARGET_REPO']}:{env['TARGET_TAG']}"
        with tempfile.TemporaryDirectory() as tmp:
            work = os.path.join(tmp, "app")
            shutil.copytree(source, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            spec_file = os.path.join(tmp, "fix-spec.json")
            with open(spec_file, "w", encoding="utf-8") as fh:
                json.dump(spec, fh)
            self.log(self._run(sys.executable, os.path.join(ROOT, "fixer", "apply_fix_spec.py"),
                               spec_file, work, cwd=tmp).strip())
            self.build(work, target)
        self.log(f"  built {target}")
