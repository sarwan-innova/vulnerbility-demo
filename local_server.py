#!/usr/bin/env python3
"""
Run the whole platform locally — no AWS, no GitHub, no Wiz credentials.

    .venv\\Scripts\\python.exe local_server.py
        the developer loop on demo-app/: mock GitHub push -> local build -> scan
        -> Fix with AI (rule-based fallback) -> Push fix (branch + PR) -> rebuild
        -> re-scan, at http://localhost:8080
    ... --bedrock-model anthropic.claude-opus-5-5 --region us-east-1
        the same, but the fix comes from Claude on Amazon Bedrock using YOUR
        AWS credentials (pip install "anthropic[bedrock]" first)
    ... --trivy        real Podman builds + real Trivy scans instead of the mock scanner
    ... --legacy       the earlier mock-Wiz sample images (no CI loop; promotion API only)

Serves the web console against the real Lambda handler code (local/app.py).
Listens on 127.0.0.1 only. Restart to reset the demo data.
"""

import argparse
import json
import mimetypes
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(ROOT, "web")
sys.path.insert(0, os.path.join(ROOT, "lambda", "common"))
sys.path.insert(0, os.path.join(ROOT, "local"))

from app import ROUTES, LocalApp  # noqa: E402
from local_codebuild import LocalCodeBuild  # noqa: E402

LOCAL_CONFIG = b'window.APP_CONFIG = { API_BASE: "/api", LOCAL: true, COGNITO: {} };\n'
MAX_BODY = 64 * 1024


def match_route(method, path):
    """'/scan/abc' -> ('GET /scan/{id}', {'id': 'abc'})"""
    for route in ROUTES:
        r_method, r_path = route.split(" ", 1)
        if r_method != method:
            continue
        pattern = "^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", r_path) + "$"
        m = re.match(pattern, path)
        if m:
            return route, m.groupdict()
    return None, None


class Handler(BaseHTTPRequestHandler):
    app = None

    def log_message(self, fmt, *args):
        if "/api/workflow/" not in str(args[0] if args else ""):  # skip status-poll noise
            sys.stderr.write("  " + (fmt % args) + "\n")

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _api(self, method):
        url = urlparse(self.path)
        path = url.path[len("/api"):]
        if method == "GET" and path.startswith("/files/"):
            key = path[len("/files/"):]
            try:
                data = self.app.store.read_object(key)
            except (OSError, ValueError):
                return self._send(404, {"error": "not found"})
            name = key.rsplit("/", 1)[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        route, params = match_route(method, path)
        if not route:
            return self._send(404, {"error": f"no route {method} {path}"})
        body = None
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
        try:
            code, payload = self.app.call(route, params, dict(parse_qsl(url.query)), body,
                                          claims={"email": "local-user@localhost"})
        except Exception as e:
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(code, payload)

    def _static(self):
        path = urlparse(self.path).path
        if path == "/config.js":
            return self._send(200, LOCAL_CONFIG, "application/javascript")
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        full = os.path.abspath(os.path.join(WEB, rel))
        if not full.startswith(WEB + os.sep) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        with open(full, "rb") as fh:
            data = fh.read()
        self._send(200, data, mimetypes.guess_type(full)[0] or "application/octet-stream")

    def do_GET(self):
        return self._api("GET") if self.path.startswith("/api/") else self._static()

    def do_HEAD(self):
        self.send_response(200 if not self.path.startswith("/api/") else 405)
        self.end_headers()

    def do_POST(self):
        if not self.path.startswith("/api/"):
            return self._send(405, {"error": "method not allowed"})
        return self._api("POST")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--agentic", action="store_true", help="enable the agent stubs (no Bedrock needed)")
    ap.add_argument("--step-delay", type=float, default=1.2, help="seconds per workflow step")
    ap.add_argument("--trivy", action="store_true",
                    help="real scanning (Trivy as the wizcli stand-in) + real image builds")
    ap.add_argument("--engine", default="podman", help="container engine for --trivy (podman|docker)")
    ap.add_argument("--include-unfixed", action="store_true",
                    help="with --trivy, also report CVEs that have no fix yet")
    ap.add_argument("--bedrock-model", default="",
                    help="Bedrock model id for Fix with AI, e.g. anthropic.claude-opus-5-5")
    ap.add_argument("--region", default="us-east-1", help="AWS region for Bedrock")
    ap.add_argument("--legacy", action="store_true",
                    help="mock-Wiz sample images instead of the push/fix loop")
    args = ap.parse_args()

    if args.bedrock_model:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            sys.exit('--bedrock-model needs the Anthropic SDK: pip install "anthropic[bedrock]"')
        os.environ["BEDROCK_MODEL_ID"] = args.bedrock_model
        os.environ["BEDROCK_REGION"] = args.region
        print(f"Fix with AI: Claude on Bedrock ({args.bedrock_model}, {args.region}) "
              "with your local AWS credentials.")
    codebuild = None
    if args.trivy:
        import shutil
        for tool in (args.engine, "trivy"):
            if not shutil.which(tool):
                sys.exit(f"{tool} not found on PATH — see demo-app/README.md")
        codebuild = LocalCodeBuild(None, engine=args.engine, ignore_unfixed=not args.include_unfixed)
        print("Real mode: building + scanning demo-app (first run pulls images, ~1-3 min)...")
    Handler.app = LocalApp(step_delay=0.3 if args.trivy else args.step_delay,
                           agentic=args.agentic, codebuild=codebuild, ci_loop=not args.legacy)
    if codebuild:
        codebuild.store = Handler.app.store
    seeded = Handler.app.seed()
    print(f"Seeded {seeded['ingested']} findings from {seeded['source']}"
          + (f" for {seeded['image']}" if seeded.get("image") else "") + ".")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Remediation console: http://localhost:{args.port}   (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
