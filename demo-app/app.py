"""
vuln-api — a deliberately VULNERABLE demo service for testing the remediation
platform end to end. Do not deploy it anywhere real.

It pins old library versions on an old base image so a scan finds real CVEs
in both layers:
  * base layer: python:3.9-alpine3.16 (EOL Alpine, old OpenSSL/zlib/busybox)
  * app layer : requirements.txt (old cryptography, jinja2, requests, urllib3)

Endpoints:  GET /health   GET /   (renders a Jinja2 template)
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import cryptography
import jinja2
import requests
import urllib3

PAGE = jinja2.Template(
    "<h1>vuln-api</h1><p>Demo image for the remediation console.</p>"
    "<ul>{% for name, ver in libs %}<li>{{ name }} {{ ver }}</li>{% endfor %}</ul>")
LIBS = [("cryptography", cryptography.__version__), ("jinja2", jinja2.__version__),
        ("requests", requests.__version__), ("urllib3", urllib3.__version__)]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body, ctype = json.dumps({"status": "ok", "libs": dict(LIBS)}).encode(), "application/json"
        else:
            body, ctype = PAGE.render(libs=LIBS).encode(), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"vuln-api listening on :{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
