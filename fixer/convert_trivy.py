#!/usr/bin/env python3
"""
Convert a Trivy JSON report to the wizcli result shape the platform reads.
Runs inside the `*-wizscan` CodeBuild project when scanner=trivy:

    python3 convert_trivy.py trivy.json base_layers.json "<base image ref>" results.json

base_layers.json is `docker image inspect <base> --format '{{json .RootFS.Layers}}'`
(or []), used to split base-layer from app-layer findings. Uses the same
trivy_adapter.py as the local --trivy mode (shipped next to this script).
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lambda", "common"))  # repo checkout
sys.path.insert(0, _HERE)  # CodeBuild: trivy_adapter.py + fix_engine.py shipped alongside

import trivy_adapter  # noqa: E402


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: convert_trivy.py <trivy.json> <base_layers.json> <base ref> <out.json>")
    trivy_json, layers_json, base_ref, out = sys.argv[1:]
    with open(trivy_json, encoding="utf-8") as fh:
        raw = json.load(fh)
    try:
        with open(layers_json, encoding="utf-8") as fh:
            layers = json.load(fh) or []
    except (OSError, ValueError):
        layers = []
    base_ref = base_ref if base_ref and base_ref != "<no value>" else None
    result = trivy_adapter.to_wizcli(raw, base_layers=layers, base_ref=base_ref)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    n = sum(len(p["vulnerabilities"]) for group in result["result"].values() for p in group)
    print(f"converted {n} vulnerabilities (base: {base_ref}, {len(layers)} base layers)")


if __name__ == "__main__":
    main()
