"""
ECR image metadata from the image itself — no build-side database writes.

The app build (CodeBuild, triggered by git push) labels every image with
standard OCI annotations plus two of ours:
  org.opencontainers.image.revision      git commit sha
  org.opencontainers.image.source        https://github.com/<owner>/<repo>
  org.opencontainers.image.base.name     the FROM image
  com.innova.git.branch                  branch that was pushed
  com.innova.base.layers                 number of layers that come from the base

describe_image() reads the manifest + config blob from ECR and returns those
fields plus the base layer digests (first N manifest layers), which scanners
use to split base-layer from app-layer findings.
"""

import json
import urllib.request

LABELS = {
    "commit": "org.opencontainers.image.revision",
    "source": "org.opencontainers.image.source",
    "base_ref": "org.opencontainers.image.base.name",
    "branch": "com.innova.git.branch",
    "base_layer_count": "com.innova.base.layers",
}
MANIFEST_TYPES = ["application/vnd.docker.distribution.manifest.v2+json",
                  "application/vnd.oci.image.manifest.v1+json"]


def parse_labels(labels, manifest_layers):
    labels = labels or {}
    meta = {k: labels.get(v) for k, v in LABELS.items()}
    try:
        n = int(meta.pop("base_layer_count") or 0)
    except ValueError:
        n = 0
    meta["base_layers"] = list(manifest_layers[:n]) if n else []
    return meta


def describe_image(ecr, repository, digest, fetch=None):
    """{commit, source, base_ref, branch, base_layers} for one pushed image."""
    img = ecr.batch_get_image(repositoryName=repository, imageIds=[{"imageDigest": digest}],
                              acceptedMediaTypes=MANIFEST_TYPES)["images"][0]
    manifest = json.loads(img["imageManifest"])
    layers = [layer["digest"] for layer in manifest.get("layers", [])]
    config_digest = manifest["config"]["digest"]
    url = ecr.get_download_url_for_layer(repositoryName=repository,
                                         layerDigest=config_digest)["downloadUrl"]
    fetch = fetch or (lambda u: urllib.request.urlopen(u, timeout=15).read())  # presigned S3 URL
    config = json.loads(fetch(url))
    return parse_labels((config.get("config") or {}).get("Labels"), layers)
