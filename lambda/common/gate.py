"""
Deterministic gate — one verdict per image, and making it bind.

  evaluate()   the image's open findings -> BLOCKED / CLEAR (waivers honoured),
               the same answer the console shows
  enforce()    after every scan, make the verdict count outside the console:
                 * GitHub commit status `security/vuln-gate` on the image's commit
                   (failure / success). With branch protection requiring that
                   check, a PR whose image is BLOCKED cannot be merged.
                 * ECR tag `approved-<tag>`: added when CLEAR, removed when a
                   re-scan turns the image BLOCKED. Deployments pull approved-*
                   tags only, so a blocked image has nothing deployable.
Enforcement problems never fail the scan: they are recorded on the image
(gate_error) and shown in the console.
"""

import os
import time

import core
import store

APPROVED_PREFIX = "approved-"
STATUS_CONTEXT = "security/vuln-gate"
CONSOLE_URL = os.environ.get("CONSOLE_URL", "")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def evaluate(image, findings=None, policy=None):
    """findings: the image's enriched findings (computed here when omitted)."""
    policy = policy or store.get_policy(core.default_policy())
    if findings is None:
        enriched = core.enrich(store.list_findings(), policy, store.list_base_images())
        findings = store.findings_for_image(enriched, image)
    decisions = core.gate_decisions(findings, policy, store.list_waivers())
    blocking = [d for d in decisions if d["decision"] == "BLOCK"]
    by_kind = {}
    for f, d in zip(findings, decisions):
        if d["decision"] == "BLOCK":
            kind = f.get("kind") or "vulnerability"
            by_kind[kind] = by_kind.get(kind, 0) + 1
    return {"verdict": core.gate_verdict(decisions), "block_on": policy["gate"]["block_on"],
            "blocking": len(blocking), "blocking_by_kind": by_kind,
            "waived": sum(1 for d in decisions if d["decision"] == "WAIVED")}


def approved_tag(tag):
    return f"{APPROVED_PREFIX}{tag}"


def is_approved_tag(tag):
    return bool(tag) and tag.startswith(APPROVED_PREFIX)


def _describe(g):
    if g["verdict"] == "CLEAR":
        return "No blocking findings" + (f" ({g['waived']} waived)" if g["waived"] else "")
    kinds = ", ".join(f"{n} {k}" for k, n in sorted(g["blocking_by_kind"].items()))
    return f"BLOCKED: {g['blocking']} {'/'.join(g['block_on'])} finding(s) ({kinds})"


def post_commit_status(github, record, g):
    target = f"{CONSOLE_URL.rstrip('/')}/#image={record['image']}" if CONSOLE_URL else None
    github.set_commit_status(record["github"], record["commit"],
                             "success" if g["verdict"] == "CLEAR" else "failure",
                             STATUS_CONTEXT, _describe(g)[:140], target)


def set_approved_tag(ecr, record, approve):
    """Add (approve=True) or remove the approved-<tag> tag. Returns the tag or None."""
    tag = approved_tag(record["tag"])
    if not approve:
        ecr.batch_delete_image(repositoryName=record["repo"], imageIds=[{"imageTag": tag}])
        return None
    got = ecr.batch_get_image(repositoryName=record["repo"],
                              imageIds=[{"imageDigest": record["digest"]}],
                              acceptedMediaTypes=[
                                  "application/vnd.docker.distribution.manifest.v2+json",
                                  "application/vnd.oci.image.manifest.v1+json",
                                  "application/vnd.oci.image.index.v1+json",
                                  "application/vnd.docker.distribution.manifest.list.v2+json"])
    image = (got.get("images") or [None])[0]
    if not image:
        raise RuntimeError(f"{record['repo']}@{record['digest']} not found in ECR")
    try:
        args = {"repositoryName": record["repo"], "imageManifest": image["imageManifest"],
                "imageTag": tag}
        if image.get("imageManifestMediaType"):
            args["imageManifestMediaType"] = image["imageManifestMediaType"]
        ecr.put_image(**args)
    except Exception as e:  # already tagged: ECR refuses an identical re-tag
        if "ImageAlreadyExists" not in type(e).__name__ + str(e):
            raise
    return tag


def enforce(record, g, github=None, ecr=None):
    """Apply verdict g to the image's commit and ECR tags. Returns the updated record."""
    out = {**record, "gate_verdict": g["verdict"], "gate_blocking": g["blocking"],
           "gate_checked_at": now()}
    errors = []
    if github is not None and record.get("github") and record.get("commit"):
        try:
            post_commit_status(github, record, g)
            out["gate_status_check"] = STATUS_CONTEXT
        except Exception as e:
            errors.append(f"GitHub status: {e}")
    if ecr is not None and record.get("repo") and record.get("digest") and record.get("tag"):
        try:
            out["approved_tag"] = set_approved_tag(ecr, record, g["verdict"] == "CLEAR")
        except Exception as e:
            errors.append(f"ECR tag: {e}")
    out["gate_error"] = "; ".join(errors) or None
    return out
