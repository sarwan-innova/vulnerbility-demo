"""
Promotion workflow — PURE state logic (no AWS), shared by the Step Functions
tasks, the status API, and the web UI. Deterministic so UI/backend/tests agree.

Flow (Requirement 9):
  SCAN -> APPLY_FIX -> DEPLOY_DEV -> VERIFY -> AWAIT_APPROVAL -> PROMOTE_PROD -> DONE
Failure branches:
  VERIFY fail  -> FAILED      (stop before approval/prod; Req 9.5)
  reject       -> REJECTED    (stop; Req 9.7)
"""

import core  # noqa: F401  (gate rules live in core; VERIFY mirrors them)
import fix_engine

STAGES = ["SCAN", "APPLY_FIX", "DEPLOY_DEV", "VERIFY", "AWAIT_APPROVAL",
          "PROMOTE_PROD", "DONE"]
TERMINAL = {"DONE", "FAILED", "REJECTED"}

# normal forward transitions
_NEXT = {
    "SCAN": "APPLY_FIX",
    "APPLY_FIX": "DEPLOY_DEV",
    "DEPLOY_DEV": "VERIFY",
    "VERIFY": "AWAIT_APPROVAL",
    "AWAIT_APPROVAL": "PROMOTE_PROD",
    "PROMOTE_PROD": "DONE",
}


def plan_remediation(image, findings, base_images):
    """
    Decide the fix action for an image from its findings (Req 9.3).
    Base-layer findings -> rebuild on the fixed base tag (fixes many at once).
    App-layer findings  -> record the dependency bumps required.
    """
    # secrets / misconfigurations are not fixed by a version bump
    findings = [f for f in findings if (f.get("kind") or "vulnerability") == "vulnerability"]
    base_findings = [f for f in findings if f.get("layerType") == "base"]
    app_findings = [f for f in findings if f.get("layerType") == "app"]

    actions = []
    if base_findings:
        # group by base image; one rebuild per distinct base
        by_base = {}
        for f in base_findings:
            by_base.setdefault(f.get("baseImage"), []).append(f)
        for base, fs in by_base.items():
            bi = base_images.get(base, {})
            actions.append({
                "type": "base-image-rebuild",
                "base_image": base,
                "fixed_tag": bi.get("fixed_tag_available", "<fixed>"),
                "downstream_image_count": bi.get("downstream_image_count", 0),
                "fixes": sorted({f["cve"] for f in fs}),
            })
    # one bump per package, to the highest fixed version, so every CVE on it is
    # cleared by a single manifest change (scanners report one row per CVE)
    by_pkg = {}
    for f in app_findings:
        by_pkg.setdefault(f.get("package"), []).append(f)
    for pkg, fs in by_pkg.items():
        fixable = [f for f in fs if f.get("fixedVersion")]
        if fixable:
            actions.append({
                "type": "app-dependency-bump",
                "package": pkg,
                "from_version": fixable[0].get("installedVersion"),
                "to_version": max((f["fixedVersion"] for f in fixable), key=fix_engine.version_key),
                "fixes": sorted({f["cve"] for f in fixable}),
            })
        unfixable = sorted({f["cve"] for f in fs if not f.get("fixedVersion")})
        if unfixable:
            actions.append({"type": "app-dependency-bump", "package": pkg,
                            "from_version": fs[0].get("installedVersion"), "to_version": None,
                            "fixes": unfixable})

    primary = "base-image-rebuild" if base_findings else "app-dependency-bump"
    return {
        "image": image,
        "primary_path": primary,
        "actions": actions,
        "total_cves": sorted({f["cve"] for f in findings}),
    }


def simulate_fixed_findings(findings, plan):
    """
    Mock-mode helper: given a remediation plan, return the findings that REMAIN
    after applying it. A base rebuild clears all base-layer CVEs for that base;
    app bumps clear their CVE. Used by VERIFY in mock mode so the demo shows a
    clean re-scan. Real mode replaces this with an actual re-scan.
    """
    fixed_cves = set()
    for a in plan.get("actions", []):
        fixed_cves.update(a.get("fixes", []))
    return [f for f in findings if f["cve"] not in fixed_cves]


def verify_result(findings_after, policy):
    """
    Re-run the gate on post-fix findings (Req 9.4). PASS only when no blocking
    findings remain. Returns (result, blocking_remaining).
    """
    block_on = set(policy["gate"]["block_on"])
    blocking = [f for f in findings_after if f.get("severity") in block_on]
    return ("PASS" if not blocking else "FAIL"), blocking


def superseded(original_findings, fixed_findings):
    """Ids of the ORIGINAL image's findings that the promoted rebuilt image no
    longer has (matched on CVE + package, since the tags differ)."""
    still = {(f["cve"], f.get("package")) for f in fixed_findings}
    return sorted(f["id"] for f in original_findings
                  if (f["cve"], f.get("package")) not in still)


def advance(state, event):
    """
    Return the next state given the current state and an event.
    events: "ok" (stage succeeded), "verify_fail", "approve", "reject".
    """
    if state in TERMINAL:
        return state
    if event == "verify_fail" and state == "VERIFY":
        return "FAILED"
    if event == "reject" and state == "AWAIT_APPROVAL":
        return "REJECTED"
    if event == "approve" and state == "AWAIT_APPROVAL":
        return _NEXT["AWAIT_APPROVAL"]
    if event == "ok":
        return _NEXT.get(state, state)
    return state


def stage_index(state):
    return STAGES.index(state) if state in STAGES else -1


def initial_state():
    return "SCAN"
