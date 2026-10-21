"""
Core remediation-orchestration logic — PURE functions, no AWS dependencies.

Ported verbatim (behaviour-preserving) from the validated demo
(demo-norstella/engine.py + actions.py). Lambdas import these; tests exercise
them with no AWS and no network. Policy is passed in as a dict so it can come
from SSM / env at runtime.

Covers requirements 2 (attribution), 3 (SLA + KEV/EPSS), 4.1 (units),
5.1-5.3 (gate + waivers), 8.1/8.3 (deterministic).
"""

import datetime

SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}
SLA_ORDER = ["BREACHED", "OVERDUE", "AT_RISK", "ON_TRACK"]


def default_policy():
    return {
        "today": datetime.date.today().isoformat(),
        "sla": {"target_days": 15, "breach_days": 30, "measure_from": "firstSeen"},
        "gate": {"block_on": ["CRITICAL", "HIGH"], "exception_requires_approval": True},
        "fast_track": {"kev": True, "epss_threshold": 0.5},
        "fast_track_days": 7,
        "staleness": {"mutable_tag_prod_warn_days": 14},
    }


def _date(s):
    return datetime.date.fromisoformat(s[:10])


# ---------------------------------------------------------------- SLA + scoring
def effective_sla_days(finding, policy):
    ft = policy["fast_track"]
    if (ft.get("kev") and finding.get("kev")) or finding.get("epss", 0) >= ft.get("epss_threshold", 1.1):
        return policy["fast_track_days"], True
    return policy["sla"]["target_days"], False


def sla_status(age_days, remaining, breach_days, age_over_breach):
    if age_over_breach:
        return "BREACHED"
    if remaining < 0:
        return "OVERDUE"
    if remaining <= 3:
        return "AT_RISK"
    return "ON_TRACK"


def priority_score(finding, status):
    score = SEV_WEIGHT.get(finding["severity"], 0)
    if finding.get("kev"):
        score += 50
    score += int(finding.get("epss", 0) * 30)
    if status in ("BREACHED", "OVERDUE"):
        score += 25
    elif status == "AT_RISK":
        score += 10
    if finding.get("runningInProd"):
        score += 5
    return score


# ---------------------------------------------------------------- enrichment
def enrich(findings, policy, base_images):
    """Attribute base/app, compute SLA, flag staleness, score. Returns sorted list."""
    today = _date(policy["today"])
    breach_days = policy["sla"]["breach_days"]
    stale_days = policy["staleness"]["mutable_tag_prod_warn_days"]
    out = []
    for f in findings:
        age = (today - _date(f["firstSeen"])).days
        sla_days, fast_tracked = effective_sla_days(f, policy)
        remaining = sla_days - age
        status = sla_status(age, remaining, breach_days, age > breach_days)

        stale = bool(f.get("mutableTag") and f.get("runningInProd") and age >= stale_days)

        kind = f.get("kind") or "vulnerability"
        if kind == "secret":
            path = "remove-secret"
            fix_hint = (f"Remove the secret at {f.get('location')} from the image and rotate it"
                        + (f" (it comes from base {f.get('baseImage')})" if f.get("baseImage") else ""))
        elif kind == "misconfig":
            path = "image-config"
            fix_hint = f.get("resolution") or f"Fix {f.get('cve')}: {f.get('title')}"
        elif f.get("layerType") == "base":
            bi = base_images.get(f.get("baseImage"), {})
            path = "base-image-rebuild"
            fix_hint = (f"Rebuild on {f.get('baseImage')}:{bi.get('fixed_tag_available', '<fixed>')}"
                        f" then redeploy ({bi.get('downstream_image_count', '?')} images)")
        else:
            path = "app-dependency-bump"
            fix_hint = f"Bump {f.get('package')} to {f.get('fixedVersion')} and rebuild"

        rec = dict(f)
        rec.update({
            "age_days": age,
            "sla_days": sla_days,
            "sla_remaining_days": remaining,
            "sla_status": status,
            "fast_tracked": fast_tracked,
            "stale_mutable_prod": stale,
            "remediation_path": path,
            "fix_hint": fix_hint,
            "priority_score": priority_score(f, status),
        })
        out.append(rec)
    out.sort(key=lambda x: x["priority_score"], reverse=True)
    return out


# ---------------------------------------------------------------- units
def build_units(enriched, base_images):
    units = {}
    for f in enriched:
        key = ("base", f["baseImage"]) if f.get("layerType") == "base" else ("app", f["repo"])
        u = units.setdefault(key, {
            "type": key[0], "target": key[1], "findings": [],
            "repos": set(), "business_units": set(),
            "max_severity": "LOW", "kev": False,
            "worst_sla": "ON_TRACK", "priority_score": 0,
        })
        u["findings"].append(f)
        u["repos"].add(f["repo"])
        u["business_units"].add(f.get("businessUnit", ""))
        u["kev"] = u["kev"] or bool(f.get("kev"))
        if SEV_WEIGHT.get(f["severity"], 0) > SEV_WEIGHT.get(u["max_severity"], 0):
            u["max_severity"] = f["severity"]
        if SLA_ORDER.index(f["sla_status"]) < SLA_ORDER.index(u["worst_sla"]):
            u["worst_sla"] = f["sla_status"]
        u["priority_score"] = max(u["priority_score"], f["priority_score"])

    result = []
    for (utype, target), u in units.items():
        u["repos"] = sorted(u["repos"])
        u["business_units"] = sorted(x for x in u["business_units"] if x)
        u["finding_count"] = len(u["findings"])
        if utype == "base":
            bi = base_images.get(target, {})
            u["downstream_image_count"] = bi.get("downstream_image_count", 0)
            u["fixed_tag"] = bi.get("fixed_tag_available", "")
            u["leverage"] = f"Fix once -> propagates to {u['downstream_image_count']} downstream images"
            u["action"] = f"Rebuild {target}:{u['fixed_tag']} and redeploy consumers"
        else:
            u["downstream_image_count"] = 1
            u["leverage"] = "Single-repo app change"
            u["action"] = f"Patch app dependencies in {target} and rebuild"
        result.append(u)
    result.sort(key=lambda x: x["priority_score"], reverse=True)
    return result


# ---------------------------------------------------------------- gate + waivers
def is_waived(finding, waivers, today):
    t = _date(today)
    for w in waivers:
        if w["cve"] == finding["cve"] and w["repo"] == finding["repo"]:
            if _date(w["expires_on"]) >= t:
                return w
    return None


def gate_decisions(enriched, policy, waivers):
    block_on = set(policy["gate"]["block_on"])
    today = policy["today"]
    log = []
    for f in enriched:
        w = is_waived(f, waivers, today)
        if f["severity"] not in block_on:
            decision, reason = "PASS", f"{f['severity']} not in gate block list"
        elif w:
            decision = "WAIVED"
            reason = f"Waiver by {w['approved_by']} until {w['expires_on']}: {w['justification']}"
        else:
            decision = "BLOCK"
            reason = f"{f['severity']} blocks promotion"
            if f.get("kev"):
                reason += " (CISA KEV)"
            if f["sla_status"] in ("BREACHED", "OVERDUE"):
                reason += f"; SLA {f['sla_status']}"
        log.append({
            "finding_id": f.get("id"), "cve": f["cve"], "repo": f["repo"],
            "account": f.get("account"), "image_tag": f.get("imageTag"),
            "severity": f["severity"], "kev": f.get("kev", False),
            "sla_status": f["sla_status"], "decision": decision,
            "reason": reason, "waiver": w,
        })
    return log


def gate_verdict(decisions):
    return "BLOCKED" if any(d["decision"] == "BLOCK" for d in decisions) else "CLEAR"


# ---------------------------------------------------------------- summary
def summarize(enriched, units):
    sev, sla = {}, {}
    base = sum(1 for f in enriched if f.get("layerType") == "base")
    for f in enriched:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        sla[f["sla_status"]] = sla.get(f["sla_status"], 0) + 1
    base_units = [u for u in units if u["type"] == "base"]
    reach = sum(u["downstream_image_count"] for u in base_units)
    total = len(enriched)
    return {
        "total_findings": total,
        "by_severity": sev,
        "by_sla": sla,
        "base_layer_findings": base,
        "app_layer_findings": total - base,
        "base_layer_pct": round(100 * base / max(1, total)),
        "kev_findings": sum(1 for f in enriched if f.get("kev")),
        "stale_mutable_prod": sum(1 for f in enriched if f.get("stale_mutable_prod")),
        "remediation_units": len(units),
        "base_rebuild_units": len(base_units),
        "downstream_images_reachable": reach,
        "leverage_ratio": round(reach / max(1, base), 1),
    }
