"""
Fix engine — PURE, deterministic remediation changes (Requirement 9.3, Phase 3).

Turns a remediation plan into a concrete, validated FIX SPEC, and applies it to
source files:
  * base-image-rebuild  -> rewrite `FROM <base>:<tag>` to the fixed tag
  * app-dependency-bump -> bump the package in its manifest
      requirements*.txt (pip), package.json (npm), *.csproj (NuGet)

The fix spec is the single contract between the planner, the CodeBuild fix
build (fixer/apply_fix_spec.py imports this module) and the mock scanner.
validate_fix_spec() guarantees every change maps to a real finding and moves
the package to the version Wiz says fixes it, so neither a bug nor an AI
suggestion can smuggle in an unrelated change.
"""

import json
import re

FIX_TAG_PREFIX = "fix-"


def version_key(v):
    """Sortable key for package versions ('2.34-100', '42.0.0', '1.26.18').
    Numeric parts compare as numbers; good enough to order a package's fixed versions."""
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.findall(r"\d+|[a-zA-Z]+", str(v or ""))]


def pick_fixed_version(installed, candidates):
    """Smallest fixed version above the installed one, from a scanner list like
    '2.2.5, 2.3.2' (same line before a major jump). Falls back to the largest."""
    vs = [c.strip() for c in str(candidates or "").split(",") if c.strip()]
    if not vs:
        return None
    above = [c for c in vs if version_key(c) > version_key(installed)]
    return min(above, key=version_key) if above else max(vs, key=version_key)


def target_image(image, wf_id):
    """The rebuilt image ref: same repo, tag fix-<workflow id>."""
    repo = image.rsplit(":", 1)[0]
    return f"{repo}:{FIX_TAG_PREFIX}{wf_id}"


def build_fix_spec(image, wf_id, plan):
    """Plan (promotion.plan_remediation) -> fix spec the build applies."""
    base_changes, dep_changes, unsupported = [], [], []
    for a in plan.get("actions", []):
        if a["type"] == "base-image-rebuild":
            if not a.get("base_image") or not a.get("fixed_tag") or a["fixed_tag"] == "<fixed>":
                unsupported.append({**a, "reason": "no fixed base tag published yet"})
                continue
            base_changes.append({"base_image": a["base_image"], "to_tag": a["fixed_tag"],
                                 "cves": a.get("fixes", [])})
        elif a["type"] == "app-dependency-bump":
            if not a.get("package") or not a.get("to_version"):
                unsupported.append({**a, "reason": "no fixed version available"})
                continue
            dep_changes.append({"package": a["package"], "from_version": a.get("from_version"),
                                "to_version": a["to_version"], "cves": a.get("fixes", [])})
    return {
        "workflow_id": wf_id,
        "source_image": image,
        "target_image": target_image(image, wf_id),
        "base_changes": base_changes,
        "dependency_changes": dep_changes,
        "unsupported": unsupported,
    }


def validate_fix_spec(spec, findings):
    """Return a list of problems (empty = valid). Every change must be backed by a
    finding for this image and target exactly the fixed version/tag."""
    problems = []
    by_cve = {}
    for f in findings:
        by_cve.setdefault(f["cve"], []).append(f)
    for c in spec.get("dependency_changes", []):
        backing = [f for cve in c.get("cves", []) for f in by_cve.get(cve, [])
                   if f.get("package") == c["package"] and f.get("layerType") == "app"]
        if not backing:
            problems.append(f"{c['package']}: no app-layer finding backs this change")
        elif all(f.get("fixedVersion") != c["to_version"] for f in backing):
            problems.append(f"{c['package']}: {c['to_version']} is not the Wiz fixed version")
        elif any(version_key(f.get("fixedVersion")) > version_key(c["to_version"]) for f in backing):
            problems.append(f"{c['package']}: {c['to_version']} does not reach every fixed version")
    for c in spec.get("base_changes", []):
        backing = [f for cve in c.get("cves", []) for f in by_cve.get(cve, [])
                   if f.get("baseImage") == c["base_image"] and f.get("layerType") == "base"]
        if not backing:
            problems.append(f"{c['base_image']}: no base-layer finding backs this rebuild")
    if spec.get("target_image") == spec.get("source_image"):
        problems.append("target image must differ from the source image")
    return problems


def fixed_cves(spec):
    cves = set()
    for c in spec.get("base_changes", []) + spec.get("dependency_changes", []):
        cves.update(c.get("cves", []))
    return cves


# ---------------------------------------------------------------- file patchers
def patch_dockerfile(content, base_image, to_tag):
    """Rewrite FROM lines that use `base_image` (any registry prefix) to `to_tag`."""
    pattern = re.compile(
        r"^(\s*FROM\s+(?:--platform=\S+\s+)?)(\S*?" + re.escape(base_image) + r")(?::[^\s@]+)?(@\S+)?(\s.*)?$",
        re.IGNORECASE | re.MULTILINE)
    new = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}:{to_tag}{m.group(4) or ''}", content)
    return new, new != content


def patch_requirements(content, package, to_version):
    """pip: pin `package` to ==to_version (keeps extras and comments)."""
    name = re.escape(package)
    pattern = re.compile(r"^(\s*" + name + r"(\[[^\]]*\])?)\s*([=<>!~]=?[^;#\s]*)?(\s*[;#].*)?$",
                         re.IGNORECASE | re.MULTILINE)
    new = pattern.sub(lambda m: f"{m.group(1)}=={to_version}{m.group(4) or ''}", content)
    return new, new != content


def patch_package_json(content, package, to_version):
    """npm: bump `package` in dependencies/devDependencies, keeping a ^/~ prefix."""
    data = json.loads(content)
    changed = False
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if package in deps:
            prefix = deps[package][0] if deps[package][:1] in ("^", "~") else ""
            if deps[package] != prefix + to_version:
                deps[package] = prefix + to_version
                changed = True
    if not changed:
        return content, False
    indent = 4 if "\n    \"" in content else 2
    return json.dumps(data, indent=indent) + ("\n" if content.endswith("\n") else ""), True


def patch_csproj(content, package, to_version):
    """NuGet: <PackageReference Include="pkg" Version="x" />."""
    pattern = re.compile(r'(<PackageReference\s+Include="' + re.escape(package) +
                         r'"\s+Version=")[^"]*(")', re.IGNORECASE)
    new = pattern.sub(lambda m: f"{m.group(1)}{to_version}{m.group(2)}", content)
    return new, new != content


def patcher_for(filename):
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name == "dockerfile" or name.endswith(".dockerfile") or name.startswith("dockerfile."):
        return "dockerfile"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"
    if name == "package.json":
        return "package_json"
    if name.endswith(".csproj"):
        return "csproj"
    return None


def apply_to_file(filename, content, spec):
    """Apply every relevant change in `spec` to one file. Returns (content, [changes])."""
    kind = patcher_for(filename)
    applied = []
    if kind == "dockerfile":
        for c in spec.get("base_changes", []):
            content, ok = patch_dockerfile(content, c["base_image"], c["to_tag"])
            if ok:
                applied.append(f"{filename}: FROM {c['base_image']}:{c['to_tag']}")
    elif kind in ("requirements", "package_json", "csproj"):
        fn = {"requirements": patch_requirements, "package_json": patch_package_json,
              "csproj": patch_csproj}[kind]
        for c in spec.get("dependency_changes", []):
            content, ok = fn(content, c["package"], c["to_version"])
            if ok:
                applied.append(f"{filename}: {c['package']} -> {c['to_version']}")
    return content, applied
