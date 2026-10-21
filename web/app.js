/* Image Remediation Console — the developer loop:
   git push -> CodeBuild -> ECR -> scan -> "Fix with AI" (Claude on Bedrock) ->
   review diff -> "Push fix" (fix/ branch + PR) -> rebuild -> re-scan (before/after).
   Talks to the HTTP API: deployed (CloudFront /api) or local_server.py (/api). */

const CFG = window.APP_CONFIG || {};
const API_BASE = CFG.API_BASE || window.API_BASE || null;
const LOCAL = !!CFG.LOCAL;
const AUTH = window.AUTH || null;
const AUTH_ON = !!(AUTH && AUTH.authConfigured && AUTH.authConfigured());

/* ---------------- helpers ---------------- */
const $ = (id) => document.getElementById(id);
const show = (id, on = true) => $(id).classList.toggle("hidden", !on);
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g,
  (c) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
const sevChip = (s) => s ? `<span class="chip sev-${esc(s)}">${esc(s)}</span>` : "";
const kevChip = (k) => k ? ' <span class="chip sev-CRITICAL">KEV</span>' : "";
const pct = (x) => (x == null ? "" : `${Math.round(x * 100)}%`);
const short = (sha) => (sha || "").slice(0, 7);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function api(path, opts) {
  opts = opts || {};
  if (AUTH_ON && (opts.method || "GET").toUpperCase() === "POST") {
    opts.headers = Object.assign({}, opts.headers, AUTH.authHeader());
  }
  const r = await fetch(API_BASE + path, opts);
  if (r.status === 401 || r.status === 403) {
    if (AUTH_ON) AUTH.signIn();
    throw new Error("not signed in");
  }
  const body = await r.json();
  if (!r.ok) throw Object.assign(new Error(body.error || `HTTP ${r.status}`), { body });
  return body;
}
const post = (path, body) => api(path, { method:"POST",
  headers:{"content-type":"application/json"}, body: JSON.stringify(body || {}) });

function requireAuth() {
  if (AUTH_ON && !AUTH.getIdToken()) { AUTH.signIn(); return false; }
  return true;
}

/* ---------------- state ---------------- */
let current = { image: null, fixId: null, poll: null };
let imagesTimer = null;

/* ---------------- images ---------------- */
function scanCell(i) {
  if (i.scan_status === "BUILD_FAILED") return '<span class="chip sev-CRITICAL">build failed</span>';
  if (i.scan_status === "SCANNING") return '<span class="muted">scanning…</span>';
  if (i.ci && i.scan_status === "DONE" && !i.finding_count) return '<span class="chip ok">clean</span>';
  return sevChip(i.worst_severity) + kevChip(i.kev);
}

async function loadImages() {
  const body = $("images-body");
  let images;
  try {
    images = (await api("/images")).images;
  } catch (e) {
    body.innerHTML = `<tr><td colspan="5" class="muted">Could not load images: ${esc(e.message)}</td></tr>`;
    return;
  }
  body.innerHTML = images.length ? "" :
    '<tr><td colspan="5" class="muted">No images yet — push to your repo to trigger a build.</td></tr>';
  images.forEach(i => {
    const tr = document.createElement("tr");
    tr.className = "selectable" + (i.image === current.image ? " selected" : "");
    const fixOf = i.source_image ? `<br><span class="chip fix">AI fix of ${esc(i.source_image)}</span>` : "";
    tr.innerHTML = `<td><strong>${esc(i.image)}</strong>${fixOf}</td>
      <td class="muted small-text">${i.branch ? `<code>${esc(i.branch)}</code><br>` : ""}${esc(short(i.commit))}</td>
      <td>${scanCell(i)}</td>
      <td style="text-align:center">${esc(i.finding_count)}</td>
      <td><button class="small">Open</button></td>`;
    tr.onclick = () => selectImage(i.image);
    body.appendChild(tr);
  });
  // keep refreshing while anything is building/scanning
  clearTimeout(imagesTimer);
  if (images.some(i => i.scan_status === "SCANNING")) imagesTimer = setTimeout(loadImages, 2500);
}

/* ---------------- detail: findings report ---------------- */
async function selectImage(image) {
  stopFixPolling();
  current.image = image;
  current.fixId = null;
  $("detail-title").textContent = `2 · ${image}`;
  show("detail-view");
  resetFixPanel();
  loadImages();

  let data;
  try {
    data = await api("/image-findings?image=" + encodeURIComponent(image));
  } catch (e) {
    $("findings-body").innerHTML = `<tr><td colspan="6" class="muted">${esc(e.message)}</td></tr>`;
    return;
  }
  const src = data.source || {};
  $("source-line").innerHTML = src.github
    ? `Built from <code>${esc(src.github)}</code> @ <code>${esc(short(src.commit))}</code>` +
      (src.branch ? ` on <code>${esc(src.branch)}</code>` : "") +
      (src.scanner ? ` · scanner: ${esc(src.scanner)}` : "") +
      (src.source_image ? ` · AI fix of <a href="#" id="orig-link">${esc(src.source_image)}</a>` : "")
    : "Known from Wiz findings only (not built by the CI pipeline).";
  const orig = $("orig-link");
  if (orig) orig.onclick = (e) => { e.preventDefault(); selectImage(src.source_image); };

  const g = data.gate;
  $("gate-banner").className = "note " + (g.verdict === "BLOCKED" ? "fail" : "ok");
  $("gate-banner").innerHTML = g.verdict === "BLOCKED"
    ? `<strong>Gate: BLOCKED</strong> — ${esc(g.blocking)} finding(s) at ${esc(g.block_on.join(" / "))}.`
    : "<strong>Gate: CLEAR</strong> — nothing blocks promotion.";
  show("gate-banner", src.scan_status !== "SCANNING");

  renderScan(data.latest_scan, src);
  renderAdvice(data.advice);
  const fs = data.findings || [];
  $("findings-body").innerHTML = fs.length
    ? fs.map(f => `<tr><td>${esc(f.cve)}${kevChip(f.kev)}</td><td>${sevChip(f.severity)}</td>
        <td class="sla-${esc(f.sla_status)}">${esc(f.sla_status || "")}</td><td>${esc(pct(f.epss))}</td>
        <td>${esc(f.layerType || "")}</td>
        <td class="muted">${esc(f.package || "")} ${esc(f.installedVersion || "")} → ${esc(f.fixedVersion || "no fix")}</td></tr>`).join("")
    : `<tr><td colspan="6" class="muted">${src.scan_status === "SCANNING" ? "Scanning…" : "No open findings. 🎉"}</td></tr>`;

  const canFix = fs.length && src.github && src.commit;
  show("fix-panel", !!canFix);
  $("fix-model").textContent = data.ai && data.ai.model
    ? `Claude on Amazon Bedrock · ${data.ai.model}`
    : "Rule-based fallback (no Bedrock model configured)";
  if (canFix && src.last_fix_id) {          // resume the latest fix for this image
    current.fixId = src.last_fix_id;
    pollFix();
  }
}

function renderScan(scan, src) {
  show("report-link", !!scan && scan.status === "SUCCEEDED");
  show("sbom-link", !!scan && scan.status === "SUCCEEDED");
  if (src && src.scan_status === "SCANNING") { $("scan-status").textContent = " — scanning…"; return; }
  if (src && src.scan_status === "BUILD_FAILED") {
    $("scan-status").textContent = " — the build failed: " + (src.scan_error || ""); return;
  }
  if (!scan) { $("scan-status").textContent = " — no scan yet."; return; }
  const s = scan.summary || {};
  const sev = Object.entries(s.by_severity || {}).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(", ");
  $("scan-status").textContent = ` — ${scan.mode || ""} scan ${scan.finishedAt || ""}: ` +
    `${s.total || 0} findings${sev ? ` (${sev})` : ""}, ${s.fixable || 0} fixable.`;
  const q = "?image=" + encodeURIComponent(current.image);
  api("/report" + q).then(r => { $("report-link").href = r.url; }).catch(() => show("report-link", false));
  api("/sbom" + q).then(r => { $("sbom-link").href = r.url; }).catch(() => show("sbom-link", false));
}

function renderAdvice(a) {
  if (!a) { show("advice-box", false); return; }
  $("advice-box").innerHTML = `<div class="mode">TRIAGE · ${a.mode === "bedrock" ? esc(a.model_id) : "rule-based"}</div>
     <div><strong>${esc(a.recommendation)}</strong></div><div class="muted">${esc(a.summary)}</div>`;
  show("advice-box");
}

async function rescan() {
  if (!requireAuth()) return;
  $("scan-btn").disabled = true;
  $("scan-status").textContent = " — scanning…";
  try {
    let { scan } = await post("/scan", { image: current.image });
    while (scan.status === "RUNNING") { await sleep(2500); scan = (await api("/scan/" + scan.id)).scan; }
  } catch (e) { $("scan-status").textContent = " — scan failed: " + e.message; }
  $("scan-btn").disabled = false;
  selectImage(current.image);
}

/* ---------------- AI fix ---------------- */
function resetFixPanel() {
  ["fix-status", "fix-result", "push-result"].forEach(id => show(id, false));
  $("fix-btn").disabled = false;
}
function stopFixPolling() { if (current.poll) clearTimeout(current.poll); current.poll = null; }

function fixStatus(text, cls = "info") {
  $("fix-status").className = "note " + cls;
  $("fix-status").innerHTML = text;
  show("fix-status");
}

async function startFix() {
  if (!requireAuth()) return;
  resetFixPanel();
  $("fix-btn").disabled = true;
  fixStatus('<span class="spinner"></span> Reading the repository and asking the model for a fix…');
  try {
    const { fix } = await post("/fix", { image: current.image });
    current.fixId = fix.id;
    pollFix();
  } catch (e) {
    fixStatus("Could not start the fix: " + esc(e.message), "fail");
    $("fix-btn").disabled = false;
  }
}

function diffHtml(text) {
  return text.split("\n").map(l => {
    const cls = l.startsWith("+++") || l.startsWith("---") ? "dh"
      : l.startsWith("@@") ? "dh" : l.startsWith("+") ? "da" : l.startsWith("-") ? "dd" : "";
    return `<span class="${cls}">${esc(l)}</span>`;
  }).join("\n");
}

function renderProposal(s) {
  const p = s.proposal || {};
  const v = s.validation || { errors: [], warnings: [] };
  $("fix-summary").innerHTML = `<div class="mode">${p.mode === "bedrock" ? "CLAUDE ON BEDROCK · " + esc(p.model) : "RULE-BASED FIX ENGINE"}</div>
    <div><strong>${esc(p.summary)}</strong></div>
    <div class="muted">Addressed ${esc((p.addressed || []).length)} CVE(s)` +
    ((p.not_addressed || []).length ? `; not addressed: ${(p.not_addressed || []).map(n => esc(n.cve) + " (" + esc(n.reason) + ")").join(", ")}` : "") + `</div>` +
    ((p.risks || []).length ? `<ul class="risks">${p.risks.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : "");
  $("fix-validation").innerHTML =
    v.errors.map(e => `<div class="note fail">✗ ${esc(e)}</div>`).join("") +
    (v.warnings.length ? `<div class="note warn"><strong>Check before merging:</strong><ul>${v.warnings.map(w => `<li>${esc(w)}</li>`).join("")}</ul></div>` : "") +
    (!v.errors.length ? '<div class="muted small-text">✓ Validation passed: only the files sent to the model changed, no secrets added.</div>' : "");
  $("fix-diffs").innerHTML = (s.diffs || []).map(d =>
    `<details open class="diff"><summary><code>${esc(d.path)}</code> <span class="muted">${esc(d.reason)}</span></summary>
     <pre>${diffHtml(d.diff)}</pre></details>`).join("");
  $("push-btn").disabled = !!v.errors.length || s.fix.status !== "READY";
  show("fix-result");
}

function renderPushed(s) {
  const f = s.fix, r = s.rebuilt;
  let html = `<div class="note ok">Pushed <code>${esc(f.branch)}</code> (${esc(short(f.fix_commit))}) · ` +
    (f.pr ? `<a href="${esc(f.pr.url.replace(" (local mock)", ""))}" target="_blank" rel="noopener">pull request #${esc(f.pr.number)}</a>${f.pr.url.includes("local mock") ? " (local mock)" : ""}` : "") + `</div>`;
  if (!r) html += '<div class="note info"><span class="spinner"></span> Waiting for CodeBuild to build the fix branch and push it to ECR…</div>';
  else if (r.scan_status !== "DONE") html += `<div class="note info"><span class="spinner"></span> Built <code>${esc(r.image)}</code> — scanning…</div>`;
  else {
    const b = f.before || {}, a = r.after || {};
    html += `<div class="compare">
      <div class="side bad"><div class="mode">BEFORE · ${esc(f.image)}</div><div class="big">${esc(b.total)}</div>findings · ${esc(b.blocking)} blocking · <strong>${esc(b.verdict)}</strong></div>
      <div class="arrow">→</div>
      <div class="side ${a.verdict === "CLEAR" ? "good" : "bad"}"><div class="mode">AFTER · ${esc(r.image)}</div><div class="big">${esc(a.total)}</div>findings · ${esc(a.blocking)} blocking · <strong>${esc(a.verdict)}</strong></div>
    </div>
    <div class="row"><button class="small" id="open-rebuilt">Open ${esc(r.image)}</button>
    <span class="muted small-text">${a.verdict === "CLEAR" ? "Re-scan is clean — review and merge the pull request." : "Blocking findings remain — check the re-scan before merging."}</span></div>`;
  }
  $("push-result").innerHTML = html;
  show("push-result");
  const btn = $("open-rebuilt");
  if (btn) btn.onclick = () => selectImage(r.image);
}

async function pollFix() {
  stopFixPolling();
  let s;
  try { s = await api("/fix/" + current.fixId); }
  catch (e) { current.poll = setTimeout(pollFix, 3000); return; }
  const f = s.fix;
  if (f.image !== current.image) return;
  if (f.status === "RUNNING") {
    $("fix-btn").disabled = true;
    fixStatus('<span class="spinner"></span> ' + (f.mode === "bedrock"
      ? `Claude (${esc(f.model)}) is reading the repository and writing the fix…`
      : "The rule-based engine is preparing the fix…"));
    current.poll = setTimeout(pollFix, 2000);
    return;
  }
  $("fix-btn").disabled = false;
  if (f.status === "FAILED") { fixStatus("The fix failed: " + esc(f.error), "fail"); return; }
  show("fix-status", false);
  renderProposal(s);
  if (f.status === "PUSHED") {
    $("push-btn").disabled = true;
    renderPushed(s);
    if (!s.rebuilt || s.rebuilt.scan_status !== "DONE") current.poll = setTimeout(pollFix, 2500);
    else loadImages();
  }
}

async function pushFix() {
  if (!requireAuth()) return;
  $("push-btn").disabled = true;
  try {
    await post(`/fix/${current.fixId}/push`);
    loadImages();
    pollFix();
  } catch (e) {
    $("push-btn").disabled = false;
    $("push-result").innerHTML = `<div class="note fail">Push failed: ${esc(e.message)}</div>`;
    show("push-result");
  }
}

/* ---------------- wire up ---------------- */
$("scan-btn").onclick = rescan;
$("fix-btn").onclick = startFix;
$("push-btn").onclick = pushFix;

function refreshAuthUi() {
  $("mode-badge").textContent = !API_BASE ? "NO API" : (LOCAL ? "LOCAL" : "LIVE");
  $("footer-note").textContent = LOCAL
    ? "Local: real handler code, mock GitHub + local builds. Restart local_server.py to reset."
    : (API_BASE ? "" : "No API configured — run `python local_server.py` or deploy the stacks.");
  if (!AUTH_ON) { show("signin-btn", false); show("signout-btn", false); return; }
  const user = AUTH.currentUser();
  $("user-label").textContent = user ? "signed in: " + user : "not signed in";
  show("signin-btn", !user);
  show("signout-btn", !!user);
}
if (AUTH_ON) {
  $("signin-btn").onclick = () => AUTH.signIn();
  $("signout-btn").onclick = () => AUTH.signOut();
}
refreshAuthUi();
if (API_BASE) loadImages();
else $("images-body").innerHTML = '<tr><td colspan="5" class="muted">No API configured — run <code>python local_server.py</code>.</td></tr>';
