"use strict";
const $ = (id) => document.getElementById(id);
const VERDICT_COLOR = { ALLOW: "#2ea96b", STEP_UP: "#e3a52c", DUAL_CONTROL: "#d9772b", DENY: "#e5484d" };
let samples = [], current = null, grid, auditGrid;

// Each operator has their own credential; the server derives identity from it. Tokens live only
// in the inputs (memory) — never in localStorage/sessionStorage.
const token = (op = "maker") => $("tok-" + op).value;

async function api(path, opts = {}, op = "maker") {
  const res = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token(op), ...(opts.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || res.statusText);
  return body;
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function verdictPill(p) {
  const v = p.value; if (!v) return "";
  const el = document.createElement("span");
  el.className = "pill"; el.textContent = v.replace("_", " ");
  el.style.background = VERDICT_COLOR[v] + "22"; el.style.color = VERDICT_COLOR[v];
  return el;
}

function initGrids() {
  const theme = agGrid.themeQuartz.withParams({
    backgroundColor: "#151b23", foregroundColor: "#e6edf3", headerBackgroundColor: "#0f141b",
    borderColor: "#263040", rowHoverColor: "#1b2330", selectedRowBackgroundColor: "#1d2b3d",
    fontFamily: ["IBM Plex Sans", "system-ui", "sans-serif"], fontSize: 13, accentColor: "#4fa3ff",
  });
  grid = agGrid.createGrid($("grid"), {
    theme, rowData: [], rowSelection: { mode: "singleRow", checkboxes: false, enableClickSelection: true },
    getRowId: (p) => p.data.id,
    columnDefs: [
      { field: "ts", headerName: "Time", width: 110, sort: "desc",
        valueFormatter: (p) => new Date(p.value * 1000).toLocaleTimeString() },
      { field: "verdict", width: 140, cellRenderer: verdictPill, filter: true },
      { field: "status", width: 115, filter: true },
      { field: "action", width: 90 },
      { field: "payee_masked", headerName: "Payee", flex: 1, minWidth: 150 },
      { field: "amount", width: 110, type: "rightAligned",
        valueFormatter: (p) => Number(p.value).toLocaleString(undefined, { minimumFractionDigits: 2 }) },
      { field: "currency", headerName: "Cur", width: 75 },
      { field: "risk", headerName: "Risk", width: 85, type: "rightAligned",
        cellStyle: (p) => ({ color: p.value >= 60 ? "#e5484d" : p.value >= 25 ? "#e3a52c" : "#2ea96b", fontWeight: 600 }) },
      { headerName: "Controls", flex: 1, minWidth: 140, valueGetter: (p) => (p.data.decision.controls || []).join(" ") },
    ],
    onRowClicked: (e) => showDetail(e.data),
  });
  auditGrid = agGrid.createGrid($("audit-grid"), {
    theme, rowData: [],
    columnDefs: [
      { field: "seq", width: 70 },
      { field: "ts", headerName: "Time", width: 110, valueFormatter: (p) => new Date(p.value * 1000).toLocaleTimeString() },
      { field: "actor", width: 140 },
      { field: "action", width: 200 },
      { headerName: "Details", flex: 2, minWidth: 220, valueGetter: (p) => JSON.stringify(p.data.details) },
      { field: "hash", headerName: "Record hash", flex: 1, minWidth: 160, cellClass: "mono",
        valueFormatter: (p) => p.value.slice(0, 20) + "…" },
    ],
  });
}

async function refresh() {
  const [rows, audit] = await Promise.all([api("/api/proposals"), api("/api/audit")]);
  grid.setGridOption("rowData", rows);
  auditGrid.setGridOption("rowData", audit);
  if (current) { const fresh = rows.find((r) => r.id === current.id); if (fresh) showDetail(fresh); }
  verifyChain();
}

async function verifyChain() {
  const b = $("b-audit");
  try {
    const v = await api("/api/audit/verify");
    b.textContent = v.valid ? `Audit chain: VALID (${v.checked})` : `Audit chain: BROKEN @${v.broken_at}`;
    b.className = "badge btn-link " + (v.valid ? "ok" : "bad");
  } catch (e) { b.textContent = "Audit chain: auth?"; b.className = "badge btn-link warn"; }
}

function showDetail(p) {
  current = p;
  $("empty").hidden = true; $("d-body").hidden = false;
  const d = p.decision;
  const v = $("d-verdict");
  v.className = "verdict v-" + p.verdict;
  v.textContent = `${p.verdict.replace("_", " ")} · ${p.status}`;
  $("d-action").textContent = p.action;
  $("d-payee").textContent = p.payee_masked;
  $("d-amount").textContent = `${p.amount} ${p.currency}`;
  $("d-risk").textContent = `${p.risk}/100`;
  $("d-riskbar").style.width = p.risk + "%";
  $("d-ref").textContent = p.paypal_ref || "—";
  $("d-reasons").innerHTML = d.reasons.map((r) => `<li>${esc(r)}</li>`).join("");
  const flags = [...d.controls];
  if (d.travel_rule) flags.push("TRAVEL-RULE");
  if (d.sar_review) flags.push("SAR-REVIEW");
  $("d-flags").innerHTML = flags.map((f) => `<span>${esc(f)}</span>`).join("");
  const pending = p.status === "PENDING";
  $("approve").hidden = !pending;
  $("d-binding").textContent = p.binding;
  const need = p.verdict === "DUAL_CONTROL" ? 2 : 1;
  $("approve-msg").textContent = pending ? `Approvals: ${p.approvals.length}/${need}` +
    (need === 2 ? " — maker and checker must be different people" : "") : "";
}

async function run() {
  const btn = $("run"); btn.disabled = true; btn.textContent = "Agent analysing…";
  try {
    const r = await api("/api/agent/analyse", { method: "POST", body: JSON.stringify({ document: $("doc").value }) });
    const s = $("summary"); s.hidden = false;
    s.innerHTML = `<b>${esc(r.engine)}</b> · ${r.proposals.length} proposal(s)<br>${esc(r.summary)}`;
    await refresh();
    if (r.proposals[0]) showDetail(r.proposals[0]);
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; btn.textContent = "Run AI agent → policy check"; }
}

async function approve(ev) {
  ev.preventDefault();
  const msg = $("approve-msg");
  try {
    const r = await api(`/api/proposals/${current.id}/approve`, {
      method: "POST",
      body: JSON.stringify({ totp: $("totp").value.trim(), binding: current.binding }),
    }, $("op").value);
    $("totp").value = "";
    if (r.status === "AWAITING_SECOND_APPROVER") {
      msg.textContent = `Approved ${r.approvals}/${r.required}. Switch to the other operator to co-sign.`;
      $("op").value = $("op").value === "maker" ? "checker" : "maker";
    }
    await refresh();
  } catch (e) { msg.textContent = "✖ " + e.message; await refresh().catch(() => {}); }
}

async function reject() {
  try {
    await api(`/api/proposals/${current.id}/reject`, { method: "POST", body: JSON.stringify({}) }, $("op").value);
    await refresh();
  } catch (e) { $("approve-msg").textContent = "✖ " + e.message; }
}

async function fillDemo() {
  try { const c = await api("/api/demo/totp"); $("totp").value = c[$("op").value]; }
  catch (e) { $("approve-msg").textContent = "Demo codes disabled — use your authenticator app."; }
}

async function boot() {
  initGrids();
  const h = await fetch("/healthz").then((r) => r.json());
  if (h.demo_mode) { $("tok-maker").value = "demo-maker-token"; $("tok-checker").value = "demo-checker-token"; }
  ["tok-maker", "tok-checker"].forEach((id) => $(id).addEventListener("change", refresh));
  $("b-paypal").textContent = "PayPal: " + h.paypal_mode;
  $("b-paypal").className = "badge " + (h.paypal_mode === "sandbox" ? "ok" : "warn");
  $("b-ai").textContent = "AI: " + h.ai_engine;
  $("b-ai").className = "badge " + (h.ai_engine.startsWith("claude") ? "ok" : "warn");
  samples = await fetch("/api/samples").then((r) => r.json());
  $("sample").innerHTML = samples.map((s, i) => `<option value="${i}">${esc(s.title)}</option>`).join("");
  $("sample").addEventListener("change", () => { $("doc").value = samples[$("sample").value].document; });
  $("doc").value = samples[0].document;
  $("run").addEventListener("click", run);
  $("approve").addEventListener("submit", approve);
  $("reject").addEventListener("click", reject);
  $("fill").addEventListener("click", fillDemo);
  $("b-audit").addEventListener("click", verifyChain);
  await refresh();
}
document.addEventListener("DOMContentLoaded", boot);
