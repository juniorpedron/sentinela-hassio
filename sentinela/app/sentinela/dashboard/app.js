// app.js — Dashboard Sentinela (SPA, sem libs/CDN). UI em PT-BR.
"use strict";

const $ = (sel) => document.querySelector(sel);

function el(tag, cls, texto) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (texto != null) n.textContent = texto;
  return n;
}

function esc(v) {
  if (v == null) return "";
  return String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function hora(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const U = (x) => new URL(String(x).replace(/^\//, ""), document.baseURI).href;
async function apiGet(url) {
  const r = await fetch(U(url), { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`GET ${url} → ${r.status}`);
  return r.json();
}

const estado = {
  devices: [], filtro: "", selecionado: null, modo: "pc",
  filtrosFeed: { device: true, dns: true, flow: true, event: true },
};

// Cores por categoria de serviço (grafo) e por confiança (dispositivos).
const CAT_COR = {
  IA: "#a78bfa", Google: "#60a5fa", Microsoft: "#2dd4bf", Apple: "#cbd5e1",
  Social: "#f472b6", Mensagens: "#4ade80", Streaming: "#fb7185", Busca: "#818cf8",
  Nuvem: "#fbbf24", Infra: "#fbbf24", CDN: "#fbbf24", Publicidade: "#ef4444",
  Dev: "#38bdf8", Jogos: "#f59e0b", Sistema: "#94a3b8", Desconhecido: "#64748b", Outro: "#64748b",
};
const TRUST_COR = { trusted: "#3ecf8e", unknown: "#f6b13f", quarantine: "#f2555f" };

// ----------------------- token / mutações -----------------------
function getToken() {
  let t = localStorage.getItem("sentinela_token");
  if (!t) {
    t = (prompt("ADMIN_TOKEN (aparece no terminal ao iniciar o Sentinela):") || "").trim();
    if (t) localStorage.setItem("sentinela_token", t);
  }
  return t;
}

async function mutarDevice(id, body) {
  const t = getToken();
  if (!t) return null;
  const r = await fetch(U(`/api/devices/${encodeURIComponent(id)}`), {
    method: "POST", headers: { "Content-Type": "application/json", "X-Sentinela-Token": t }, body: JSON.stringify(body),
  });
  if (r.status === 401) { localStorage.removeItem("sentinela_token"); alert("Token inválido. Tente de novo."); return null; }
  if (!r.ok) { alert("Falha ao salvar (" + r.status + ")."); return null; }
  return r.json();
}

// ----------------------- header: health/stats/toggle -----------------------
async function carregarHealth() {
  try {
    const h = await apiGet("/api/health");
    estado.modo = (h.mode || "pc").toLowerCase();
    const badge = $("#badge-modo");
    badge.textContent = "MODO " + estado.modo.toUpperCase();
    badge.classList.toggle("modo-pi", estado.modo === "pi");
    badge.classList.toggle("modo-pc", estado.modo !== "pi");
    $("#aviso-limite").classList.toggle("oculto", estado.modo === "pi");
    estado.readonly = !!h.readonly;
    document.body.classList.toggle("somente-leitura", estado.readonly);
    const bro = $("#badge-ro"); if (bro) bro.classList.toggle("oculto", !estado.readonly);
  } catch (e) { console.error("health", e); }
}

async function carregarStats() {
  try {
    const s = await apiGet("/api/stats");
    $("#stat-devices").textContent = s.devices ?? "—";
    $("#stat-unknown").textContent = s.unknown_devices ?? "—";
    $("#stat-dns").textContent = s.dns_24h ?? "—";
    $("#stat-events").textContent = s.events_24h ?? "—";
  } catch (e) { console.error("stats", e); }
}

async function carregarControl() {
  try { const c = await apiGet("/api/control"); setToggle(c.sniffer_enabled); }
  catch (e) { console.error("control", e); }
}

function setToggle(on) {
  const b = $("#btn-sniffer");
  if (!b) return;
  if (on == null) { b.textContent = "○ Sniffer n/d"; b.className = "btn-sniffer off"; b.dataset.on = ""; return; }
  b.dataset.on = on ? "1" : "0";
  b.className = "btn-sniffer " + (on ? "on" : "off");
  b.textContent = on ? "◉ Sniffer: LIGADO" : "○ Sniffer: desligado";
}

async function toggleSniffer() {
  const b = $("#btn-sniffer");
  const on = b.dataset.on === "1";
  const t = getToken();
  if (!t) return;
  const r = await fetch(U("/api/control/sniffer"), {
    method: "POST", headers: { "Content-Type": "application/json", "X-Sentinela-Token": t }, body: JSON.stringify({ enabled: !on }),
  });
  if (r.status === 401) { localStorage.removeItem("sentinela_token"); alert("Token inválido."); return; }
  if (!r.ok) { alert("Falha (" + r.status + ")."); return; }
  const c = await r.json();
  setToggle(c.sniffer_enabled);
}

// ----------------------- mapa da rede (canvas nebula) -----------------------
const GV = { canvas: null, ctx: null, dpr: 1, W: 0, H: 0, nodes: [], edges: [], byId: {},
  stars: [], clusters: {}, adj: {}, scale: 1, ox: 0, oy: 0, drag: null, pan: null,
  moved: false, hover: null, started: false, idle: 0,
  glow: 0.7, nodeSize: 1, linkOp: 0.26, repuls: 1 };
window.__GV = GV;
window.__abrir = (id)=>abrirDetalhe(id);

function gvColor(n) {
  if (n.kind === "gateway") return "#f5b13b";
  if (n.kind === "device") return TRUST_COR[n.trust_state] || "#8aa0b6";
  return CAT_COR[n.category] || "#7c8aa0";
}
function gvBaseR(n) {
  if (n.kind === "gateway") return 15;
  if (n.kind === "device") return 8;
  return 4.5 + Math.min(11, Math.sqrt(n.count || 1) * 1.5);
}
function gvClusterKey(n) {
  if (n.kind === "gateway") return "__gw";
  if (n.kind === "device") return "__dev";
  return n.category || "Outro";
}
function w2s(n) { return { x: n.x * GV.scale + GV.ox, y: n.y * GV.scale + GV.oy }; }
function s2w(px, py) { return { x: (px - GV.ox) / GV.scale, y: (py - GV.oy) / GV.scale }; }

function gvResize() {
  const rect = GV.canvas.parentElement.getBoundingClientRect();
  GV.dpr = window.devicePixelRatio || 1;
  GV.W = Math.max(320, Math.floor(rect.width || document.documentElement.clientWidth || 900));
  GV.H = 560;
  GV.canvas.width = GV.W * GV.dpr;
  GV.canvas.height = GV.H * GV.dpr;
  GV.canvas.style.height = GV.H + "px";
  gvMakeStars();
  gvKick();
}
function gvMakeStars() {
  const n = Math.floor((GV.W * GV.H) / 5200);
  GV.stars = [];
  for (let k = 0; k < n; k++) {
    GV.stars.push({ x: Math.random() * GV.W, y: Math.random() * GV.H, r: Math.random() * 1.1 + 0.2, a: Math.random() * 0.5 + 0.15 });
  }
}
function gvInit() {
  GV.canvas = document.getElementById("grafo-canvas");
  if (!GV.canvas) return;
  GV.ctx = GV.canvas.getContext("2d");
  gvResize();
  window.addEventListener("resize", gvResize);
  GV.canvas.addEventListener("wheel", gvWheel, { passive: false });
  GV.canvas.addEventListener("pointerdown", gvDown);
  window.addEventListener("pointermove", gvMove);
  window.addEventListener("pointerup", gvUp);
  gvControls();
}
function gvControls() {
  const bind = (id, prop, after) => {
    const el2 = document.getElementById(id);
    if (!el2) return;
    el2.addEventListener("input", () => { GV[prop] = parseFloat(el2.value); if (after) after(); gvKick(); gvDraw(); });
  };
  bind("gc-glow", "glow");
  bind("gc-size", "nodeSize");
  bind("gc-link", "linkOp");
  bind("gc-rep", "repuls", () => { for (const n of GV.nodes) { n.vx += (Math.random() - 0.5) * 2; n.vy += (Math.random() - 0.5) * 2; } });
  const rb = document.getElementById("gc-reset");
  if (rb) rb.addEventListener("click", () => { gvFit(); gvDraw(); });
}
function gvSetData(data) {
  const old = GV.byId;
  const nodes = (data.nodes || []).map((n) => {
    const p = old[n.id];
    return Object.assign({}, n, {
      x: p ? p.x : GV.W / 2 + (Math.random() - 0.5) * 260,
      y: p ? p.y : GV.H / 2 + (Math.random() - 0.5) * 240,
      vx: 0, vy: 0, r: gvBaseR(n), color: gvColor(n), ck: gvClusterKey(n),
    });
  });
  GV.nodes = nodes;
  GV.byId = {}; nodes.forEach((n) => { GV.byId[n.id] = n; });
  GV.edges = data.edges || [];
  GV.adj = {};
  for (const e of GV.edges) { (GV.adj[e.source] = GV.adj[e.source] || new Set()).add(e.target); (GV.adj[e.target] = GV.adj[e.target] || new Set()).add(e.source); }

  // Centros de cluster (galaxias) em um anel; gateway no centro.
  const keys = [...new Set(nodes.filter((n) => n.ck !== "__gw").map((n) => n.ck))];
  const Rx = GV.W * 0.33, Ry = GV.H * 0.36;
  GV.clusters = { __gw: { x: GV.W / 2, y: GV.H / 2 } };
  keys.forEach((k, idx) => {
    const a = -Math.PI / 2 + (idx / Math.max(1, keys.length)) * Math.PI * 2;
    GV.clusters[k] = { x: GV.W / 2 + Math.cos(a) * Rx, y: GV.H / 2 + Math.sin(a) * Ry };
  });

  // Marca rotulos "hub": gateway + top servicos por conexoes.
  const svc = nodes.filter((n) => n.kind === "service").sort((a, b) => (b.count || 0) - (a.count || 0));
  const hubSet = new Set(svc.slice(0, 8).map((n) => n.id));
  nodes.forEach((n) => { n.hub = n.kind === "gateway" || hubSet.has(n.id); });

  for (let it = 0; it < 320; it++) gvStep();
  gvFit();
  gvDraw();
  gvKick();
}
function gvStep() {
  const n = GV.nodes, REP = 900 * GV.repuls, DAMP = 0.86;
  for (let i = 0; i < n.length; i++) {
    const a = n[i];
    for (let j = i + 1; j < n.length; j++) {
      const b = n[j];
      let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy || 1, d = Math.sqrt(d2);
      const f = REP / d2, ux = dx / d, uy = dy / d;
      if (a !== GV.drag) { a.vx += ux * f; a.vy += uy * f; }
      if (b !== GV.drag) { b.vx -= ux * f; b.vy -= uy * f; }
    }
  }
  for (const e of GV.edges) {
    const a = GV.byId[e.source], b = GV.byId[e.target];
    if (!a || !b) continue;
    let dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1;
    const len = (a.kind === "gateway" || b.kind === "gateway") ? 120 : 62;
    const f = (d - len) * 0.015, ux = dx / d, uy = dy / d;
    if (a !== GV.drag) { a.vx += ux * f; a.vy += uy * f; }
    if (b !== GV.drag) { b.vx -= ux * f; b.vy -= uy * f; }
  }
  let energy = 0;
  for (const a of n) {
    if (a === GV.drag) continue;
    const c = GV.clusters[a.ck] || GV.clusters.__gw;
    const cg = a.kind === "gateway" ? 0.09 : 0.022;
    a.vx += (c.x - a.x) * cg; a.vy += (c.y - a.y) * cg;
    a.vx *= DAMP; a.vy *= DAMP; a.x += a.vx; a.y += a.vy;
    energy += Math.abs(a.vx) + Math.abs(a.vy);
  }
  return energy;
}
function gvFit() {
  if (!GV.nodes.length) return;
  let mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9;
  for (const n of GV.nodes) { if (n.x < mnx) mnx = n.x; if (n.y < mny) mny = n.y; if (n.x > mxx) mxx = n.x; if (n.y > mxy) mxy = n.y; }
  const bw = Math.max(1, mxx - mnx), bh = Math.max(1, mxy - mny), pad = 74;
  GV.scale = Math.max(0.25, Math.min(1.5, Math.min((GV.W - 2 * pad) / bw, (GV.H - 2 * pad) / bh)));
  GV.ox = (GV.W - (mnx + mxx) * GV.scale) / 2;
  GV.oy = (GV.H - (mny + mxy) * GV.scale) / 2;
}
function gvDraw() {
  const ctx = GV.ctx;
  if (!ctx) return;
  ctx.setTransform(GV.dpr, 0, 0, GV.dpr, 0, 0);
  ctx.clearRect(0, 0, GV.W, GV.H);
  ctx.fillStyle = "#05070e"; ctx.fillRect(0, 0, GV.W, GV.H);
  // estrelas
  ctx.fillStyle = "#cfe0f5";
  for (const st of GV.stars) { ctx.globalAlpha = st.a; ctx.beginPath(); ctx.arc(st.x, st.y, st.r, 0, 6.283); ctx.fill(); }
  ctx.globalAlpha = 1;
  const neigh = GV.hover ? (GV.adj[GV.hover.id] || new Set()) : null;
  // arestas
  for (const e of GV.edges) {
    const a = GV.byId[e.source], b = GV.byId[e.target];
    if (!a || !b) continue;
    const A = w2s(a), B = w2s(b);
    const hot = GV.hover && (e.source === GV.hover.id || e.target === GV.hover.id);
    const warm = a.kind === "gateway" || b.kind === "gateway";
    ctx.strokeStyle = hot ? "rgba(120,200,255,0.55)" : warm ? `rgba(245,177,59,${GV.linkOp * 0.7})` : `rgba(150,170,200,${GV.linkOp})`;
    ctx.lineWidth = hot ? 1.4 : 0.7;
    ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.lineTo(B.x, B.y); ctx.stroke();
  }
  // nos
  for (const nd of GV.nodes) {
    const S = w2s(nd), r = Math.max(2, nd.r * GV.nodeSize * GV.scale);
    const dim = GV.hover && nd !== GV.hover && !(neigh && neigh.has(nd.id));
    ctx.globalAlpha = dim ? 0.35 : 1;
    ctx.shadowColor = nd.color;
    ctx.shadowBlur = (nd.kind === "service" ? 8 : 16) * GV.glow * Math.min(1.5, GV.scale);
    ctx.beginPath(); ctx.arc(S.x, S.y, r, 0, 6.283);
    ctx.fillStyle = nd.color; ctx.fill();
    ctx.shadowBlur = 0;
    if (nd.kind !== "service") { ctx.lineWidth = 1.8; ctx.strokeStyle = "rgba(255,255,255,0.7)"; ctx.stroke(); }
    if (nd === GV.hover) { ctx.lineWidth = 2; ctx.strokeStyle = "#fff"; ctx.beginPath(); ctx.arc(S.x, S.y, r + 3, 0, 6.283); ctx.stroke(); }
    ctx.globalAlpha = 1;
  }
  // rotulos (so hubs, gateway, dispositivos com zoom, e o hover)
  ctx.textAlign = "center"; ctx.textBaseline = "top";
  for (const nd of GV.nodes) {
    const mostrar = nd === GV.hover || nd.hub || (nd.kind === "device" && GV.scale > 1.35);
    if (!mostrar) continue;
    const S = w2s(nd), r = Math.max(2, nd.r * GV.nodeSize * GV.scale);
    const fs = nd.kind === "gateway" ? 13 : nd.kind === "device" ? 12 : 11;
    ctx.font = (nd.hub || nd === GV.hover ? "600 " : "") + fs + "px system-ui, sans-serif";
    const lab = nd.label.length > 24 ? nd.label.slice(0, 22) + "…" : nd.label;
    ctx.shadowColor = "rgba(0,0,0,0.9)"; ctx.shadowBlur = 4;
    ctx.fillStyle = nd.kind === "device" ? "#eaf1f8" : "rgba(210,222,238,0.92)";
    ctx.fillText(lab, S.x, S.y + r + 4);
    ctx.shadowBlur = 0;
  }
}
function gvLoop() {
  if (!GV.started) return;
  const energy = gvStep();
  gvDraw();
  if (energy < 0.5 && !GV.drag && !GV.pan) GV.idle = (GV.idle || 0) + 1; else GV.idle = 0;
  if (GV.idle > 40) { GV.started = false; return; }
  requestAnimationFrame(gvLoop);
}
function gvKick() { if (!GV.started) { GV.started = true; GV.idle = 0; requestAnimationFrame(gvLoop); } }
function gvHit(px, py) {
  for (let i = GV.nodes.length - 1; i >= 0; i--) {
    const nd = GV.nodes[i], S = w2s(nd);
    if (Math.hypot(S.x - px, S.y - py) <= Math.max(6, nd.r * GV.nodeSize * GV.scale) + 4) return nd;
  }
  return null;
}
function gvLocal(ev) { const r = GV.canvas.getBoundingClientRect(); return { x: ev.clientX - r.left, y: ev.clientY - r.top }; }
function gvWheel(ev) {
  ev.preventDefault();
  const p = gvLocal(ev), before = s2w(p.x, p.y);
  GV.scale = Math.max(0.25, Math.min(3.5, GV.scale * (ev.deltaY < 0 ? 1.12 : 0.9)));
  GV.ox = p.x - before.x * GV.scale; GV.oy = p.y - before.y * GV.scale;
  gvKick(); gvDraw();
}
function gvDown(ev) {
  const p = gvLocal(ev), hit = gvHit(p.x, p.y);
  GV.moved = false;
  if (hit) GV.drag = hit; else GV.pan = { x: p.x, y: p.y, ox: GV.ox, oy: GV.oy };
  gvKick();
}
function gvMove(ev) {
  if (!GV.canvas) return;
  const p = gvLocal(ev);
  if (GV.drag) { const w = s2w(p.x, p.y); GV.drag.x = w.x; GV.drag.y = w.y; GV.drag.vx = 0; GV.drag.vy = 0; GV.moved = true; gvKick(); }
  else if (GV.pan) { GV.ox = GV.pan.ox + (p.x - GV.pan.x); GV.oy = GV.pan.oy + (p.y - GV.pan.y); GV.moved = true; gvDraw(); }
  else { const h = gvHit(p.x, p.y); if (h !== GV.hover) { GV.hover = h; GV.canvas.style.cursor = h ? "pointer" : "grab"; gvDraw(); } }
}
function gvUp() {
  if (GV.drag && !GV.moved) gvInspect(GV.drag);
  else if (GV.pan && !GV.moved) { const inf = $("#grafo-info"); if (inf) inf.classList.add("oculto"); }
  GV.drag = null; GV.pan = null;
}
function gvInspect(n) { if (n.kind === "device") abrirDetalhe(n.id); else mostrarNo(n); }

async function carregarGrafo() {
  try {
    const data = await apiGet("/api/graph?limit=40");
    if (!GV.ctx) gvInit();
    gvSetData(data);
  } catch (e) { console.error("grafo", e); }
}

function mostrarNo(n) {
  const info = $("#grafo-info"), m = n.meta || {};
  let corpo = "";
  if (n.kind === "service") {
    corpo = `<div class="gi-linha"><span class="chip">${esc(m.categoria || "")}</span> <strong>${m.conexoes || 0}</strong> conexões</div>
      <div class="gi-sec mono">hosts reais</div><div class="gi-hosts mono">${(m.hosts || []).map(esc).join("<br>") || "—"}</div>
      <div class="gi-sec mono">dispositivos</div><div class="mono">${(m.dispositivos || []).map(esc).join(", ") || "—"}</div>`;
  } else if (n.kind === "gateway") {
    corpo = `<div class="gi-linha">Roteador / rede local — ${m.dispositivos || 0} dispositivos.</div>
      <div class="gi-sec mono">dica</div><div class="mono">scroll = zoom · arraste os nós · clique num dispositivo pra ver detalhes.</div>`;
  }
  info.innerHTML = `<div class="gi-cab"><span class="gi-nome">${esc(n.label)}</span><button class="btn-fechar" id="gi-fechar" title="Fechar">✕</button></div>${corpo}`;
  info.classList.remove("oculto");
  const f = $("#gi-fechar");
  if (f) f.addEventListener("click", () => info.classList.add("oculto"));
}

// ----------------------- resumo (chart + tops) -----------------------
async function carregarResumo() {
  try {
    const [tl, dom, apps] = await Promise.all([
      apiGet("/api/timeline?hours=24"),
      apiGet("/api/top?kind=domains&hours=24&limit=8"),
      apiGet("/api/top?kind=apps&hours=24&limit=8"),
    ]);
    renderChart(tl);
    renderTop($("#top-domains"), dom);
    renderTop($("#top-apps"), apps);
  } catch (e) { console.error("resumo", e); }
}

function renderChart(tl) {
  const host = $("#chart");
  if (!tl || !tl.length) { host.innerHTML = '<p class="vazio">Sem dados ainda.</p>'; return; }
  const W = 520, H = 120, pad = 8, n = tl.length;
  const maxV = Math.max(1, ...tl.map((b) => Math.max(b.flows || 0, b.dns || 0)));
  const px = (i) => (n === 1 ? W / 2 : pad + (i * (W - 2 * pad)) / (n - 1));
  const py = (v) => H - pad - ((v || 0) / maxV) * (H - 2 * pad);
  const linha = (k) => tl.map((b, i) => `${px(i).toFixed(1)},${py(b[k]).toFixed(1)}`).join(" ");
  const area = (k) => `${pad.toFixed(1)},${(H - pad).toFixed(1)} ${linha(k)} ${px(n - 1).toFixed(1)},${(H - pad).toFixed(1)}`;
  host.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" width="100%" height="120" preserveAspectRatio="none" class="chart-svg">
      <polygon points="${area("flows")}" fill="rgba(45,212,191,0.14)" />
      <polyline points="${linha("flows")}" fill="none" stroke="var(--teal)" stroke-width="1.6" />
      <polygon points="${area("dns")}" fill="rgba(245,158,11,0.10)" />
      <polyline points="${linha("dns")}" fill="none" stroke="var(--amb)" stroke-width="1.6" />
    </svg>`;
}

function renderTop(host, itens) {
  if (!itens || !itens.length) { host.innerHTML = '<p class="vazio">Sem dados.</p>'; return; }
  const max = Math.max(1, ...itens.map((i) => i.total || 0));
  host.innerHTML = itens.map((i) => `
    <div class="top-item">
      <div class="top-barra" style="width:${Math.round((100 * (i.total || 0)) / max)}%"></div>
      <span class="top-label" title="${esc(i.label)}">${esc(i.label || "—")}</span>
      <span class="top-total mono">${i.total ?? 0}</span>
    </div>`).join("");
}

// ----------------------- lista de dispositivos -----------------------
async function carregarDevices() {
  try { estado.devices = await apiGet("/api/devices"); renderDevices(); atualizarNivel(); }
  catch (e) { console.error("devices", e); $("#lista-devices").innerHTML = '<p class="vazio">Falha ao carregar.</p>'; }
}

function chipTrust(e_) {
  const s = (e_ || "unknown").toLowerCase();
  const rot = { unknown: "desconhecido", trusted: "confiável", quarantine: "quarentena" };
  const cls = ["unknown", "trusted", "quarantine"].includes(s) ? s : "unknown";
  return `<span class="chip chip-${cls}">${esc(rot[cls] || cls)}</span>`;
}

function casaFiltro(d, termo) {
  if (!termo) return true;
  return [d.mac, d.mac_vendor, d.hostname, d.ip4, d.ip6, d.label].filter(Boolean).join(" ").toLowerCase().includes(termo);
}

function renderDevices() {
  const cont = $("#lista-devices");
  const termo = estado.filtro.trim().toLowerCase();
  const lista = estado.devices.filter((d) => casaFiltro(d, termo));
  lista.sort((a, b) => {
    const ua = a.trust_state === "unknown" ? 0 : 1, ub = b.trust_state === "unknown" ? 0 : 1;
    if (ua !== ub) return ua - ub;
    return String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
  });
  if (!lista.length) { cont.innerHTML = '<p class="vazio">Nenhum dispositivo.</p>'; return; }
  cont.innerHTML = "";
  for (const d of lista) {
    const card = el("div", "device dev-" + ((d.trust_state || "unknown")));
    card.dataset.id = d.id;
    if (d.id === estado.selecionado) card.classList.add("ativo");
    const nome = d.label || d.hostname || d.mac || d.id;
    card.innerHTML = `
      <div class="device-linha1"><span class="device-nome">${esc(nome)}</span>${chipTrust(d.trust_state)}</div>
      <div class="device-linha2 mono"><span title="MAC">${esc(d.mac || "—")}</span><span title="IPv4">${esc(d.ip4 || "—")}</span></div>
      <div class="device-linha3"><span class="device-vendor">${esc(d.mac_vendor || "fabricante desconhecido")}</span><span class="device-visto mono">${hora(d.last_seen)}</span></div>`;
    card.addEventListener("click", () => abrirDetalhe(d.id));
    cont.appendChild(card);
  }
}

// Nivel de seguranca da rede (assinatura): verde/ambar/vermelho conforme os estados.
function atualizarNivel() {
  const secao = $("#nivel-rede"); if (!secao) return;
  const devs = estado.devices || [];
  const q = devs.filter((d) => d.trust_state === "quarantine").length;
  const u = devs.filter((d) => (d.trust_state || "unknown") === "unknown").length;
  const t = devs.filter((d) => d.trust_state === "trusted").length;
  let nivel = "", titulo = "Avaliando rede…", sub = "mapeando dispositivos e tráfego";
  if (q > 0) { nivel = "nr-alert"; titulo = "Alerta"; sub = `${q} em quarentena · ${u} não classificado${u === 1 ? "" : "s"}`; }
  else if (u > 0) { nivel = "nr-warn"; titulo = "Atenção"; sub = `${u} dispositivo${u === 1 ? "" : "s"} desconhecido${u === 1 ? "" : "s"} — classifique como confiável ou marque`; }
  else if (devs.length) { nivel = "nr-safe"; titulo = "Rede segura"; sub = `todos os ${t} dispositivos são confiáveis`; }
  secao.classList.remove("nr-safe", "nr-warn", "nr-alert");
  if (nivel) secao.classList.add(nivel);
  $("#nr-titulo").textContent = titulo;
  $("#nr-sub").textContent = sub;
}

// ----------------------- feed ao vivo (WS) -----------------------
let ws = null, reconexaoMs = 1000;
const MAX_FEED = 200;

function conectarWS() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  try { ws = new WebSocket(U("api/live").replace(/^http/, "ws")); }
  catch (e) { agendarReconexao(); return; }
  ws.onopen = () => { reconexaoMs = 1000; marcarWS(true); };
  ws.onmessage = (ev) => { let m; try { m = JSON.parse(ev.data); } catch { return; } if (m && m.kind) appendFeed(m); };
  ws.onclose = () => { marcarWS(false); agendarReconexao(); };
  ws.onerror = () => { try { ws.close(); } catch {} };
}
function agendarReconexao() { marcarWS(false); setTimeout(conectarWS, reconexaoMs); reconexaoMs = Math.min(reconexaoMs * 2, 15000); }
function marcarWS(on) { const s = $("#status-ws"); s.textContent = on ? "● ao vivo" : "● offline"; s.classList.toggle("conectado", on); s.classList.toggle("desconectado", !on); }

function descreveMsg(msg) {
  const p = msg.payload || {};
  switch (msg.kind) {
    case "device": return { icone: "◈", titulo: "Dispositivo", texto: `${esc(p.hostname || p.mac || p.id || "novo")} — ${esc(p.mac_vendor || "")}`, sev: "info", ts: p.last_seen || p.first_seen };
    case "dns": return { icone: "⌘", titulo: p.blocked ? "DNS bloqueado" : "DNS", texto: `${esc(p.qname || "")} ${p.qtype ? "(" + esc(p.qtype) + ")" : ""}`, sev: p.blocked ? "warning" : "info", ts: p.ts };
    case "flow": return { icone: "⇄", titulo: "Conexão", texto: `${p.app_proto ? esc(p.app_proto) + " → " : ""}${esc(p.sni || p.dst_ip || "")}${p.dst_port ? ":" + esc(p.dst_port) : ""} ${esc(p.proto || "")}`, sev: "info", ts: p.ts };
    case "event": return { icone: "⚑", titulo: esc(p.title || p.type || "Evento"), texto: esc(p.detail || ""), sev: (p.severity || "info").toLowerCase(), ts: p.ts };
    default: return { icone: "•", titulo: esc(msg.kind), texto: "", sev: "info", ts: null };
  }
}

function appendFeed(msg) {
  if (msg.kind === "device") { carregarDevices(); carregarStats(); }
  if (msg.kind === "event") carregarStats();
  if ((msg.kind === "dns" || msg.kind === "flow") && msg.payload && msg.payload.device_id === estado.selecionado) {
    const lst = $("#live-lista");
    if (lst) {
      const v = lst.querySelector(".vazio"); if (v) v.remove();
      const p = msg.payload, host = msg.kind === "dns" ? p.qname : (p.sni || p.dst_ip);
      if (hostValido(host)) { lst.insertAdjacentHTML("afterbegin", liveRowHtml(msg.kind, host, p.ts || new Date().toISOString())); while (lst.children.length > 80) lst.removeChild(lst.lastChild); }
    }
  }
  if (!estado.filtrosFeed[msg.kind]) return;
  const feed = $("#feed");
  const vazio = feed.querySelector(".vazio");
  if (vazio) vazio.remove();
  const d = descreveMsg(msg);
  const item = el("div", `feed-item sev-${d.sev}`);
  item.innerHTML = `<span class="feed-icone">${d.icone}</span>
    <div class="feed-conteudo">
      <div class="feed-titulo">${d.titulo}<span class="feed-hora mono">${hora(d.ts || new Date().toISOString())}</span></div>
      <div class="feed-texto mono">${d.texto}</div>
    </div>`;
  feed.prepend(item);
  while (feed.children.length > MAX_FEED) feed.removeChild(feed.lastChild);
}

// ----------------------- detalhe do dispositivo -----------------------
async function abrirDetalhe(id) {
  estado.selecionado = id;
  renderDevices();
  const aside = $("#detalhe");
  aside.classList.remove("oculto");
  aside.setAttribute("aria-hidden", "false");
  $("#detalhe-corpo").innerHTML = '<p class="vazio">Carregando…</p>';
  try {
    const [dev, flows, dns] = await Promise.all([
      apiGet(`/api/devices/${encodeURIComponent(id)}`),
      apiGet(`/api/flows?device_id=${encodeURIComponent(id)}&limit=50`),
      apiGet(`/api/dns?device_id=${encodeURIComponent(id)}&limit=50`),
    ]);
    renderDetalhe(dev, flows, dns);
  } catch (e) { console.error("detalhe", e); $("#detalhe-corpo").innerHTML = '<p class="vazio">Falha ao carregar.</p>'; }
}

function fecharDetalhe() {
  const aside = $("#detalhe");
  aside.classList.add("oculto");
  aside.setAttribute("aria-hidden", "true");
  estado.selecionado = null;
  renderDevices();
}

function linhaProp(rot, val) {
  return `<div class="prop"><span class="prop-rotulo mono">${esc(rot)}</span><span class="prop-valor">${val}</span></div>`;
}

// nomes amigaveis (versao leve do services.py, para o painel ao vivo)
const _FRULES = [
  ["anthropic", "Claude", "IA"], ["claude.ai", "Claude", "IA"], ["openai", "ChatGPT", "IA"], ["chatgpt", "ChatGPT", "IA"],
  ["googlevideo", "YouTube", "Streaming"], ["youtube", "YouTube", "Streaming"], ["ytimg", "YouTube", "Streaming"],
  ["netflix", "Netflix", "Streaming"], ["nflxvideo", "Netflix", "Streaming"], ["spotify", "Spotify", "Streaming"], ["twitch", "Twitch", "Streaming"],
  ["whatsapp", "WhatsApp", "Mensagens"], ["telegram", "Telegram", "Mensagens"],
  ["instagram", "Instagram", "Social"], ["cdninstagram", "Instagram", "Social"], ["facebook", "Facebook", "Social"], ["fbcdn", "Facebook", "Social"], ["tiktok", "TikTok", "Social"], ["twimg", "X", "Social"], ["twitter", "X", "Social"],
  ["github", "GitHub", "Dev"], ["duckduckgo", "DuckDuckGo", "Busca"],
  ["doubleclick", "Anúncios", "Publicidade"], ["googlesyndication", "Anúncios", "Publicidade"], ["adservice", "Anúncios", "Publicidade"], ["scorecardresearch", "Anúncios", "Publicidade"], ["crashlytics", "Telemetria", "Publicidade"],
  ["gstatic", "Google", "Google"], ["googleapis", "Google", "Google"], ["google", "Google", "Google"],
  ["windowsupdate", "Windows Update", "Microsoft"], ["office", "Microsoft 365", "Microsoft"], ["microsoft", "Microsoft", "Microsoft"], ["azure", "Azure", "Nuvem"], ["bing", "Bing", "Microsoft"],
  ["icloud", "iCloud", "Apple"], ["mzstatic", "Apple", "Apple"], ["apple", "Apple", "Apple"],
  ["cloudfront", "Amazon CloudFront", "CDN"], ["amazonaws", "Amazon AWS", "Nuvem"], ["media-amazon", "Amazon", "Nuvem"], ["a2z.com", "Amazon / Alexa", "Nuvem"], ["amazon", "Amazon", "Nuvem"],
  ["akamai", "Akamai", "CDN"], ["cloudflare", "Cloudflare", "Infra"], ["fastly", "Fastly", "CDN"], ["firebase", "Firebase", "Nuvem"],
  ["ntp", "Relógio (NTP)", "Sistema"], ["fortinet", "Fortinet VPN", "Sistema"], ["fortiguard", "Fortinet VPN", "Sistema"],
];
function friendlyJS(host) {
  if (!host) return { name: "?", cat: "Outro" };
  const h = String(host).toLowerCase().replace(/\.$/, "");
  const ehIP = /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(":");
  for (const [k, n, c] of _FRULES) if (h.includes(k)) return { name: n, cat: c };
  if (ehIP) return { name: "IP " + host, cat: "Desconhecido" };
  const parts = h.split(".");
  const reg = parts.length >= 2 ? parts[parts.length - 2] : h;
  return { name: reg.charAt(0).toUpperCase() + reg.slice(1), cat: "Outro" };
}
function hostValido(h) { if (!h) return false; const x = String(h).toLowerCase(); if (x.includes(":")) return false; if (/^[0-9.]+$/.test(x)) return false; if (!x.includes(".")) return false; if (x.endsWith(".arpa") || x.endsWith(".local") || x.endsWith(".home") || x.endsWith(".lan")) return false; return true; }
function liveRowHtml(kind, host, ts) {
  const fr = friendlyJS(host), cor = CAT_COR[fr.cat] || "#64748b";
  const tag = kind === "dns" ? "consultou" : "conectou";
  return `<div class="live-row"><span class="live-dot" style="color:${cor};background:${cor}"></span>
    <div class="live-mid"><span class="live-nome">${esc(fr.name)}</span><span class="live-host mono">${tag} · ${esc(host)}</span></div>
    <span class="live-hora mono">${hora(ts)}</span></div>`;
}
function mesclarLive(flows, dns) {
  const rows = [];
  (flows || []).forEach((f) => { const h = f.sni || f.dst_ip; if (hostValido(h)) rows.push({ ts: f.ts, kind: "flow", host: h }); });
  (dns || []).forEach((q) => { if (hostValido(q.qname)) rows.push({ ts: q.ts, kind: "dns", host: q.qname }); });
  rows.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
  return rows.slice(0, 50).map((r) => liveRowHtml(r.kind, r.host, r.ts)).join("");
}

function renderDetalhe(dev, flows, dns) {
  if (!dev) { $("#detalhe-corpo").innerHTML = '<p class="vazio">Não encontrado.</p>'; return; }
  $("#detalhe-titulo").textContent = dev.label || dev.hostname || dev.mac || dev.id;
  const id = dev.id;
  const box = estado.readonly ? '<p class="intercept-aviso">🔒 Modo somente leitura (rede não-confiável) — interceptação desabilitada.</p>' : dev.ip4 ? `
    <div class="int-box">
      <button class="btn-int" id="btn-intercept">▶ Interceptar tráfego ao vivo</button>
      <span class="intercept-status mono" id="intercept-status"></span>
      <p class="intercept-aviso">Vê em tempo real o que este aparelho acessa (ARP). Ativo e detectável · auto-desliga em 3 min · restaura sozinho · só na sua rede.</p>
    </div>` : `<p class="intercept-aviso">Sem IPv4 conhecido — ainda não dá pra interceptar.</p>`;
  const liveInit = mesclarLive(flows, dns);
  const info = `<div class="detalhe-secao">
    ${linhaProp("mac", esc(dev.mac || "—"))}${linhaProp("fabricante", esc(dev.mac_vendor || "—"))}
    ${linhaProp("ipv4", esc(dev.ip4 || "—"))}${linhaProp("ipv6", esc(dev.ip6 || "—"))}
    ${linhaProp("confiança", chipTrust(dev.trust_state))}${linhaProp("último visto", hora(dev.last_seen))}
  </div>`;
  const acoes = `<div class="acoes">
      <button class="btn btn-trusted" data-trust="trusted">Confiável</button>
      <button class="btn btn-unknown" data-trust="unknown">Desconhecido</button>
      <button class="btn btn-quarantine" data-trust="quarantine">Quarentena</button>
    </div>
    <div class="acao-label"><input id="in-label" class="busca" placeholder="rótulo (ex.: TV da sala)" value="${esc(dev.label || "")}" /><button class="btn" id="btn-label">Salvar</button></div>`;
  $("#detalhe-corpo").innerHTML = `${box}
    <div class="live-cab"><h3 class="detalhe-h3">Acessando agora</h3><span class="live-tag" id="live-tag">● tempo real</span></div>
    <div class="live-lista" id="live-lista">${liveInit || '<p class="vazio">Nada capturado ainda — clique em interceptar e interaja com o aparelho.</p>'}</div>
    <h3 class="detalhe-h3">Dados do dispositivo</h3>${info}
    <h3 class="detalhe-h3">Classificação</h3>${acoes}`;
  $("#detalhe-corpo").querySelectorAll("[data-trust]").forEach((b) =>
    b.addEventListener("click", async () => { if (await mutarDevice(id, { trust_state: b.dataset.trust })) { await carregarDevices(); abrirDetalhe(id); } }));
  const bl = $("#btn-label");
  if (bl) bl.addEventListener("click", async () => { if (await mutarDevice(id, { label: $("#in-label").value.trim() })) { await carregarDevices(); abrirDetalhe(id); } });
  const bi = $("#btn-intercept");
  if (bi) { bi.addEventListener("click", () => toggleIntercept(id)); atualizarInterceptStatus(id); }
}

let _interceptTimer = null;
async function toggleIntercept(id) {
  const t = getToken(); if (!t) return;
  let ativo = false;
  try { const st = await apiGet("/api/intercept"); ativo = (st.ativos || []).some((a) => a.device_id === id); } catch (e) {}
  const r = await fetch(U(`/api/intercept/${encodeURIComponent(id)}`), { method: "POST", headers: { "Content-Type": "application/json", "X-Sentinela-Token": t }, body: JSON.stringify({ enabled: !ativo }) });
  if (r.status === 401) { localStorage.removeItem("sentinela_token"); alert("Token inválido."); return; }
  const res = await r.json().catch(() => ({}));
  if (res && res.ok === false) { alert("Não deu: " + (res.erro || "?")); return; }
  setTimeout(() => atualizarInterceptStatus(id), 400);
}
async function atualizarInterceptStatus(id) {
  const el2 = $("#intercept-status"), btn = $("#btn-intercept");
  if (!el2 || !btn) { if (_interceptTimer) { clearInterval(_interceptTimer); _interceptTimer = null; } return; }
  let a = null;
  try { const st = await apiGet("/api/intercept"); a = (st.ativos || []).find((x) => x.device_id === id); } catch (e) {}
  if (a) {
    el2.textContent = "● interceptando · " + a.restante_s + "s";
    btn.textContent = "■ Parar interceptação"; btn.classList.add("on");
    if (!_interceptTimer) _interceptTimer = setInterval(() => atualizarInterceptStatus(id), 3000);
  } else {
    el2.textContent = ""; btn.textContent = "▶ Interceptar tráfego ao vivo"; btn.classList.remove("on");
    if (_interceptTimer) { clearInterval(_interceptTimer); _interceptTimer = null; }
  }
}

// ----------------------- init -----------------------
function init() {
  $("#busca").addEventListener("input", (e) => { estado.filtro = e.target.value; renderDevices(); });
  $("#feed-filtros").querySelectorAll("input[type=checkbox]").forEach((cb) =>
    cb.addEventListener("change", () => { estado.filtrosFeed[cb.dataset.kind] = cb.checked; }));
  $("#btn-sniffer").addEventListener("click", toggleSniffer);
  const ga = $("#grafo-atualizar");
  if (ga) ga.addEventListener("click", carregarGrafo);
  $("#detalhe-fechar").addEventListener("click", fecharDetalhe);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") fecharDetalhe(); });

  carregarHealth();
  carregarStats();
  carregarControl();
  carregarDevices();
  carregarResumo();
  carregarGrafo();
  conectarWS();

  setInterval(carregarStats, 30000);
  setInterval(carregarResumo, 30000);
  setInterval(carregarGrafo, 30000);
  setInterval(carregarControl, 15000);
}

document.addEventListener("DOMContentLoaded", init);
