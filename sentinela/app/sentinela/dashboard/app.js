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
  filtroDev: "ativos", aba: "conexoes", trafego: { conexoes: [], volume: [], dns: [] },
  trafegoDev: "", trafegoBusca: "", grafoHoras: 168, view: "geral",
};

// ----------------------- navegação por seções -----------------------
function mostrarView(v) {
  estado.view = v;
  try { localStorage.setItem("sentinela_view", v); } catch (e) {}
  document.querySelectorAll("#nav-views .nav-v").forEach((b) => b.classList.toggle("ativa", b.dataset.view === v));
  document.querySelectorAll("[data-views]").forEach((n) => {
    const some = !n.dataset.views.split(" ").includes(v);
    n.classList.toggle("fora-da-view", some);
  });
  document.body.dataset.view = v;
  if (v === "mapa") { if (!GV.ctx) carregarGrafo(); else { gvResize(); gvFit(); gvDraw(); } }
  window.scrollTo(0, 0);
}

// ----------------------- formatação / identificação -----------------------
const KIND_ICON = { router: "🌐", server: "🗄️", computer: "💻", phone: "📱", tablet: "📱", watch: "⌚",
  tv: "📺", console: "🎮", speaker: "🔊", printer: "🖨️", camera: "📷", iot: "💡", unknown: "❔" };

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1).replace(".", ",") + " " + u[i];
}

function haQuanto(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "—";
  const s2 = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s2 < 90) return "agora";
  if (s2 < 3600) return "há " + Math.round(s2 / 60) + " min";
  if (s2 < 86400) return "há " + Math.round(s2 / 3600) + " h";
  return "há " + Math.round(s2 / 86400) + " d";
}

function devPorId(id) { return estado.devices.find((d) => d.id === id) || (estado.todosDevs || []).find((d) => d.id === id); }
function nomeDev(id, fallback) { const d = devPorId(id); return d ? (d.display_name || d.label || d.hostname || d.mac) : (fallback || "?"); }
function iconeDev(d) { return KIND_ICON[(d && d.kind) || "unknown"] || "❔"; }
function corCat(cat) { return CAT_COR[cat] || "#64748b"; }

// Cores por categoria de serviço (grafo) e por confiança (dispositivos).
const CAT_COR = {
  IA: "#a78bfa", Google: "#60a5fa", Microsoft: "#2dd4bf", Apple: "#cbd5e1",
  Social: "#f472b6", Mensagens: "#4ade80", Streaming: "#fb7185", Busca: "#818cf8",
  Nuvem: "#fbbf24", Infra: "#fbbf24", CDN: "#fbbf24", Publicidade: "#ef4444",
  Dev: "#38bdf8", Jogos: "#f59e0b", Bancos: "#34d399", Compras: "#fb923c", Estudo: "#c084fc", IoT: "#22d3ee", Sistema: "#94a3b8", Desconhecido: "#64748b", Outro: "#64748b",
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
    renderCaptura(h.capture);
  } catch (e) { console.error("health", e); }
}

// Barra com o que o sensor está de fato enxergando (contadores desde o início).
function renderCaptura(c) {
  const bar = $("#captura-bar"); if (!bar) return;
  const res = $("#captura-resumo");
  if (!c) { bar.innerHTML = '<span class="mudo">A captura não está ativa: só há inventário.</span>'; if (res) res.textContent = "· inativa"; return; }
  const st = c.stats || {};
  const item = (rot, v, tit) => `<span class="cap-item" title="${esc(tit || "")}"><b>${Number(v || 0).toLocaleString("pt-BR")}</b> ${rot}</span>`;
  if (res) res.textContent = `· ${c.filtro === "rico" ? "completa" : "reduzida"} · ${Number(st.erros || 0)} erros · interface ${c.iface || "?"}`;
  bar.innerHTML =
    item("sites identificados", st.tls, "inícios de conexão segura em que o nome do site foi lido") +
    item("consultas de nome", st.dns, "consultas DNS distintas") +
    item("conexões de vídeo/app rápidas", st.quic, "inícios de conexão HTTP/3 (QUIC)") +
    item("páginas sem criptografia", st.http, "requisições HTTP em texto claro") +
    item("conexões com volume medido", st.tcp_fechadas, "conexões TCP encerradas") +
    item("conexões em andamento", c.conexoes_abertas, "conexões TCP abertas agora") +
    item("aparelhos que se apresentaram", st.dhcp, "pedidos DHCP com nome/sistema") +
    item("conexões vindas de fora", st.entrada, "tentativas iniciadas da internet para dentro") +
    item("volumes descartados", st.volume_descartado, "medições impossíveis ignoradas");
}

async function carregarStats() {
  try {
    const s = await apiGet("/api/stats");
    $("#stat-dns").textContent = Number(s.dns_24h || 0).toLocaleString("pt-BR");
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

// ----------------------- mapa da rede (constelação) -----------------------
// Layout radial estruturado (sem hairball): gateway no centro, dispositivos num
// anel interno agrupados por tipo, serviços em setores por categoria no anel
// externo. Arestas ficam ocultas em repouso e só ACENDEM ao focar (hover/clique)
// um nó — o que resolve o emaranhado de linhas.
const GV = { canvas: null, ctx: null, dpr: 1, W: 0, H: 0, nodes: [], edges: [], byId: {},
  adj: {}, stars: [], scale: 1, ox: 0, oy: 0, pan: null, press: null, moved: false,
  hover: null, fixo: null, started: false, t: 0,
  glow: 0.8, nodeSize: 1, orb: 1, devLabels: [], catLabels: [], center: null };
window.__GV = GV;
window.__abrir = (id) => abrirDetalhe(id);

// Grupos de dispositivos (anel interno) + cor de cada setor.
const GV_GRUPOS = ["Rede", "Computadores", "Celulares", "TV & Mídia", "Voz", "IoT", "Outros"];
const GV_GRUPO_COR = { Rede: "#f5b13b", Computadores: "#5eb1ef", Celulares: "#3ecf8e",
  "TV & Mídia": "#fb7185", Voz: "#a78bfa", IoT: "#2dd4bf", Outros: "#8aa0b6" };

function gvGrupo(n) {
  if (n.group && GV_GRUPOS.includes(n.group)) return n.group;   // tipo já identificado pela API
  const s = ((n.label || "") + " " + ((n.meta && n.meta.fabricante) || "")).toLowerCase();
  if (/twibi|modem|roteador|raspberry|\bpi\b|sentinela|gateway|intelbras|huawei|ubiquiti|mikrotik|tp-?link/.test(s)) return "Rede";
  if (/\bpc\b|macbook|\basus\b|omen|notebook|computador|laptop|desktop|imac|dell|lenovo/.test(s)) return "Computadores";
  if (/iphone|android|\bwatch\b|celular|galaxy|xiaomi|pixel|dona|tania|tablet|ipad/.test(s)) return "Celulares";
  if (/\btv\b|firetv|fire tv|chromecast|receiver|harman|\bps4\b|\bps5\b|playstation|xbox|roku|apple ?tv|soundbar/.test(s)) return "TV & Mídia";
  if (/alexa|echo|nest|google home|homepod/.test(s)) return "Voz";
  if (/shelly|positivo|creality|controle|sensor|\besp\b|tuya|iot|lâmpada|lampada|plug|tomada|impressora|printer/.test(s)) return "IoT";
  return "Outros";
}
// Esconde nós internos do Home Assistant (rede docker 172.30.x).
function gvInterno(n) {
  const ip = (n.meta && n.meta.ipv4) || "", lab = (n.label || "").toLowerCase();
  return (ip && ip.startsWith("172.30.")) || lab.includes("ha interno") || lab.includes("hass.io");
}
function gvColor(n) {
  if (n.kind === "gateway") return "#f5b13b";
  if (n.kind === "device") return TRUST_COR[n.trust_state] || "#8aa0b6";
  return CAT_COR[n.category] || "#7c8aa0";
}
function gvBaseR(n) {
  if (n.kind === "gateway") return 16;
  if (n.kind === "device") return 8.5;
  return 5 + Math.min(10, Math.sqrt(n.count || 1) * 1.6);
}
// "respiração": nós oscilam de leve (amplitude ~2px) em fases distintas — vivo, sem embolar.
function w2s(n) {
  const wob = n.ph != null ? Math.sin(GV.t + n.ph) * 2.0 : 0;
  return { x: n.bx * GV.scale + GV.ox, y: (n.by + wob) * GV.scale + GV.oy };
}
function s2w(px, py) { return { x: (px - GV.ox) / GV.scale, y: (py - GV.oy) / GV.scale }; }
function gvFoco() { return GV.fixo || GV.hover; }

function gvResize() {
  const rect = GV.canvas.parentElement.getBoundingClientRect();
  GV.dpr = window.devicePixelRatio || 1;
  GV.W = Math.max(320, Math.floor(rect.width || document.documentElement.clientWidth || 900));
  GV.H = 580;
  GV.canvas.width = GV.W * GV.dpr;
  GV.canvas.height = GV.H * GV.dpr;
  GV.canvas.style.height = GV.H + "px";
  gvMakeStars();
  gvLayout(); gvFit(); gvDraw();
}
function gvMakeStars() {
  const n = Math.floor((GV.W * GV.H) / 6000);
  GV.stars = [];
  for (let k = 0; k < n; k++) {
    GV.stars.push({ x: Math.random() * GV.W, y: Math.random() * GV.H, r: Math.random() * 1.1 + 0.2, a: Math.random() * 0.5 + 0.12 });
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
  if (!GV._raf) gvAnim();
}
// Loop suave só pra "respiração" (rAF pausa sozinho quando a aba não está visível).
function gvAnim() {
  GV.t += 0.02;
  gvDraw();
  GV._raf = requestAnimationFrame(gvAnim);
}
function gvControls() {
  const bind = (id, prop, after) => {
    const el2 = document.getElementById(id);
    if (!el2) return;
    el2.addEventListener("input", () => { GV[prop] = parseFloat(el2.value); if (after) after(); gvDraw(); });
  };
  bind("gc-glow", "glow");
  bind("gc-size", "nodeSize");
  bind("gc-orb", "orb", () => { gvLayout(); gvFit(); });
  const rb = document.getElementById("gc-reset");
  if (rb) rb.addEventListener("click", () => { gvFit(); gvDraw(); });
}
function gvLayout() {
  if (!GV.nodes.length) return;
  const cx = GV.W / 2, cy = GV.H / 2;
  const Ri = Math.min(GV.W, GV.H) * 0.205 * GV.orb;  // anel de dispositivos
  const Ro = Math.min(GV.W, GV.H) * 0.60 * GV.orb;   // anel de serviços
  const gw = GV.nodes.find((n) => n.kind === "gateway");
  if (gw) { gw.bx = cx; gw.by = cy; }
  // dispositivos: agrupados por tipo em arcos contíguos
  const devs = GV.nodes.filter((n) => n.kind === "device");
  devs.sort((a, b) => GV_GRUPOS.indexOf(a.grp) - GV_GRUPOS.indexOf(b.grp));
  const nd = devs.length || 1;
  GV.devLabels = [];
  const gStart = {};
  devs.forEach((n, i) => {
    const ang = -Math.PI / 2 + (i / nd) * Math.PI * 2;
    n.ang = ang; n.bx = cx + Math.cos(ang) * Ri; n.by = cy + Math.sin(ang) * Ri;
    if (gStart[n.grp] === undefined) gStart[n.grp] = { a0: ang };
    gStart[n.grp].aN = ang;
  });
  for (const g of GV_GRUPOS) {
    const s = gStart[g]; if (!s) continue;
    const am = (s.a0 + s.aN) / 2;
    GV.devLabels.push({ txt: g.toUpperCase(), x: cx + Math.cos(am) * (Ri * 0.66), y: cy + Math.sin(am) * (Ri * 0.66), cor: GV_GRUPO_COR[g] });
  }
  // serviços: setores por categoria no anel externo ("Outro" por último)
  const svcs = GV.nodes.filter((n) => n.kind === "service");
  const cats = {}; svcs.forEach((n) => { (cats[n.category] = cats[n.category] || []).push(n); });
  const ehOutro = (k) => (k === "Outro" || k === "Desconhecido");
  const catKeys = Object.keys(cats).sort((a, b) => {
    if (ehOutro(a) !== ehOutro(b)) return ehOutro(a) ? 1 : -1;
    return cats[b].length - cats[a].length;
  });
  GV.catLabels = [];
  const ns2 = svcs.length || 1; let acc = 0;
  for (const c of catKeys) {
    const arr = cats[c], frac = arr.length / ns2, span = frac * Math.PI * 2;
    const a0 = -Math.PI / 2 + acc * Math.PI * 2, aCenter = a0 + span / 2;
    arr.forEach((n, j) => {
      const t = arr.length === 1 ? 0.5 : j / (arr.length - 1);
      const a = a0 + t * span * 0.86 + span * 0.07;
      const rr = Ro + ((j % 2) ? 18 : -6);
      n.ang = a; n.bx = cx + Math.cos(a) * rr; n.by = cy + Math.sin(a) * rr;
    });
    GV.catLabels.push({ txt: c.toUpperCase(), x: cx + Math.cos(aCenter) * (Ro + 52), y: cy + Math.sin(aCenter) * (Ro + 52),
      cor: CAT_COR[c] || "#7c8aa0", a0, span, cx, cy, Ro });
    acc += frac;
  }
  GV.center = { cx, cy, Ri, Ro };
}
function gvSetData(data) {
  const old = GV.byId || {};
  const raw = data.nodes || [];
  const skip = new Set();
  raw.forEach((n) => {
    if (n.kind === "device" && gvInterno(n)) skip.add(n.id);
    // ruído: serviço sem categoria e com 1 só acesso (aws-diagnostic, .arpa, etc.)
    if (n.kind === "service" && (n.category === "Outro" || n.category === "Desconhecido") && (n.count || 0) < 2) skip.add(n.id);
  });
  const nodes = raw.filter((n) => !skip.has(n.id)).map((n) => Object.assign({}, n, {
    grp: n.kind === "device" ? gvGrupo(n) : null, r: gvBaseR(n), color: gvColor(n),
    ph: (old[n.id] && old[n.id].ph != null) ? old[n.id].ph : (n.kind === "gateway" ? null : Math.random() * 6.283),
  }));
  GV.nodes = nodes;
  GV.byId = {}; nodes.forEach((n) => { GV.byId[n.id] = n; });
  GV.edges = (data.edges || []).filter((e) => !skip.has(e.source) && !skip.has(e.target) && GV.byId[e.source] && GV.byId[e.target]);
  GV.adj = {};
  for (const e of GV.edges) { (GV.adj[e.source] = GV.adj[e.source] || new Set()).add(e.target); (GV.adj[e.target] = GV.adj[e.target] || new Set()).add(e.source); }
  // hubs (rótulo sempre visível): gateway + top serviços por conexões
  const svc = nodes.filter((n) => n.kind === "service").sort((a, b) => (b.count || 0) - (a.count || 0));
  const hub = new Set(svc.slice(0, 6).map((n) => n.id));
  nodes.forEach((n) => { n.hub = (n.kind === "gateway" || hub.has(n.id)); });
  // preserva foco fixado entre atualizações
  if (GV.fixo) GV.fixo = GV.byId[GV.fixo.id] || null;
  GV.hover = null;
  gvLayout(); gvFit(); gvDraw();
}
function gvFit() {
  if (!GV.nodes.length) return;
  let mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9;
  for (const n of GV.nodes) { if (n.bx < mnx) mnx = n.bx; if (n.by < mny) mny = n.by; if (n.bx > mxx) mxx = n.bx; if (n.by > mxy) mxy = n.by; }
  const bw = Math.max(1, mxx - mnx), bh = Math.max(1, mxy - mny), pad = 96;
  GV.scale = Math.max(0.3, Math.min(1.4, Math.min((GV.W - 2 * pad) / bw, (GV.H - 2 * pad) / bh)));
  GV.ox = (GV.W - (mnx + mxx) * GV.scale) / 2;
  GV.oy = (GV.H - (mny + mxy) * GV.scale) / 2;
}
function gvDraw() {
  const ctx = GV.ctx; if (!ctx) return;
  ctx.setTransform(GV.dpr, 0, 0, GV.dpr, 0, 0);
  // fundo com vinheta radial
  const g = ctx.createRadialGradient(GV.W / 2, GV.H * 0.42, 60, GV.W / 2, GV.H * 0.42, Math.max(GV.W, GV.H) * 0.75);
  g.addColorStop(0, "#0c1524"); g.addColorStop(1, "#060910");
  ctx.fillStyle = g; ctx.fillRect(0, 0, GV.W, GV.H);
  ctx.fillStyle = "#cfe0f5";
  for (const s of GV.stars) { ctx.globalAlpha = s.a; ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, 6.283); ctx.fill(); }
  ctx.globalAlpha = 1;
  // auras dos setores de categoria
  for (const cl of GV.catLabels) {
    const p = w2s({ bx: cl.cx, by: cl.cy });
    ctx.beginPath(); ctx.arc(p.x, p.y, cl.Ro * GV.scale + 9, cl.a0, cl.a0 + cl.span);
    ctx.strokeStyle = cl.cor + "22"; ctx.lineWidth = 26 * GV.scale; ctx.stroke();
  }
  const f = gvFoco(), neigh = f ? (GV.adj[f.id] || new Set()) : null;
  const gw = GV.nodes.find((n) => n.kind === "gateway");
  // repouso: raios fraquíssimos disp→gateway; foco: acende as conexões do nó
  if (!f && gw) {
    const G = w2s(gw);
    for (const n of GV.nodes) {
      if (n.kind !== "device") continue;
      const S = w2s(n);
      ctx.strokeStyle = "rgba(120,140,175,0.07)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(G.x, G.y); ctx.lineTo(S.x, S.y); ctx.stroke();
    }
  }
  if (f) {
    for (const e of GV.edges) {
      if (e.source !== f.id && e.target !== f.id) continue;
      const a = GV.byId[e.source], b = GV.byId[e.target], A = w2s(a), B = w2s(b);
      const grad = ctx.createLinearGradient(A.x, A.y, B.x, B.y);
      grad.addColorStop(0, (a.color || "#8ac") + "cc"); grad.addColorStop(1, (b.color || "#8ac") + "cc");
      ctx.strokeStyle = grad; ctx.lineWidth = 1.5;
      const mx = (A.x + B.x) / 2, my = (A.y + B.y) / 2;
      ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.quadraticCurveTo(mx, my, B.x, B.y); ctx.stroke();
    }
  }
  // nós
  for (const n of GV.nodes) {
    const S = w2s(n), r = Math.max(2.4, n.r * GV.nodeSize * GV.scale);
    const dim = f && n !== f && !(neigh && neigh.has(n.id));
    ctx.globalAlpha = dim ? 0.22 : 1;
    ctx.shadowColor = n.color; ctx.shadowBlur = (n.kind === "service" ? 7 : 15) * GV.glow * Math.min(1.4, GV.scale);
    ctx.beginPath(); ctx.arc(S.x, S.y, r, 0, 6.283); ctx.fillStyle = n.color; ctx.fill(); ctx.shadowBlur = 0;
    if (n.kind !== "service") { ctx.lineWidth = 1.8; ctx.strokeStyle = "rgba(255,255,255,0.75)"; ctx.stroke(); }
    if (n === f) { ctx.lineWidth = 2; ctx.strokeStyle = "#fff"; ctx.beginPath(); ctx.arc(S.x, S.y, r + 4, 0, 6.283); ctx.stroke(); }
    ctx.globalAlpha = 1;
  }
  // rótulos de grupo de dispositivos
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  for (const l of GV.devLabels) {
    const p = w2s({ bx: l.x, by: l.y });
    ctx.font = "700 10px " + "var(--mono), monospace"; ctx.fillStyle = l.cor + "cc";
    ctx.shadowColor = "rgba(0,0,0,0.8)"; ctx.shadowBlur = 4; ctx.fillText(l.txt, p.x, p.y); ctx.shadowBlur = 0;
  }
  // rótulos de categoria
  for (const cl of GV.catLabels) {
    const p = w2s({ bx: cl.x, by: cl.y });
    ctx.font = "700 10px monospace"; ctx.fillStyle = cl.cor + "dd";
    ctx.shadowColor = "rgba(0,0,0,0.85)"; ctx.shadowBlur = 4; ctx.fillText(cl.txt, p.x, p.y); ctx.shadowBlur = 0;
  }
  // rótulos de nós: dispositivos = radiais rotacionados; serviços/gateway = horizontais
  for (const n of GV.nodes) {
    const mostrar = n === f || n.hub || n.kind === "device" || n.kind === "gateway";
    if (!mostrar) continue;
    const dim = f && n !== f && !(neigh && neigh.has(n.id));
    if (dim && n.kind === "service") continue;
    const S = w2s(n), r = Math.max(2.4, n.r * GV.nodeSize * GV.scale);
    const lab = (n.label || "").length > 24 ? n.label.slice(0, 22) + "…" : (n.label || "");
    ctx.globalAlpha = dim ? 0.4 : 1;
    ctx.shadowColor = "rgba(0,0,0,0.92)"; ctx.shadowBlur = 4;
    if (n.kind === "device") {
      const a = n.ang, flip = Math.cos(a) < 0;
      ctx.save(); ctx.translate(S.x, S.y); ctx.rotate(flip ? a + Math.PI : a);
      ctx.font = (n === f ? "600 " : "") + "11px system-ui, sans-serif";
      ctx.textAlign = flip ? "right" : "left"; ctx.textBaseline = "middle";
      ctx.fillStyle = "#eaf1f8"; ctx.fillText(lab, (flip ? -1 : 1) * (r + 7), 0);
      ctx.restore();
    } else {
      const fs = n.kind === "gateway" ? 12 : 10.5;
      ctx.font = (n.hub || n === f ? "600 " : "") + fs + "px system-ui, sans-serif";
      ctx.textAlign = "center"; ctx.textBaseline = "top";
      ctx.fillStyle = "rgba(210,222,238,0.92)"; ctx.fillText(lab, S.x, S.y + r + 4);
    }
    ctx.shadowBlur = 0; ctx.globalAlpha = 1;
  }
}
function gvHit(px, py) {
  for (let i = GV.nodes.length - 1; i >= 0; i--) {
    const n = GV.nodes[i], S = w2s(n);
    if (Math.hypot(S.x - px, S.y - py) <= Math.max(7, n.r * GV.nodeSize * GV.scale) + 4) return n;
  }
  return null;
}
function gvLocal(ev) { const r = GV.canvas.getBoundingClientRect(); return { x: ev.clientX - r.left, y: ev.clientY - r.top }; }
function gvWheel(ev) {
  ev.preventDefault();
  const p = gvLocal(ev), before = s2w(p.x, p.y);
  GV.scale = Math.max(0.3, Math.min(3.5, GV.scale * (ev.deltaY < 0 ? 1.12 : 0.9)));
  GV.ox = p.x - before.x * GV.scale; GV.oy = p.y - before.y * GV.scale;
  gvDraw();
}
function gvDown(ev) {
  const p = gvLocal(ev), hit = gvHit(p.x, p.y);
  GV.moved = false;
  if (hit) GV.press = hit; else GV.pan = { x: p.x, y: p.y, ox: GV.ox, oy: GV.oy };
}
function gvMove(ev) {
  if (!GV.canvas) return;
  const p = gvLocal(ev);
  if (GV.pan) { GV.ox = GV.pan.ox + (p.x - GV.pan.x); GV.oy = GV.pan.oy + (p.y - GV.pan.y); GV.moved = true; gvDraw(); }
  else { const h = gvHit(p.x, p.y); if (h !== GV.hover) { GV.hover = h; GV.canvas.style.cursor = h ? "pointer" : "grab"; gvDraw(); } }
}
function gvUp() {
  if (GV.press && !GV.moved) {
    // clique num dispositivo abre o painel completo; num serviço/gateway, o card do grafo
    if (GV.press.kind === "device") { abrirDetalhe(GV.press.id); }
    else { GV.fixo = (GV.fixo === GV.press) ? null : GV.press; mostrarNo(GV.fixo); gvDraw(); }
  } else if (GV.pan && !GV.moved) {
    GV.fixo = null; const inf = $("#grafo-info"); if (inf) inf.classList.add("oculto"); gvDraw();
  }
  GV.press = null; GV.pan = null;
}

async function carregarGrafo() {
  if (estado.view !== "mapa") return;
  try {
    const data = await apiGet("/api/graph?limit=40&hours=" + estado.grafoHoras);
    if (!GV.ctx) gvInit();
    gvSetData(data);
  } catch (e) { console.error("grafo", e); }
}

function mostrarNo(n) {
  const info = $("#grafo-info");
  if (!n) { info.classList.add("oculto"); return; }
  const m = n.meta || {};
  let corpo = "";
  if (n.kind === "service") {
    corpo = `<div class="gi-linha"><span class="chip" style="color:${n.color};border-color:${n.color}66">${esc(m.categoria || "")}</span> <strong>${m.conexoes || 0}</strong> conexões</div>
      <div class="gi-sec mono">hosts reais</div><div class="gi-hosts mono">${(m.hosts || []).map(esc).join("<br>") || "—"}</div>
      <div class="gi-sec mono">quem acessa</div><div class="mono">${(m.dispositivos || []).map(esc).join(", ") || "—"}</div>`;
  } else if (n.kind === "gateway") {
    corpo = `<div class="gi-linha">Roteador / rede local — ${m.dispositivos || 0} dispositivos.</div>
      <div class="gi-sec mono">dica</div><div class="mono">passe o mouse num nó pra ver só as conexões dele · clique num dispositivo pra abrir os detalhes.</div>`;
  }
  info.innerHTML = `<div class="gi-cab"><span class="gi-nome">${esc(n.label)}</span><button class="btn-fechar" id="gi-fechar" title="Fechar">✕</button></div>${corpo}`;
  info.classList.remove("oculto");
  const f = $("#gi-fechar");
  if (f) f.addEventListener("click", () => { info.classList.add("oculto"); GV.fixo = null; gvDraw(); });
}

// ----------------------- resumo (chart + tops) -----------------------
async function carregarResumo() {
  try {
    const [tl, ov] = await Promise.all([
      apiGet("/api/timeline?hours=24"),
      apiGet("/api/overview?hours=24"),
    ]);
    renderChart(tl);
    const sb = $("#stat-bytes"); if (sb) sb.textContent = fmtBytes((ov.bytes_up || 0) + (ov.bytes_down || 0));
    const se = $("#stat-events"); if (se) { se.textContent = Number(ov.alerts_24h || 0).toLocaleString("pt-BR"); se.classList.toggle("amb", (ov.alerts_24h || 0) > 0); }
    renderNovos(ov.new_devices || []);
    const temVol = (x) => (x.bytes_up || 0) + (x.bytes_down || 0) > 0;
    renderTop($("#top-devices"), (ov.top_devices || []).slice(0, 8).map((d) => ({
      label: (KIND_ICON[d.kind] || "❔") + " " + d.name,
      total: temVol(d) ? (d.bytes_up + d.bytes_down) : (d.flows + d.dns),
      texto: temVol(d) ? fmtBytes(d.bytes_up + d.bytes_down) : (d.flows + d.dns) + " reg.",
      id: d.id,
    })), (i) => abrirDetalhe(i.id));
    renderTop($("#top-services"), (ov.top_services || []).slice(0, 8).map((x) => ({
      label: x.name, cor: corCat(x.category), total: x.bytes_up + x.bytes_down,
      texto: fmtBytes(x.bytes_up + x.bytes_down), dica: `${x.category} · ${x.conns} conexões · ${x.devices} aparelho(s)`,
      busca: x.name,
    })), (i) => { estado.aba = "volume"; estado.trafegoBusca = i.busca; $("#trafego-busca").value = i.busca; marcarAba(); mostrarView("trafego"); renderTrafego(); });
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
  // os baldes vêm em UTC ("AAAA-MM-DDTHH"); o eixo mostra a hora local
  const hLocal = (b) => { const d = new Date(b.bucket + ":00:00Z"); return isNaN(d) ? "" : d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }); };
  const pico = tl.reduce((a, b) => ((b.flows || 0) + (b.dns || 0) > (a.flows || 0) + (a.dns || 0) ? b : a), tl[0]);
  const marcas = [0, Math.floor((n - 1) / 3), Math.floor((2 * (n - 1)) / 3), n - 1].filter((v, i, a) => a.indexOf(v) === i);
  host.innerHTML = `
    <div class="chart-topo mono"><span>pico: ${hLocal(pico)} · ${(pico.flows || 0)} conexões, ${(pico.dns || 0)} consultas</span><span>máx. ${maxV}/h</span></div>
    <svg viewBox="0 0 ${W} ${H}" width="100%" height="120" preserveAspectRatio="none" class="chart-svg">
      <polygon points="${area("flows")}" fill="rgba(45,212,191,0.14)" />
      <polyline points="${linha("flows")}" fill="none" stroke="var(--teal)" stroke-width="1.6" />
      <polygon points="${area("dns")}" fill="rgba(245,158,11,0.10)" />
      <polyline points="${linha("dns")}" fill="none" stroke="var(--amb)" stroke-width="1.6" />
    </svg>
    <div class="chart-eixo">${marcas.map((i) => `<span>${hLocal(tl[i])}</span>`).join("")}</div>`;
}

// ----------------------- visão geral em linguagem direta -----------------------
const SEV_ICONE = { ok: "✔", info: "•", warn: "!", alert: "‼" };

async function carregarInsights() {
  try {
    const itens = await apiGet("/api/insights");
    const cont = $("#resumo-insights"); if (!cont) return;
    cont.innerHTML = itens.map((i, k) => `
      <div class="insight sev-${esc(i.sev)}${i.view || i.device_id ? " clicavel" : ""}" data-k="${k}">
        <span class="insight-ic">${SEV_ICONE[i.sev] || "•"}</span>
        <div><div class="insight-tit">${esc(i.title)}</div><div class="insight-txt">${esc(i.text || "")}</div></div>
      </div>`).join("") || '<p class="vazio">Sem observações.</p>';
    cont.querySelectorAll(".insight.clicavel").forEach((n) => n.addEventListener("click", () => {
      const i = itens[+n.dataset.k];
      if (i.device_id) abrirDetalhe(i.device_id); else if (i.view) mostrarView(i.view);
    }));
  } catch (e) { console.error("insights", e); }
}

async function carregarAgora() {
  try {
    const sel = $("#agora-janela");
    const min = sel ? parseInt(sel.value, 10) || 15 : 15;
    const r = await apiGet("/api/now?minutes=" + min);
    const cont = $("#agora-lista"); if (!cont) return;
    if (!r.devices.length) { cont.innerHTML = `<p class="vazio">Nenhum aparelho com atividade nos últimos ${min} min.</p>`; return; }
    cont.innerHTML = r.devices.slice(0, 14).map((d) => `
      <div class="agora-item" data-id="${esc(d.id)}">
        <span class="agora-ic">${KIND_ICON[d.kind] || "❔"}</span>
        <div class="agora-corpo">
          <div class="agora-nome"><b>${esc(d.name)}</b><span class="mudo mono">${haQuanto(d.last)}</span></div>
          <div class="agora-chips">${d.services.map((sv) => `<span class="svc-chip" style="border-color:${corCat(sv.category)}66" title="${esc(sv.category)} · ${sv.count} registro(s)"><i class="dot" style="background:${corCat(sv.category)}"></i>${esc(sv.name)}</span>`).join("")}${d.mais ? `<span class="svc-chip mudo">+${d.mais}</span>` : ""}</div>
        </div>
      </div>`).join("");
    cont.querySelectorAll(".agora-item").forEach((n) => n.addEventListener("click", () => abrirDetalhe(n.dataset.id)));
  } catch (e) { console.error("agora", e); }
}

async function carregarCategorias() {
  try {
    const cats = (await apiGet("/api/categories?hours=24")).filter((c) => c.conns > 0 || c.bytes > 0);
    const cont = $("#cats"); if (!cont) return;
    if (!cats.length) { cont.innerHTML = '<p class="vazio">Sem dados ainda.</p>'; return; }
    const total = cats.reduce((a, c) => a + c.conns, 0) || 1;
    cont.innerHTML = cats.slice(0, 9).map((c) => `
      <div class="top-item clicavel" data-cat="${esc(c.category)}" title="${esc((c.top || []).join(", "))}">
        <div class="top-barra" style="width:${Math.round((100 * c.conns) / cats[0].conns)}%;background:${corCat(c.category)}33"></div>
        <span class="top-label"><i class="dot" style="background:${corCat(c.category)}"></i>${esc(c.category)} <span class="mudo">${esc((c.top || []).slice(0, 3).join(", "))}</span></span>
        <span class="top-total mono">${Math.round((100 * c.conns) / total)}%${c.bytes ? " · " + fmtBytes(c.bytes) : ""}</span>
      </div>`).join("");
    cont.querySelectorAll(".top-item").forEach((n) => n.addEventListener("click", () => {
      estado.aba = "conexoes"; estado.trafegoBusca = n.dataset.cat; $("#trafego-busca").value = n.dataset.cat; marcarAba(); mostrarView("trafego"); renderTrafego();
    }));
  } catch (e) { console.error("categorias", e); }
}

const EV_ROTULO = { "inbound.tcp": "Conexão vinda de fora", "device.new": "Aparelho novo", "device.update": "Alteração no painel",
  "device.alias": "Vínculo de MAC", "passive.name": "Nome descoberto", "discovery.ssdp": "Descoberta (UPnP)", "discovery.sweep": "Varredura da rede" };
const EV_ROTINA = new Set(["discovery.ssdp", "discovery.sweep", "passive.name"]);

async function carregarEventos() {
  try {
    const tb = $("#eventos-tabela"); if (!tb) return;
    const rotina = $("#ev-rotina") && $("#ev-rotina").checked;
    const evs = (await apiGet("/api/events?limit=600")).filter((e) => rotina || !EV_ROTINA.has(e.type)).slice(0, 200);
    const cor = { warning: "var(--amb)", critical: "var(--verm)", info: "var(--teal)" };
    const linhas = evs.map((e) => { const d = devPorId(e.device_id) || (estado.devices || []).find((x) => (x.members || []).some((m) => m.id === e.device_id)); return `
      <tr><td class="mono t-hora" title="${hora(e.ts)}">${haQuanto(e.ts)}</td>
      <td><i class="dot" style="background:${cor[e.severity] || cor.info};border-radius:50%"></i>${esc(EV_ROTULO[e.type] || e.type)}</td>
      ${celDev(d ? d.id : "", d ? d.display_name : "—", d ? d.kind : "unknown")}
      <td class="t-host" style="max-width:none;white-space:normal">${esc(e.title || "")}${e.detail ? ` <span class="mudo mono">${esc(e.detail)}</span>` : ""}</td></tr>`; });
    tb.innerHTML = `<thead><tr><th>quando</th><th>tipo</th><th>aparelho</th><th>o que aconteceu</th></tr></thead><tbody>${linhas.join("") || '<tr><td colspan="4" class="vazio">Nenhum alerta ou evento neste filtro.</td></tr>'}</tbody>`;
    tb.querySelectorAll("a[data-dev]").forEach((a) => a.addEventListener("click", (ev) => { ev.preventDefault(); if (a.dataset.dev) abrirDetalhe(a.dataset.dev); }));
  } catch (e) { console.error("eventos", e); }
}

function renderNovos(lista) {
  const sec = $("#novos-secao"), cont = $("#novos-lista"); if (!sec || !cont) return;
  sec.classList.toggle("oculto", !lista.length);
  cont.innerHTML = lista.map((d) => `
    <button class="novo-item dev-${esc(d.trust_state || "unknown")}" data-id="${esc(d.id)}">
      <span class="novo-ic">${KIND_ICON[d.kind] || "❔"}</span>
      <span class="novo-txt"><b>${esc(d.name)}</b><small class="mono">${esc(d.ip4 || "—")} · ${esc(d.vendor || (d.private_mac ? "MAC privado" : "fabricante desconhecido"))} · ${haQuanto(d.first_seen)}</small></span>
    </button>`).join("");
  cont.querySelectorAll(".novo-item").forEach((b) => b.addEventListener("click", () => abrirDetalhe(b.dataset.id)));
}

function renderTop(host, itens, aoClicar) {
  if (!host) return;
  if (!itens || !itens.length) { host.innerHTML = '<p class="vazio">Sem dados ainda.</p>'; return; }
  const max = Math.max(1, ...itens.map((i) => i.total || 0));
  host.innerHTML = itens.map((i, k) => `
    <div class="top-item${aoClicar ? " clicavel" : ""}" data-k="${k}" title="${esc(i.dica || i.label)}">
      <div class="top-barra" style="width:${Math.round((100 * (i.total || 0)) / max)}%${i.cor ? `;background:${i.cor}33` : ""}"></div>
      <span class="top-label">${i.cor ? `<i class="dot" style="background:${i.cor}"></i>` : ""}${esc(i.label || "—")}</span>
      <span class="top-total mono">${esc(i.texto ?? i.total ?? 0)}</span>
    </div>`).join("");
  if (aoClicar) host.querySelectorAll(".top-item").forEach((n) => n.addEventListener("click", () => aoClicar(itens[+n.dataset.k])));
}

// ----------------------- lista de dispositivos -----------------------
// Dispositivos internos do Home Assistant (rede docker 172.30.x) — ruído, ficam fora
// da lista/contagem/mapa (o mapa já os filtra por conta própria).
function ehInternoDev(d) {
  // A API já entrega só a LAN; mantido para rótulos antigos ("HA interno").
  return !!d.internal || (d.label || "").toLowerCase().startsWith("ha interno");
}

async function carregarDevices() {
  try {
    const todos = await apiGet("/api/devices?hours=24");
    estado.todosDevs = todos || [];
    estado.devices = estado.todosDevs.filter((d) => !ehInternoDev(d));
    const nn = $("#nav-n-dev"); if (nn) nn.textContent = estado.devices.filter((d) => d.active).length;
    renderDevices(); atualizarNivel(); preencherSelectDev();
  } catch (e) { console.error("devices", e); $("#lista-devices").innerHTML = '<p class="vazio">Falha ao carregar.</p>'; }
}

function preencherSelectDev() {
  const sel = $("#trafego-dev"); if (!sel) return;
  const atual = estado.trafegoDev;
  const lista = estado.devices.filter((d) => d.capturado).sort((a, b) => a.display_name.localeCompare(b.display_name, "pt-BR"));
  sel.innerHTML = '<option value="">todos os dispositivos</option>' +
    lista.map((d) => `<option value="${esc(d.id)}">${iconeDev(d)} ${esc(d.display_name)}</option>`).join("");
  sel.value = lista.some((d) => d.id === atual) ? atual : "";
}

function chipTrust(e_) {
  const s = (e_ || "unknown").toLowerCase();
  const rot = { unknown: "desconhecido", trusted: "confiável", quarantine: "quarentena" };
  const cls = ["unknown", "trusted", "quarantine"].includes(s) ? s : "unknown";
  return `<span class="chip chip-${cls}">${esc(rot[cls] || cls)}</span>`;
}

function casaFiltro(d, termo) {
  if (!termo) return true;
  return [d.display_name, d.mac, d.mac_vendor, d.hostname, d.ip4, d.ip6, d.label, d.kind_label, d.os]
    .filter(Boolean).join(" ").toLowerCase().includes(termo);
}

const FILTROS_DEV = {
  ativos: (d) => d.active,
  desconhecidos: (d) => (d.trust_state || "unknown") === "unknown" && d.active,
  semnome: (d) => !d.named && d.active,
  todos: () => true,
};

const ORDEM_GRUPOS = ["Celulares", "Computadores", "TV & Mídia", "Voz", "IoT", "Rede", "Outros"];
const NOME_GRUPO = { IoT: "Casa inteligente", Voz: "Som e assistentes", Rede: "Rede e servidores", Outros: "Não identificados" };

function cardDevice(d) {
  const vol = (d.bytes_up || 0) + (d.bytes_down || 0);
  const card = el("div", "device dev-" + ((d.trust_state || "unknown")) + (d.active ? "" : " dev-inativo"));
  card.dataset.id = d.id;
  if (d.id === estado.selecionado) card.classList.add("ativo");
  const pistas = [d.kind_label, d.os, d.mac_vendor].filter(Boolean).join(" · ");
  const uso = vol > 0
    ? `<span title="recebido / enviado em 24 h">↓ ${fmtBytes(d.bytes_down)} · ↑ ${fmtBytes(d.bytes_up)}</span>`
    : (d.capturado ? "<span>volume ainda não medido</span>" : '<span class="mudo">sem tráfego capturado em 24 h</span>');
  const cont2 = d.capturado ? `<span>${d.flows} conexões · ${d.dns} DNS</span>` : "";
  const selos = (d.novo ? '<span class="chip chip-novo" title="apareceu pela primeira vez nas últimas 48 h">novo</span>' : "") +
    (d.macs > 1 ? `<span class="chip chip-macs" title="o mesmo aparelho já usou ${d.macs} endereços MAC">${d.macs} MACs</span>` : "");
  card.innerHTML = `
    <div class="device-icone" title="${esc(d.kind_label)} (palpite por ${esc(d.kind_source)})">${iconeDev(d)}</div>
    <div class="device-corpo">
      <div class="device-linha1"><span class="device-nome" title="${esc(d.display_name)}">${esc(d.display_name)}</span><span class="device-selos">${selos}${chipTrust(d.trust_state)}</span></div>
      <div class="device-linha2 mono"><span title="IPv4 atual">${esc(d.ip4 || "—")}</span><span title="MAC atual${d.private_mac ? " — privado (aleatório)" : ""}">${esc(d.mac || "—")}${d.private_mac ? " ⚑" : ""}</span></div>
      <div class="device-linha3"><span class="device-vendor">${esc(pistas || "sem pistas de identificação")}</span><span class="device-visto mono" title="${hora(d.last_seen)}">${haQuanto(d.last_seen)}</span></div>
      <div class="device-linha4 mono">${uso}${cont2}</div>
    </div>`;
  card.addEventListener("click", () => abrirDetalhe(d.id));
  return card;
}

function renderDevices() {
  const cont = $("#lista-devices");
  const termo = estado.filtro.trim().toLowerCase();
  for (const k of Object.keys(FILTROS_DEV)) { const b = $("#fc-" + k); if (b) b.textContent = estado.devices.filter(FILTROS_DEV[k]).length; }
  // com busca digitada, procura em todos (inclusive os antigos)
  const base = termo ? estado.devices : estado.devices.filter(FILTROS_DEV[estado.filtroDev] || FILTROS_DEV.ativos);
  const lista = base.filter((d) => casaFiltro(d, termo));
  const vol = (d) => (d.bytes_up || 0) + (d.bytes_down || 0);
  lista.sort((a, b) => (vol(b) - vol(a)) || ((b.flows + b.dns) - (a.flows + a.dns)) ||
    String(b.last_seen || "").localeCompare(String(a.last_seen || "")));
  if (!lista.length) { cont.innerHTML = '<p class="vazio">Nenhum dispositivo neste filtro.</p>'; return; }
  cont.innerHTML = "";
  for (const g of ORDEM_GRUPOS) {
    const doGrupo = lista.filter((d) => (ORDEM_GRUPOS.includes(d.kind_group) ? d.kind_group : "Outros") === g);
    if (!doGrupo.length) continue;
    const rot = el("div", "grupo-rot");
    rot.innerHTML = `${esc(NOME_GRUPO[g] || g)} <b>${doGrupo.length}</b>`;
    cont.appendChild(rot);
    for (const d of doGrupo) cont.appendChild(cardDevice(d));
  }
}

// Nivel de seguranca da rede (assinatura): verde/ambar/vermelho conforme os estados.
function atualizarNivel() {
  const secao = $("#nivel-rede"); if (!secao) return;
  const todos = estado.devices || [];
  const devs = todos.filter((d) => d.active);
  const q = todos.filter((d) => d.trust_state === "quarantine").length;
  const u = devs.filter((d) => (d.trust_state || "unknown") === "unknown").length;
  const t = devs.filter((d) => d.trust_state === "trusted").length;
  const sd = $("#stat-devices"); if (sd) sd.innerHTML = `${devs.length}<small> / ${todos.length}</small>`;
  const su = $("#stat-unknown"); if (su) su.textContent = u;
  let nivel = "", titulo = "Avaliando rede…", sub = "mapeando dispositivos e tráfego";
  if (q > 0) { nivel = "nr-alert"; titulo = "Alerta"; sub = `${q} em quarentena · ${u} ativo${u === 1 ? "" : "s"} não classificado${u === 1 ? "" : "s"}`; }
  else if (u > 0) { nivel = "nr-warn"; titulo = "Atenção"; sub = `${u} dispositivo${u === 1 ? "" : "s"} ativo${u === 1 ? "" : "s"} sem classificação — abra e marque como confiável ou quarentena`; }
  else if (devs.length) { nivel = "nr-safe"; titulo = "Rede segura"; sub = `os ${t} dispositivos ativos são confiáveis`; }
  secao.classList.remove("nr-safe", "nr-warn", "nr-alert");
  if (nivel) secao.classList.add(nivel);
  $("#nr-titulo").textContent = titulo;
  $("#nr-sub").textContent = sub;
}

// ----------------------- tráfego identificado -----------------------
async function carregarTrafego() {
  try {
    const q = estado.trafegoDev ? "&device_id=" + encodeURIComponent(estado.trafegoDev) : "";
    const [con, vol, dns] = await Promise.all([
      apiGet("/api/traffic?limit=400" + q),
      apiGet("/api/usage?hours=24&limit=400" + q),
      apiGet("/api/dns?limit=400" + q),
    ]);
    estado.trafego = { conexoes: con || [], volume: vol || [], dns: dns || [] };
    renderTrafego();
  } catch (e) { console.error("trafego", e); }
}

function marcarAba() {
  document.querySelectorAll("#trafego-abas .aba").forEach((b) => b.classList.toggle("ativa", b.dataset.aba === estado.aba));
}

function celDev(id, nome, kind) {
  return `<td class="t-dev"><a href="#" data-dev="${esc(id || "")}">${KIND_ICON[kind] || "❔"} ${esc(nome || "?")}</a></td>`;
}
function celSvc(nome, cat) {
  return `<td class="t-svc"><i class="dot" style="background:${corCat(cat)}"></i>${esc(nome)}<span class="t-cat">${esc(cat || "")}</span></td>`;
}

function renderTrafego() {
  const tb = $("#trafego-tabela"); if (!tb) return;
  const termo = (estado.trafegoBusca || "").trim().toLowerCase();
  const casa = (...v) => !termo || v.filter(Boolean).join(" ").toLowerCase().includes(termo);
  let cab = "", linhas = [];
  if (estado.aba === "conexoes") {
    cab = "<tr><th>quando</th><th>dispositivo</th><th>serviço</th><th>destino</th><th>tipo</th></tr>";
    linhas = estado.trafego.conexoes.filter((r) => casa(r.device, r.service, r.category, r.host, r.dst_ip, r.app)).slice(0, 250).map((r) =>
      `<tr><td class="mono t-hora" title="${hora(r.ts)}">${haQuanto(r.ts)}</td>${celDev(r.device_id, r.device, r.kind)}${celSvc(r.service, r.category)}
       <td class="mono t-host">${esc(r.host || r.dst_ip || "—")}${r.dst_port && r.dst_port !== 443 ? ":" + esc(r.dst_port) : ""}</td><td class="mono t-app">${esc(r.app || r.proto || "")}</td></tr>`);
  } else if (estado.aba === "volume") {
    cab = "<tr><th>dispositivo</th><th>serviço</th><th>site</th><th class='num'>recebido</th><th class='num'>enviado</th><th class='num'>conexões</th></tr>";
    const rows = estado.trafego.volume.filter((r) => casa(r.device, r.service, r.category, r.host));
    const max = Math.max(1, ...rows.map((r) => r.bytes_down + r.bytes_up));
    linhas = rows.slice(0, 250).map((r) =>
      `<tr>${celDev(r.device_id, r.device, r.kind)}${celSvc(r.service, r.category)}<td class="mono t-host">${esc(r.host)}</td>
       <td class="num mono"><span class="t-barra" style="width:${Math.round(60 * (r.bytes_down + r.bytes_up) / max)}px;background:${corCat(r.category)}"></span>${fmtBytes(r.bytes_down)}</td>
       <td class="num mono">${fmtBytes(r.bytes_up)}</td><td class="num mono">${r.conns}</td></tr>`);
  } else {
    cab = "<tr><th>quando</th><th>dispositivo</th><th>serviço</th><th>nome consultado</th><th>tipo</th></tr>";
    linhas = estado.trafego.dns.map((r) => { const fr = friendlyJS(r.qname); const d = devPorId(r.device_id) || {}; return { r, fr, d }; })
      .filter(({ r, fr, d }) => casa(d.display_name, fr.name, fr.cat, r.qname)).slice(0, 250).map(({ r, fr, d }) =>
        `<tr><td class="mono t-hora" title="${hora(r.ts)}">${haQuanto(r.ts)}</td>${celDev(r.device_id, d.display_name || r.client_ip, d.kind)}${celSvc(fr.name, fr.cat)}
         <td class="mono t-host">${esc(r.qname)}</td><td class="mono t-app">${esc(r.qtype || "")}</td></tr>`);
  }
  const vazio = estado.aba === "volume"
    ? "Ainda sem volume medido. O volume aparece quando as conexões TCP se encerram (não inclui QUIC/UDP)."
    : "Nada capturado neste filtro.";
  tb.innerHTML = `<thead>${cab}</thead><tbody>${linhas.join("") || `<tr><td colspan="6" class="vazio">${vazio}</td></tr>`}</tbody>`;
  tb.querySelectorAll("a[data-dev]").forEach((a) => a.addEventListener("click", (ev) => { ev.preventDefault(); if (a.dataset.dev) abrirDetalhe(a.dataset.dev); }));
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
  const quem = p.device_id ? `<b class="feed-quem">${esc(nomeDev(p.device_id, p.src_ip || p.client_ip))}</b> ` : "";
  switch (msg.kind) {
    case "device": return { icone: "◈", titulo: "Dispositivo", texto: `${esc(p.hostname || p.mac || p.id || "novo")} — ${esc(p.mac_vendor || "")}`, sev: "info", ts: p.last_seen || p.first_seen };
    case "dns": { const fr = friendlyJS(p.qname); return { icone: "⌘", titulo: p.blocked ? "DNS bloqueado" : "DNS", texto: `${quem}consultou ${esc(fr.name)} · ${esc(p.qname || "")} ${p.qtype ? "(" + esc(p.qtype) + ")" : ""}`, sev: p.blocked ? "warning" : "info", ts: p.ts }; }
    case "flow": { const alvo = p.sni || p.dst_ip || ""; const fr = friendlyJS(alvo); return { icone: "⇄", titulo: "Conexão", texto: `${quem}→ ${esc(fr.name)} · ${esc(alvo)}${p.dst_port && p.dst_port !== 443 ? ":" + esc(p.dst_port) : ""} ${esc(p.app_proto || p.proto || "")}`, sev: "info", ts: p.ts }; }
    case "event": return { icone: "⚑", titulo: esc(p.title || p.type || "Evento"), texto: quem + esc(p.detail || ""), sev: (p.severity || "info").toLowerCase(), ts: p.ts };
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
    const [dev, flows, dns, uso] = await Promise.all([
      apiGet(`/api/devices/${encodeURIComponent(id)}`),
      apiGet(`/api/flows?device_id=${encodeURIComponent(id)}&limit=50`),
      apiGet(`/api/dns?device_id=${encodeURIComponent(id)}&limit=50`),
      apiGet(`/api/usage?hours=24&limit=15&device_id=${encodeURIComponent(id)}`).catch(() => []),
    ]);
    renderDetalhe(dev, flows, dns, uso);
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
  ["playstation", "PlayStation", "Jogos"], ["xboxlive", "Xbox", "Jogos"], ["nintendo", "Nintendo", "Jogos"], ["roblox", "Roblox", "Jogos"],
  ["disney", "Disney+", "Streaming"], ["hbomax", "Max (HBO)", "Streaming"], ["primevideo", "Prime Video", "Streaming"], ["globo", "Globo", "Streaming"], ["deezer", "Deezer", "Streaming"],
  ["nubank", "Nubank", "Bancos"], ["itau", "Itaú", "Bancos"], ["bradesco", "Bradesco", "Bancos"], ["santander", "Santander", "Bancos"], ["mercadopago", "Mercado Pago", "Bancos"],
  ["mercadoli", "Mercado Livre", "Compras"], ["shopee", "Shopee", "Compras"], ["aliexpress", "AliExpress", "Compras"],
  ["duolingo", "Duolingo", "Estudo"], ["discord", "Discord", "Mensagens"], ["zoom.us", "Zoom", "Mensagens"], ["tuya", "Tuya", "IoT"], ["shelly", "Shelly", "IoT"],
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

function renderDetalhe(dev, flows, dns, uso) {
  if (!dev) { $("#detalhe-corpo").innerHTML = '<p class="vazio">Não encontrado.</p>'; return; }
  $("#detalhe-titulo").textContent = iconeDev(dev) + " " + (dev.display_name || dev.label || dev.hostname || dev.mac || dev.id);
  const m = dev.meta || {};
  const ident = `<div class="detalhe-secao">
    ${linhaProp("tipo", esc(dev.kind_label || "—") + ` <span class="mudo">(palpite por ${esc(dev.kind_source || "?")})</span>`)}
    ${linhaProp("sistema", esc(dev.os || "—"))}
    ${linhaProp("nome que anuncia", esc(m.dhcp_name || "—"))}
    ${linhaProp("nome na rede", esc(dev.hostname || "—"))}
    ${m.ua ? linhaProp("navegador / app", `<span class="mono quebra">${esc(m.ua)}</span>`) : ""}
    ${m.dhcp_vendor ? linhaProp("classe DHCP", `<span class="mono">${esc(m.dhcp_vendor)}</span>`) : ""}
    ${dev.private_mac ? linhaProp("mac privado", "sim — endereço aleatório; o mesmo aparelho pode reaparecer com outro MAC") : ""}
    ${linhaProp("primeira vez", hora(dev.first_seen))}
  </div>`;
  const membros = dev.members || [];
  const listaMacs = membros.length > 1 ? `<div class="macs-lista">${membros.map((mb) => `
      <div class="mac-item"><span class="mono">${esc(mb.mac || "—")}</span>
        <span class="mudo mono">${hora(mb.first_seen).slice(0, 5)} → ${haQuanto(mb.last_seen)}${mb.principal ? " · principal" : ""}</span>
        ${mb.principal ? "" : `<button class="btn-mini" data-desvincular="${esc(mb.id)}" title="voltar a tratar este MAC como outro aparelho">separar</button>`}
      </div>`).join("")}</div>` : "";
  // candidatos: outros aparelhos (os com rótulo primeiro) para dizer "é o mesmo que…"
  const candidatos = (estado.devices || []).filter((d) => d.id !== dev.id)
    .sort((a, b) => (b.label ? 1 : 0) - (a.label ? 1 : 0) || a.display_name.localeCompare(b.display_name, "pt-BR"));
  const vinculo = `<div class="vinculo">
      <p class="intercept-aviso">Celular que trocou de MAC aparece como aparelho novo. Se este é um aparelho que você já conhece, vincule: o histórico, o nome e a confiança passam a ser um só.</p>
      <div class="acao-label"><select id="sel-vinculo" class="sel-mini sel-larga"><option value="">é o mesmo aparelho que…</option>
        ${candidatos.map((d) => `<option value="${esc(d.id)}">${iconeDev(d)} ${esc(d.display_name)}${d.active ? "" : " (fora do ar)"}</option>`).join("")}
      </select><button class="btn" id="btn-vinculo">Vincular</button></div>
    </div>`;
  const maxU = Math.max(1, ...(uso || []).map((u) => u.bytes_up + u.bytes_down));
  const consumo = (uso && uso.length) ? uso.map((u) => `
    <div class="top-item" title="${esc(u.host)} · ${u.conns} conexões">
      <div class="top-barra" style="width:${Math.round(100 * (u.bytes_up + u.bytes_down) / maxU)}%;background:${corCat(u.category)}33"></div>
      <span class="top-label"><i class="dot" style="background:${corCat(u.category)}"></i>${esc(u.service)} <span class="mudo mono">${esc(u.host)}</span></span>
      <span class="top-total mono">↓ ${fmtBytes(u.bytes_down)} · ↑ ${fmtBytes(u.bytes_up)}</span>
    </div>`).join("") : '<p class="vazio">Sem volume medido em 24 h.</p>';
  const id = dev.id;
  const box = estado.modo === "pi" ? '<p class="intercept-aviso">Tráfego deste aparelho capturado de forma passiva pelo espelho da rede (SPAN).</p>' : estado.readonly ? '<p class="intercept-aviso">🔒 Modo somente leitura (rede não-confiável) — interceptação desabilitada.</p>' : dev.ip4 ? `
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
    <div class="live-lista" id="live-lista">${liveInit || '<p class="vazio">Nada capturado deste aparelho ainda.</p>'}</div>
    <h3 class="detalhe-h3">Consumo por serviço — 24h</h3><div class="top-list top-solta">${consumo}</div>
    <h3 class="detalhe-h3">Identificação</h3>${ident}
    <h3 class="detalhe-h3">Mesmo aparelho, vários MACs${membros.length > 1 ? " (" + membros.length + ")" : ""}</h3>${listaMacs}${vinculo}
    <h3 class="detalhe-h3">Dados do dispositivo</h3>${info}
    <h3 class="detalhe-h3">Classificação</h3>${acoes}`;
  $("#detalhe-corpo").querySelectorAll("[data-trust]").forEach((b) =>
    b.addEventListener("click", async () => { if (await mutarDevice(id, { trust_state: b.dataset.trust })) { await carregarDevices(); abrirDetalhe(id); } }));
  const bl = $("#btn-label");
  if (bl) bl.addEventListener("click", async () => { if (await mutarDevice(id, { label: $("#in-label").value.trim() })) { await carregarDevices(); abrirDetalhe(id); } });
  const bi = $("#btn-intercept");
  if (bi) { bi.addEventListener("click", () => toggleIntercept(id)); atualizarInterceptStatus(id); }
  const bv = $("#btn-vinculo");
  if (bv) bv.addEventListener("click", async () => {
    const alvo = $("#sel-vinculo").value; if (!alvo) return;
    if (await vincular(id, alvo)) { await carregarDevices(); carregarTrafego(); abrirDetalhe(alvo); }
  });
  $("#detalhe-corpo").querySelectorAll("[data-desvincular]").forEach((b) =>
    b.addEventListener("click", async () => { if (await vincular(b.dataset.desvincular, null)) { await carregarDevices(); carregarTrafego(); abrirDetalhe(id); } }));
}

// Diz à API que o registro `id` é o mesmo aparelho que `principal` (null = separar).
async function vincular(id, principal) {
  const t = getToken(); if (!t) return false;
  const r = await fetch(U(`/api/devices/${encodeURIComponent(id)}/alias`), {
    method: "POST", headers: { "Content-Type": "application/json", "X-Sentinela-Token": t }, body: JSON.stringify({ primary_id: principal }),
  });
  if (r.status === 401) { localStorage.removeItem("sentinela_token"); alert("Token inválido. Tente de novo."); return false; }
  if (!r.ok) { const e = await r.json().catch(() => ({})); alert("Não foi possível vincular: " + (e.detail || r.status)); return false; }
  return true;
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
  document.querySelectorAll("#nav-views .nav-v").forEach((b) => b.addEventListener("click", () => mostrarView(b.dataset.view)));
  let vInicial = "geral";
  try { vInicial = localStorage.getItem("sentinela_view") || "geral"; } catch (e) {}
  if (!document.querySelector(`#nav-views [data-view="${vInicial}"]`)) vInicial = "geral";
  mostrarView(vInicial);
  const gj = $("#grafo-janela");
  if (gj) gj.addEventListener("change", () => { estado.grafoHoras = parseInt(gj.value, 10) || 168; carregarGrafo(); });
  document.querySelectorAll("#dev-filtros .fchip").forEach((b) => b.addEventListener("click", () => {
    estado.filtroDev = b.dataset.f;
    document.querySelectorAll("#dev-filtros .fchip").forEach((x) => x.classList.toggle("ativa", x === b));
    renderDevices();
  }));
  document.querySelectorAll("#trafego-abas .aba").forEach((b) => b.addEventListener("click", () => { estado.aba = b.dataset.aba; marcarAba(); renderTrafego(); }));
  $("#trafego-busca").addEventListener("input", (e) => { estado.trafegoBusca = e.target.value; renderTrafego(); });
  $("#trafego-dev").addEventListener("change", (e) => { estado.trafegoDev = e.target.value; carregarTrafego(); });

  carregarHealth();
  carregarStats();
  carregarControl();
  carregarDevices();
  carregarResumo();
  carregarGrafo();
  carregarTrafego();
  carregarInsights();
  carregarAgora();
  carregarCategorias();
  carregarEventos();
  const aj = $("#agora-janela"); if (aj) aj.addEventListener("change", carregarAgora);
  const er = $("#ev-rotina"); if (er) er.addEventListener("change", carregarEventos);
  setInterval(carregarAgora, 20000);
  setInterval(carregarInsights, 60000);
  setInterval(carregarCategorias, 60000);
  setInterval(carregarEventos, 60000);
  conectarWS();

  setInterval(carregarStats, 30000);
  setInterval(carregarHealth, 30000);
  setInterval(carregarDevices, 60000);
  setInterval(carregarTrafego, 20000);
  setInterval(carregarResumo, 30000);
  setInterval(carregarGrafo, 30000);
  setInterval(carregarControl, 15000);
}

document.addEventListener("DOMContentLoaded", init);
