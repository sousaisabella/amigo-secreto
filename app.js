(() => {
  "use strict";
  const KEY = "amigo-secreto-v6", OLD5 = "amigo-secreto-v5", OLD4 = "amigo-secreto-natal-v4";
  const BASE = location.href.split("#")[0];
  const HOSTED = /^https?:\/\//.test(BASE);
  const LOCAL = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);
  /* emulador local do Firebase, só para testes: abra http://localhost:PORTA/?emu=1 */
  const EMU = LOCAL && (() => { try { if (/[?&]emu=1\b/.test(location.search)) sessionStorage.setItem("emu", "1"); return sessionStorage.getItem("emu") === "1"; } catch (e) { return false; } })();
  const NS = "amigo-secreto-64e8b";
  const DB = EMU ? "http://127.0.0.1:9000" : "https://amigo-secreto-64e8b-default-rtdb.firebaseio.com";
  const sub = crypto.subtle, te = new TextEncoder(), td = new TextDecoder();
  const app = document.getElementById("app");
  const OPEN = new Set();                       // <details> abertos, sobrevivem aos redesenhos

  /* estado local: várias festas por aparelho */
  let S = { cur: "", rooms: {} };
  /* conta (anônima ou Google) */
  let U = null, ready = false, authErr = false, TOK = "";
  /* estado da sala */
  let offT = null, D = null, es = null, pollT = null, snap = "", dirty = false, ptr = false, off = false, seq = 0;
  let msg = "", work = "", reveal = false, mine = { key: "" }, hintGoogle = false;
  const once = {};
  const dr = { n: "", w: "", d: "", p: "", f: "", lt: "", lu: "", q: {}, a: {} };
  /* links de resultado antigos (#x…) */
  let rec = null, bad = false, shown = false, loading = location.hash.length > 1;

  /* ---------- utilidades ---------- */
  const hx = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const ub = s => { const o = new Uint8Array(s.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16); return o; };
  const b64u = b => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const ub64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const rid = n => hx(crypto.getRandomValues(new Uint8Array(n)));
  const clone = v => v == null ? null : JSON.parse(JSON.stringify(v));
  const entries = o => (o && typeof o === "object") ? Object.keys(o).map(k => [k, o[k]]) : [];
  const str = (v, n) => typeof v === "string" ? v.slice(0, n) : (typeof v === "number" ? String(v) : "");
  const nm = p => str(p && p.n, 30) || "?";
  const LEGACY_ID = /^[0-9a-f]{16}$/;           // ids de participante da versão anterior (antes do login)

  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(k => {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") e.className = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    });
    kids.flat(Infinity).forEach(c => { if (c != null && c !== false) e.append(c); });
    return e;
  }
  function det(k, summary, ...kids) {
    return h("details", { open: OPEN.has(k) ? "" : null, ontoggle: e => { e.currentTarget.open ? OPEN.add(k) : OPEN.delete(k); } },
      h("summary", {}, summary), kids);
  }

  /* ---------- armazenamento local ---------- */
  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) { const d = JSON.parse(raw); if (d && d.rooms && typeof d.rooms === "object") S = { cur: d.cur || "", rooms: d.rooms }; }
      else {
        /* versões anteriores: guarda o id antigo para migrar a pessoa e o organizador */
        const v5 = JSON.parse(localStorage.getItem(OLD5) || "null"), v4 = JSON.parse(localStorage.getItem(OLD4) || "null");
        if (v5 && v5.rooms) entries(v5.rooms).forEach(([id, r]) => { if (r && r.db && r.db !== "demo") S.rooms[id] = { db: DB, room: id, t: r.t || "", lpid: r.pid || "", lorg: !!r.org, mig: r.mig || null }; });
        else if (v4 && v4.db && v4.room && v4.db !== "demo") S.rooms[v4.room] = { db: DB, room: v4.room, lpid: v4.pid || "", lorg: !!v4.org, mig: v4.ex || null };
        if (v5 && v5.cur && S.rooms[v5.cur]) S.cur = v5.cur; else if (v4 && S.rooms[v4.room]) S.cur = v4.room;
        save();
      }
    } catch (e) {}
    if (S.rooms.demo) { delete S.rooms.demo; if (S.cur === "demo") S.cur = ""; }
    if (S.cur && !S.rooms[S.cur]) S.cur = "";
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch (e) {} }
  const R = () => S.rooms[S.cur] || null;
  const PID = () => U ? U.uid : "";
  const myKey = r => (r && r.sk && r.skUid === PID()) ? r.sk : null;

  /* ---------- criptografia do resultado ---------- */
  const EC = { name: "ECDH", namedCurve: "P-256" };
  async function genKeys() {
    const k = await sub.generateKey(EC, true, ["deriveBits"]);
    return { pk: hx(new Uint8Array(await sub.exportKey("raw", k.publicKey))), sk: await sub.exportKey("jwk", k.privateKey) };
  }
  async function shared(priv, pubHex) {
    const pub = await sub.importKey("raw", ub(pubHex), EC, false, []);
    const bits = await sub.deriveBits({ name: "ECDH", public: pub }, priv, 256);
    return sub.importKey("raw", await sub.digest("SHA-256", bits), "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  /* cifra para a chave pública de uma pessoa: só ela abre */
  async function seal(pkHex, obj) {
    const eph = await sub.generateKey(EC, true, ["deriveBits"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await sub.encrypt({ name: "AES-GCM", iv }, await shared(eph.privateKey, pkHex), te.encode(JSON.stringify(obj)));
    return { e: hx(new Uint8Array(await sub.exportKey("raw", eph.publicKey))), i: hx(iv), c: hx(new Uint8Array(ct)) };
  }
  async function unseal(skJwk, box) {
    const sk = await sub.importKey("jwk", skJwk, EC, false, ["deriveBits"]);
    const pt = await sub.decrypt({ name: "AES-GCM", iv: ub(box.i) }, await shared(sk, box.e), ub(box.c));
    return JSON.parse(td.decode(pt));
  }

  /* ---------- banco: Firebase Realtime Database (REST + streaming, com login) ou memória ---------- */
  function setPath(root, path, val) {
    const parts = path.split("/").filter(Boolean);
    if (!parts.length) return val == null || typeof val !== "object" ? {} : clone(val);
    if (!root || typeof root !== "object") root = {};
    let o = root;
    for (let i = 0; i < parts.length - 1; i++) { if (!o[parts[i]] || typeof o[parts[i]] !== "object") o[parts[i]] = {}; o = o[parts[i]]; }
    const k = parts[parts.length - 1];
    if (val == null) delete o[k]; else o[k] = clone(val);
    return root;
  }
  async function tok(force) { if (!window.FBAuth || !U) return ""; try { TOK = await window.FBAuth.token(force); } catch (e) {} return TOK; }
  const qs = () => "?" + [EMU ? "ns=" + NS : "", TOK ? "auth=" + encodeURIComponent(TOK) : ""].filter(Boolean).join("&");
  async function req(path, method = "GET", body, retry = true) {
    await tok(false);
    const x = await fetch(DB + path + ".json" + qs(), { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    if ((x.status === 401 || x.status === 403) && retry && U) { await tok(true); return req(path, method, body, false); }
    if (!x.ok) { const e = new Error("http " + x.status); e.status = x.status; throw e; }
    return x.json();
  }
  function api(path, method = "GET", body) {
    const r = R();
    if (!r) return Promise.reject(new Error("sem sala"));
    return req("/rooms/" + r.room + path, method, body);
  }
  /* índice privado da conta Google: festas e a chave do resultado, legível só pela própria pessoa */
  function uapi(path, method, body) { return U && !U.anon ? req("/users/" + U.uid + "/rooms" + path, method, body) : Promise.resolve(null); }

  function poll() {
    const my = ++seq, room = S.cur;
    if (document.hidden && D) return Promise.resolve();
    return api("").then(d => { if (my !== seq || room !== S.cur) return; D = d && typeof d === "object" ? d : {}; off = false; changed(); })
      .catch(e => { if (room !== S.cur) return; if (e.status === 401 || e.status === 403) msg = "Sem permissão para abrir esta festa."; off = !e.status; if (!D) D = {}; changed(true); });
  }
  function stopLive() { if (es) { es.close(); es = null; } clearInterval(pollT); pollT = null; clearTimeout(offT); off = false; }
  async function live() {
    stopLive();
    const r = R(); if (!r || rec || bad) return;
    if (!U) return;                               // espera o login terminar
    const room = r.room;
    await tok(false);
    if (S.cur !== room) return;
    if (!window.EventSource) { pollT = setInterval(poll, 4000); poll(); return; }
    stopLive();
    const src = new EventSource(DB + "/rooms/" + room + ".json" + qs()); es = src;
    const apply = (e, patch) => {
      if (es !== src) return;
      let m; try { m = JSON.parse(e.data); } catch (x) { return; }
      if (!m || typeof m.path !== "string") return;
      if (patch) Object.keys(m.data || {}).forEach(k => { D = setPath(D, m.path.replace(/\/$/, "") + "/" + k, m.data[k]); });
      else D = setPath(D, m.path, m.data);
      clearTimeout(offT); off = false; changed();
    };
    src.addEventListener("put", e => apply(e, false));
    src.addEventListener("patch", e => apply(e, true));
    /* o login vale uma hora: o banco avisa quando vence, e a conexão é refeita com um novo */
    src.addEventListener("auth_revoked", () => { if (es !== src) return; tok(true).then(() => { if (es === src) live(); }); });
    src.addEventListener("cancel", () => { if (es !== src) return; stopLive(); msg = "Sem permissão para abrir esta festa."; if (!D) D = {}; changed(true); });
    src.onerror = () => {
      if (es !== src) return;
      if (src.readyState === 2) { es = null; pollT = setInterval(poll, 4000); poll(); }
      else { if (!D) { D = {}; changed(); } clearTimeout(offT); offT = setTimeout(() => { if (es === src && src.readyState !== 1) { off = true; changed(); } }, 4000); }
    };
  }
  function refresh() { if (R() && !es) poll(); }
  function write(path, method, body, after) {
    return api(path, method, body)
      .then(() => { if (after) after(); refresh(); dirty = true; flush(); })
      .catch(e => { msg = e.status === 401 || e.status === 403 ? "Você não tem permissão para fazer isso." : "Não consegui salvar. Confira sua conexão."; render(); });
  }

  /* redesenha só quando os dados mudam, e nunca no meio de uma digitação ou de um toque */
  function typing() { const a = document.activeElement; return !!a && (a.tagName === "TEXTAREA" || (a.tagName === "INPUT" && !/^(checkbox|radio|button|submit)$/.test(a.type))); }
  function changed(force) {
    const s = JSON.stringify(D) + "|" + off + "|" + PID();
    if (s === snap && !force) return;
    snap = s; afterData(); dirty = true; flush();
  }
  function flush() { if (dirty && !typing() && !ptr) render(); }

  /* ---------- conta ---------- */
  async function google() {
    if (!window.FBAuth) { msg = "Não consegui carregar o login. Confira sua conexão."; render(); return false; }
    try { await window.FBAuth.google(); return true; }
    catch (e) {
      const c = e && e.code || "";
      msg = c === "auth/popup-closed-by-user" || c === "auth/cancelled-popup-request" ? ""
        : c === "auth/popup-blocked" ? "O navegador bloqueou a janela do Google. Permita pop-ups para este site e tente de novo."
        : c === "auth/operation-not-supported-in-this-environment" || c === "auth/web-storage-unsupported" ? "Este navegador não permite o login do Google. Abra o link no Chrome ou no Safari."
        : "Não consegui entrar com o Google. Tente de novo.";
      render(); return false;
    }
  }
  function onAuth(u, err) {
    if (!u) { if (err) { authErr = true; ready = true; render(); } return; }
    const prev = U; U = u; ready = true; authErr = false;
    if (prev && prev.uid === u.uid && prev.anon === u.anon) return;
    if (prev && prev.uid !== u.uid) { mine = { key: "" }; reveal = false; }
    if (!u.anon) syncAccount();
    if (R() && !rec && !bad) { snap = ""; live(); }
    render();
  }
  /* antes de trocar para uma conta Google que já existe, tira a pessoa anônima das festas (os dados vão junto) */
  async function beforeSwitch() {
    const out = [];
    for (const r of Object.values(S.rooms)) {
      if (r.db !== DB || !U) continue;
      try {
        const p = await req("/rooms/" + r.room + "/people/" + U.uid);
        if (p && myKey(r)) { out.push({ room: r.room, p, sk: r.sk }); await req("/rooms/" + r.room + "/people/" + U.uid, "DELETE"); }
      } catch (e) {}
    }
    pending = out;
  }
  let pending = [];
  async function syncAccount() {
    if (!U || U.anon) return;
    try {
      /* traz o que veio de outra conta anônima deste aparelho */
      for (const m of pending.splice(0)) {
        try {
          const cur = await req("/rooms/" + m.room + "/people/" + U.uid);
          if (!cur) { await req("/rooms/" + m.room + "/people/" + U.uid, "PUT", m.p); const r = S.rooms[m.room]; if (r) { r.sk = m.sk; r.skUid = U.uid; } }
        } catch (e) {}
      }
      const idx = (await uapi("")) || {};
      entries(idx).forEach(([room, v]) => {
        if (!/^[0-9a-f]{6,40}$/.test(room) || !v) return;
        const r = S.rooms[room] || (S.rooms[room] = { db: DB, room });
        if (v.t && !r.t) r.t = str(v.t, 50);
        if (v.org) r.org = true;
        if (v.sk && !myKey(r)) { r.sk = v.sk; r.skUid = U.uid; }
      });
      /* guarda na conta as chaves que só existiam neste aparelho */
      for (const r of Object.values(S.rooms)) {
        if (r.db !== DB) continue;
        const i = idx[r.room];
        if (myKey(r) && !(i && i.sk)) await uapi("/" + r.room, "PATCH", { sk: r.sk, t: str(r.t, 50) || "" }).catch(() => {});
      }
      save(); mine = { key: "" }; snap = ""; if (R() && D) changed(true); else { dirty = true; flush(); }
    } catch (e) {}
  }
  function signOutAll() {
    if (!confirm("Sair da sua conta neste aparelho? As festas deixam de aparecer aqui até você entrar de novo.")) return;
    stopLive(); S = { cur: "", rooms: {} }; save(); resetRoom(); U = null; ready = false; render(true);
    window.FBAuth.signOut();
  }
  function account() {
    if (!ready || !U) return null;
    if (U.anon) return h("p", { class: "acct" }, "Sem login neste aparelho. ",
      h("button", { class: "link", type: "button", disabled: work ? "disabled" : null, onclick: async () => { work = "login"; render(); await google(); work = ""; render(); } }, "Entrar com Google"),
      " para usar em outros aparelhos.");
    return h("p", { class: "acct" }, "👤 " + (U.name || U.email || "Conta Google") + " · ",
      h("button", { class: "link", type: "button", onclick: signOutAll }, "Sair da conta"));
  }

  /* ---------- efeitos quando chegam dados novos ---------- */
  function afterData() {
    const r = R(); if (!r || !D) return;
    const m = D.meta || {}, uid = PID(), k = r.room + ":" + uid + ":";
    if (typeof m.t === "string" && r.t !== m.t) { r.t = str(m.t, 50); save(); if (U && !U.anon && D.people && D.people[uid]) uapi("/" + r.room, "PATCH", { t: r.t }).catch(() => {}); }
    if (m.owner && uid && m.owner === uid && !r.org) { r.org = true; save(); }
    /* participante da versão anterior: entra de novo com a conta nova, levando nome, dica e links */
    if (U && m.owner && r.lpid && D.people && D.people[r.lpid] && !D.people[uid] && !once[k + "mig"]) {
      once[k + "mig"] = 1;
      const old = D.people[r.lpid];
      genKeys().then(kk => {
        const p = { n: nm(old), pk: kk.pk }; if (old.w) p.w = str(old.w, 120);
        const l = {}; entries(old.l).forEach(([i, v]) => { if (v && /^https?:\/\//.test(str(v.u, 300))) l[i] = { t: str(v.t, 60), u: str(v.u, 300) }; });
        if (Object.keys(l).length) p.l = l;
        return api("/people/" + uid, "PUT", p).then(() => { r.sk = kk.sk; r.skUid = uid; delete r.lpid; save(); if (U && !U.anon) uapi("/" + r.room, "PATCH", { sk: kk.sk, t: str(r.t, 50) || "" }).catch(() => {}); refresh(); });
      }).catch(() => { delete once[k + "mig"]; });
    }
    /* restrições que ficavam só no aparelho do organizador (versão bem antiga) */
    if (isOrg() && r.mig) {
      const u = {};
      entries(r.mig).forEach(e => (Array.isArray(e[1]) ? e[1] : []).forEach(b => { if (e[0] !== b) u["ex/" + e[0] + "/" + b] = true; }));
      delete r.mig; save();
      if (Object.keys(u).length) write("", "PATCH", u);
    }
    /* abre o meu resultado, cifrado para a minha chave */
    const box = D.res && D.res[uid], sk = myKey(r);
    if (box && sk) {
      const key = JSON.stringify(box);
      if (mine.key !== key) {
        mine = { key, r: null, err: false }; reveal = false;
        unseal(sk, box).then(o => { if (mine.key === key) { mine.r = o; dirty = true; flush(); } })
          .catch(() => { if (mine.key === key) { mine.err = true; dirty = true; flush(); } });
      }
    } else if (!box) mine = { key: "" };
  }

  /* ---------- navegação ---------- */
  function resetRoom() { D = null; snap = ""; mine = { key: "" }; reveal = false; msg = ""; hintGoogle = false; OPEN.clear(); }
  function openRoom(id) { S.cur = id; save(); resetRoom(); render(true); live(); }
  function home() { stopLive(); S.cur = ""; save(); resetRoom(); render(true); }
  function forget(id) {
    const r = S.rooms[id];
    if (r && r.db === DB) uapi("/" + id, "DELETE").catch(() => {});
    delete S.rooms[id]; if (S.cur === id) S.cur = ""; save(); home();
  }
  function join(o) {
    /* só aceita convites para o banco deste app: o login nunca é enviado a outro endereço */
    if (!o || o.u !== DB && !(o.u === "https://amigo-secreto-64e8b-default-rtdb.firebaseio.com" && EMU) || !/^[0-9a-f]{6,40}$/.test(o.r || "")) return false;
    if (!S.rooms[o.r]) S.rooms[o.r] = { db: DB, room: o.r };
    S.cur = o.r; save(); resetRoom(); return true;
  }
  async function readHash() {
    const t = location.hash.slice(1);
    rec = null; bad = false; shown = false;
    if (!t) { loading = false; render(true); if (R()) live(); else stopLive(); return; }
    loading = true; render(true);
    const c = t.charAt(0);
    if (c === "x") { rec = await dec(t); bad = !rec; if (rec) stopLive(); }
    else if (c === "J" || c === "j") {
      try { bad = !join(JSON.parse(td.decode(c === "J" ? ub64u(t.slice(1)) : ub(t.slice(1))))); } catch (e) { bad = true; }
      if (!bad) history.replaceState(null, "", BASE);
    } else bad = true;
    loading = false; render(true);
    if (!rec && !bad) live();
  }

  /* ---------- criar festa (exige conta Google, contra abuso) ---------- */
  async function create() {
    msg = "";
    if (!U || U.anon) {
      work = "create"; render();
      const ok = await google();                  // abre a janela do Google dentro do toque
      if (!ok) { work = ""; render(); return; }
      U = window.FBAuth.user() || U;
    }
    work = "create"; render();
    try {
      const room = rid(6);
      await tok(true);
      await req("/rooms/" + room + "/meta", "PUT", { owner: U.uid, v: "", t: "" });
      S.rooms[room] = { db: DB, room, org: true }; S.cur = room; save();
      uapi("/" + room, "PATCH", { org: true, t: "" }).catch(() => {});
      resetRoom();
    } catch (e) {
      msg = e.status === 401 || e.status === 403 ? "O banco recusou a criação da festa (permissão negada). Se você é a administradora, confira se as regras novas do Firebase foram publicadas."
        : e.status ? "O banco respondeu com erro (HTTP " + e.status + "). Tente de novo em instantes."
        : "Não consegui falar com o banco. Confira sua conexão.";
    }
    work = ""; render(true); if (S.cur) live();
  }
  /* organizador da versão anterior assume a festa com a conta Google */
  async function claimLegacy() {
    msg = "";
    if (!U || U.anon) { work = "claim"; render(); const ok = await google(); if (!ok) { work = ""; render(); return; } }
    work = "claim"; render();
    try {
      await tok(true);
      await api("/meta/owner", "PUT", U.uid);
      await api("/meta/oh", "DELETE").catch(() => {});
      R().org = true; save(); uapi("/" + R().room, "PATCH", { org: true, t: str(R().t, 50) || "" }).catch(() => {});
    } catch (e) { msg = "Não consegui assumir a festa. Talvez outra pessoa já tenha assumido."; }
    work = ""; refresh(); render();
  }

  /* ---------- leitura da sala ---------- */
  function me() { return (D && D.people && D.people[PID()]) || null; }
  function isOrg() { return !!(D && D.meta && D.meta.owner && D.meta.owner === PID()); }
  function people() { return entries(D && D.people).filter(e => e[1] && typeof e[1] === "object").sort((a, b) => nm(a[1]).localeCompare(nm(b[1]), "pt-BR")); }
  function fmtDate(s) { const p = String(s).split("-"); if (p.length !== 3) return String(s); const d = new Date(+p[0], +p[1] - 1, +p[2]); return isNaN(d) ? String(s) : d.toLocaleDateString("pt-BR", { weekday: "short", day: "2-digit", month: "short" }); }
  function daysTo(s) { const p = String(s).split("-").map(Number); if (p.length !== 3 || p.some(isNaN)) return null; const t = new Date(); t.setHours(0, 0, 0, 0); return Math.round((new Date(p[0], p[1] - 1, p[2]) - t) / 864e5); }
  function opts(key) {
    const P = (D && D.people) || {};
    return entries(D[key]).filter(e => e[1] && typeof e[1] === "object").map(e => {
      const vs = (D.votes && D.votes[key] && D.votes[key][e[0]]) || {};
      const who = Object.keys(vs).filter(p => P[p]);
      return { k: e[0], t: str(e[1].t, 60), n: who.length, mine: !!vs[PID()], u: e[1].u };
    }).sort((a, b) => b.n - a.n || (a.k < b.k ? -1 : 1));
  }
  function leadRaw(key) { const o = opts(key); return o.length && o[0].n > 0 ? o[0].t : ""; }
  function revealOpen() { const m = D.meta || {}; if (!m.drawn) return false; if (m.rv) return true; const s = leadRaw("d"), d = s ? daysTo(s) : null; return d !== null && d <= 0; }

  /* ---------- convites e compartilhamento ---------- */
  const inviteLink = () => { const r = R(); return BASE + "#J" + b64u(te.encode(JSON.stringify({ u: DB, r: r.room }))); };
  const title = () => str(D && D.meta && D.meta.t, 50) || "Amigo secreto de Natal";
  const inviteMsg = () => "🎄 " + title() + "! Entre no mural do amigo secreto: adicione sua dica de presente, vote no melhor dia e sugira local e comida:\n" + inviteLink();
  const drawnMsg = () => "🎅 O sorteio do " + title() + " saiu! Abra o mural para ver quem você tirou (só você vê):\n" + inviteLink();
  function wa(m) { window.open("https://wa.me/?text=" + encodeURIComponent(m), "_blank", "noopener"); }
  function copy(text, btn, box) {
    const fb = () => {
      if (box.querySelector("input.cp")) return;
      const i = h("input", { type: "text", class: "cp", readonly: "readonly", value: text.replace(/\n/g, " "), "aria-label": "Texto para copiar", style: "margin-top:8px" });
      box.append(i); i.focus(); i.select();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(() => { btn.textContent = "Copiado ✓"; }, fb); else fb();
  }
  function shareRow(fn) {
    const box = h("div", {}), dis = HOSTED ? null : "disabled";
    return [h("div", { class: "row" },
      h("button", { class: "btn", type: "button", disabled: dis, onclick: () => wa(fn()) }, "WhatsApp"),
      navigator.share ? h("button", { class: "btn alt", type: "button", disabled: dis, onclick: () => { navigator.share({ text: fn() }).catch(() => {}); } }, "Compartilhar") : null,
      h("button", { class: "btn alt", type: "button", disabled: dis, onclick: e => copy(fn(), e.currentTarget, box) }, "Copiar")), box];
  }
  function warn() { return HOSTED ? null : h("p", { class: "err", style: "margin:0 0 14px" }, "⚠️ Você está vendo uma prévia do arquivo, então os convites e links não funcionam aqui. Abra o app pelo endereço do GitHub Pages."); }

  /* ---------- sorteio ---------- */
  function shuffle(a) { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const b = new Uint32Array(1); crypto.getRandomValues(b); const j = b[0] % (i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
  async function draw() {
    const P = people().filter(e => !LEGACY_ID.test(e[0])), m = D.meta || {};
    const nok = P.filter(e => !e[1].pk).map(e => nm(e[1]));
    if (nok.length) { msg = "Ainda sem chave de segurança: " + nok.join(", ") + ". Peça para abrirem o mural de novo."; render(); return; }
    if (P.length < 3) { msg = "O sorteio precisa de pelo menos 3 pessoas."; render(); return; }
    const ids = P.map(e => e[0]), ex = D.ex || {}, cyc = !!m.cyc;
    const blocked = (a, b) => a === b || !!(ex[a] && ex[a][b]) || !!(ex[b] && ex[b][a]);
    let ok = null;
    for (let t = 0; t < 20000 && !ok; t++) {
      const q = shuffle(ids), map = {}; let good = true;
      for (let i = 0; i < ids.length && good; i++) {
        const a = cyc ? q[i] : ids[i], b = cyc ? q[(i + 1) % q.length] : q[i];
        if (blocked(a, b)) good = false; else map[a] = b;
      }
      if (good) ok = map;
    }
    if (!ok) { msg = "Com essas restrições não existe sorteio possível" + (cyc ? " em roda" : "") + ". Remova alguma" + (cyc ? " ou desligue o sorteio em roda" : "") + "."; render(); return; }
    work = "draw"; msg = ""; render();
    const round = rid(4), res = {}, idm = {};
    try { for (const a of ids) { res[a] = await seal(D.people[a].pk, { r: ok[a], rd: round }); idm[a] = true; } }
    catch (e) { work = ""; msg = "Não consegui proteger o sorteio. A chave de alguém está com problema."; render(); return; }
    await write("", "PATCH", { res, "meta/round": round, "meta/drawn": { at: Date.now(), ids: idm }, rev: null });
    work = ""; reveal = false; render();
  }

  /* ---------- ações ---------- */
  async function joinNow() {
    const n = dr.n.replace(/\s+/g, " ").trim().slice(0, 30);
    if (!n) { msg = "Digite seu nome."; render(); return; }
    if (people().some(e => nm(e[1]).toLowerCase() === n.toLowerCase())) { msg = n + " já está no mural. Se for você em outro aparelho, entre com o Google."; render(); return; }
    if (!U) { msg = "Conectando… tente de novo em instantes."; render(); return; }
    work = "join"; msg = ""; render();
    try {
      const k = await genKeys(), r = R(), uid = PID(), p = { n, pk: k.pk };
      if (dr.w.trim()) p.w = dr.w.trim().slice(0, 120);
      await api("/people/" + uid, "PUT", p);
      r.sk = k.sk; r.skUid = uid; save(); dr.w = ""; dr.n = "";
      if (U && !U.anon) uapi("/" + r.room, "PATCH", { sk: k.sk, t: str(r.t, 50) || "" }).catch(() => {});
      hintGoogle = !!(U && U.anon);
    } catch (e) { msg = e.status === 401 || e.status === 403 ? "Esta festa não aceita novas pessoas agora." : "Não consegui entrar. Confira sua conexão."; }
    work = ""; refresh(); render();
  }
  function cleanup(id, u) {
    u["people/" + id] = null; u["res/" + id] = null; u["rev/" + id] = null; u["ex/" + id] = null;
    entries(D.ex).forEach(e => { if (e[0] !== id && e[1] && e[1][id]) u["ex/" + e[0] + "/" + id] = null; });
    entries(D.qa).forEach(e => { if (e[1] && e[1].to === id) u["qa/" + e[0]] = null; });
    entries(D.rev).forEach(e => { if (e[1] === id && e[0] !== id) u["rev/" + e[0]] = null; });
    entries(D.votes).forEach(k => entries(k[1]).forEach(o => { if (o[1] && o[1][id]) u["votes/" + k[0] + "/" + o[0] + "/" + id] = null; }));
    return u;
  }
  function removePerson(id) { const u = cleanup(id, {}); if (D.keys && D.keys[id]) u["keys/" + id] = null; write("", "PATCH", u); }
  function removeLegacy() {
    const u = {};
    people().forEach(([id]) => { if (LEGACY_ID.test(id)) cleanup(id, u); });
    if (D.keys) u.keys = null;
    write("", "PATCH", u);
  }
  /* LGPD: a pessoa apaga tudo o que é dela nesta festa */
  function eraseMe() {
    const r = R(), id = PID();
    if (!me()) return;
    if (!confirm("Apagar seus dados desta festa? Seu nome, dica, links, votos e perguntas para você serão removidos. Isso não pode ser desfeito.")) return;
    write("", "PATCH", cleanup(id, {}), () => {
      delete r.sk; delete r.skUid; save(); mine = { key: "" };
      uapi("/" + r.room, "PATCH", { sk: null }).catch(() => {});
    });
  }
  /* LGPD: o organizador apaga a festa inteira */
  function eraseRoom() {
    if (!confirm("Apagar a festa inteira para todo mundo? O mural, os votos e o sorteio serão removidos. Isso não pode ser desfeito.")) return;
    const id = S.cur;
    api("", "DELETE").then(() => forget(id)).catch(() => { msg = "Não consegui apagar a festa."; render(); });
  }
  function addLink(id) {
    let u = dr.lu.trim(), x;
    if (!u) return;
    if (!/^https?:\/\//i.test(u)) u = "https://" + u;
    try { x = new URL(u); if (!/^https?:$/.test(x.protocol) || !x.hostname.includes(".")) throw 0; } catch (e) { msg = "Esse link não parece válido."; render(); return; }
    if (x.href.length > 300) { msg = "Link longo demais."; render(); return; }
    const t = dr.lt.trim().slice(0, 60) || x.hostname.replace(/^www\./, "");
    write("/people/" + id + "/l/" + rid(4), "PUT", { t, u: x.href }, () => { dr.lt = ""; dr.lu = ""; msg = ""; });
  }

  /* ---------- telas ---------- */
  function googleBox(text) {
    return h("div", { class: "box" },
      h("p", { style: "margin:0 0 10px" }, text),
      h("div", { class: "row" },
        h("button", { class: "btn", type: "button", disabled: work ? "disabled" : null, onclick: async () => { work = "login"; render(); await google(); work = ""; hintGoogle = false; render(); } }, work === "login" ? "Abrindo…" : "Entrar com Google"),
        hintGoogle ? h("button", { class: "btn alt", type: "button", onclick: () => { hintGoogle = false; render(); } }, "Agora não") : null));
  }
  function linkList(p) {
    const l = entries(p && p.l).filter(e => e[1] && /^https?:\/\//i.test(str(e[1].u, 300)));
    if (!l.length) return null;
    return h("span", { class: "lk" }, l.map(e => h("a", { href: str(e[1].u, 300), target: "_blank", rel: "noopener noreferrer nofollow" }, "🔗 " + (str(e[1].t, 60) || "link"))));
  }
  function countdown() {
    const s = leadRaw("d"); if (!s) return null;
    const d = daysTo(s); if (d === null || d < 0) return null;
    return h("p", { class: "count" }, d === 0 ? "🎉 A festa é hoje!" : d === 1 ? "⏳ A festa é amanhã! (" + fmtDate(s) + ")" : "⏳ Faltam " + d + " dias para a festa (" + fmtDate(s) + ")");
  }

  function pollSection(label, key, type, ph, hint) {
    const list = opts(key), top = list.length && list[0].n > 0 ? list[0].k : null, ok = !!me(), org = isOrg(), uid = PID();
    const inp = h("input", { type, value: dr[key] || "", placeholder: ph, maxlength: "60", "aria-label": label, oninput: e => { dr[key] = e.target.value; } });
    return [
      h("h2", {}, label),
      h("ul", {}, list.map(o => h("li", { class: "mini" },
        h("b", {}, (o.k === top ? "🏆 " : "") + (key === "d" ? fmtDate(o.t) : o.t)),
        h("span", { class: "row", style: "align-items:center" },
          h("span", { class: "seen" }, o.n + (o.n === 1 ? " voto" : " votos")),
          h("button", { class: "btn" + (o.mine ? "" : " alt"), type: "button", disabled: ok ? null : "disabled", onclick: () => write("/votes/" + key + "/" + o.k + "/" + uid, o.mine ? "DELETE" : "PUT", true) }, o.mine ? "✓ Meu voto" : "Votar"),
          org ? h("button", { class: "x", type: "button", "aria-label": "Remover opção", onclick: () => write("", "PATCH", { [key + "/" + o.k]: null, ["votes/" + key + "/" + o.k]: null }) }, "×") : null)))),
      list.length ? null : h("p", { class: "hint" }, hint),
      h("div", { class: "row", style: "flex-wrap:nowrap;margin-top:10px" }, inp,
        h("button", { class: "btn", type: "button", disabled: ok ? null : "disabled", onclick: () => {
          const v = inp.value.trim(); if (!v) return;
          if (list.some(o => o.t.toLowerCase() === v.toLowerCase())) { dr[key] = ""; inp.value = ""; return; }
          write("/" + key, "POST", { t: v.slice(0, 60), by: nm(me()), u: uid }, () => { dr[key] = ""; });
        } }, "Sugerir"))
    ];
  }

  function qaItem(q, isMe) {
    const [qid, o] = q, a = str(o.a, 140);
    return h("div", {},
      h("p", {}, "❓ " + str(o.q, 140)),
      a ? h("p", {}, "💬 " + a)
        : isMe ? h("div", { class: "row" },
            h("input", { type: "text", value: dr.a[qid] || "", maxlength: "140", placeholder: "Sua resposta", "aria-label": "Responder: " + str(o.q, 140), oninput: e => { dr.a[qid] = e.target.value; } }),
            h("button", { class: "btn", type: "button", onclick: () => { const v = (dr.a[qid] || "").trim(); if (v) write("/qa/" + qid + "/a", "PUT", v.slice(0, 140), () => { delete dr.a[qid]; }); } }, "Responder"))
        : h("p", { class: "hint" }, "Aguardando resposta"),
      isOrg() || isMe ? h("button", { class: "link", type: "button", style: "min-height:32px;font-size:14px", onclick: () => write("/qa/" + qid, "DELETE") }, "remover pergunta") : null);
  }

  function personCard(e) {
    const [id, p] = e, isMe = id === PID(), ok = !!me(), org = isOrg(), legacy = LEGACY_ID.test(id);
    const others = people().filter(o => o[0] !== id && !LEGACY_ID.test(o[0])), ex = (D.ex && D.ex[id]) || {};
    const qs2 = entries(D.qa).filter(q => q[1] && q[1].to === id).sort((a, b) => a[0] < b[0] ? -1 : 1);
    const links = entries(p.l).filter(l => l[1] && typeof l[1] === "object");
    return h("li", { class: "card" },
      h("div", { class: "top" }, h("b", {}, "🎁 " + nm(p) + (isMe ? " (você)" : "") + (legacy ? " · versão antiga" : "")),
        org && !isMe ? h("button", { class: "x", type: "button", "aria-label": "Remover " + nm(p), onclick: () => { if (confirm("Remover " + nm(p) + " da festa?")) removePerson(id); } }, "×") : null),
      isMe ? [
        h("input", { type: "text", value: str(p.w, 120), placeholder: "Sua dica de presente", "aria-label": "Sua dica de presente", maxlength: "120", onchange: ev => write("/people/" + id + "/w", "PUT", ev.target.value.trim()) }),
        links.length ? h("ul", { class: "links" }, links.map(l => h("li", {},
          /^https?:\/\//i.test(str(l[1].u, 300)) ? h("a", { class: "lnk", href: str(l[1].u, 300), target: "_blank", rel: "noopener noreferrer nofollow" }, "🔗 " + (str(l[1].t, 60) || "link")) : h("span", {}, str(l[1].t, 60)),
          h("button", { class: "x", type: "button", "aria-label": "Remover link", onclick: () => write("/people/" + id + "/l/" + l[0], "DELETE") }, "×")))) : null,
        links.length < 5 ? det("l" + id, "🔗 Adicionar link da lista de desejos",
          h("input", { type: "text", value: dr.lt, placeholder: "O que é (ex.: livro de receitas)", maxlength: "60", "aria-label": "Nome do item", style: "margin-bottom:8px", oninput: ev => { dr.lt = ev.target.value; } }),
          h("div", { class: "row", style: "flex-wrap:nowrap" },
            h("input", { type: "url", value: dr.lu, placeholder: "https://…", maxlength: "300", "aria-label": "Link do item", oninput: ev => { dr.lu = ev.target.value; } }),
            h("button", { class: "btn", type: "button", onclick: () => addLink(id) }, "Salvar"))) : null
      ] : [h("p", { style: "margin:0;color:var(--ink)" }, str(p.w, 120) || "Ainda sem dica"), linkList(p)],
      qs2.length ? h("div", { class: "qa" }, qs2.map(q => qaItem(q, isMe))) : null,
      !isMe && ok && !legacy ? det("q" + id, "❓ Perguntar anonimamente",
        h("div", { class: "row", style: "flex-wrap:nowrap" },
          h("input", { type: "text", value: dr.q[id] || "", maxlength: "140", placeholder: "Ex.: chocolate ou vinho?", "aria-label": "Pergunta anônima para " + nm(p), oninput: ev => { dr.q[id] = ev.target.value; } }),
          h("button", { class: "btn", type: "button", onclick: () => { const q = (dr.q[id] || "").trim(); if (q) write("/qa/" + rid(6), "PUT", { to: id, q: q.slice(0, 140) }, () => { dr.q[id] = ""; }); } }, "Enviar")),
        h("p", { class: "hint" }, "Ninguém fica sabendo quem perguntou. Todo mundo vê a pergunta e a resposta.")) : null,
      org && others.length && !legacy ? det("x" + id, "🚫 Não pode tirar…", others.map(o => h("label", { class: "chk" },
        h("input", { type: "checkbox", checked: ex[o[0]] ? "checked" : null, onchange: ev => write("/ex/" + id + "/" + o[0], ev.target.checked ? "PUT" : "DELETE", true) }), nm(o[1])))) : null);
  }

  function joinBlock() {
    if (me()) return hintGoogle && U && U.anon ? googleBox("Pronto, você está no mural! Para ver seu resultado em outro aparelho (ou se limpar o navegador), entre com o Google.") : null;
    const r = R(), m = D.meta || {};
    if (!m.owner) return r.lorg ? null : h("div", { class: "box warnbox" }, h("p", { style: "margin:0" }, "Esta festa veio da versão anterior do app e está esperando o organizador reativá-la."));
    const P = people(), dis = work || !U ? "disabled" : null;
    return [
      h("h2", {}, "👋 Entre no mural"),
      h("label", { class: "lab" }, "Seu nome", h("input", { type: "text", value: dr.n, maxlength: "30", autocomplete: "given-name", oninput: e => { dr.n = e.target.value; } })),
      h("label", { class: "lab" }, "Sua dica de presente", h("input", { type: "text", value: dr.w, maxlength: "120", placeholder: "Ex.: livros, café, plantas", oninput: e => { dr.w = e.target.value; } })),
      h("button", { class: "btn", type: "button", disabled: dis, onclick: joinNow }, work === "join" ? "Entrando…" : "Entrar no mural"),
      P.length && U && U.anon ? [h("p", { class: "hint", style: "margin-top:14px" }, "Já entrou por outro aparelho usando o Google?"),
        h("button", { class: "btn alt", type: "button", style: "margin-top:8px", disabled: work ? "disabled" : null, onclick: async () => { work = "login"; render(); await google(); work = ""; render(); } }, "Entrar com Google")] : null
    ];
  }

  function resultBlock() {
    const r = R(), m = D.meta || {}, p = me(), uid = PID();
    if (!m.drawn || !p) return null;
    const box = D.res && D.res[uid], head = h("h2", {}, "🎅 Seu amigo secreto");
    if (!box) return [head, h("div", { class: "box warnbox" }, h("p", { style: "margin:0" }, "O sorteio já foi feito, mas você entrou depois. Peça ao organizador para refazer o sorteio."))];
    if (!myKey(r)) return [head, U && U.anon
      ? googleBox("Você entrou no mural por outro aparelho. Entre com a mesma conta Google para ver seu resultado aqui.")
      : h("p", {}, "A chave do seu resultado está no aparelho em que você entrou no mural, sem login. Abra o resultado por lá.")];
    if (mine.err) return [head, h("p", {}, "Não consegui abrir seu resultado neste aparelho. Peça ao organizador para refazer o sorteio.")];
    if (!mine.r) return [head, h("p", {}, "Abrindo seu resultado…")];
    const rp = D.people && D.people[mine.r.r];
    if (!reveal) return [head,
      h("p", {}, "Só você vê este resultado. Confira se ninguém está olhando."),
      h("button", { class: "btn wide", type: "button", style: "margin-top:4px", onclick: () => { reveal = true; render(); } }, "🎁 Mostrar quem eu tirei")];
    const rows = [];
    if (rp) { if (rp.w) rows.push(["Dica", str(rp.w, 120)]); const lk = linkList(rp); if (lk) rows.push(["Lista", lk]); }
    if (m.v) rows.push(["Valor", str(m.v, 40)]);
    const dd = leadRaw("d"), pl = leadRaw("p"), fd = leadRaw("f");
    if (dd) rows.push(["Data", fmtDate(dd)]);
    if (pl) rows.push(["Local", pl]);
    if (fd) rows.push(["Comida", fd]);
    const revd = D.rev && D.rev[uid];
    return [head,
      h("div", { class: "tag" }, h("small", {}, nm(p) + ", você tirou"), h("strong", {}, rp ? nm(rp) : "Alguém que saiu da festa")),
      rp ? null : h("p", { class: "err" }, "Essa pessoa saiu depois do sorteio. Peça ao organizador para refazer."),
      rows.length ? h("dl", {}, rows.map(x => [h("dt", {}, x[0]), h("dd", {}, x[1])])) : null,
      revealOpen() && rp && !revd ? h("button", { class: "btn wide", type: "button", onclick: () => { if (confirm("Mostrar para todo mundo no mural que você tirou " + nm(rp) + "?")) write("/rev/" + uid, "PUT", mine.r.r); } }, "🎉 Revelar no mural") : null,
      h("button", { class: "btn alt wide", type: "button", onclick: () => { reveal = false; render(); } }, "Esconder")];
  }

  function revealList() {
    const P = (D.people) || {};
    const rv = entries(D.rev).filter(e => P[e[0]] && typeof e[1] === "string" && P[e[1]]);
    if (!rv.length) return null;
    return [h("h2", {}, "🎉 Revelações"),
      h("ul", {}, rv.map(e => h("li", { class: "mini" }, h("b", {}, nm(P[e[0]]) + " tirou " + nm(P[e[1]])))))];
  }

  function orgPanel() {
    const m = D.meta || {}, dw = m.drawn, P = people().filter(e => !LEGACY_ID.test(e[0])), n = P.length;
    const old = people().length - P.length;
    const legacyBox = old ? h("div", { class: "box warnbox" },
      h("p", { style: "margin:0 0 8px" }, old + (old === 1 ? " perfil é" : " perfis são") + " da versão anterior do app. Quem abrir o convite de novo entra automaticamente com a conta nova; depois, remova os perfis antigos."),
      h("button", { class: "btn alt", type: "button", onclick: () => { if (confirm("Remover os perfis da versão anterior?")) removeLegacy(); } }, "Remover perfis antigos")) : null;
    const cycBox = h("label", { class: "chk" }, h("input", { type: "checkbox", checked: m.cyc ? "checked" : null, onchange: e => write("/meta/cyc", "PUT", e.target.checked) }), "Sorteio em roda (ninguém tira quem tirou a pessoa)");
    if (!dw) return [h("h2", {}, "🎅 Sorteio"), legacyBox, cycBox,
      h("button", { class: "btn wide", type: "button", disabled: n < 3 || work ? "disabled" : null, onclick: draw }, work === "draw" ? "Sorteando…" : n < 3 ? "Sortear (faltam " + (3 - n) + ")" : "🎅 Sortear " + n + " pessoas")];
    const ids = (dw.ids && typeof dw.ids === "object") ? dw.ids : {};
    const late = P.filter(e => !ids[e[0]]).map(e => nm(e[1]));
    const gone = Object.keys(ids).filter(x => !(D.people && D.people[x])).length;
    return [
      h("h2", {}, "🎅 Sorteio feito!"),
      h("p", {}, "Cada pessoa vê quem tirou aqui no mural, protegido na conta dela. Nem você consegue ver o resultado dos outros."),
      legacyBox,
      late.length || gone ? h("div", { class: "box warnbox" },
        late.length ? h("p", { style: "margin:0 0 6px" }, "Entraram depois do sorteio: " + late.join(", ") + ".") : null,
        gone ? h("p", { style: "margin:0 0 6px" }, gone + (gone === 1 ? " pessoa saiu" : " pessoas saíram") + " depois do sorteio.") : null,
        h("p", { style: "margin:0" }, h("b", {}, "Refaça o sorteio para incluir todo mundo."))) : null,
      h("p", { style: "margin:12px 0 8px" }, "Avise a galera que o sorteio saiu:"), shareRow(drawnMsg),
      h("label", { class: "chk", style: "margin-top:14px" }, h("input", { type: "checkbox", checked: m.rv ? "checked" : null, onchange: e => write("/meta/rv", "PUT", e.target.checked) }), "Liberar a revelação agora"),
      h("p", { class: "hint" }, "No dia mais votado, a revelação libera sozinha: cada um pode mostrar no mural quem tirou."),
      cycBox,
      h("button", { class: "link", type: "button", disabled: work ? "disabled" : null, onclick: () => { if (confirm("Refazer o sorteio? Todo mundo vai tirar de novo.")) draw(); } }, work === "draw" ? "Sorteando…" : "Refazer o sorteio")];
  }

  function footer() {
    const org = isOrg();
    return h("div", { class: "foot" },
      h("div", { class: "row", style: "margin-top:8px" },
        h("button", { class: "link", type: "button", onclick: home }, "Minhas festas"),
        me() ? h("button", { class: "link", type: "button", onclick: eraseMe }, "Apagar meus dados") : null,
        org ? h("button", { class: "link", type: "button", onclick: eraseRoom }, "Apagar a festa") : null,
        h("a", { class: "link", href: "privacidade.html", style: "display:inline-flex;align-items:center" }, "Privacidade"),
        h("button", { class: "link", type: "button", onclick: () => { if (confirm("Esquecer esta festa neste aparelho?" + (U && U.anon && me() ? " Sem login, você não conseguirá voltar a ela como você." : ""))) forget(S.cur); } }, "Esquecer neste aparelho")));
  }

  function roomView() {
    if (!ready) return [h("p", {}, "Conectando…")];
    if (authErr) return [h("h1", {}, "🎄 Amigo Secreto"), h("p", { class: "err" }, "Não consegui conectar. Confira sua internet e recarregue a página.")];
    if (!D) return [account(), h("p", {}, "Carregando o mural…")];
    const r = R(), m = D.meta || {}, P = people(), n = P.length, org = isOrg();
    const out = [account(), h("h1", {}, "🎄 " + (str(m.t, 50) || "Amigo Secreto")), warn(),
      h("p", { class: "err", "aria-live": "polite", style: "margin:0 0 8px" }, msg || (off ? "Sem conexão com o banco. Tentando de novo…" : "")),
      countdown()];
    if (!m.owner && r.lorg) out.push(h("div", { class: "box" },
      h("p", { style: "margin:0 0 10px" }, "Esta festa foi criada na versão anterior do app. Para continuar como organizador(a), entre com sua conta Google. Os participantes entram de novo sozinhos ao abrir o convite."),
      h("button", { class: "btn", type: "button", disabled: work ? "disabled" : null, onclick: claimLegacy }, work === "claim" ? "Abrindo…" : "Entrar com Google e reativar")));
    if (org) out.push(
      h("p", {}, "Convide a galera. Cada amigo entra pelo convite e já aparece no mural."), shareRow(inviteMsg),
      h("label", { class: "lab", style: "margin-top:16px" }, "Nome da festa", h("input", { type: "text", value: str(m.t, 50), placeholder: "Ex.: Natal da família", maxlength: "50", onchange: e => write("/meta/t", "PUT", e.target.value.trim()) })),
      h("label", { class: "lab" }, "Valor sugerido", h("input", { type: "text", value: str(m.v, 40), placeholder: "Ex.: R$ 50", maxlength: "40", onchange: e => write("/meta/v", "PUT", e.target.value.trim()) })));
    else if (m.v) out.push(h("p", {}, "Valor sugerido: ", h("b", {}, str(m.v, 40))));
    out.push(resultBlock(), joinBlock(),
      h("h2", {}, "🎁 Mural de dicas (" + n + ")"),
      n ? h("ul", {}, P.map(personCard)) : h("p", { class: "hint" }, "Ninguém entrou ainda."),
      pollSection("📅 Qual dia?", "d", "date", "", "Sugira uma data e todo mundo vota nos dias que preferir."),
      pollSection("📍 Onde?", "p", "text", "Sugerir um local", "Sugira um local para a festa."),
      pollSection("🍽️ O que vamos comer?", "f", "text", "Sugerir um tipo de comida", "Sugira o que vai rolar de comida."),
      revealList(), org ? orgPanel() : null, footer());
    return out;
  }

  function homeView() {
    const rs = Object.values(S.rooms).filter(x => x && x.room);
    const needLogin = !U || U.anon;
    return [
      account(),
      h("h1", {}, "🎄 Amigo Secreto"),
      h("p", {}, "Crie a festa, convide a galera e deixe todo mundo adicionar dicas, votar no mural e ver quem tirou, sem ninguém espiar."),
      h("p", { class: "err", "aria-live": "polite" }, authErr ? "Não consegui conectar. Confira sua internet e recarregue a página." : msg),
      h("button", { class: "btn wide", type: "button", disabled: work || !ready || authErr ? "disabled" : null, onclick: create }, work === "create" ? "Criando…" : needLogin ? "Entrar com Google e criar uma festa" : "Criar uma festa"),
      needLogin ? h("p", { class: "hint", style: "text-align:center" }, "Para criar uma festa é preciso entrar com o Google. Os convidados entram sem login.") : null,
      h("p", { class: "hint", style: "margin-top:18px;text-align:center" }, "Sem anúncios e sem rastreamento. ", h("a", { href: "privacidade.html", style: "color:inherit" }, "Política de privacidade")),
      rs.length ? [h("h2", {}, "🎄 Minhas festas"), h("ul", {}, rs.map(x => h("li", { class: "mini" },
        h("b", {}, (x.t || "Festa " + x.room.slice(0, 4)) + (x.org ? " · organizador" : "")),
        h("span", { class: "row", style: "align-items:center" },
          h("button", { class: "btn", type: "button", onclick: () => openRoom(x.room) }, "Abrir"),
          h("button", { class: "x", type: "button", "aria-label": "Esquecer esta festa", onclick: () => { if (confirm("Esquecer esta festa neste aparelho?")) forget(x.room); } }, "×")))))] : null
    ];
  }

  /* ---------- links de resultado da primeira versão (#x…) ---------- */
  async function dec(t) {
    try {
      if (t.length < 90 || t.length % 2 === 0) return null;
      const s = t.slice(1), key = await sub.importKey("raw", ub(s.slice(0, 32)), "AES-GCM", false, ["decrypt"]);
      const pt = await sub.decrypt({ name: "AES-GCM", iv: ub(s.slice(32, 56)) }, key, ub(s.slice(56)));
      const o = JSON.parse(td.decode(pt)); return o && o.g && o.r ? o : null;
    } catch (e) { return null; }
  }
  function recView() {
    if (!shown) return [
      h("p", { class: "hand" }, "🎄 Amigo secreto de"), h("div", { class: "who" }, rec.g),
      h("p", {}, "Só " + rec.g + " deve ver a próxima tela. Confira se ninguém está olhando."),
      h("button", { class: "btn wide", type: "button", onclick: () => { shown = true; render(); } }, "🎁 Mostrar quem eu tirei")];
    const rows = [["Dicas de presente", rec.w], ["Valor", rec.v], ["Data", rec.d], ["Local", rec.l], ["Comida", rec.f]].filter(x => x[1]);
    const a = Object.keys(rec.a || {});
    return [
      h("div", { class: "tag" }, h("small", {}, rec.g + ", você tirou"), h("strong", {}, rec.r)),
      rows.length ? h("dl", {}, rows.map(x => [h("dt", {}, x[0]), h("dd", {}, String(x[1]))])) : null,
      a.length ? h("details", { class: "wall", style: "margin-top:22px" }, h("summary", {}, "🎁 Mural de dicas de todo mundo"), a.map(n => h("p", {}, h("b", {}, n + ": "), h("span", {}, String(rec.a[n]))))) : null,
      h("p", { style: "margin-top:20px" }, "Guarde o segredo. Se o organizador refez o sorteio, este link pode não valer mais."),
      h("button", { class: "btn alt wide", type: "button", onclick: () => { shown = false; render(); } }, "Esconder")];
  }

  function render(top) {
    dirty = false;
    let c;
    if (loading) c = [h("p", {}, "Abrindo…")];
    else if (rec) c = recView();
    else if (bad) c = [h("h1", {}, "Link inválido"), h("p", {}, "Este link está incompleto, foi alterado ou é de outro site. Peça ao organizador para enviar de novo."),
      h("button", { class: "btn alt wide", type: "button", onclick: () => { history.replaceState(null, "", BASE); readHash(); } }, "Ir para o início")];
    else if (R()) c = roomView();
    else c = homeView();
    app.replaceChildren();
    [c].flat(Infinity).forEach(x => { if (x) app.append(x); });
    if (top === true) window.scrollTo(0, 0);
  }

  /* um toque em andamento segura o redesenho, para o clique não cair num botão que sumiu */
  document.addEventListener("pointerdown", () => { ptr = true; }, true);
  const release = () => setTimeout(() => { ptr = false; flush(); }, 350);
  document.addEventListener("pointerup", release, true);
  document.addEventListener("pointercancel", release, true);
  setInterval(flush, 400);

  load(); readHash();
  window.addEventListener("hashchange", readHash);
  if (window.FBAuth) {
    window.FBAuth.onChange(onAuth);
    window.FBAuth.beforeSwitch(beforeSwitch);
    window.FBAuth.start(EMU);
  } else { authErr = true; ready = true; render(); }
  setTimeout(() => { if (!ready) { authErr = true; ready = true; render(); } }, 15000);
  if (HOSTED && "serviceWorker" in navigator && !EMU && (location.protocol === "https:" || LOCAL))
    navigator.serviceWorker.register("sw.js").catch(() => {});
})();

/* música de fundo: caixinha de música tocando "Jingle Bells" (domínio público), gerada no navegador */
(() => {
  "use strict";
  const KEY = "amigo-secreto-musica", btn = document.getElementById("music");
  const AC = window.AudioContext || window.webkitAudioContext;
  if (!AC) { btn.hidden = true; return; }
  const F = { C3: 130.81, D3: 146.83, F3: 174.61, G3: 196.0, C5: 523.25, D5: 587.33, E5: 659.25, F5: 698.46, G5: 783.99 };
  const A = [["E5",1],["E5",1],["E5",2],["E5",1],["E5",1],["E5",2],["E5",1],["G5",1],["C5",1.5],["D5",.5],["E5",4]];
  const MEL = [].concat(
    A, [["F5",1],["F5",1],["F5",1.5],["F5",.5],["F5",1],["E5",1],["E5",1],["E5",.5],["E5",.5],["E5",1],["D5",1],["D5",1],["E5",1],["D5",2],["G5",2]],
    A, [["F5",1],["F5",1],["F5",1.5],["F5",.5],["F5",1],["E5",1],["E5",1],["E5",.5],["E5",.5],["G5",1],["G5",1],["F5",1],["D5",1],["C5",4]]);
  const BASS = ["C3","C3","C3","C3","F3","C3","D3","G3","C3","C3","C3","C3","F3","C3","G3","C3"];
  const BEAT = 0.42, LOOP = 66;                    /* 64 tempos de música + 2 de pausa */
  let ctx = null, out = null, on = false, t0 = 0, next = 0, timer = null;
  try { on = localStorage.getItem(KEY) === "1"; } catch (e) {}

  function note(freq, when, dur, vol) {
    const o = ctx.createOscillator(), o2 = ctx.createOscillator(), g = ctx.createGain();
    o.type = "triangle"; o.frequency.value = freq; o2.type = "sine"; o2.frequency.value = freq * 2;
    g.gain.setValueAtTime(0.0001, when);
    g.gain.exponentialRampToValueAtTime(vol, when + 0.008);
    g.gain.exponentialRampToValueAtTime(0.0001, when + Math.max(0.35, dur * 0.95) + 0.4);
    o.connect(g); o2.connect(g); g.connect(out);
    const end = when + dur + 0.5;
    o.start(when); o2.start(when); o.stop(end); o2.stop(end);
  }
  /* agenda as notas com antecedência para o ritmo não falhar */
  function schedule() {
    const horizon = ctx.currentTime + 0.6;
    while (true) {
      const loop = Math.floor(next / LOOP), pos = next - loop * LOOP;
      const at = t0 + next * BEAT;
      if (at > horizon) break;
      let beat = 0, step = null;
      for (const [n, d] of MEL) { if (Math.abs(beat - pos) < 1e-6) { step = [n, d]; break; } beat += d; }
      if (step) note(F[step[0]], at, step[1] * BEAT, 0.5);
      if (pos < 64 && pos % 4 === 0) note(F[BASS[pos / 4]], at, 3.5 * BEAT, 0.28);
      next += 0.5;                                  /* menor duração da melodia: meio tempo */
    }
  }
  function start() {
    if (!ctx) {
      ctx = new AC(); out = ctx.createGain(); out.gain.value = 0.09; out.connect(ctx.destination);
    }
    ctx.resume();
    if (!timer) { t0 = ctx.currentTime + 0.1; next = 0; timer = setInterval(schedule, 150); schedule(); }
  }
  function stop() { clearInterval(timer); timer = null; if (ctx) { const c = ctx; ctx = null; out = null; c.close().catch(() => {}); } }
  function paint() { btn.setAttribute("aria-pressed", on ? "true" : "false"); btn.textContent = on ? "🎵" : "🔇"; btn.title = on ? "Desligar música" : "Ligar música de fundo"; }
  btn.addEventListener("click", () => {
    on = !on; try { localStorage.setItem(KEY, on ? "1" : "0"); } catch (e) {}
    on ? start() : stop(); paint();
  });
  /* o navegador só deixa tocar som depois de um toque: se estava ligada, volta no primeiro toque */
  const first = e => { if (e.target === btn) return; document.removeEventListener("pointerdown", first, true); if (on && !timer) start(); };
  document.addEventListener("pointerdown", first, true);
  document.addEventListener("visibilitychange", () => { if (!ctx) return; document.hidden ? ctx.suspend() : (on && ctx.resume()); });
  paint();
})();
