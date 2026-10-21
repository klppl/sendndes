"use strict";
// send n*des server: admin page. Same look and words as the Mac app (see coordination/ndesd-ux-v1.md).
// First visit: claim (setup code + password). Then a guided setup (link vault, reachability, connect),
// then a dashboard. Everything goes through /api/*; the server keeps all state.
(() => {
const app = document.getElementById("app");
const MIB = 1024 * 1024;
const SVGNS = "http://www.w3.org/2000/svg";

// ---------------- tiny DOM helpers ----------------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  setAttrs(el, attrs);
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}
function setAttrs(el, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.setAttribute("class", v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
}
function fill(el, ...kids) { el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false)); }

let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
}

async function api(method, path, body) {
  const opt = { method, headers: { "X-Ndes-Admin": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (res.status === 401 && path !== "/api/login") { boot(); throw new Error("Please sign in again"); }
  if (!res.ok) throw new Error(sentence(data.error || "Something went wrong (" + res.status + ")"));
  return data;
}
function sentence(m) { m = String(m); return m.charAt(0).toUpperCase() + m.slice(1) + (/[.!?]$/.test(m) ? "" : "."); }

// Runs a button's action with a busy state. Errors go to `out` (a banner slot) or a toast.
async function act(btn, fn, out) {
  const label = btn.textContent;
  btn.disabled = true;
  if (out) fill(out);
  try { await fn(); }
  catch (e) { if (out) fill(out, banner("bad", e.message)); else toast(e.message); }
  finally { btn.disabled = false; if (btn.textContent !== label && btn.dataset.keep !== "1") btn.textContent = label; }
}

function banner(kind, ...text) { return h("div", { class: "banner " + kind, role: kind === "bad" ? "alert" : "status" }, h("span", {}, ...text)); }
function pill(kind, text) { return h("span", { class: "pill " + kind }, text); }
function btn(label, cls, onclick, extra) { return h("button", Object.assign({ class: "btn " + (cls || ""), type: "button", onclick }, extra || {}), label); }

function fmtBytes(n) {
  if (n == null || n < 0) return "unknown";
  const u = ["bytes", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + u[i];
}
function ago(sec) {
  const d = Date.now() / 1000 - sec;
  if (d < 45) return "just now";
  if (d < 3600) return Math.round(d / 60) + " min ago";
  if (d < 86400) return Math.round(d / 3600) + " h ago";
  if (d < 172800) return "yesterday";
  return new Date(sec * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

async function copy(text, label) {
  try { await navigator.clipboard.writeText(text); toast(label + " copied"); }
  catch (_) { toast("Couldn't copy. Select the text and copy it by hand."); }
}

// ---------------- Aster (same geometry as app/Sources/sendndes/Mascot.swift) ----------------

const ARM_ANGLES = [30, 90, 150];
function heartPath(cx, cy, r) {
  return `M${cx} ${cy + r * 0.9} C${cx - r * 1.9} ${cy - r * 0.2} ${cx - r * 0.9} ${cy - r * 1.6} ${cx} ${cy - r * 0.5}` +
    ` C${cx + r * 0.9} ${cy - r * 1.6} ${cx + r * 1.9} ${cy - r * 0.2} ${cx} ${cy + r * 0.9}Z`;
}
function aster(mood, size) {
  const L = 94, T = 23.5, O = 3.5;
  const arms = (cls, grow) => s("g", { class: cls }, ARM_ANGLES.map((a) =>
    s("rect", { x: 50 - (L + grow) / 2, y: 50 - (T + grow) / 2, width: L + grow, height: T + grow, rx: (T + grow) / 2, transform: `rotate(${a} 50 50)` })));
  const ex = [42.65, 57.35], ey = 46;
  const big = mood === "wow";
  const eyes = s("g", { class: "eyes" });
  for (const x of ex) {
    if (mood === "asleep") eyes.append(s("path", { class: "stroke", d: `M${x - 4.6} ${ey - 0.5} Q${x} ${ey + 3.5} ${x + 4.6} ${ey - 0.5}` }));
    else if (mood === "smitten") eyes.append(s("path", { class: "heart", d: heartPath(x, ey, 5) }));
    else {
      const rx = big ? 3.75 : 3.1, ry = big ? 5.25 : 4.4;
      eyes.append(s("ellipse", { class: "fill", cx: x, cy: ey, rx, ry }));
      eyes.append(s("circle", { class: "shine", cx: x + rx * 0.35, cy: ey - ry * 0.45, r: rx * 0.36 }));
    }
  }
  const mouths = {
    happy: () => s("path", { class: "stroke", d: "M44 55.2 Q50 61.2 56 55.2" }),
    asleep: () => s("path", { class: "stroke", d: "M47 57.3 Q50 58.6 53 57.3" }),
    wow: () => s("ellipse", { class: "fill", cx: 50, cy: 58.5, rx: 3, ry: 4 }),
    oops: () => s("circle", { class: "stroke", cx: 50, cy: 58, r: 2.4 }),
    working: () => s("path", { class: "stroke", d: "M46 57 Q50 59.6 54 57" }),
    smitten: () => s("path", { class: "fill", d: "M43 55 L57 55 Q56.4 63.5 50 63.5 Q43.6 63.5 43 55Z" }),
  };
  const hot = mood === "smitten";
  const face = s("g", { class: "face" }, eyes,
    s("circle", { class: "cheek", cx: hot ? 35.5 : 36, cy: 54.5, r: hot ? 3.75 : 2.5 }),
    s("circle", { class: "cheek", cx: hot ? 64.5 : 64, cy: 54.5, r: hot ? 3.75 : 2.5 }),
    (mouths[mood] || mouths.happy)());
  const extra = [];
  if (mood === "asleep") extra.push(s("text", { class: "zzz", x: 86, y: 24 }, "z"), s("text", { class: "zzz small", x: 95, y: 11 }, "z"));
  const svg = s("svg", { class: "aster " + mood, viewBox: "-6 -6 112 112", width: size, height: size, "aria-hidden": "true", focusable: "false" },
    s("g", { class: "body" }, s("g", { class: "arms" }, arms("outline", O * 2), arms("petal", 0)), face, extra));
  svg.addEventListener("click", () => { svg.classList.remove("poke"); void svg.getBoundingClientRect(); svg.classList.add("poke"); });
  return svg;
}

function wordmark() {
  return h("div", { class: "brand" }, aster("happy", 40),
    h("span", { class: "wordmark" }, "send n", h("span", { class: "ast" }, "*"), "des"), h("span", { class: "tag" }, "server"));
}

// ---------------- claim (first visit) and sign-in ----------------

function claimScreen() {
  const code = h("input", { id: "code", class: "code", autocomplete: "off", spellcheck: "false", placeholder: "XXXXX-XXXXX", maxlength: "11", "aria-describedby": "code-help" });
  const pw = h("input", { id: "pw", type: "password", autocomplete: "new-password" });
  const pw2 = h("input", { id: "pw2", type: "password", autocomplete: "new-password" });
  const cLen = h("li", {}, "At least 10 characters");
  const cSame = h("li", {}, "Both passwords match");
  const cCode = h("li", {}, "Setup code has 10 characters");
  const out = h("div", {});
  const go = btn("Claim this server", "primary", () => act(go, async () => {
    await api("POST", "/api/setup", { code: code.value, password: pw.value });
    boot();
  }, out));
  const update = () => {
    const raw = code.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 10);
    const fmt = raw.length > 5 ? raw.slice(0, 5) + "-" + raw.slice(5) : raw;
    if (code.value !== fmt) code.value = fmt;
    const ok = [raw.length === 10, pw.value.length >= 10, pw.value !== "" && pw.value === pw2.value];
    cCode.classList.toggle("met", ok[0]); cLen.classList.toggle("met", ok[1]); cSame.classList.toggle("met", ok[2]);
    go.disabled = !ok.every(Boolean);
  };
  for (const el of [code, pw, pw2]) el.addEventListener("input", update);
  pw2.addEventListener("keydown", (e) => { if (e.key === "Enter" && !go.disabled) go.click(); });
  update();
  fill(app, h("section", { class: "sticker card narrow" },
    h("div", { class: "hero-title" }, aster("wow", 104),
      h("h1", {}, "Hi! Let's claim this server."),
      h("p", { class: "soft" }, "Prove it's yours with the one-time setup code, then choose a password for this page.")),
    h("label", { class: "field", for: "code" }, h("span", { class: "field-label" }, "Setup code"), code),
    h("details", { class: "plain", id: "code-help" }, h("summary", {}, "Where's the code?"),
      h("p", { class: "small" }, "ndesd prints it when it starts. With Docker: ", h("code", {}, "docker compose logs ndesd"),
        ". It's also saved as ", h("code", {}, "setup-code"), " in the data folder and works once.")),
    h("label", { class: "field", for: "pw" }, h("span", { class: "field-label" }, "Admin password"), pw),
    h("label", { class: "field", for: "pw2" }, h("span", { class: "field-label" }, "Repeat password"), pw2),
    h("ul", { class: "checks" }, cCode, cLen, cSame),
    out,
    h("div", { class: "actions" }, h("span", { class: "grow" }), go)));
  code.focus();
}

function loginScreen() {
  const pw = h("input", { id: "pw", type: "password", autocomplete: "current-password", placeholder: "Admin password", "aria-label": "Admin password" });
  const go = h("button", { class: "go", type: "button", "aria-label": "Sign in", disabled: true }, "→");
  const out = h("div", {});
  const card = h("section", { class: "sticker card narrow" });
  const submit = async () => {
    await act(go, async () => {
      try { await api("POST", "/api/login", { password: pw.value }); }
      catch (e) { pw.value = ""; card.classList.remove("shake"); void card.offsetWidth; card.classList.add("shake"); throw e; }
      boot();
    }, out);
    go.disabled = pw.value === "";
  };
  go.addEventListener("click", submit);
  pw.addEventListener("input", () => { go.disabled = pw.value === ""; });
  pw.addEventListener("keydown", (e) => { if (e.key === "Enter" && pw.value) submit(); });
  fill(card,
    h("div", { class: "hero-title" }, aster("asleep", 104),
      h("h1", {}, "The server is napping."),
      h("p", { class: "soft" }, "Your admin password wakes this page up.")),
    h("div", { class: "inline-field" }, pw, go),
    out);
  fill(app, card);
  pw.focus();
}

// ---------------- shared state ----------------

let S = null;            // last /api/status
let ifaces = [];
let poll = null;
let view = null;         // {name, redraw()} of what is on screen

async function refresh() {
  S = await api("GET", "/api/status");
  if (view && view.redraw) view.redraw();
}
function startPolling(ms) {
  clearInterval(poll);
  poll = setInterval(() => { if (!document.hidden) refresh().catch(() => {}); }, ms);
}

function splitListen(l) {
  const i = l.lastIndexOf(":");
  return [l.slice(0, i).replace(/^\[|\]$/g, ""), l.slice(i + 1)];
}
function isLoop(host) { return host === "127.0.0.1" || host === "localhost" || host === "::1"; }

// The address devices use. A wildcard listen uses the name this page was opened with.
function connectURL() {
  const [host, port] = splitListen(S.sync.settings.listen);
  let name = host, guessed = false;
  if (host === "0.0.0.0" || host === "::" || host === "") { name = location.hostname; guessed = true; }
  if (isLoop(host)) name = "127.0.0.1";
  if (name.includes(":")) name = "[" + name + "]";
  return { url: (S.sync.settings.tls_cert ? "https" : "http") + "://" + name + ":" + port, guessed, loopback: isLoop(host) };
}

function topBar(withSignOut) {
  return h("header", { class: "top" }, wordmark(),
    withSignOut ? btn("Sign out", "quiet small", (e) => act(e.currentTarget, async () => {
      await api("POST", "/api/logout"); clearInterval(poll); boot();
    })) : null);
}

// ---------------- pieces used by setup and the dashboard ----------------

// Paste box for the vault's server keys. Saves by itself once both lines are there.
function keysForm(onLinked) {
  const ta = h("textarea", { id: "keys", spellcheck: "false", autocomplete: "off", "aria-label": "Server keys",
    placeholder: "inbox_pub: …\nk_auth: …" });
  const cPub = h("li", {}, "inbox_pub");
  const cAuth = h("li", {}, "k_auth");
  const out = h("div", {});
  const save = btn("Link vault", "primary", () => act(save, async () => {
    S.sync = await api("POST", "/api/keys", { text: ta.value });
    ta.value = "";
    update();
    await refresh();
    onLinked();
  }, out));
  let auto = null;
  function update() {
    const has = (k) => new RegExp("^\\s*" + k + "\\s*[:=]\\s*\\S{20,}", "m").test(ta.value);
    const a = has("inbox_pub"), b = has("k_auth");
    cPub.classList.toggle("met", a); cAuth.classList.toggle("met", b);
    save.disabled = !(a && b);
    clearTimeout(auto);
    if (a && b) auto = setTimeout(() => { if (!save.disabled) save.click(); }, 350);
  }
  ta.addEventListener("input", update);
  update();
  return { el: h("div", {}, ta, h("ul", { class: "checks row" }, cPub, cAuth), out, h("div", { class: "actions" }, h("span", { class: "grow" }), save)), focus: () => ta.focus() };
}

// Reachability: a choice between situations, not between raw addresses.
function reachForm(opts) {
  const st = S.sync.settings;
  const [curHost, curPort] = splitListen(st.listen);
  const choices = [];
  for (const i of ifaces.filter((x) => x.kind === "tailscale"))
    choices.push({ host: i.addr, badge: "ts", glyph: "T", title: "Tailscale", rec: true, ack: "implicit",
      desc: "Your devices on the same tailnet reach " + i.addr + ". Tailscale encrypts the connection." });
  choices.push({ host: "127.0.0.1", badge: "px", glyph: "⇄", title: "A proxy on this machine", ack: "none",
    desc: "tailscale serve, Caddy or Cloudflare Tunnel adds HTTPS and forwards to this machine. Nothing else can reach it directly." });
  for (const i of ifaces.filter((x) => x.kind === "lan"))
    choices.push({ host: i.addr, badge: "lan", glyph: "⌂", title: "Local network · " + i.addr, ack: "ask",
      desc: "Devices on this network (home Wi-Fi). Plain HTTP: only on a network you trust." });
  for (const i of ifaces.filter((x) => x.kind === "public"))
    choices.push({ host: i.addr, badge: "all", glyph: "!", title: "Public address · " + i.addr, ack: "ask",
      desc: "Reachable from the internet over plain HTTP. Not recommended without HTTPS." });
  choices.push({ host: "0.0.0.0", badge: "all", glyph: "✱", title: "Every network interface", ack: "ask",
    desc: "For Docker (the port mapping decides who gets in) or when your firewall does the work." });
  if (!choices.some((c) => c.host === curHost))
    choices.push({ host: curHost, badge: "lan", glyph: "•", title: "Saved address · " + curHost, ack: isLoop(curHost) ? "none" : "ask", desc: "The address set earlier." });

  let pick = choices.find((c) => c.host === curHost) || choices[0];
  if (opts.preferTailscale && isLoop(curHost) && choices[0].rec) pick = choices[0];
  const ack = h("input", { type: "checkbox", id: "ack" });
  ack.checked = !!st.ack_plain_http;
  const ackRow = h("label", { class: "check", for: "ack" }, ack,
    h("span", {}, "I understand traffic to this address isn't encrypted by send n*des, and I trust this network (or there's HTTPS in front)."));
  const port = h("input", { id: "port", type: "number", min: "1", max: "65535", value: curPort });
  const out = h("div", {});
  const list = h("div", { class: "choices", role: "radiogroup", "aria-label": "Reachability" });

  function draw() {
    fill(list, choices.map((c, n) => {
      const radio = h("input", { type: "radio", name: "reach", id: "reach" + n, checked: c === pick });
      radio.addEventListener("change", () => { pick = c; draw(); });
      return h("label", { class: "choice" + (c === pick ? " on" : ""), for: "reach" + n }, radio,
        h("span", { class: "badge " + c.badge, "aria-hidden": "true" }, c.glyph),
        h("span", { class: "t" }, c.title, c.rec ? h("span", { class: "rec" }, "Recommended") : null),
        h("span", { class: "d" }, c.desc),
        c === pick && c.ack === "ask" ? h("span", { class: "more" }, ackRow) : null);
    }));
    update();
  }
  function update() { save.disabled = pick.ack === "ask" && !ack.checked && !st.tls_cert; }
  ack.addEventListener("change", update);

  const save = btn(opts.saveLabel || "Save", "primary", () => act(save, async () => {
    const host = pick.host.includes(":") ? "[" + pick.host + "]" : pick.host;
    const now = S.sync.settings;
    S.sync = await api("POST", "/api/settings", Object.assign({}, now, {
      listen: host + ":" + port.value,
      ack_plain_http: pick.ack === "implicit" || (pick.ack === "ask" && ack.checked),
      tls_cert: now.tls_cert || "", tls_key: now.tls_key || "",
    }));
    if (!S.sync.running && !S.sync.stopped) await api("POST", "/api/server/start").catch(() => {});
    await refresh();
    if (S.sync.error) throw new Error(sentence(S.sync.error));
    if (opts.onSaved) opts.onSaved(); else toast("Saved. The inbox is listening on " + connectURL().url);
  }, out));
  draw();
  return h("div", {}, list,
    h("details", { class: "plain" }, h("summary", {}, "Port"),
      h("label", { class: "field", for: "port" }, h("span", { class: "field-label" }, "Sync port (not this page's port)"), port)),
    out, h("div", { class: "actions" }, opts.back || null, h("span", { class: "grow" }), save));
}

// Address + token for a device, with copy buttons.
function connectBlock() {
  const c = connectURL();
  const tokVal = h("span", { class: "val", "aria-label": "Access token" }, "•••••••• •••••••• ••••••••");
  let shown = false;
  const reveal = btn("Show", "small", () => act(reveal, async () => {
    if (shown) { shown = false; tokVal.textContent = "•••••••• •••••••• ••••••••"; reveal.textContent = "Show"; return; }
    tokVal.textContent = (await api("GET", "/api/token")).token; shown = true; reveal.dataset.keep = "1"; reveal.textContent = "Hide";
  }));
  return h("div", {},
    h("span", { class: "field-label" }, "Server address"),
    h("div", { class: "copyrow" }, h("span", { class: "val" }, c.url),
      h("span", { class: "btns" }, btn("Copy", "small primary", () => copy(c.url, "Address")))),
    h("span", { class: "field-label tokenlabel" }, "Access token"),
    h("div", { class: "copyrow" }, tokVal,
      h("span", { class: "btns" }, reveal, btn("Copy", "small primary", (e) => act(e.currentTarget, async () => copy((await api("GET", "/api/token")).token, "Token"))))),
    c.guessed ? banner("info", "This server listens on every interface, so the address uses the name you opened this page with. Use whatever name or IP your devices reach this machine by.") : null,
    c.loopback ? banner("info", "This address only works on this machine. With a proxy (tailscale serve, Caddy, a tunnel), give your devices the proxy's https address instead.") : null);
}

// ---------------- guided setup ----------------

function stepper(now) {
  const names = ["Link your vault", "Reachability", "Connect"];
  return h("ol", { class: "steps", "aria-label": "Setup progress" }, names.map((n, i) =>
    h("li", { class: i < now ? "done" : i === now ? "now" : "", "aria-current": i === now ? "step" : false },
      h("span", { class: "dot" }, i < now ? "✓" : String(i + 1)), h("span", {}, n))));
}

function setupFlow(start) {
  let step = start;
  let baseline = null;   // inbox count when the connect step opened
  const box = h("div", { class: "wizard" });
  fill(app, topBar(true), box);

  function draw() {
    if (step === 0) {
      const f = keysForm(() => { step = 1; draw(); });
      fill(box, stepper(0), h("section", { class: "sticker card" },
        h("div", { class: "hero-title" }, aster("happy", 92), h("h2", {}, "Link your vault"),
          h("p", { class: "soft" }, "In the Mac app open Settings → Server → Copy Server Keys (or run ", h("code", {}, "ndes server-config"), "), then paste here.")),
        f.el,
        h("p", { class: "note" }, "These keys let the server seal files for your vault. They can't open anything, but they can't be changed later either: give them only to your own server.")));
      f.focus();
      view = { redraw() {} };
    } else if (step === 1) {
      fill(box, stepper(1), h("section", { class: "sticker card" },
        h("div", { class: "hero-title" }, aster("happy", 92), h("h2", {}, "How will your devices reach it?"),
          h("p", { class: "soft" }, "Pick the situation that matches yours. You can change it later.")),
        S.sync.fingerprint ? banner("ok", "Vault linked. Key check ", h("b", {}, S.sync.fingerprint), ", the same value the Mac app showed when you copied the keys.") : null,
        reachForm({ saveLabel: "Continue", preferTailscale: true, onSaved: () => { step = 2; draw(); },
          back: btn("Back", "quiet", () => { step = 0; draw(); }) })));
      view = { redraw() {} };
    } else {
      baseline = baseline == null ? S.file_count : baseline;
      const live = h("div", {});
      const mascot = h("div", {});
      const done = btn("Finish", "primary", () => act(done, async () => {
        S.sync = await api("POST", "/api/setup/finish");
        dashboard();
      }));
      fill(box, stepper(2), h("section", { class: "sticker card" },
        h("div", { class: "hero-title" }, mascot, h("h2", {}, "Connect your Mac"),
          h("p", { class: "soft" }, "In the Mac app open Send and paste these two. The token stays in your Mac's keychain.")),
        connectBlock(), live,
        h("div", { class: "actions" }, btn("Back", "quiet", () => { step = 1; draw(); }), h("span", { class: "grow" }), done)));
      const drawLive = () => {
        const arrived = S.file_count > baseline;
        fill(mascot, aster(arrived ? "smitten" : "happy", 92));
        fill(live, arrived
          ? banner("ok", h("b", {}, "It works! "), "A file just arrived. It waits here until your vault pulls it in.")
          : h("div", { class: "banner wait", role: "status" }, h("i", { class: "spinner", "aria-hidden": "true" }),
              h("span", {}, "Waiting for a first file… Send any file from the Mac app to test the connection.")));
        if (arrived) { done.textContent = "Done, show my server"; startPolling(5000); }
      };
      drawLive();
      view = { redraw: () => { if (S.file_count > baseline || S.file_count < baseline) drawLive(); } };
      startPolling(2000);
      return;
    }
    startPolling(5000);
  }
  draw();
}

// ---------------- dashboard ----------------

function heroState() {
  const { sync } = S;
  const c = connectURL();
  if (!sync.running && sync.error)
    return { mood: "oops", pill: pill("bad", "Error"), title: "The inbox couldn't start.", text: sentence(sync.error), act: "start", actLabel: "Try again" };
  if (!sync.running)
    return { mood: "asleep", pill: pill("off", "Closed"), title: "Your inbox is closed.", text: "Devices can't send files until you open it.", act: "start", actLabel: "Open the inbox" };
  if (c.loopback)
    return { mood: "happy", pill: pill("ok", "Open"), title: "Open on this machine.", text: "Right if a proxy (tailscale serve, Caddy, a tunnel) forwards to it. Otherwise pick a network under Reachability.", url: c.url, act: "stop", actLabel: "Close" };
  return { mood: "happy", pill: pill("ok", "Open"), title: "Your inbox is open.", text: "Devices send to", url: c.url, act: "stop", actLabel: "Close" };
}

function dashboard() {
  const hero = h("section", { class: "sticker hero" });
  const inbox = h("section", { class: "sticker card" });
  const connect = h("section", { class: "sticker card" },
    h("div", { class: "card-head" }, h("h2", {}, "Connect a device")),
    h("p", { class: "soft small" }, "Paste these in the Mac app under Send, or use them with ", h("code", {}, "ndes pull"), "."),
    h("div", {}));
  const connectBody = connect.lastChild;
  let lastKey = "";

  function drawHero() {
    const st = heroState();
    const action = btn(st.actLabel, st.act === "start" ? "primary" : "", () => act(action, async () => {
      if (st.act === "stop" && !confirm("Close the inbox? Devices can't send until you open it again. Files already waiting stay.")) return;
      S.sync = await api("POST", "/api/server/" + st.act);
      await refresh();
      toast(st.act === "stop" ? "Inbox closed" : "Inbox open");
    }));
    fill(hero, aster(st.mood, 84),
      h("div", {}, h("div", { class: "card-head" }, h("h1", {}, st.title)), st.pill,
        h("p", { class: "soft" }, st.text, st.url ? " " : null, st.url ? h("span", { class: "url" }, st.url) : null)),
      h("div", { class: "hero-actions" }, action));
  }

  function drawInbox() {
    const files = S.files || [];
    const del = (f) => (e) => act(e.currentTarget, async () => {
      if (!confirm("Delete this file from the server? It hasn't reached your vault yet and can't be recovered.")) return;
      await api("DELETE", "/api/inbox/" + f.id); await refresh(); toast("Deleted");
    });
    fill(inbox,
      h("div", { class: "card-head" }, h("h2", {}, "Waiting in the inbox")),
      h("div", { class: "stats" },
        h("div", { class: "stat" }, h("b", {}, String(S.file_count)), h("span", {}, S.file_count === 1 ? "file" : "files")),
        h("div", { class: "stat" }, h("b", {}, fmtBytes(S.file_bytes)), h("span", {}, "used")),
        h("div", { class: "stat" }, h("b", {}, fmtBytes(S.free_bytes)), h("span", {}, "disk free"))),
      files.length
        ? h("ul", { class: "files" }, files.map((f) => h("li", {},
            h("span", { class: "id", title: f.id }, f.id.slice(0, 8)),
            h("span", { class: "meta" }, fmtBytes(f.size) + " · " + ago(f.mtime)),
            h("button", { class: "btn quiet small danger icon-btn", type: "button", "aria-label": "Delete " + f.id.slice(0, 8), title: "Delete", onclick: del(f) }, "✕"))))
        : h("div", { class: "empty" }, aster("asleep", 64), h("b", {}, "Nothing waiting."),
            h("p", { class: "soft small" }, "Your vault pulls files in when it unlocks.")),
      S.file_count > files.length ? h("p", { class: "note" }, "Showing the newest " + files.length + " of " + S.file_count + ".") : null,
      files.length ? h("p", { class: "note" }, "Names stay sealed until the files are in your vault, so they're listed by id.") : null);
  }

  function drawConnect() {
    const key = connectURL().url;
    if (key === lastKey) return;
    lastKey = key;
    fill(connectBody, connectBlock());
  }

  function settings() {
    const panel = (title, desc, body, open) => h("details", { class: "sticker", open }, h("summary", {}, h("span", { class: "t" }, title), h("span", { class: "d" }, desc)), h("div", { class: "body" }, body));
    const keys = keysForm(() => toast("Vault linked"));
    const regenOut = h("div", {});
    const regen = btn("Make a new token", "danger", () => act(regen, async () => {
      if (!confirm("Make a new token? Every device using the old one stops sending until you paste the new one.")) return;
      const r = await api("POST", "/api/token/regenerate");
      lastKey = ""; drawConnect();
      fill(regenOut, banner(r.warning ? "warn" : "ok", r.warning ? sentence(r.warning) : "New token made. Copy it into your devices from Connect a device."));
    }, regenOut));
    const cur = h("input", { id: "curpw", type: "password", autocomplete: "current-password" });
    const nw = h("input", { id: "newpw", type: "password", autocomplete: "new-password" });
    const pwOut = h("div", {});
    const pwGo = btn("Change password", "", () => act(pwGo, async () => {
      if (nw.value.length < 10) throw new Error("Use at least 10 characters.");
      await api("POST", "/api/password", { current: cur.value, new: nw.value });
      cur.value = nw.value = "";
      fill(pwOut, banner("ok", "Password changed. Other browsers were signed out."));
    }, pwOut));
    return h("div", {},
      h("div", { class: "section-title" }, h("h2", {}, "Settings")),
      panel("Reachability", "Where your devices connect", reachForm({ saveLabel: "Save and apply" })),
      panel("Limits and HTTPS", "File size, queue length, certificate", limitsForm()),
      panel("Vault keys", S.sync.fingerprint ? "Linked · key check " + S.sync.fingerprint : "Not linked",
        h("div", {}, h("p", { class: "soft small" }, "Only paste new keys if this server should serve a different vault. Files already waiting were sealed for the old one."), keys.el)),
      panel("Access token", "Change it if a device is lost", h("div", {},
        h("p", { class: "soft small" }, "Every device sends this token. A new one locks out every device until you paste it again."), regenOut,
        h("div", { class: "actions" }, regen))),
      panel("Admin password", "For this page", h("div", {},
        h("div", { class: "row" },
          h("label", { class: "field", for: "curpw" }, h("span", { class: "field-label" }, "Current password"), cur),
          h("label", { class: "field", for: "newpw" }, h("span", { class: "field-label" }, "New password (10+ characters)"), nw)),
        pwOut, h("div", { class: "actions" }, pwGo))));
  }

  fill(app, topBar(true), hero, h("div", { class: "grid2" }, inbox, connect), settings(),
    h("footer", {}, h("p", { class: "soft small" }, "This page only answers this machine, your local network and Tailscale.")));
  view = { redraw() { drawHero(); drawInbox(); drawConnect(); } };
  view.redraw();
  startPolling(5000);
}

function limitsForm() {
  const st = S.sync.settings;
  const maxUp = h("input", { id: "maxup", type: "number", min: "1", value: String(Math.round(st.max_upload_bytes / MIB)) });
  const maxFiles = h("input", { id: "maxfiles", type: "number", min: "1", value: String(st.max_inbox_files) });
  const conc = h("input", { id: "conc", type: "number", min: "1", max: "64", value: String(st.max_concurrent_uploads) });
  const cert = h("input", { id: "cert", value: st.tls_cert || "", placeholder: "/path/to/fullchain.pem" });
  const key = h("input", { id: "tlskey", value: st.tls_key || "", placeholder: "/path/to/privkey.pem" });
  const budget = h("p", { class: "note" });
  const out = h("div", {});
  function update() {
    const worst = Number(maxFiles.value) * (Number(maxUp.value) * MIB * 1.0003 + 70 * 1024);
    const over = S.free_bytes > 0 && worst > S.free_bytes;
    fill(budget, over
      ? banner("warn", "A full inbox could take " + fmtBytes(worst) + " but only " + fmtBytes(S.free_bytes) + " is free. Lower one of the limits.")
      : "A full inbox takes at most " + fmtBytes(worst) + "; " + fmtBytes(S.free_bytes) + " is free.");
  }
  for (const el of [maxUp, maxFiles]) el.addEventListener("input", update);
  update();
  const save = btn("Save and apply", "primary", () => act(save, async () => {
    const tlsOn = cert.value.trim() !== "";
    S.sync = await api("POST", "/api/settings", Object.assign({}, S.sync.settings, {
      tls_cert: cert.value.trim(), tls_key: key.value.trim(),
      ack_plain_http: tlsOn ? false : S.sync.settings.ack_plain_http,
      max_upload_bytes: Math.round(Number(maxUp.value) * MIB),
      max_inbox_files: Number(maxFiles.value),
      max_concurrent_uploads: Number(conc.value),
    }));
    await refresh();
    if (S.sync.error) throw new Error(sentence(S.sync.error));
    toast("Saved");
  }, out));
  const lbl = (id, text, input) => h("label", { class: "field", for: id }, h("span", { class: "field-label" }, text), input);
  return h("div", {},
    h("div", { class: "row" }, lbl("maxup", "Largest file (MiB)", maxUp), lbl("maxfiles", "Files waiting at most", maxFiles), lbl("conc", "Uploads at once", conc)),
    budget,
    h("div", { class: "row" }, lbl("cert", "HTTPS certificate file", cert), lbl("tlskey", "HTTPS key file", key)),
    h("p", { class: "note" }, "With a certificate the inbox speaks HTTPS itself. Leave both empty when a proxy handles HTTPS."),
    out, h("div", { class: "actions" }, h("span", { class: "grow" }), save));
}

// ---------------- boot ----------------

async function mainScreen() {
  [S, ifaces] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/interfaces")]);
  if (!S.sync.linked) setupFlow(0);
  else if (!S.sync.setup_done) setupFlow(1);
  else dashboard();
}

async function boot() {
  clearInterval(poll);
  view = null;
  try {
    const st = await api("GET", "/api/state");
    if (st.setup_needed) claimScreen();
    else if (!st.authed) loginScreen();
    else await mainScreen();
  } catch (e) {
    fill(app, h("section", { class: "sticker card narrow" }, h("div", { class: "hero-title" }, aster("oops", 92), h("h2", {}, "Can't reach the server")),
      banner("bad", e.message), h("div", { class: "actions" }, btn("Try again", "primary", boot))));
  }
}

boot();
})();
