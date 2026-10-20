"use strict";
(() => {
const app = document.getElementById("app");
const MIB = 1024 * 1024;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
}

async function api(method, path, body) {
  const opt = { method, headers: { "X-Valv-Admin": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (res.status === 401 && path !== "/api/login") { boot(); throw new Error("Please sign in again"); }
  if (!res.ok) throw new Error(data.error || "Something went wrong (" + res.status + ")");
  return data;
}

// run a button action with a busy state and error toast
async function act(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message); } finally { btn.disabled = false; }
}

function fmtBytes(n) {
  if (n < 0 || n == null) return "unknown";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + u[i];
}
function fmtTime(s) { return new Date(s * 1000).toLocaleString(); }

async function copy(text, label) {
  try { await navigator.clipboard.writeText(text); toast((label || "Text") + " copied"); }
  catch (_) { toast("Copy failed, select the text and copy it by hand"); }
}

function fill(el, ...kids) {
  el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
}

// ---------------- sign-in screens ----------------

function shell(...cards) {
  app.replaceChildren(...cards);
}

function setupScreen() {
  const code = h("input", { id: "code", autocomplete: "off", placeholder: "XXXXX-XXXXX", spellcheck: "false" });
  const pw = h("input", { id: "pw", type: "password", autocomplete: "new-password" });
  const pw2 = h("input", { id: "pw2", type: "password", autocomplete: "new-password" });
  const go = h("button", { class: "primary" }, "Create password");
  go.addEventListener("click", () => act(go, async () => {
    if (pw.value !== pw2.value) throw new Error("The two passwords differ");
    await api("POST", "/api/setup", { code: code.value, password: pw.value });
    boot();
  }));
  shell(h("div", { class: "card narrow" },
    h("div", { class: "logo", style: "margin-bottom:12px" }),
    h("h1", {}, "Welcome to your Valv server"),
    h("p", { class: "muted" }, "Pick a password for this admin page. Only you will see it."),
    h("label", { for: "code" }, "Setup code"),
    code,
    h("p", { class: "muted small" }, "The code is printed in the server log when valvd starts (for Docker: ",
      h("code", {}, "docker logs"), "), and saved as the file ",
      h("code", {}, "setup-code"), " in the data folder. It is used once."),
    h("label", { for: "pw" }, "Password (10+ characters)"), pw,
    h("label", { for: "pw2" }, "Repeat password"), pw2,
    h("div", { class: "actions" }, go)));
  code.focus();
}

function loginScreen() {
  const pw = h("input", { id: "pw", type: "password", autocomplete: "current-password" });
  const go = h("button", { class: "primary" }, "Sign in");
  const submit = () => act(go, async () => { await api("POST", "/api/login", { password: pw.value }); boot(); });
  go.addEventListener("click", submit);
  pw.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  shell(h("div", { class: "card narrow" },
    h("div", { class: "logo", style: "margin-bottom:12px" }),
    h("h1", {}, "Valv server"),
    h("label", { for: "pw" }, "Password"), pw,
    h("div", { class: "actions" }, go)));
  pw.focus();
}

// ---------------- main screen ----------------

let S = null;            // last /api/status
let ifaces = [];
let poll = null;
const live = {};         // containers refreshed by polling

function pill(sync) {
  if (!sync.linked) return h("span", { class: "pill warn" }, "Needs setup");
  if (sync.running) return h("span", { class: "pill ok" }, "Running");
  if (sync.error) return h("span", { class: "pill bad" }, "Error");
  return h("span", { class: "pill" }, "Stopped");
}

function stepNum(n, done) {
  return h("span", { class: "num" + (done ? " done" : "") }, done ? "✓" : String(n));
}

function drawLive() {
  const { sync } = S;
  fill(live.pill, pill(sync));
  fill(live.banner, 
    sync.error ? h("div", { class: "note bad" }, sync.error) : null,
    !sync.linked ? h("div", { class: "note" }, "Start with step 1: link your vault. Then your devices can send files here.") : null);

  // step 1
  fill(live.n1, stepNum(1, sync.linked));
  fill(live.linked, sync.linked
    ? h("div", { class: "note" }, "Vault linked. Key check: ", h("b", {}, sync.fingerprint))
    : null);
  live.keysLabel.textContent = sync.linked ? "Replace the keys (only if you changed vault)" : "Server keys from your vault";

  // step 2
  fill(live.n2, stepNum(2, sync.running));

  // step 3
  fill(live.n3, stepNum(3, false));
  drawConnect();

  // server controls
  fill(live.controls, 
    sync.running ? h("button", { onclick: (e) => act(e.target, () => serverAction("stop")) }, "Stop sync server") : null,
    sync.running ? h("button", { onclick: (e) => act(e.target, () => serverAction("restart")) }, "Restart") : null,
    !sync.running && sync.linked ? h("button", { class: "primary", onclick: (e) => act(e.target, () => serverAction("start")) }, "Start sync server") : null);

  drawInbox();
}

async function serverAction(a) {
  const st = await api("POST", "/api/server/" + a);
  S.sync = st;
  await refresh();
  toast(a === "stop" ? "Sync server stopped" : "Sync server running");
}

function connectURL(sync) {
  const [host, port] = splitListen(sync.settings.listen);
  let hostName = host;
  let guessed = false;
  if (host === "0.0.0.0" || host === "::" || host === "") { hostName = location.hostname; guessed = true; }
  if (host === "127.0.0.1" || host === "localhost") { hostName = "127.0.0.1"; }
  return { url: (sync.settings.tls_cert ? "https" : "http") + "://" + hostName + ":" + port, guessed, loopback: hostName === "127.0.0.1" };
}

function drawConnect() {
  const { sync } = S;
  if (!sync.linked) {
    fill(live.connect, h("p", { class: "muted" }, "Available after step 1."));
    return;
  }
  const c = connectURL(sync);
  const tokenCode = h("code", {}, "••••••••••••••••••••");
  let shown = null;
  const reveal = h("button", {}, "Show");
  reveal.addEventListener("click", () => act(reveal, async () => {
    if (shown) { shown = null; tokenCode.textContent = "••••••••••••••••••••"; reveal.textContent = "Show"; return; }
    shown = (await api("GET", "/api/token")).token;
    tokenCode.textContent = shown; reveal.textContent = "Hide";
  }));
  const copyTok = h("button", {}, "Copy");
  copyTok.addEventListener("click", () => act(copyTok, async () => copy((await api("GET", "/api/token")).token, "Token")));
  const regen = h("button", { class: "danger" }, "Make a new token");
  regen.addEventListener("click", () => act(regen, async () => {
    if (!confirm("Make a new token? Every device using the old token stops working until you paste the new one.")) return;
    const r = await api("POST", "/api/token/regenerate");
    shown = r.token; tokenCode.textContent = shown; reveal.textContent = "Hide";
    toast(r.warning ? r.warning : "New token created");
  }));
  fill(live.connect, 
    h("p", { class: "muted" }, "Put these two values in the Valv app (or ", h("code", {}, "valv pull"), ") on your own devices."),
    h("div", { class: "kv" }, h("span", { class: "k muted" }, "Server"), h("code", {}, c.url),
      h("button", { onclick: () => copy(c.url, "Address") }, "Copy")),
    h("div", { class: "kv" }, h("span", { class: "k muted" }, "Token"), tokenCode,
      h("span", {}, reveal, " ", copyTok)),
    c.guessed ? h("div", { class: "note warn" }, "The server listens on every interface, so the address above uses the name you opened this page with. Use whatever name or IP your devices reach this machine by.") : null,
    c.loopback ? h("div", { class: "note warn" }, "The sync server only listens on this machine. Choose a Tailscale or local-network address in step 2 so your other devices can reach it.") : null,
    h("div", { class: "actions" }, regen));
}

function drawInbox() {
  const files = S.files || [];
  const tbl = files.length ? h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "File ID"), h("th", { class: "r" }, "Size"), h("th", {}, "Received"), h("th", {}))),
    h("tbody", {}, files.map((f) => h("tr", {},
      h("td", { class: "id" }, f.id), h("td", { class: "r" }, fmtBytes(f.size)), h("td", {}, fmtTime(f.mtime)),
      h("td", { class: "r" }, h("button", { class: "danger", onclick: (e) => act(e.target, async () => {
        if (!confirm("Delete this sealed file from the server? It cannot be recovered.")) return;
        await api("DELETE", "/api/inbox/" + f.id); await refresh(); toast("Deleted");
      }) }, "Delete")))))) : null;
  fill(live.inbox, 
    h("div", { class: "stats" },
      h("div", {}, h("b", {}, String(S.file_count)), h("span", { class: "muted small" }, "files waiting")),
      h("div", {}, h("b", {}, fmtBytes(S.file_bytes)), h("span", { class: "muted small" }, "used by them")),
      h("div", {}, h("b", {}, fmtBytes(S.free_bytes)), h("span", { class: "muted small" }, "disk free"))),
    files.length ? null : h("p", { class: "muted" }, "Nothing waiting. Files you send show up here until your Mac pulls them into the vault."),
    tbl,
    S.file_count > files.length ? h("p", { class: "muted small" }, "Showing the newest " + files.length + " of " + S.file_count + ".") : null);
}

function splitListen(l) {
  const i = l.lastIndexOf(":");
  return [l.slice(0, i).replace(/^\[|\]$/g, ""), l.slice(i + 1)];
}

function keysCard() {
  const ta = h("textarea", { id: "keys", spellcheck: "false", autocomplete: "off",
    placeholder: "inbox_pub: …\nk_auth: …" });
  const save = h("button", { class: "primary" }, "Save keys");
  save.addEventListener("click", () => act(save, async () => {
    S.sync = await api("POST", "/api/keys", { text: ta.value });
    ta.value = "";
    await refresh();
    toast("Vault linked");
  }));
  live.keysLabel = h("label", { for: "keys" }, "Server keys from your vault");
  live.n1 = h("span", {}); live.linked = h("div", {});
  return h("section", { class: "card" },
    h("h2", {}, live.n1, "Link your vault"),
    h("p", { class: "muted" }, "Paste the two lines your vault gives you for its server: in the Mac app, Settings → Copy server keys, or the output of ",
      h("code", {}, "valv server-config"), ". They let this server seal incoming files for you. They cannot open anything."),
    live.linked, live.keysLabel, ta,
    h("div", { class: "actions" }, save));
}

function networkCard() {
  const st = S.sync.settings;
  const [host, port] = splitListen(st.listen);
  const sel = h("select", { id: "addr" });
  const opts = ifaces.slice();
  if (!opts.some((o) => o.addr === host)) opts.push({ addr: host, label: "Saved address", kind: "other" });
  for (const o of opts) sel.append(h("option", { value: o.addr }, o.label + " (" + o.addr + ")"));
  sel.value = host;
  const portIn = h("input", { id: "port", type: "number", min: "1", max: "65535", value: port });
  const ack = h("input", { id: "ack", type: "checkbox" });
  ack.checked = !!st.ack_plain_http;
  const ackRow = h("label", { class: "check" }, ack,
    h("span", {}, "I understand this address is not encrypted by Valv. I'm using Tailscale, a VPN, or a private network, or I put HTTPS in front of it."));
  const cert = h("input", { id: "cert", value: st.tls_cert || "", placeholder: "/path/to/fullchain.pem" });
  const key = h("input", { id: "tlskey", value: st.tls_key || "", placeholder: "/path/to/privkey.pem" });
  const maxUp = h("input", { id: "maxup", type: "number", min: "1", value: String(Math.round(st.max_upload_bytes / MIB)) });
  const maxFiles = h("input", { id: "maxfiles", type: "number", min: "1", value: String(st.max_inbox_files) });
  const conc = h("input", { id: "conc", type: "number", min: "1", max: "64", value: String(st.max_concurrent_uploads) });
  const budget = h("p", { class: "muted small" });

  function update() {
    const nonLoop = !(sel.value === "127.0.0.1" || sel.value === "localhost");
    ackRow.style.display = nonLoop && !cert.value ? "" : "none";
    const worst = Number(maxFiles.value) * (Number(maxUp.value) * MIB * 1.0003 + 70 * 1024);
    const over = S.free_bytes > 0 && worst > S.free_bytes;
    budget.textContent = "Worst case the inbox can fill " + fmtBytes(worst) + " (files waiting × upload size); " + fmtBytes(S.free_bytes) + " is free." +
      (over ? " That is more than the free space, lower one of the limits." : "");
    budget.style.color = over ? "var(--warn)" : "";
  }
  for (const el of [sel, cert, maxUp, maxFiles]) el.addEventListener("input", update);
  update();

  const save = h("button", { class: "primary" }, "Save and apply");
  save.addEventListener("click", () => act(save, async () => {
    S.sync = await api("POST", "/api/settings", {
      listen: (sel.value.includes(":") ? "[" + sel.value + "]" : sel.value) + ":" + portIn.value,
      tls_cert: cert.value.trim(), tls_key: key.value.trim(),
      ack_plain_http: ack.checked && !cert.value,
      max_upload_bytes: Math.round(Number(maxUp.value) * MIB),
      max_inbox_files: Number(maxFiles.value),
      max_concurrent_uploads: Number(conc.value),
    });
    await refresh();
    toast(S.sync.running ? "Applied. Sync server is running." : "Saved");
  }));

  live.n2 = h("span", {});
  return h("section", { class: "card" },
    h("h2", {}, live.n2, "Network"),
    h("p", { class: "muted" }, "Where devices reach the sync server. This is a different port from this admin page, so you can open one without the other."),
    h("div", { class: "row" },
      h("div", {}, h("label", { for: "addr" }, "Listen on"), sel),
      h("div", { class: "shrink" }, h("label", { for: "port" }, "Sync port"), portIn)),
    ackRow,
    h("details", {},
      h("summary", {}, "Limits and HTTPS (optional)"),
      h("div", { class: "row" },
        h("div", {}, h("label", { for: "maxup" }, "Biggest file (MiB)"), maxUp),
        h("div", {}, h("label", { for: "maxfiles" }, "Files waiting at most"), maxFiles),
        h("div", {}, h("label", { for: "conc" }, "Uploads at once"), conc)),
      budget,
      h("div", { class: "row" },
        h("div", {}, h("label", { for: "cert" }, "HTTPS certificate file"), cert),
        h("div", {}, h("label", { for: "tlskey" }, "HTTPS key file"), key))),
    h("div", { class: "actions" }, save, live.controls = h("span", { class: "actions", style: "margin:0" })));
}

function passwordCard() {
  const cur = h("input", { id: "curpw", type: "password", autocomplete: "current-password" });
  const n1 = h("input", { id: "newpw", type: "password", autocomplete: "new-password" });
  const go = h("button", {}, "Change password");
  go.addEventListener("click", () => act(go, async () => {
    await api("POST", "/api/password", { current: cur.value, new: n1.value });
    cur.value = n1.value = "";
    toast("Password changed. Other sessions were signed out.");
  }));
  return h("details", { class: "card" },
    h("summary", {}, "Admin password"),
    h("div", { class: "row" },
      h("div", {}, h("label", { for: "curpw" }, "Current password"), cur),
      h("div", {}, h("label", { for: "newpw" }, "New password (10+ characters)"), n1)),
    h("div", { class: "actions" }, go));
}

async function refresh() {
  S = await api("GET", "/api/status");
  if (live.pill) drawLive();
}

async function mainScreen() {
  [S, ifaces] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/interfaces")]);
  live.pill = h("span", {});
  live.banner = h("div", {});
  live.connect = h("div", {});
  live.inbox = h("div", {});
  live.n3 = h("span", {});
  const out = h("button", {}, "Sign out");
  out.addEventListener("click", () => act(out, async () => { await api("POST", "/api/logout"); clearInterval(poll); boot(); }));
  const keys = keysCard();
  const net = networkCard();
  shell(
    h("header", {},
      h("div", { class: "left" }, h("div", { class: "logo" }), h("h1", {}, "Valv server"), live.pill),
      out),
    live.banner, keys, net,
    h("section", { class: "card" }, h("h2", {}, live.n3, "Connect your devices"), live.connect),
    h("section", { class: "card" }, h("h2", {}, "Waiting in the inbox"), live.inbox),
    passwordCard(),
    h("p", { class: "muted small center" }, "This page only answers this machine, your local network and Tailscale."));
  drawLive();
  clearInterval(poll);
  poll = setInterval(() => { if (!document.hidden) refresh().catch(() => {}); }, 5000);
}

async function boot() {
  clearInterval(poll);
  for (const k of Object.keys(live)) delete live[k];
  try {
    const st = await api("GET", "/api/state");
    if (st.setup_needed) setupScreen();
    else if (!st.authed) loginScreen();
    else await mainScreen();
  } catch (e) {
    app.replaceChildren(h("div", { class: "card narrow" }, h("p", {}, e.message)));
  }
}

boot();
})();
