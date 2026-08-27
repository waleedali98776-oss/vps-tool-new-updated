const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const pino = require("pino");
const {
  makeWASocket,
  useMultiFileAuthState,
  delay,
  makeCacheableSignalKeyStore,
  Browsers,
  fetchLatestBaileysVersion,
  DisconnectReason
} = require("@whiskeysockets/baileys");
const { randomBytes, createHash } = require("crypto");
const qrcode = require("qrcode");

// ─── Crash Protection ───
process.on("uncaughtException", (e) => console.error("⚠️ Uncaught:", e.message));
process.on("unhandledRejection", (e) => console.error("⚠️ Unhandled:", e?.message || e));

const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.slice(1).split(".")[0]);
if (majorVersion > 20) {
  console.warn(`⚠️ Node ${nodeVersion} detected. Best on 18/20 LTS.`);
}

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Directories ───
const AUTH_DIR = "./auth_sessions";
const UPLOAD_DIR = "./uploads";
const TEMP_DIR = "./temp";
const PUBLIC_DIR = "./public";
[AUTH_DIR, UPLOAD_DIR, TEMP_DIR, PUBLIC_DIR].forEach((d) => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 2 * 1024 * 1024 } });

// ─── Middleware ───
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

// ─── Data Stores ───
const users = new Map();
const ADMIN_USER = "Waleedxd";
const ADMIN_PASS_HASH = createHash("sha256").update("Waleedxd").digest("hex");
const userSessions = new Map();
const userToSessions = new Map();
const activeTasks = new Map();

const MAX_LOGS = 50; // Memory saver: max logs per task

function genId(p = "") { return p + randomBytes(12).toString("hex"); }
function hashPwd(p) { return createHash("sha256").update(p).digest("hex"); }

function setUserCookie(res, u) { res.cookie("user", u, { httpOnly: true, maxAge: 604800000, sameSite: "lax" }); }
function setAdminCookie(res) { res.cookie("admin", "true", { httpOnly: true, maxAge: 604800000, sameSite: "lax" }); }
function getUser(req) { return req.cookies.user || null; }
function isAdmin(req) { return req.cookies.admin === "true"; }

// ─── Periodic Cleanup (Memory Saver) ───
setInterval(() => {
  for (const [tid, info] of activeTasks) {
    if (!info.taskInfo.isSending) activeTasks.delete(tid);
  }
  // Clean orphaned upload files older than 1hr
  try {
    const now = Date.now();
    fs.readdirSync(UPLOAD_DIR).forEach((f) => {
      const fp = path.join(UPLOAD_DIR, f);
      const st = fs.statSync(fp);
      if (now - st.mtimeMs > 3600000) fs.unlinkSync(fp);
    });
  } catch (_) {}
}, 120000); // every 2 min

// ─── Baileys Session Init ───
async function initSession(sessionId, userId, phoneNumber) {
  const authPath = path.join(AUTH_DIR, sessionId);
  if (!fs.existsSync(authPath)) fs.mkdirSync(authPath, { recursive: true });

  const { state, saveCreds } = await useMultiFileAuthState(authPath);
  const { version } = await fetchLatestBaileysVersion();
  const silentLogger = pino({ level: "silent" });

  const sock = makeWASocket({
    version,
    logger: silentLogger,
    printQRInTerminal: false,
    browser: Browsers.macOS("Desktop"),
    auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, silentLogger) },
    markOnlineOnConnect: true,
    generateHighQualityLinkPreview: false,
    syncFullHistory: false, // saves memory
  });

  sock.ev.on("creds.update", saveCreds);
  sock.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update;
    const sess = userSessions.get(sessionId);

    if (qr && sess) {
      qrcode.toDataURL(qr, (err, url) => { if (!err) sess.qrCode = url; });
    }
    if (connection === "open" && sess) {
      sess.isConnected = true;
      sess.client = sock;
      sess.number = sock.authState.creds.me?.id?.split(":")[0] || phoneNumber;
      sess.qrCode = null;
      console.log(`✅ ${sessionId} connected`);
    }
    if (connection === "close") {
      if (sess) sess.isConnected = false;
      const reason = lastDisconnect?.error?.output?.statusCode;
      if (reason !== DisconnectReason.loggedOut) {
        setTimeout(() => initSession(sessionId, userId, phoneNumber), 5000);
      } else {
        userSessions.delete(sessionId);
        const arr = userToSessions.get(userId) || [];
        userToSessions.set(userId, arr.filter((id) => id !== sessionId));
        fs.rmSync(authPath, { recursive: true, force: true });
      }
    }
  });
  return sock;
}

// ─── Auth Routes ───
app.post("/signup", (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.json({ success: false, error: "All fields required" });
  if (users.has(username)) return res.json({ success: false, error: "Username taken" });
  users.set(username, { email, passwordHash: hashPwd(password), createdAt: new Date().toISOString() });
  setUserCookie(res, username);
  res.json({ success: true, redirect: "/dashboard" });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const u = users.get(username);
  if (!u || u.passwordHash !== hashPwd(password)) return res.json({ success: false, error: "Invalid credentials" });
  setUserCookie(res, username);
  res.json({ success: true, redirect: "/dashboard" });
});

app.post("/admin-login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && hashPwd(password) === ADMIN_PASS_HASH) {
    setAdminCookie(res);
    return res.json({ success: true, redirect: "/admin-dashboard" });
  }
  res.json({ success: false, error: "Invalid admin credentials" });
});

app.get("/logout", (req, res) => { res.clearCookie("user"); res.clearCookie("admin"); res.redirect("/"); });

// ─── Pairing Code ───
app.post("/generate-pairing-code", async (req, res) => {
  const username = getUser(req);
  if (!username) return res.json({ success: false, error: "Not logged in" });
  const { number } = req.body;
  if (!number) return res.json({ success: false, error: "Phone number required" });
  const clean = number.replace(/[^0-9]/g, "");
  if (clean.length < 9 || clean.length > 15) return res.json({ success: false, error: "Invalid number format (e.g. 919876543210)" });

  const sessionId = genId("sess_");
  const authPath = path.join(AUTH_DIR, sessionId);
  if (!fs.existsSync(authPath)) fs.mkdirSync(authPath, { recursive: true });

  try {
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    const { version } = await fetchLatestBaileysVersion();
    const sl = pino({ level: "silent" });
    const sock = makeWASocket({
      version, logger: sl, printQRInTerminal: false,
      auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, sl) },
      browser: Browsers.macOS("Desktop"), syncFullHistory: false, markOnlineOnConnect: true,
    });
    sock.ev.on("creds.update", saveCreds);
    await delay(4000);

    let pairCode = null, qrDataUrl = null;
    try {
      pairCode = await sock.requestPairingCode(clean);
    } catch (e) {
      qrDataUrl = await new Promise((resolve) => {
        const handler = (u) => { if (u.qr) qrcode.toDataURL(u.qr, (err, url) => { if (!err) resolve(url); }); };
        sock.ev.on("connection.update", handler);
        setTimeout(() => { sock.ev.off("connection.update", handler); resolve(null); }, 15000);
      });
    }

    const sessObj = { sessionId, userId: username, number: clean, isConnected: false, client: sock, createdAt: new Date(), tasks: new Map(), qrCode: qrDataUrl };
    userSessions.set(sessionId, sessObj);
    if (!userToSessions.has(username)) userToSessions.set(username, []);
    userToSessions.get(username).push(sessionId);

    sock.ev.on("connection.update", (update) => {
      const { connection, lastDisconnect } = update;
      if (connection === "open") {
        sessObj.isConnected = true;
        sessObj.number = sock.authState.creds.me?.id?.split(":")[0] || clean;
        sessObj.qrCode = null;
      }
      if (connection === "close") {
        const r = lastDisconnect?.error?.output?.statusCode;
        if (r !== DisconnectReason.loggedOut) setTimeout(() => initSession(sessionId, username, clean), 5000);
        else sessObj.isConnected = false;
      }
    });

    res.json({ success: true, code: pairCode, qr: qrDataUrl, sessionId, message: pairCode ? "Pairing code generated" : "Use QR code" });
  } catch (err) {
    try { fs.rmSync(authPath, { recursive: true, force: true }); } catch (_) {}
    res.json({ success: false, error: "Session error: " + err.message });
  }
});

// ─── API Routes ───
app.get("/api/get-numbers", (req, res) => {
  const u = getUser(req);
  if (!u) return res.json([]);
  const map = new Map();
  for (const sid of userToSessions.get(u) || []) {
    const s = userSessions.get(sid);
    if (s) {
      if (!map.has(s.number)) map.set(s.number, { number: s.number, sessions: [] });
      map.get(s.number).sessions.push({ sessionId: sid, isConnected: s.isConnected });
    }
  }
  res.json(Array.from(map.values()));
});

app.get("/api/live-status", (req, res) => {
  const s = userSessions.get(req.query.sessionId);
  if (!s) return res.json({ error: "Not found" });
  const tasks = Array.from(s.tasks.values()).map((t) => ({
    taskId: t.taskId, target: t.target, targetType: t.targetType,
    totalMessages: t.totalMessages, sentMessages: t.sentMessages,
    isSending: t.isSending, startTime: t.startTime.toLocaleString(),
  }));
  res.json({ number: s.number, isConnected: s.isConnected, createdAt: s.createdAt.toLocaleString(), tasks });
});

app.get("/api/live-logs", (req, res) => {
  const s = userSessions.get(req.query.sessionId);
  if (!s) return res.json({ error: "Not found" });
  const t = s.tasks.get(req.query.taskId);
  if (!t) return res.json({ error: "Task not found" });
  res.json({ taskInfo: { sentMessages: t.sentMessages, totalMessages: t.totalMessages, isSending: t.isSending }, logs: t.logs || [] });
});

// ─── Send Message ───
app.post("/send-message", upload.single("messageFile"), async (req, res) => {
  const { selectedSession, target, targetType, delaySec, prefix } = req.body;
  const file = req.file;
  if (!selectedSession || !target || !file || !delaySec) return res.json({ success: false, error: "Missing fields" });
  const sess = userSessions.get(selectedSession);
  if (!sess?.client || !sess.isConnected) return res.json({ success: false, error: "Session not active" });

  let messages;
  try { messages = fs.readFileSync(file.path, "utf8").split(/\r?\n/).filter((l) => l.trim()); }
  finally { fs.unlink(file.path, () => {}); }
  if (!messages.length) return res.json({ success: false, error: "Empty file" });

  const taskId = genId("task_");
  const taskInfo = { taskId, target, targetType, totalMessages: messages.length, sentMessages: 0, currentIndex: 0, isSending: true, startTime: new Date(), logs: [], stopRequested: false };
  sess.tasks.set(taskId, taskInfo);
  activeTasks.set(taskId, { sessionId: selectedSession, taskInfo });

  (async () => {
    const sock = sess.client;
    const ms = parseInt(delaySec) * 1000;
    const jid = targetType === "group"
      ? (target.includes("@g.us") ? target : `${target}@g.us`)
      : (target.includes("@s.whatsapp.net") ? target : `${target}@s.whatsapp.net`);

    for (let i = 0; i < messages.length && !taskInfo.stopRequested; i++) {
      const msg = prefix ? `${prefix} ${messages[i]}` : messages[i];
      try {
        await sock.sendMessage(jid, { text: msg });
        taskInfo.sentMessages++;
        if (taskInfo.logs.length < MAX_LOGS) taskInfo.logs.push({ type: "success", message: `Sent #${i + 1}`, details: msg.slice(0, 80) });
        else { taskInfo.logs.shift(); taskInfo.logs.push({ type: "success", message: `Sent #${i + 1}`, details: msg.slice(0, 80) }); }
      } catch (err) {
        if (taskInfo.logs.length < MAX_LOGS) taskInfo.logs.push({ type: "error", message: `Failed #${i + 1}`, details: err.message });
        else { taskInfo.logs.shift(); taskInfo.logs.push({ type: "error", message: `Failed #${i + 1}`, details: err.message }); }
      }
      if (i < messages.length - 1 && !taskInfo.stopRequested) await delay(ms);
    }
    taskInfo.isSending = false;
    taskInfo.endTime = new Date();
    activeTasks.delete(taskId); // cleanup
  })();

  res.json({ success: true, redirect: `/session-status?sessionId=${selectedSession}` });
});

// ─── Stop / Delete ───
app.post("/stop-session", async (req, res) => {
  const s = userSessions.get(req.body.sessionId);
  if (!s) return res.json({ success: false, error: "Not found" });
  for (const [, t] of s.tasks) { t.stopRequested = true; t.isSending = false; }
  if (s.client) s.client.end();
  userSessions.delete(req.body.sessionId);
  const arr = userToSessions.get(s.userId) || [];
  userToSessions.set(s.userId, arr.filter((id) => id !== req.body.sessionId));
  fs.rmSync(path.join(AUTH_DIR, req.body.sessionId), { recursive: true, force: true });
  res.json({ success: true });
});

app.post("/stop-task", (req, res) => {
  const s = userSessions.get(req.body.sessionId);
  const t = s?.tasks.get(req.body.taskId);
  if (!t) return res.json({ success: false, error: "Not found" });
  t.stopRequested = true; t.isSending = false;
  res.json({ success: true });
});

app.get("/get-groups", async (req, res) => {
  const s = userSessions.get(req.query.sessionId);
  if (!s?.client || !s.isConnected) return res.json({ success: false, error: "Not active" });
  try {
    const chats = await s.client.groupFetchAllParticipating();
    const groups = Object.entries(chats).map(([id, c]) => ({ subject: c.subject, groupId: id, participantsCount: c.participants?.length || 0 }));
    res.json({ success: true, groups, number: s.number });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── Admin Routes ───
app.get("/api/admin/all-sessions", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json([]);
  const all = [];
  for (const [sid, s] of userSessions) {
    all.push({ sessionId: sid, number: s.number, username: s.userId, isConnected: s.isConnected, tasksCount: s.tasks.size, activeTasksCount: Array.from(s.tasks.values()).filter((t) => t.isSending).length, createdAt: s.createdAt.toLocaleString() });
  }
  res.json(all);
});

app.get("/api/admin/session-details", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
  const s = userSessions.get(req.query.sessionId);
  if (!s) return res.json({ error: "Not found" });
  res.json({ sessionId: req.query.sessionId, number: s.number, username: s.userId, isConnected: s.isConnected, tasks: Array.from(s.tasks.values()).map((t) => ({ taskId: t.taskId, target: t.target, totalMessages: t.totalMessages, sentMessages: t.sentMessages, isSending: t.isSending })) });
});

app.get("/api/admin/task-logs", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
  for (const [, s] of userSessions) { const t = s.tasks.get(req.query.taskId); if (t) return res.json({ logs: t.logs || [] }); }
  res.json({ logs: [] });
});

app.post("/api/admin/delete-session", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
  const s = userSessions.get(req.body.sessionId);
  if (s) {
    if (s.client) s.client.end();
    userSessions.delete(req.body.sessionId);
    const arr = userToSessions.get(s.userId) || [];
    userToSessions.set(s.userId, arr.filter((id) => id !== req.body.sessionId));
    fs.rmSync(path.join(AUTH_DIR, req.body.sessionId), { recursive: true, force: true });
  }
  res.json({ success: true });
});

app.post("/api/admin/delete-task", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
  const s = userSessions.get(req.body.sessionId);
  const t = s?.tasks.get(req.body.taskId);
  if (t) { t.stopRequested = true; t.isSending = false; s.tasks.delete(req.body.taskId); }
  res.json({ success: true });
});

app.get("/health", (req, res) => {
  let total = 0, active = 0;
  for (const s of userSessions.values()) { total += s.tasks.size; for (const t of s.tasks.values()) if (t.isSending) active++; }
  const m = process.memoryUsage();
  res.json({ status: "ok", sessions: userSessions.size, tasks: total, activeTasks: active, uptime: process.uptime().toFixed(0) + "s", memory: { used: (m.heapUsed / 1048576).toFixed(1) + "MB", total: (m.heapTotal / 1048576).toFixed(1) + "MB" } });
});

// ─── HTML UI ───
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Waleed WP Server</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a1a;--card:rgba(15,15,35,0.7);--border:rgba(139,92,246,0.25);--accent:#8b5cf6;--accent2:#06b6d4;--green:#22c55e;--red:#ef4444;--text:#e2e8f0;--muted:#94a3b8}
@keyframes bgShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes glow{0%,100%{box-shadow:0 0 5px var(--accent)}50%{box-shadow:0 0 20px var(--accent),0 0 40px rgba(139,92,246,0.3)}}
body{background:linear-gradient(-45deg,#0a0a1a,#1a0a2e,#0a1628,#0d1117);background-size:400% 400%;animation:bgShift 15s ease infinite;font-family:'Segoe UI',system-ui,sans-serif;color:var(--text);min-height:100vh;padding:16px}
.wrap{max-width:900px;margin:0 auto}
.glass{background:var(--card);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:20px;padding:24px;margin:16px 0;animation:slideUp .4s ease}
h1{text-align:center;font-size:1.6rem;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:12px 0 4px;font-weight:800;letter-spacing:-0.5px}
.subtitle{text-align:center;color:var(--muted);font-size:.8rem;margin-bottom:16px}
h2{font-size:1.1rem;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px}
input,select,button{width:100%;padding:13px 18px;margin:8px 0;background:rgba(15,15,35,0.8);border:1px solid rgba(139,92,246,0.2);border-radius:14px;color:var(--text);font-size:.95rem;transition:all .2s}
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(139,92,246,0.15)}
button{background:linear-gradient(135deg,var(--accent),#7c3aed);cursor:pointer;font-weight:700;border:none;letter-spacing:.3px;transition:all .2s}
button:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(139,92,246,0.4)}
button:active{transform:translateY(0)}
.btn-danger{background:linear-gradient(135deg,var(--red),#dc2626)}
.btn-sm{width:auto;padding:8px 18px;font-size:.8rem;border-radius:10px;display:inline-flex;align-items:center;gap:6px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-size:.75rem;font-weight:600}
.badge-on{background:rgba(34,197,94,0.15);color:var(--green)}
.badge-on::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.badge-off{background:rgba(239,68,68,0.15);color:var(--red)}
.badge-off::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--red)}
.card{background:rgba(10,10,26,0.6);border:1px solid rgba(139,92,246,0.15);border-radius:16px;padding:16px;margin:10px 0;transition:all .2s}
.card:hover{border-color:rgba(139,92,246,0.4)}
.progress-bar{height:6px;background:rgba(139,92,246,0.15);border-radius:10px;overflow:hidden;margin:8px 0}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:10px;transition:width .5s ease}
.toast{position:fixed;top:20px;right:20px;padding:14px 22px;border-radius:14px;font-size:.9rem;font-weight:600;z-index:9999;animation:slideUp .3s ease;backdrop-filter:blur(10px);max-width:350px}
.toast-ok{background:rgba(34,197,94,0.2);border:1px solid var(--green);color:var(--green)}
.toast-err{background:rgba(239,68,68,0.2);border:1px solid var(--red);color:var(--red)}
.link{color:var(--accent2);cursor:pointer;text-decoration:none;font-size:.85rem;transition:color .2s}
.link:hover{color:var(--accent)}
.hidden{display:none!important}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:12px 0}
.stat-box{background:rgba(139,92,246,0.08);border:1px solid rgba(139,92,246,0.15);border-radius:14px;padding:14px;text-align:center}
.stat-box .num{font-size:1.4rem;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat-box .lbl{font-size:.7rem;color:var(--muted);margin-top:2px}
a{color:var(--accent2);text-decoration:none}
.top-bar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px}
.top-bar .uptime{font-size:.75rem;color:var(--muted)}
@media(max-width:600px){body{padding:10px}.glass{padding:16px;border-radius:16px}h1{font-size:1.3rem}}
</style>
</head>
<body>
<div class="wrap" id="app"></div>
<script>
let SI=null,LI=null,UI=null,NC=[];
const $=id=>document.getElementById(id);
const api=async(u,o={})=>{const r=await fetch(u,{credentials:'same-origin',headers:{'Content-Type':'application/json',...o.headers},...o});return r.json()};

function toast(msg,ok=true){const d=document.createElement('div');d.className='toast '+(ok?'toast-ok':'toast-err');d.innerHTML='<i class="fas '+(ok?'fa-check-circle':'fa-exclamation-circle')+'"></i> '+msg;document.body.appendChild(d);setTimeout(()=>d.remove(),3500)}
function clearTimers(){[SI,LI,UI].forEach(t=>{if(t)clearInterval(t)});SI=LI=UI=null}

async function uptime(){try{const d=await api('/health');const e=$('uptime');if(e)e.innerHTML='<i class="fas fa-signal"></i> '+d.uptime+' | <i class="fas fa-memory"></i> '+d.memory.used}catch(e){}}

function showLogin(){
clearTimers();
$('app').innerHTML=\`
<div class="top-bar"><span class="uptime" id="uptime"></span></div>
<h1><i class="fas fa-bolt"></i> Waleed WP Server</h1>
<p class="subtitle">WhatsApp Control Panel</p>
<div class="glass">
<h2><i class="fas fa-sign-in-alt"></i> Login</h2>
<input id="lu" placeholder="Username" autocomplete="username">
<input id="lp" type="password" placeholder="Password" autocomplete="current-password">
<button onclick="doLogin()"><i class="fas fa-arrow-right"></i> Login</button>
<p style="text-align:center;margin-top:14px;font-size:.85rem;color:var(--muted)">New? <span class="link" onclick="showSignup()">Sign up</span> · <span class="link" onclick="showAdmin()">Admin</span></p>
</div>\`;
UI=setInterval(uptime,10000);uptime();
}

async function doLogin(){const r=await api('/login',{method:'POST',body:JSON.stringify({username:$('lu').value,password:$('lp').value})});r.success?location.href='/dashboard':toast(r.error,false)}

function showSignup(){
clearTimers();
$('app').innerHTML=\`
<h1><i class="fas fa-bolt"></i> Waleed WP Server</h1>
<p class="subtitle">Create Account</p>
<div class="glass">
<h2><i class="fas fa-user-plus"></i> Sign Up</h2>
<input id="su" placeholder="Username"><input id="se" type="email" placeholder="Email"><input id="sp" type="password" placeholder="Password">
<button onclick="doSignup()"><i class="fas fa-check"></i> Register</button>
<p style="text-align:center;margin-top:14px;font-size:.85rem;color:var(--muted)"><span class="link" onclick="showLogin()">← Back to Login</span></p>
</div>\`;
}
async function doSignup(){const r=await api('/signup',{method:'POST',body:JSON.stringify({username:$('su').value,email:$('se').value,password:$('sp').value})});r.success?location.href='/dashboard':toast(r.error,false)}

function showAdmin(){
clearTimers();
$('app').innerHTML=\`
<h1><i class="fas fa-shield-halved"></i> Admin Portal</h1>
<p class="subtitle">Waleed Server Administration</p>
<div class="glass">
<h2><i class="fas fa-lock"></i> Admin Login</h2>
<input id="au" placeholder="Admin Username"><input id="ap" type="password" placeholder="Password">
<button onclick="doAdmin()"><i class="fas fa-key"></i> Authenticate</button>
<p style="text-align:center;margin-top:14px;font-size:.85rem;color:var(--muted)"><span class="link" onclick="showLogin()">← Back</span></p>
</div>\`;
}
async function doAdmin(){const r=await api('/admin-login',{method:'POST',body:JSON.stringify({username:$('au').value,password:$('ap').value})});r.success?location.href='/admin-dashboard':toast('Invalid credentials',false)}

async function showDash(){
clearTimers();
$('app').innerHTML=\`
<div class="top-bar"><span class="uptime" id="uptime"></span><button class="btn-sm btn-danger" onclick="location.href='/logout'"><i class="fas fa-sign-out-alt"></i> Logout</button></div>
<h1><i class="fas fa-bolt"></i> Waleed WP Server</h1>
<p class="subtitle">Dashboard</p>

<div class="glass">
<h2><i class="fas fa-link"></i> Pair Device</h2>
<input id="pp" placeholder="Phone with country code (e.g. 919876543210)">
<button onclick="doPair()"><i class="fas fa-qrcode"></i> Generate Code</button>
<div id="pairRes"></div>
</div>

<div class="glass">
<h2><i class="fas fa-satellite-dish"></i> Sessions</h2>
<button class="btn-sm" onclick="loadSess()"><i class="fas fa-sync-alt"></i> Refresh</button>
<div id="sessList" style="margin-top:10px">Loading...</div>
</div>

<div class="glass">
<h2><i class="fas fa-paper-plane"></i> Bulk Sender</h2>
<select id="sn" onchange="loadSS()"><option value="">-- Phone Number --</option></select>
<select id="ss" class="hidden" onchange="$('sf').classList.toggle('hidden',!this.value)"><option value="">-- Session --</option></select>
<div id="sf" class="hidden">
<input id="st" placeholder="Target: Phone or Group ID">
<select id="stt"><option value="individual">Individual</option><option value="group">Group</option></select>
<input type="file" id="mf" accept=".txt">
<input type="number" id="dl" placeholder="Delay (sec)" value="5" min="1">
<input id="px" placeholder="Prefix (optional)">
<button onclick="doSend()"><i class="fas fa-rocket"></i> Start Sending</button>
</div>
</div>

<div class="glass">
<h2><i class="fas fa-users"></i> Groups</h2>
<select id="gn" onchange="loadGS()"><option value="">-- Phone Number --</option></select>
<select id="gs2" class="hidden"><option value="">-- Session --</option></select>
<button id="fgb" class="btn-sm hidden" onclick="doGroups()" style="margin-top:8px"><i class="fas fa-list"></i> Fetch</button>
<div id="gd" style="margin-top:10px"></div>
</div>\`;
UI=setInterval(uptime,10000);uptime();
await loadNums();loadSess();
}

async function loadNums(){NC=await api('/api/get-numbers');['sn','gn'].forEach(id=>{const e=$(id);if(e){e.innerHTML='<option value="">-- Phone Number --</option>';NC.forEach((n,i)=>e.innerHTML+=\`<option value="\${i}">\${n.number} (\${n.sessions.length})</option>\`)}})}

function loadSS(){const i=$('sn').value,s=$('ss'),p=$('sf');if(!i){s.classList.add('hidden');p.classList.add('hidden');return}s.innerHTML='<option value="">-- Session --</option>';(NC[i]?.sessions||[]).forEach(x=>s.innerHTML+=\`<option value="\${x.sessionId}">\${x.sessionId.slice(0,10)}… \${x.isConnected?'✅':'⚠️'}</option>\`);s.classList.remove('hidden');p.classList.add('hidden')}
function loadGS(){const i=$('gn').value,s=$('gs2'),b=$('fgb');if(!i){s.classList.add('hidden');b.classList.add('hidden');return}s.innerHTML='<option value="">-- Session --</option>';(NC[i]?.sessions||[]).forEach(x=>s.innerHTML+=\`<option value="\${x.sessionId}">\${x.sessionId.slice(0,10)}…</option>\`);s.classList.remove('hidden');b.classList.remove('hidden')}

async function doPair(){const p=$('pp').value;if(!p)return toast('Enter phone number',false);toast('Generating…');const r=await api('/generate-pairing-code',{method:'POST',body:JSON.stringify({number:p})});if(r.success){let h='<div class="card"><strong>✅ Session Created</strong><br><small>'+r.sessionId+'</small>';if(r.code)h+='<br><br><span style="font-size:1.5rem;font-weight:800;color:var(--accent);letter-spacing:4px">'+r.code+'</span><br><small style="color:var(--muted)">WhatsApp → Settings → Linked Devices → Link with phone number</small>';if(r.qr)h+='<br><img src="'+r.qr+'" style="max-width:180px;margin:10px 0;border-radius:12px">';h+='</div>';$('pairRes').innerHTML=h;loadNums();loadSess()}else toast(r.error,false)}

async function loadSess(){const c=$('sessList');if(!c)return;c.innerHTML='<i class="fas fa-spinner fa-spin" style="color:var(--accent)"></i>';const d=await api('/api/get-numbers');let h='';for(const n of d)for(const s of n.sessions){const st=await api('/api/live-status?sessionId='+s.sessionId);const ac=(st.tasks||[]).filter(t=>t.isSending).length;h+='<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px"><strong>'+n.number+'</strong><span class="badge '+(st.isConnected?'badge-on':'badge-off')+'">'+(st.isConnected?'Connected':'Offline')+'</span></div><small style="color:var(--muted)">'+s.sessionId.slice(0,14)+'… · Tasks: '+(st.tasks||[]).length+' ('+ac+' active)</small><div style="margin-top:8px;display:flex;gap:10px"><span class="link" onclick="viewSess(\\''+s.sessionId+'\\')"><i class="fas fa-chart-line"></i> Monitor</span><span class="link" style="color:var(--red)" onclick="delSess(\\''+s.sessionId+'\\')"><i class="fas fa-trash"></i> Delete</span></div></div>'}c.innerHTML=h||'<p style="color:var(--muted);text-align:center;padding:20px">No sessions yet. Pair a device to start.</p>'}

async function doSend(){const sid=$('ss').value,t=$('st').value,tt=$('stt').value,dl=$('dl').value,px=$('px').value,f=$('mf');if(!sid||!t||!f.files.length)return toast('Fill all fields + select .txt file',false);const fd=new FormData();fd.append('selectedSession',sid);fd.append('target',t);fd.append('targetType',tt);fd.append('messageFile',f.files[0]);fd.append('delaySec',dl);fd.append('prefix',px);toast('Starting…');const r=await(await fetch('/send-message',{method:'POST',body:fd})).json();r.success?location.href=r.redirect:toast(r.error,false)}

async function doGroups(){const sid=$('gs2').value;if(!sid)return;$('gd').innerHTML='<i class="fas fa-spinner fa-spin" style="color:var(--accent)"></i>';try{const r=await api('/get-groups?sessionId='+sid);if(r.success&&r.groups?.length){$('gd').innerHTML=r.groups.map(g=>'<div class="card"><strong>'+g.subject+'</strong><br><small style="color:var(--muted)">'+g.groupId+' · '+g.participantsCount+' members</small></div>').join('')}else $('gd').innerHTML='<p style="color:var(--muted)">No groups found</p>'}catch(e){$('gd').innerHTML='<p style="color:var(--red)">Error</p>'}}

async function delSess(sid){if(!confirm('Delete this session?'))return;await api('/stop-session',{method:'POST',body:JSON.stringify({sessionId:sid})});toast('Deleted');loadSess();loadNums()}

async function viewSess(sid){
clearTimers();
$('app').innerHTML=\`
<div class="top-bar"><span class="uptime" id="uptime"></span><span class="link" onclick="showDash();location.href='/dashboard'"><i class="fas fa-arrow-left"></i> Back</span></div>
<h1><i class="fas fa-chart-line"></i> Session Monitor</h1>
<div class="glass" id="sd"></div>
<div class="glass"><h2><i class="fas fa-tasks"></i> Tasks</h2><div id="tl"></div></div>\`;
UI=setInterval(uptime,10000);uptime();
await refSess(sid);SI=setInterval(()=>refSess(sid),5000);
}

async function refSess(sid){const d=await api('/api/live-status?sessionId='+sid);const sd=$('sd'),tl=$('tl');if(sd)sd.innerHTML='<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px"><strong style="font-size:1.1rem">'+d.number+'</strong><span class="badge '+(d.isConnected?'badge-on':'badge-off')+'">'+(d.isConnected?'Online':'Offline')+'</span></div><small style="color:var(--muted)">Created: '+d.createdAt+'</small>';if(tl&&d.tasks){if(!d.tasks.length)tl.innerHTML='<p style="color:var(--muted);text-align:center;padding:16px">No tasks</p>';else tl.innerHTML=d.tasks.map(t=>{const pct=t.totalMessages?Math.round(t.sentMessages/t.totalMessages*100):0;return '<div class="card"><div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:4px"><strong>'+t.target+'</strong><span class="badge '+(t.isSending?'badge-on':'badge-off')+'">'+(t.isSending?'Running':'Done')+'</span></div><div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div><small style="color:var(--muted)">'+t.sentMessages+'/'+t.totalMessages+' ('+pct+'%)</small><div style="margin-top:6px;display:flex;gap:10px"><span class="link" onclick="viewLogs(\\''+sid+'\\',\\''+t.taskId+'\\')"><i class="fas fa-scroll"></i> Logs</span>'+(t.isSending?'<span class="link" style="color:var(--red)" onclick="stopTask(\\''+sid+'\\',\\''+t.taskId+'\\')"><i class="fas fa-stop"></i> Stop</span>':'')+'</div></div>'}).join('')}}

async function viewLogs(sid,tid){
clearTimers();
$('app').innerHTML=\`
<div class="top-bar"><span class="uptime" id="uptime"></span><span class="link" onclick="viewSess('\\'+sid+'\\');history.pushState(null,null,'/session-status?sessionId='+sid)"><i class="fas fa-arrow-left"></i> Back</span></div>
<h1><i class="fas fa-scroll"></i> Task Logs</h1>
<div class="glass"><div id="lc">Loading...</div></div>\`;
UI=setInterval(uptime,10000);uptime();
await refLogs(sid,tid);LI=setInterval(()=>refLogs(sid,tid),4000);
}

async function refLogs(sid,tid){const d=await api('/api/live-logs?sessionId='+sid+'&taskId='+tid);const c=$('lc');if(c&&d.logs){const pct=d.taskInfo?.totalMessages?Math.round(d.taskInfo.sentMessages/d.taskInfo.totalMessages*100):0;c.innerHTML='<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div><small style="color:var(--muted)">'+d.taskInfo.sentMessages+'/'+d.taskInfo.totalMessages+'</small><div style="max-height:350px;overflow:auto;margin-top:10px">'+d.logs.slice().reverse().map(l=>'<div class="card" style="border-left:3px solid '+(l.type==='success'?'var(--green)':'var(--red)')+';padding:10px"><strong>'+l.message+'</strong><br><small style="color:var(--muted)">'+l.details+'</small></div>').join('')+'</div>'}}

async function stopTask(sid,tid){if(!confirm('Stop?'))return;await api('/stop-task',{method:'POST',body:JSON.stringify({sessionId:sid,taskId:tid})});toast('Stopped');refSess(sid)}

async function showAdminDash(){
clearTimers();
$('app').innerHTML=\`
<div class="top-bar"><span class="uptime" id="uptime"></span><button class="btn-sm btn-danger" onclick="location.href='/logout'"><i class="fas fa-sign-out-alt"></i> Logout</button></div>
<h1><i class="fas fa-shield-halved"></i> Admin Panel</h1>
<p class="subtitle">Waleed Server Control</p>
<div class="glass"><h2><i class="fas fa-chart-bar"></i> Stats</h2><div id="astats"></div></div>
<div class="glass"><h2><i class="fas fa-list"></i> All Sessions</h2><button class="btn-sm" onclick="loadAS()"><i class="fas fa-sync-alt"></i> Refresh</button><div id="asl" style="margin-top:10px"></div></div>\`;
UI=setInterval(uptime,10000);uptime();loadAStats();loadAS();
}

async function loadAStats(){const h=await api('/health');$('astats').innerHTML='<div class="stats-row"><div class="stat-box"><div class="num">'+h.sessions+'</div><div class="lbl">Sessions</div></div><div class="stat-box"><div class="num">'+h.tasks+'</div><div class="lbl">Tasks</div></div><div class="stat-box"><div class="num">'+h.activeTasks+'</div><div class="lbl">Active</div></div><div class="stat-box"><div class="num">'+h.memory.used+'</div><div class="lbl">Memory</div></div></div>'}

async function loadAS(){const ss=await api('/api/admin/all-sessions');$('asl').innerHTML=ss.length?ss.map(s=>'<div class="card"><div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px"><strong>'+s.number+'</strong><span class="badge '+(s.isConnected?'badge-on':'badge-off')+'">'+(s.isConnected?'Online':'Offline')+'</span></div><small style="color:var(--muted)">User: '+s.username+' · Tasks: '+s.tasksCount+' ('+s.activeTasksCount+' active)</small><div style="margin-top:6px;display:flex;gap:10px"><span class="link" onclick="aView(\\''+s.sessionId+'\\')"><i class="fas fa-eye"></i> Details</span><span class="link" style="color:var(--red)" onclick="aDel(\\''+s.sessionId+'\\')"><i class="fas fa-trash"></i> Delete</span></div></div>').join(''):'<p style="color:var(--muted);text-align:center">No sessions</p>'}

window.aView=async(sid)=>{const d=await api('/api/admin/session-details?sessionId='+sid);let t=d.tasks?.map(x=>x.target+' '+x.sentMessages+'/'+x.totalMessages).join('\\n')||'None';alert('Session: '+d.number+'\\nUser: '+d.username+'\\nTasks:\\n'+t)};
window.aDel=async(sid)=>{if(!confirm('Delete?'))return;await api('/api/admin/delete-session',{method:'POST',body:JSON.stringify({sessionId:sid})});toast('Deleted');loadAS()};

function router(){clearTimers();const p=location.pathname,q=new URLSearchParams(location.search);if(p==='/session-status'&&q.get('sessionId'))viewSess(q.get('sessionId'));else if(p==='/dashboard')showDash();else if(p==='/admin-dashboard')showAdminDash();else if(p==='/signup')showSignup();else if(p==='/admin-login')showAdmin();else showLogin()}
window.addEventListener('popstate',router);router();
</script>
</body>
</html>`;

fs.writeFileSync(path.join(PUBLIC_DIR, "index.html"), HTML);
app.get("*", (req, res) => res.sendFile("index.html", { root: PUBLIC_DIR }));

app.listen(PORT, () => {
  console.log(`🚀 Waleed WP Server → http://localhost:${PORT}`);
  console.log(`👑 Admin: Waleedxd / Waleedxd`);
});