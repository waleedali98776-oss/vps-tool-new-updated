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
    DisconnectReason,
    isJidBroadcast
} = require("@whiskeysockets/baileys");
const { randomBytes, createHash } = require("crypto");
const qrcode = require("qrcode");

const app = express();
const PORT = process.env.PORT || 5000;

// ------------------------- Directories -------------------------
const AUTH_DIR = "./auth_sessions";
const UPLOAD_DIR = "./uploads";
const TEMP_DIR = "./temp";
const PUBLIC_DIR = "./public";
[AUTH_DIR, UPLOAD_DIR, TEMP_DIR, PUBLIC_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});
const upload = multer({ dest: UPLOAD_DIR });

// ------------------------- Middleware -------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

// ------------------------- Data Stores -------------------------
const users = new Map();
const ADMIN_USER = "arjun";
const ADMIN_PASS_HASH = createHash("sha256").update("arjun").digest("hex");
const userSessions = new Map();
const userToSessions = new Map();
const activeTasks = new Map();
const manuallyDisconnectedSessions = new Set();
const sessionRestartAttempts = new Map();

function generateId(prefix = "") {
    return prefix + randomBytes(16).toString("hex");
}
function hashPassword(pwd) {
    return createHash("sha256").update(pwd).digest("hex");
}
function setUserCookie(res, username) {
    res.cookie("user", username, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
}
function setAdminCookie(res) {
    res.cookie("admin", "true", { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
}
function getUserFromCookie(req) {
    return req.cookies.user || null;
}
function isAdmin(req) {
    return req.cookies.admin === "true";
}

// ------------------------- Baileys Helpers -------------------------
async function initWhatsAppSession(sessionId, userId, phoneNumber) {
    const authPath = path.join(AUTH_DIR, sessionId);
    if (!fs.existsSync(authPath)) fs.mkdirSync(authPath, { recursive: true });
    
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    const { version } = await fetchLatestBaileysVersion();
    
    const sock = makeWASocket({
        version,
        logger: pino({ level: "silent" }),
        printQRInTerminal: false,
        browser: Browsers.ubuntu('Chrome'),
        auth: {
            creds: state.creds,
            keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" })),
        },
        markOnlineOnConnect: true,
        generateHighQualityLinkPreview: false,
        syncFullHistory: false,
        shouldIgnoreJid: jid => isJidBroadcast(jid),
        getMessage: async () => ({}),
    });
    
    sock.ev.on("creds.update", saveCreds);
    
    sock.ev.on("connection.update", async (update) => {
        const { connection, lastDisconnect, qr } = update;
        
        if (qr) {
            const session = userSessions.get(sessionId);
            if (session) {
                qrcode.toDataURL(qr, (err, url) => {
                    if (!err) session.qrCode = url;
                });
            }
        }
        
        if (connection === "open") {
            console.log(`✅ Session ${sessionId} connected`);
            const session = userSessions.get(sessionId);
            if (session) {
                session.isConnected = true;
                session.client = sock;
                const authInfo = sock.authState.creds;
                const myNumber = authInfo.me?.id?.split(":")[0] || phoneNumber;
                session.number = myNumber;
                session.qrCode = null;
            }
        }
        
        if (connection === "close") {
            console.log(`❌ Session ${sessionId} disconnected`);
            const session = userSessions.get(sessionId);
            if (session) session.isConnected = false;
            
            const reason = lastDisconnect?.error?.output?.statusCode;
            if (reason !== DisconnectReason.loggedOut) {
                setTimeout(() => initWhatsAppSession(sessionId, userId, phoneNumber), 5000);
            } else {
                userSessions.delete(sessionId);
                const userSess = userToSessions.get(userId) || [];
                userToSessions.set(userId, userSess.filter(id => id !== sessionId));
                fs.rmSync(authPath, { recursive: true, force: true });
            }
        }
    });
    
    return sock;
}

// ------------------------- API Endpoints -------------------------
app.post("/signup", (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.json({ success: false, error: "All fields required" });
    if (users.has(username)) return res.json({ success: false, error: "Username taken" });
    
    users.set(username, {
        email,
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
    });
    setUserCookie(res, username);
    res.json({ success: true, redirect: "/dashboard" });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.get(username);
    if (!user || user.passwordHash !== hashPassword(password)) {
        return res.json({ success: false, error: "Invalid credentials" });
    }
    setUserCookie(res, username);
    res.json({ success: true, redirect: "/dashboard" });
});

app.post("/admin-login", (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && hashPassword(password) === ADMIN_PASS_HASH) {
        setAdminCookie(res);
        res.json({ success: true, redirect: "/admin-dashboard" });
    } else {
        res.json({ success: false, error: "Invalid admin credentials" });
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("user");
    res.clearCookie("admin");
    res.redirect("/");
});

// ✅ WORKING PAIRING CODE - From uploaded file
app.post("/generate-pairing-code", async (req, res) => {
    const { number: num } = req.body;
    const username = getUserFromCookie(req);
    
    if (!username) {
        return res.json({ success: false, error: "Not logged in" });
    }
    if (!num) {
        return res.json({ success: false, error: "Phone number is required" });
    }
    
    try {
        const sessionId = generateId("sess_");
        const sessionPath = path.join(AUTH_DIR, sessionId);
        if (!fs.existsSync(sessionPath)) {
            fs.mkdirSync(sessionPath, { recursive: true });
        }
        
        const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
        const { version } = await fetchLatestBaileysVersion();
        
        const waClient = makeWASocket({
            version,
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" }))
            },
            printQRInTerminal: false,
            logger: pino({ level: "silent" }),
            browser: Browsers.ubuntu('Chrome'),
            syncFullHistory: false,
            generateHighQualityLinkPreview: true,
            shouldIgnoreJid: jid => isJidBroadcast(jid),
            getMessage: async () => { return {} },
            markOnlineOnConnect: false,
            retryRequestDelayMs: 3000,
            maxRetries: 1000000000,
            connectTimeoutMs: 60000
        });
        
        if (!waClient.authState.creds.registered) {
            await delay(1500);
            const phoneNumber = num.replace(/[^0-9]/g, "");
            const code = await waClient.requestPairingCode(phoneNumber);
            
            userSessions.set(sessionId, {
                client: waClient,
                number: num,
                authPath: sessionPath,
                isConnected: false,
                tasks: new Map(),
                userId: username,
                createdAt: new Date().toISOString()
            });
            
            if (!userToSessions.has(username)) userToSessions.set(username, []);
            userToSessions.get(username).push(sessionId);
            
            console.log(`🔑 Pairing code generated for ${num}: ${code}`);
            
            res.json({
                success: true,
                code: code,
                sessionId: sessionId,
                number: num
            });
        }
        
        waClient.ev.on("creds.update", saveCreds);
        
        waClient.ev.on("connection.update", async (s) => {
            const { connection, lastDisconnect } = s;
            
            if (connection === "open") {
                console.log(`✅ WhatsApp Connected for ${num}! Session ID: ${sessionId}`);
                const clientInfo = userSessions.get(sessionId);
                if (clientInfo) {
                    clientInfo.isConnected = true;
                    const authInfo = waClient.authState.creds;
                    const myNumber = authInfo.me?.id?.split(":")[0] || num;
                    clientInfo.number = myNumber;
                }
            } else if (connection === "close") {
                const clientInfo = userSessions.get(sessionId);
                if (clientInfo) {
                    clientInfo.isConnected = false;
                    console.log(`⚠️ Connection closed for Session ID: ${sessionId}`);
                    
                    const statusCode = lastDisconnect?.error?.output?.statusCode;
                    if (statusCode === 401) {
                        console.log(`❌ Session ${sessionId} logged out. Removing...`);
                        userSessions.delete(sessionId);
                        const userSess = userToSessions.get(username) || [];
                        userToSessions.set(username, userSess.filter(id => id !== sessionId));
                        fs.rmSync(sessionPath, { recursive: true, force: true });
                        return;
                    }
                    
                    console.log(`🔄 Attempting to reconnect for Session ID: ${sessionId}...`);
                    await delay(10000);
                    initWhatsAppSession(sessionId, username, num);
                }
            }
        });
        
    } catch (err) {
        console.error("❌ Error in pairing:", err.message);
        res.json({ success: false, error: err.message });
    }
});

// ------------------------- Other API Endpoints -------------------------
app.get("/api/get-numbers", (req, res) => {
    const username = getUserFromCookie(req);
    if (!username) return res.json([]);
    
    const sessionIds = userToSessions.get(username) || [];
    const numbersMap = new Map();
    
    for (const sid of sessionIds) {
        const sess = userSessions.get(sid);
        if (sess) {
            const phone = sess.number;
            if (!numbersMap.has(phone)) numbersMap.set(phone, { number: phone, sessions: [] });
            numbersMap.get(phone).sessions.push({ 
                sessionId: sid, 
                isConnected: sess.isConnected 
            });
        }
    }
    
    res.json(Array.from(numbersMap.values()));
});

app.get("/api/live-status", (req, res) => {
    const { sessionId } = req.query;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ error: "Session not found" });
    
    const tasks = Array.from(sess.tasks.values()).map(t => ({
        taskId: t.taskId,
        target: t.target,
        targetType: t.targetType,
        totalMessages: t.totalMessages,
        sentMessages: t.sentMessages,
        currentIndex: t.currentIndex,
        isSending: t.isSending,
        createdAtFormatted: t.startTime.toLocaleString(),
    }));
    
    res.json({
        number: sess.number,
        isConnected: sess.isConnected,
        createdAtFormatted: sess.createdAt.toLocaleString(),
        tasks,
    });
});

app.get("/api/live-logs", (req, res) => {
    const { sessionId, taskId } = req.query;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ error: "Session not found" });
    
    const task = sess.tasks.get(taskId);
    if (!task) return res.json({ error: "Task not found" });
    
    res.json({
        taskInfo: {
            sentMessages: task.sentMessages,
            totalMessages: task.totalMessages,
            isSending: task.isSending,
        },
        logs: task.logs || [],
    });
});

app.post("/send-message", upload.single("messageFile"), async (req, res) => {
    const { selectedSession, target, targetType, delaySec, prefix } = req.body;
    const file = req.file;
    
    if (!selectedSession || !target || !file || !delaySec) {
        return res.json({ success: false, error: "Missing fields" });
    }
    
    const sess = userSessions.get(selectedSession);
    if (!sess || !sess.client) return res.json({ success: false, error: "Session not active" });
    if (!sess.isConnected) return res.json({ success: false, error: "WhatsApp not connected" });
    
    const fileContent = fs.readFileSync(file.path, "utf8");
    const messages = fileContent.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (messages.length === 0) return res.json({ success: false, error: "No messages in file" });
    
    const taskId = generateId("task_");
    const taskInfo = {
        taskId,
        target,
        targetType,
        totalMessages: messages.length,
        sentMessages: 0,
        currentIndex: 0,
        isSending: true,
        startTime: new Date(),
        logs: [],
        stopRequested: false,
    };
    
    sess.tasks.set(taskId, taskInfo);
    activeTasks.set(taskId, { sessionId: selectedSession, taskInfo });
    
    (async () => {
        const sock = sess.client;
        const delayMs = parseInt(delaySec) * 1000;
        
        for (let i = 0; i < messages.length && !taskInfo.stopRequested; i++) {
            let msg = messages[i];
            if (prefix) msg = prefix + " " + msg;
            
            try {
                let jid = target;
                if (targetType === "individual") {
                    jid = target.includes("@s.whatsapp.net") ? target : `${target}@s.whatsapp.net`;
                } else {
                    jid = target.includes("@g.us") ? target : `${target}@g.us`;
                }
                
                await sock.sendMessage(jid, { text: msg });
                taskInfo.sentMessages++;
                taskInfo.currentIndex = i + 1;
                taskInfo.logs.push({ 
                    type: "success", 
                    message: `Sent message ${i+1}`, 
                    details: msg.substring(0, 100) 
                });
            } catch (err) {
                taskInfo.logs.push({ 
                    type: "error", 
                    message: `Failed message ${i+1}`, 
                    details: err.message 
                });
            }
            
            if (i < messages.length - 1 && !taskInfo.stopRequested) {
                await delay(delayMs);
            }
        }
        
        taskInfo.isSending = false;
        taskInfo.endTime = new Date();
        fs.unlink(file.path, () => {});
    })();
    
    res.json({ success: true, redirect: `/session-status?sessionId=${selectedSession}` });
});

app.post("/stop-session", async (req, res) => {
    const { sessionId } = req.body;
    const sess = userSessions.get(sessionId);
    
    if (!sess) return res.json({ success: false, error: "Session not found" });
    
    for (let [tid, task] of sess.tasks) {
        task.stopRequested = true;
        task.isSending = false;
    }
    
    if (sess.client) sess.client.end();
    userSessions.delete(sessionId);
    
    const userSess = userToSessions.get(sess.userId) || [];
    userToSessions.set(sess.userId, userSess.filter(id => id !== sessionId));
    
    const authPath = path.join(AUTH_DIR, sessionId);
    fs.rmSync(authPath, { recursive: true, force: true });
    
    res.json({ success: true, message: "Session deleted" });
});

app.post("/stop-task", (req, res) => {
    const { sessionId, taskId } = req.body;
    const sess = userSessions.get(sessionId);
    
    if (!sess) return res.json({ success: false, error: "Session not found" });
    
    const task = sess.tasks.get(taskId);
    if (!task) return res.json({ success: false, error: "Task not found" });
    
    task.stopRequested = true;
    task.isSending = false;
    
    res.json({ success: true, message: "Task stopped" });
});

app.get("/get-groups", async (req, res) => {
    const { sessionId } = req.query;
    const sess = userSessions.get(sessionId);
    
    if (!sess || !sess.client) return res.json({ success: false, error: "Session not active" });
    if (!sess.isConnected) return res.json({ success: false, error: "WhatsApp not connected" });
    
    try {
        const groups = [];
        const chats = await sess.client.groupFetchAllParticipating();
        
        for (let id in chats) {
            const chat = chats[id];
            groups.push({
                subject: chat.subject,
                groupId: id,
                participantsCount: chat.participants?.length || 0,
                creation: chat.creation ? new Date(chat.creation * 1000).toLocaleString() : null,
            });
        }
        
        res.json({ success: true, groups, number: sess.number });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.get("/api/admin/all-sessions", (req, res) => {
    if (!isAdmin(req)) return res.status(403).json([]);
    
    const all = [];
    for (let [sid, sess] of userSessions) {
        all.push({
            sessionId: sid,
            number: sess.number,
            username: sess.userId,
            isConnected: sess.isConnected,
            tasksCount: sess.tasks.size,
            activeTasksCount: Array.from(sess.tasks.values()).filter(t => t.isSending).length,
            createdAtFormatted: sess.createdAt.toLocaleString(),
        });
    }
    
    res.json(all);
});

app.get("/health", (req, res) => {
    const totalTasks = Array.from(userSessions.values()).reduce((acc, s) => acc + s.tasks.size, 0);
    const activeTasksCount = Array.from(userSessions.values()).reduce((acc, s) => {
        return acc + Array.from(s.tasks.values()).filter(t => t.isSending).length;
    }, 0);
    
    const memUsage = process.memoryUsage();
    
    res.json({
        status: "ok",
        sessions: userSessions.size,
        tasks: totalTasks,
        activeTasks: activeTasksCount,
        uptime: process.uptime().toFixed(1) + " sec",
        memory: {
            used: (memUsage.heapUsed / 1024 / 1024).toFixed(2) + " MB",
            total: (memUsage.heapTotal / 1024 / 1024).toFixed(2) + " MB",
        },
    });
});

// ------------------------- HTML UI -------------------------
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Waleed WP Server</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root { --bg: #09090b; --card: rgba(24, 24, 27, 0.6); --border: rgba(255,255,255,0.08); --primary: #8b5cf6; --primary-glow: rgba(139, 92, 246, 0.4); --accent: #06b6d4; --success: #10b981; --danger: #ef4444; --text: #f4f4f5; --muted: #a1a1aa; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); font-family: 'Inter', sans-serif; color: var(--text); min-height: 100vh; overflow-x: hidden; }
body::before { content: ''; position: fixed; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle at 50% 50%, rgba(139,92,246,0.15) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(6,182,212,0.1) 0%, transparent 40%); z-index: -1; animation: pulseBg 15s ease-in-out infinite alternate; }
@keyframes pulseBg { 0% { transform: scale(1); } 100% { transform: scale(1.1); } }
.container { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }
.glass-box { background: var(--card); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 24px; padding: 32px; margin: 24px 0; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
h1 { font-size: 2rem; font-weight: 800; text-align: center; margin-bottom: 8px; background: linear-gradient(135deg, #fff 0%, var(--primary) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.subtitle { text-align: center; color: var(--muted); font-size: 0.9rem; margin-bottom: 32px; }
h2 { font-size: 1.2rem; font-weight: 700; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; color: #fff; }
h2 i { color: var(--primary); }
input, select { width: 100%; padding: 14px 18px; margin: 10px 0; background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 14px; color: var(--text); font-size: 0.95rem; transition: all 0.2s; font-family: inherit; }
input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-glow); }
button { width: 100%; padding: 14px; margin-top: 12px; background: linear-gradient(135deg, var(--primary), #7c3aed); border: none; border-radius: 14px; color: white; font-weight: 700; font-size: 1rem; cursor: pointer; transition: all 0.3s; font-family: inherit; }
button:hover { transform: translateY(-2px); box-shadow: 0 10px 25px var(--primary-glow); }
.btn-danger { background: linear-gradient(135deg, var(--danger), #dc2626); }
.btn-danger:hover { box-shadow: 0 10px 25px rgba(239,68,68,0.4); }
.hidden { display: none !important; }
.session-card, .task-card { background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: 16px; padding: 20px; margin: 12px 0; }
.status-badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 30px; font-size: 0.75rem; font-weight: 600; }
.status-connected { background: rgba(16,185,129,0.15); color: var(--success); }
.status-disconnected { background: rgba(239,68,68,0.15); color: var(--danger); }
.status-connected::before, .status-disconnected::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.link { color: var(--accent); text-decoration: none; font-size: 0.85rem; font-weight: 500; }
.link:hover { color: var(--primary); }
@media(max-width: 600px) { .container { padding: 20px 12px; } .glass-box { padding: 24px 20px; } h1 { font-size: 1.5rem; } }
</style>
</head>
<body>
<div class="container" id="app"></div>
<script>
let statusInterval = null, logsInterval = null, numbersCache = [];
async function apiCall(url, options = {}) {
    const res = await fetch(url, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...options.headers }, ...options });
    return res.json();
}
function showAlert(containerId, message) {
    const el = document.getElementById(containerId);
    if (el) { 
        el.innerHTML = '<div style="background:rgba(239,68,68,0.1);border:1px solid var(--danger);padding:12px;border-radius:14px;color:var(--danger);font-size:0.9rem;margin-top:10px;">'+message+'</div>'; 
        setTimeout(()=>el.innerHTML='',4000); 
    }
}
async function updateUptimeDisplay() {
    try { 
        const data = await apiCall('/health'); 
        const div = document.getElementById('globalUptime'); 
        if(div) div.innerHTML = '<i class="fas fa-bolt" style="color:var(--primary)"></i> Uptime: '+data.uptime+' | RAM: '+data.memory?.used; 
    } catch(e) {}
}

function showLogin() {
    document.getElementById('app').innerHTML = \`
    <div id="globalUptime"></div>
    <h1><i class="fas fa-bolt"></i> Waleed WP Server</h1>
    <p class="subtitle">Premium WhatsApp Control Panel</p>
    <div class="glass-box">
        <h2><i class="fas fa-sign-in-alt"></i> User Login</h2>
        <div id="loginAlert"></div>
        <input type="text" id="loginUsername" placeholder="Username">
        <input type="password" id="loginPassword" placeholder="Password">
        <button onclick="handleLogin()">Login <i class="fas fa-arrow-right"></i></button>
        <p style="text-align:center;margin-top:20px;font-size:0.85rem;color:var(--muted)">New? <a href="#" onclick="showSignup();return false;">Sign up</a> · <a href="#" onclick="showAdminLogin();return false;">Admin</a></p>
    </div>\`;
    updateUptimeDisplay();
}
async function handleLogin() {
    const res = await apiCall('/login', { method:'POST', body: JSON.stringify({ username:document.getElementById('loginUsername').value, password:document.getElementById('loginPassword').value }) });
    if(res.success) window.location.href = '/dashboard'; 
    else showAlert('loginAlert', res.error);
}

function showSignup() {
    document.getElementById('app').innerHTML = \`
    <h1><i class="fas fa-user-plus"></i> Create Account</h1>
    <p class="subtitle">Join Waleed WP Server</p>
    <div class="glass-box">
        <h2><i class="fas fa-user"></i> Sign Up</h2>
        <div id="signupAlert"></div>
        <input type="text" id="signupName" placeholder="Username">
        <input type="email" id="signupEmail" placeholder="Email">
        <input type="password" id="signupPass" placeholder="Password">
        <button onclick="handleSignup()">Register</button>
        <p style="text-align:center;margin-top:20px;font-size:0.85rem;color:var(--muted)"><a href="#" onclick="showLogin();return false;">← Back to Login</a></p>
    </div>\`;
    updateUptimeDisplay();
}
async function handleSignup() {
    const res = await apiCall('/signup', { method:'POST', body: JSON.stringify({ username:document.getElementById('signupName').value, email:document.getElementById('signupEmail').value, password:document.getElementById('signupPass').value }) });
    if(res.success) window.location.href = '/dashboard'; 
    else showAlert('signupAlert', res.error);
}

function showAdminLogin() {
    document.getElementById('app').innerHTML = \`
    <h1><i class="fas fa-shield-alt"></i> Admin Portal</h1>
    <p class="subtitle">Restricted Access</p>
    <div class="glass-box">
        <h2><i class="fas fa-lock"></i> Administrator Access</h2>
        <div id="adminAlert"></div>
        <input type="text" id="adminUser" placeholder="Admin Username">
        <input type="password" id="adminPass" placeholder="Password">
        <button onclick="handleAdminLogin()">Authenticate</button>
        <p style="text-align:center;margin-top:20px;font-size:0.85rem;color:var(--muted)"><a href="#" onclick="showLogin();return false;">← Back to user login</a></p>
    </div>\`;
    updateUptimeDisplay();
}
async function handleAdminLogin() {
    const res = await apiCall('/admin-login', { method:'POST', body: JSON.stringify({ username:document.getElementById('adminUser').value, password:document.getElementById('adminPass').value }) });
    if(res.success) window.location.href = '/admin-dashboard'; 
    else showAlert('adminAlert', 'Invalid admin credentials');
}

async function showDashboard() {
    document.getElementById('app').innerHTML = \`
    <div id="globalUptime" style="text-align:right;font-size:0.8rem;color:var(--muted);margin-bottom:10px;"></div>
    <h1><i class="fas fa-bolt"></i> Waleed WP Server</h1>
    <p class="subtitle">Dashboard</p>
    <div class="glass-box">
        <h2><i class="fas fa-link"></i> Pair Device</h2>
        <div id="pairAlert"></div>
        <input type="text" id="pairPhone" placeholder="Phone with country code (e.g., 919876543210)">
        <button onclick="generatePairing()">Generate Code <i class="fas fa-qrcode"></i></button>
        <div id="pairResult" style="margin-top:15px;"></div>
        <a href="/logout" style="display:inline-block;margin-top:20px;background:rgba(239,68,68,0.1);color:var(--danger);padding:10px 20px;border-radius:12px;font-size:0.85rem;">Logout <i class="fas fa-sign-out-alt"></i></a>
    </div>
    <div class="glass-box">
        <h2><i class="fas fa-satellite-dish"></i> My Sessions</h2>
        <button onclick="loadUserSessions()" style="width:auto;padding:10px 20px;font-size:0.85rem;"><i class="fas fa-sync-alt"></i> Refresh</button>
        <div id="mySessionsList" style="margin-top:15px;">Loading...</div>
    </div>
    <div class="glass-box">
        <h2><i class="fas fa-paper-plane"></i> Bulk Message Sender</h2>
        <div id="sendMsgAlert"></div>
        <select id="senderNumberSelect" onchange="loadSenderSessions()"> <option value="">-- Select Phone Number --</option> </select>
        <select id="senderSessionSelect" class="hidden" onchange="showSendForm()"> <option value="">-- Select Session --</option> </select>
        <div id="sendFormPanel" class="hidden">
            <input type="text" id="targetId" placeholder="Target: Group ID or Phone">
            <select id="targetTypeSelect"> <option value="individual">Individual</option> <option value="group">WhatsApp Group</option> </select>
            <input type="file" id="msgFile" accept=".txt">
            <input type="number" id="delaySec" placeholder="Delay (seconds)" min="1" value="5">
            <input type="text" id="msgPrefix" placeholder="Optional prefix">
            <button onclick="startBulkSend()">Start Sending <i class="fas fa-rocket"></i></button>
        </div>
    </div>\`;
    updateUptimeDisplay();
    await loadPhoneNumbersForDropdowns();
    loadUserSessions();
}

async function loadPhoneNumbersForDropdowns() {
    const data = await apiCall('/api/get-numbers');
    numbersCache = data;
    const senderSelect = document.getElementById('senderNumberSelect');
    if(senderSelect) senderSelect.innerHTML = '<option value="">-- Select Phone Number --</option>';
    data.forEach((item, idx) => {
        const opt = \`<option value="\${idx}">\${item.number} (\${item.sessions.length} session)</option>\`;
        if(senderSelect) senderSelect.innerHTML += opt;
    });
}
function loadSenderSessions() {
    const idx = document.getElementById('senderNumberSelect').value;
    const sessionSelect = document.getElementById('senderSessionSelect');
    const sendPanel = document.getElementById('sendFormPanel');
    if(idx === "") { sessionSelect.classList.add('hidden'); sendPanel.classList.add('hidden'); return; }
    const sessions = numbersCache[idx]?.sessions || [];
    sessionSelect.innerHTML = '<option value="">-- Choose Session --</option>';
    sessions.forEach(s => { 
        sessionSelect.innerHTML += \`<option value="\${s.sessionId}">\${s.sessionId.slice(0,12)}... (\${s.isConnected ? '✅ Connected' : '⚠️ Disconnected'})</option>\`; 
    });
    sessionSelect.classList.remove('hidden');
    sendPanel.classList.add('hidden');
}
function showSendForm() {
    const sessionId = document.getElementById('senderSessionSelect').value;
    const panel = document.getElementById('sendFormPanel');
    if(sessionId) panel.classList.remove('hidden'); else panel.classList.add('hidden');
}

async function loadUserSessions() {
    const container = document.getElementById('mySessionsList');
    if(!container) return;
    container.innerHTML = '<p style="color:var(--muted)"><i class="fas fa-spinner fa-pulse"></i> Fetching...</p>';
    const data = await apiCall('/api/get-numbers');
    let html = '';
    for(let item of data) {
        for(let sess of item.sessions) {
            const statusData = await apiCall(\`/api/live-status?sessionId=\${sess.sessionId}\`);
            const tasks = statusData.tasks || [];
            const activeTasks = tasks.filter(t => t.isSending).length;
            html += \`<div class="session-card">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:10px;">
                    <strong style="font-size:1.1rem;">\${item.number}</strong>
                    <span class="status-badge \${statusData.isConnected ? 'status-connected' : 'status-disconnected'}">\${statusData.isConnected ? 'Online' : 'Offline'}</span>
                </div>
                <small style="color:var(--muted)">\${sess.sessionId.slice(0,16)}... · Tasks: \${tasks.length} (\${activeTasks} active)</small>
                <div style="margin-top:12px;display:flex;gap:15px;">
                    <a href="#" onclick="viewSessionStatus('\${sess.sessionId}'); return false;" class="link"><i class="fas fa-chart-line"></i> Monitor</a>
                    <a href="#" onclick="confirmDeleteSession('\${sess.sessionId}'); return false;" class="link" style="color:var(--danger)"><i class="fas fa-trash"></i> Delete</a>
                </div>
            </div>\`;
        }
    }
    if(html === '') html = '<p style="color:var(--muted);text-align:center;padding:20px;">No active sessions. Generate a pairing code to start.</p>';
    container.innerHTML = html;
}

async function viewSessionStatus(sessionId) {
    document.getElementById('app').innerHTML = \`
    <div id="globalUptime" style="text-align:right;font-size:0.8rem;color:var(--muted);margin-bottom:10px;"></div>
    <h1><i class="fas fa-chart-line"></i> Session Monitor</h1>
    <p class="subtitle">Real-time tracking</p>
    <div class="glass-box" id="sessionDetailsBox"></div>
    <div class="glass-box"><h2><i class="fas fa-tasks"></i> Active Tasks</h2><div id="sessionTasksList"></div></div>
    <a href="#" onclick="showDashboard(); return false;" class="link" style="font-size:0.9rem;"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>\`;
    updateUptimeDisplay();
    await refreshSessionStatus(sessionId);
    if(statusInterval) clearInterval(statusInterval);
    statusInterval = setInterval(() => refreshSessionStatus(sessionId), 5000);
}

async function refreshSessionStatus(sessionId) {
    const data = await apiCall(\`/api/live-status?sessionId=\${sessionId}\`);
    const detailsDiv = document.getElementById('sessionDetailsBox');
    const tasksDiv = document.getElementById('sessionTasksList');
    if(detailsDiv) {
        detailsDiv.innerHTML = \`<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
            <strong style="font-size:1.2rem;">\${data.number}</strong>
            <span class="status-badge \${data.isConnected ? 'status-connected' : 'status-disconnected'}">\${data.isConnected ? 'Online' : 'Offline'}</span>
        </div><small style="color:var(--muted)">Created: \${data.createdAtFormatted}</small>\`;
    }
    if(tasksDiv && data.tasks) {
        if(data.tasks.length===0) tasksDiv.innerHTML = '<p style="color:var(--muted);text-align:center;padding:20px;">No tasks yet</p>';
        else {
            let tasksHtml = '';
            data.tasks.forEach(t => {
                tasksHtml += \`<div class="task-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <strong>\${t.target}</strong>
                        <span class="status-badge \${t.isSending ? 'status-connected' : 'status-disconnected'}">\${t.isSending ? 'Running' : 'Done'}</span>
                    </div>
                    <small style="color:var(--muted)">\${t.sentMessages}/\${t.totalMessages} sent</small>
                    <div style="margin-top:10px;display:flex;gap:15px;">
                        <a href="#" onclick="viewTaskLogs('\${sessionId}','\${t.taskId}'); return false;" class="link"><i class="fas fa-scroll"></i> Logs</a>
                        \${t.isSending ? \`<a href="#" onclick="confirmStopTask('\${sessionId}','\${t.taskId}')" class="link" style="color:var(--danger)"><i class="fas fa-stop"></i> Stop</a>\` : ''}
                    </div>
                </div>\`;
            });
            tasksDiv.innerHTML = tasksHtml;
        }
    }
}

async function viewTaskLogs(sessionId, taskId) {
    document.getElementById('app').innerHTML = \`
    <div id="globalUptime" style="text-align:right;font-size:0.8rem;color:var(--muted);margin-bottom:10px;"></div>
    <h1><i class="fas fa-scroll"></i> Task Logs</h1>
    <p class="subtitle">Detailed activity log</p>
    <div class="glass-box"><div id="taskLogsContainer">Loading logs...</div></div>
    <a href="#" onclick="viewSessionStatus('\${sessionId}'); return false;" class="link" style="font-size:0.9rem;"><i class="fas fa-arrow-left"></i> Back to Session</a>\`;
    updateUptimeDisplay();
    await refreshLogs(sessionId, taskId);
    if(logsInterval) clearInterval(logsInterval);
    logsInterval = setInterval(() => refreshLogs(sessionId, taskId), 4500);
}

async function refreshLogs(sessionId, taskId) {
    const data = await apiCall(\`/api/live-logs?sessionId=\${sessionId}&taskId=\${taskId}\`);
    const container = document.getElementById('taskLogsContainer');
    if(container && data.logs) {
        let html = \`<p style="color:var(--muted);margin-bottom:15px;">Progress: \${data.taskInfo?.sentMessages || 0}/\${data.taskInfo?.totalMessages || 0}</p><div style="max-height:400px;overflow:auto;">\`;
        data.logs.slice().reverse().forEach(l => {
            html += \`<div style="background:rgba(0,0,0,0.2);border-radius:12px;padding:14px;margin:8px 0;border-left:4px solid \${l.type==='success'?'var(--success)':l.type==='error'?'var(--danger)':'var(--accent)'}">
                <strong>\${l.message}</strong><br><small style="color:var(--muted)">\${l.details}</small>
            </div>\`;
        });
        html += \`</div>\`;
        container.innerHTML = html;
    }
}

async function generatePairing() {
    const phone = document.getElementById('pairPhone').value;
    if(!phone) return showAlert('pairAlert','Enter phone number');
    showAlert('pairAlert','Generating...');
    const res = await apiCall('/generate-pairing-code', { method:'POST', body: JSON.stringify({ number:phone }) });
    if(res.success) {
        let html = \`<div class="session-card"><h3 style="color:var(--success);margin-bottom:10px;">✅ Session Created</h3><p style="color:var(--muted);font-size:0.85rem;">Session ID: \${res.sessionId}</p>\`;
        if(res.code) html += \`<div style="text-align:center;margin:20px 0;"><span style="font-size:2rem;font-weight:800;color:var(--primary);letter-spacing:5px;">\${res.code}</span><br><small style="color:var(--muted);margin-top:10px;display:block;">WhatsApp → Settings → Linked Devices → Link with phone number</small></div>\`;
        html += \`</div>\`;
        document.getElementById('pairResult').innerHTML = html;
        loadPhoneNumbersForDropdowns();
        loadUserSessions();
    } else showAlert('pairAlert', res.error);
}

async function startBulkSend() {
    const sessionId = document.getElementById('senderSessionSelect').value;
    const target = document.getElementById('targetId').value;
    const targetType = document.getElementById('targetTypeSelect').value;
    const delay = document.getElementById('delaySec').value;
    const prefix = document.getElementById('msgPrefix').value;
    const fileInput = document.getElementById('msgFile');

    if(!sessionId || !target || !fileInput.files.length) return showAlert('sendMsgAlert','Fill all fields and select .txt file');
    
    const formData = new FormData();
    formData.append('selectedSession', sessionId);
    formData.append('target', target);
    formData.append('targetType', targetType);
    formData.append('messageFile', fileInput.files[0]);
    formData.append('delaySec', delay);
    formData.append('prefix', prefix);

    showAlert('sendMsgAlert', '📝 Starting text sending task...');
    const res = await fetch('/send-message', { method:'POST', body:formData });
    const data = await res.json();
    if(data.success) window.location.href = data.redirect;
    else showAlert('sendMsgAlert', data.error);
}

async function confirmDeleteSession(sessionId) {
    if(confirm('Delete this session permanently?')) {
        await apiCall('/stop-session', { method:'POST', body: JSON.stringify({ sessionId }) });
        loadUserSessions(); 
        loadPhoneNumbersForDropdowns();
    }
}

async function confirmStopTask(sessionId, taskId) {
    if(confirm('Stop this task?')) {
        await apiCall('/stop-task', { method:'POST', body: JSON.stringify({ sessionId, taskId }) });
        refreshSessionStatus(sessionId);
    }
}

function router() {
    const pathname = window.location.pathname;
    const params = new URLSearchParams(window.location.search);
    if (pathname === '/session-status') { 
        const sessionId = params.get('sessionId'); 
        if (sessionId) viewSessionStatus(sessionId); 
        else showLogin(); 
    } else if (pathname === '/' || pathname === '/login') showLogin();
    else if (pathname === '/signup') showSignup();
    else if (pathname === '/admin-login') showAdminLogin();
    else if (pathname === '/dashboard') showDashboard();
    else if (pathname === '/admin-dashboard') showAdminDashboard();
    else showLogin();
}

async function showAdminDashboard() {
    document.getElementById('app').innerHTML = \`
    <div id="globalUptime" style="text-align:right;font-size:0.8rem;color:var(--muted);margin-bottom:10px;"></div>
    <h1><i class="fas fa-shield-alt"></i> Admin Control</h1>
    <p class="subtitle">System Overview</p>
    <div class="glass-box"><h2><i class="fas fa-chart-bar"></i> System Stats</h2><div id="adminStats"></div><a href="/logout" style="display:inline-block;margin-top:15px;background:rgba(239,68,68,0.1);color:var(--danger);padding:10px 20px;border-radius:12px;font-size:0.85rem;">Logout <i class="fas fa-sign-out-alt"></i></a></div>
    <div class="glass-box"><h2><i class="fas fa-list"></i> All User Sessions</h2><button onclick="loadAllSessionsAdmin()" style="width:auto;padding:10px 20px;font-size:0.85rem;"><i class="fas fa-sync-alt"></i> Refresh</button><div id="adminSessionsList" style="margin-top:15px;"></div></div>\`;
    updateUptimeDisplay();
    loadAdminStats(); 
    loadAllSessionsAdmin();
}

async function loadAdminStats() {
    const health = await apiCall('/health');
    document.getElementById('adminStats').innerHTML = \`<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:15px;">
        <div class="session-card" style="text-align:center;"><div style="font-size:1.5rem;font-weight:800;color:var(--primary);">\${health.sessions}</div><small style="color:var(--muted)">Sessions</small></div>
        <div class="session-card" style="text-align:center;"><div style="font-size:1.5rem;font-weight:800;color:var(--accent);">\${health.tasks}</div><small style="color:var(--muted)">Tasks</small></div>
        <div class="session-card" style="text-align:center;"><div style="font-size:1.5rem;font-weight:800;color:var(--success);">\${health.activeTasks}</div><small style="color:var(--muted)">Active</small></div>
        <div class="session-card" style="text-align:center;"><div style="font-size:1.5rem;font-weight:800;color:#f59e0b;">\${health.memory?.used}</div><small style="color:var(--muted)">Memory</small></div>
    </div>\`;
}

async function loadAllSessionsAdmin() {
    const sessions = await apiCall('/api/admin/all-sessions');
    let html = '';
    sessions.forEach(s => {
        html += \`<div class="session-card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:10px;">
                <strong>\${s.number}</strong>
                <span class="status-badge \${s.isConnected ? 'status-connected' : 'status-disconnected'}">\${s.isConnected ? 'Online' : 'Offline'}</span>
            </div>
            <small style="color:var(--muted)">User: \${s.username} · Tasks: \${s.tasksCount} (\${s.activeTasksCount} active)</small>
            <div style="margin-top:12px;display:flex;gap:15px;">
                <a href="#" onclick="adminViewSession('\${s.sessionId}')" class="link"><i class="fas fa-eye"></i> Details</a>
                <a href="#" onclick="adminDeleteSession('\${s.sessionId}')" class="link" style="color:var(--danger)"><i class="fas fa-trash"></i> Delete</a>
            </div>
        </div>\`;
    });
    document.getElementById('adminSessionsList').innerHTML = html || '<p style="color:var(--muted);text-align:center;padding:20px;">No sessions</p>';
}

window.adminViewSession = async (sessionId) => {
    const data = await apiCall(\`/api/admin/session-details?sessionId=\${sessionId}\`);
    let tasksHtml = '';
    data.tasks?.forEach(t => { tasksHtml += \`<div style="padding:8px 0;border-bottom:1px solid var(--border);">\${t.target} - \${t.sentMessages}/\${t.totalMessages}</div>\`; });
    alert(\`Session: \${data.number}\\nUser: \${data.username}\\nTasks:\\n\${tasksHtml || 'No tasks'}\`);
};

window.adminDeleteSession = async (sessionId) => { 
    if(confirm('Delete session?')){ 
        await apiCall('/api/admin/delete-session',{method:'POST',body:JSON.stringify({sessionId})}); 
        loadAllSessionsAdmin(); 
    } 
};

window.addEventListener('popstate', router);
router();
setInterval(updateUptimeDisplay, 10000);
</script>
</body>
</html>`;

fs.writeFileSync(path.join(PUBLIC_DIR, "index.html"), HTML_CONTENT);

app.get("*", (req, res) => {
    res.sendFile("index.html", { root: PUBLIC_DIR });
});

app.listen(PORT, () => {
    console.log(`🚀 Waleed WP Server running on http://localhost:${PORT}`);
    console.log(` Admin login: arjun / arjun`);
    console.log(`📱 Use international format without + (e.g., 919876543210 for India)`);
    console.log(`✅ WORKING PAIRING CODE integrated from uploaded file`);
});
