const BACKEND_URL =
  location.hostname === "localhost"
    ? "http://localhost:3000"
    : location.origin;

const $ = (id) => document.getElementById(id);

const connectOverlay = $("connectOverlay");
const appMain        = $("appMain");
const statusEl       = $("status");
const roomKeyInput   = $("roomKey");
const pairCodeInput  = $("pairCode");
const createBtn      = $("create");
const joinBtn        = $("join");
const copyInviteBtn  = $("copyInvite");
const closeRoomBtn   = $("closeRoom");
const lockRoomBtn    = $("lockRoom");
const leaveRoomBtn   = $("leaveRoom");
const chat           = $("chat");
const input          = $("input");
const sendBtn        = $("send");
const typingEl       = $("typing");

sendBtn.disabled = true;
input.disabled   = true;

let socket       = null;
let joined       = false;
let isOwner      = false;
let roomKey      = null;
let pairCode     = null;
let roomSalt     = null;
let cryptoKey    = null;
let isRoomLocked = false;
let currentPeers = 0;
let appShown     = false;

const params = new URLSearchParams(location.search);
if (params.get("key")) roomKeyInput.value = params.get("key");

const rxRoomKey = /^[A-Za-z0-9]{12}$/;
const rxPair    = /^[0-9]{6}$/;

// ── generate key ──────────────────────────────────────────────────────────────

$("genKey").addEventListener("click", async () => {
  if (socket) return;
  try {
    const res = await fetch(`${BACKEND_URL}/api/genkey`, { cache: "no-store" });
    const { key } = await res.json();
    roomKeyInput.value = key;
  } catch {
    alert("Could not generate key.");
  }
});

// ── UI helpers ────────────────────────────────────────────────────────────────

function updateStatusUI(text, isGood = true) {
  const dot        = statusEl.querySelector(".dot");
  const statusText = statusEl.querySelector(".status-text");
  statusText.textContent = text;
  dot.classList.toggle("red", !isGood);
}

function updateLockUI(locked) {
  isRoomLocked = locked;
  updateStatusUI(`${currentPeers} Peer(s) ${locked ? "🔒" : ""}`, true);
  if (isOwner) {
    lockRoomBtn.innerHTML = locked
      ? '<i data-lucide="lock"></i>'
      : '<i data-lucide="unlock"></i>';
    if (window.lucide) lucide.createIcons();
  }
}

function showApp() {
  if (appShown) return;
  appShown = true;
  connectOverlay.classList.add("hidden");
  appMain.style.display = "flex";
  lucide.createIcons();
}

// ── textarea auto-resize ──────────────────────────────────────────────────────

input.addEventListener("input", () => {
  input.style.height = "auto";
  input.style.height = Math.min(input.scrollHeight, 180) + "px";
});

// ── connect ───────────────────────────────────────────────────────────────────

async function connectAndJoin(role) {
  if (socket) return;

  if (!window.crypto || !window.crypto.subtle) {
    alert("Use HTTPS or localhost.");
    return;
  }

  const rk = roomKeyInput.value.trim();
  const pc = pairCodeInput.value.trim();

  if (!rxRoomKey.test(rk)) { alert("Room Key must be 12 alphanumeric chars."); return; }
  if (!rxPair.test(pc))    { alert("Pair Code must be 6 digits."); return; }

  createBtn.disabled = true;
  joinBtn.disabled   = true;

  socket = io(BACKEND_URL, { transports: ["websocket"], upgrade: false });

  wireEvents();

  socket.on("connect", () => {
    console.log("🟢 Connected to server");
    socket.emit("join", { key: rk, pairCode: pc, role });
  });

  socket.on("connect_error", (err) => {
    console.error("❌ Connection error:", err);
    alert("Connection failed: " + err.message);
    socket = null;
    createBtn.disabled = false;
    joinBtn.disabled   = false;
  });

  socket.on("disconnect", () => {
    if (joined) updateStatusUI("Connection lost — reconnecting…", false);
  });
}

createBtn.onclick = () => connectAndJoin("owner");
joinBtn.onclick   = () => connectAndJoin("guest");

// ── socket events ─────────────────────────────────────────────────────────────

function wireEvents() {
  let typingTO;

  socket.onAny((ev, ...args) => console.log(`[Socket] ${ev}:`, args));

  socket.on("typing", () => {
    typingEl.textContent = "Peer is typing…";
    clearTimeout(typingTO);
    typingTO = setTimeout(() => { typingEl.textContent = ""; }, 1000);
  });

  socket.on("error-msg", (m) => {
    console.warn("📛 error-msg:", m);
    alert(m);
    updateStatusUI("Disconnected", false);
    socket?.disconnect();
    socket = null;
    createBtn.disabled = false;
    joinBtn.disabled   = false;
  });

  socket.on("room-info", async (data) => {
    console.log("📦 room-info:", data);
    const payload = Array.isArray(data) ? data[0] : data;

    if (!payload?.roomKey) {
      console.error("❌ Invalid room-info payload");
      alert("Server returned invalid room data.");
      return;
    }

    roomKey      = payload.roomKey;
    roomSalt     = payload.salt;
    isOwner      = !!payload.owner;
    pairCode     = pairCodeInput.value.trim();
    currentPeers = payload.members;

    try {
      cryptoKey = await deriveKey(pairCode, roomSalt);
      joined = true;
    } catch (e) {
      console.error("❌ Encryption failure:", e);
      alert("Encryption failure.");
      return;
    }

    updateLockUI(payload.locked);
    addMeta("🔐 End-to-End Encryption Established");

    roomKeyInput.readOnly  = true;
    pairCodeInput.readOnly = true;
    sendBtn.disabled = false;
    input.disabled   = false;
    input.focus();

    showApp();

    [copyInviteBtn, closeRoomBtn, lockRoomBtn].forEach(
      (el) => (el.style.display = isOwner ? "grid" : "none")
    );
    leaveRoomBtn.style.display = "grid";

    chat.querySelector(".empty-state")?.remove();
  });

  socket.on("peer-joined", (data) => {
    const payload = Array.isArray(data) ? data[0] : data;
    if (typeof payload?.members !== "number") return;
    currentPeers = payload.members;
    updateLockUI(isRoomLocked);
    addMeta("👋 A peer securely joined.");
  });

  socket.on("peer-left", (data) => {
    const payload = Array.isArray(data) ? data[0] : data;
    if (typeof payload?.members !== "number") return;
    currentPeers = payload.members;
    updateLockUI(isRoomLocked);
    addMeta("💨 A peer left.");
  });

  socket.on("room-locked", (data) => {
    const payload = Array.isArray(data) ? data[0] : data;
    updateLockUI(payload.locked);
    addMeta(payload.locked ? "🔒 Room locked." : "🔓 Room unlocked.");
  });

  socket.on("room-closed", () => {
    alert("Room closed.");
    location.href = "/";
  });

  socket.on("left", () => { location.href = "/"; });

  socket.on("ciphertext", async (data) => {
    const packet = typeof data === "string" ? data : data?.[0];
    if (!packet) return;

    try {
      const p = base64ToBytes(packet);
      const v = new DataView(p.buffer);
      let o   = 0;

      if (v.getUint8(o++) !== 1) throw new Error("Invalid version");
      o += 8;

      const iv = p.slice(o, o + 12); o += 12;
      const ct = p.slice(o);

      const dec  = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct);
      const text = new TextDecoder().decode(new Uint8Array(dec));
      addMsg(text, "them");
    } catch (e) {
      console.error("Decrypt fail:", e);
      addMeta("⚠️ Failed to decrypt.");
    }
  });

  copyInviteBtn.onclick = async () => {
    await navigator.clipboard.writeText(
      `${location.origin}/?key=${encodeURIComponent(roomKey)}`
    );
    addMeta("🔗 Invite link copied.");
  };

  closeRoomBtn.onclick = () => socket?.emit("close-room");

  lockRoomBtn.onclick = () => {
    const newState = !isRoomLocked;
    updateLockUI(newState);
    socket?.emit("lock-room", { key: roomKey, locked: newState });
  };

  leaveRoomBtn.onclick = () => socket?.emit("leave-room");

  input.addEventListener("input", () => {
    if (socket && joined) socket.emit("typing", { key: roomKey });
  });
}

// ── send ──────────────────────────────────────────────────────────────────────

input.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendBtn.click();
  }
});

sendBtn.onclick = async () => {
  const text = input.value.trim();
  if (!text || !socket || !cryptoKey) return;

  input.value = "";
  input.style.height = "auto";
  addMsg(text, "me");

  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    new TextEncoder().encode(text)
  );

  const ct  = new Uint8Array(enc);
  const buf = new Uint8Array(1 + 4 + 4 + 12 + ct.length);
  const v   = new DataView(buf.buffer);

  let o = 0;
  v.setUint8(o++, 1);
  v.setUint32(o, 0);            o += 4;
  v.setUint32(o, Math.floor(Date.now() / 1000)); o += 4;
  buf.set(iv, o);               o += 12;
  buf.set(ct, o);

  socket.emit("ciphertext", { key: roomKey, packet: bytesToBase64(buf) });
};

// ── crypto ────────────────────────────────────────────────────────────────────

async function deriveKey(pc, saltB64) {
  const pw   = new TextEncoder().encode(pc);
  const salt = base64ToBytes(saltB64);
  const km   = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveKey"]);

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
    km,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ── DOM helpers ───────────────────────────────────────────────────────────────

function formatTime(date) {
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit", minute: "2-digit", hour12: false,
  });
}

function addMsg(text, who) {
  const d      = document.createElement("div");
  d.className  = `msg ${who}`;

  const bubble = document.createElement("div");
  bubble.className   = "msg-bubble";
  bubble.textContent = text;
  d.appendChild(bubble);

  const time = document.createElement("span");
  time.className   = "msg-time";
  time.textContent = formatTime(new Date());
  d.appendChild(time);

  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
}

function addMeta(text) {
  const d = document.createElement("div");
  d.className   = "meta";
  d.textContent = text;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}