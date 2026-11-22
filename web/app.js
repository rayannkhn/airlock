// AirLock web app: pair, send and receive between ANY two devices with a screen and a camera.
// All cryptography lives in airlock-core.js; this file is only the user interface.
import * as A from "./airlock-core.js";
import * as S from "./store.js";

const APP_VERSION = "1.0.0";
const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let me = null;           // this device's identity
let current = "loading"; // current screen
const history = [];

// ---------------------------------------------------------------- plain-language errors

const FRIENDLY = {
  replay: "Rejected: this exact transfer was already received. Someone may be replaying an old recording.",
  too_old: "Rejected: this transfer is more than 24 hours old, so it could be a replayed recording.",
  future: "Rejected: the sender's clock is ahead. Check both devices' date and time.",
  untrusted: "Rejected: the sender is not one of your contacts. Pair with them first.",
  bad_signature: "Rejected: the signature does not match. The data was altered or forged.",
  not_for_me: "Rejected: this transfer was locked for a different device.",
  tampering: "Aborted: many pieces failed their integrity check. Someone is injecting fake data.",
  hash: "Rejected: the reassembled file does not match its fingerprint.",
  manifest: "Rejected: the file description is damaged.",
  too_big: "Rejected: the file is too large.",
  bad_key: "Rejected: the sender's key is invalid.",
  version: "Rejected: this transfer was made by an incompatible AirLock version.",
};
const friendly = (e) => FRIENDLY[e?.code] || `Stopped: ${e?.message || e}`;

// ---------------------------------------------------------------- navigation

function go(screen, { push = true } = {}) {
  if (screen === current) return;
  leave(current);
  if (push && current !== "loading") history.push(current);
  current = screen;
  document.querySelectorAll("main > section").forEach((s) => (s.hidden = s.dataset.screen !== screen));
  $("backBtn").hidden = !["pair", "contacts", "send", "receive", "about"].includes(screen);
  enter(screen);
  window.scrollTo(0, 0);
}
function back() { go(history.pop() || "home", { push: false }); }
$("backBtn").onclick = back;
document.addEventListener("click", (e) => { const t = e.target.closest("[data-go]"); if (t) go(t.dataset.go); });

function enter(screen) {
  if (screen === "home") renderHome();
  if (screen === "pair") renderPair();
  if (screen === "contacts") renderContacts();
  if (screen === "send") renderSend();
  if (screen === "receive") resetReceive();
  if (screen === "about") $("version").textContent = `AirLock web ${APP_VERSION} · protocol v${A.PROTOCOL_VERSION}`;
}
function leave(screen) {
  if (screen === "pair") pairScanner?.stop();
  if (screen === "receive") stopReceive(false);
}

// ---------------------------------------------------------------- QR drawing

function makeQr(text) {
  const qr = globalThis.qrcode(0, "M"); // error correction M: ~15% damage tolerated
  qr.addData(text, "Alphanumeric");
  qr.make();
  return qr;
}
function drawQr(canvas, qr) {
  const n = qr.getModuleCount(), quiet = 4;
  const px = Math.max(2, Math.floor(Math.min(1400, Math.min(innerWidth, innerHeight) * devicePixelRatio) / (n + 2 * quiet)));
  canvas.width = canvas.height = px * (n + 2 * quiet);
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#000";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * px, (r + quiet) * px, px, px);
}

// ---------------------------------------------------------------- camera scanner

class Scanner {
  constructor(video, msgEl, onText) { this.video = video; this.msgEl = msgEl; this.onText = onText; this.running = false; this.last = null; this.reads = 0; }
  async start() {
    if (!navigator.mediaDevices?.getUserMedia) throw new Error("this browser has no camera access (it needs HTTPS)");
    this.stream = await navigator.mediaDevices.getUserMedia({ audio: false,
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } } });
    this.video.srcObject = this.stream;
    await this.video.play();
    this.msgEl.hidden = true;
    // Use the platform's built-in QR reader when there is one (fast on phones); otherwise jsQR.
    this.detector = null;
    if ("BarcodeDetector" in globalThis) {
      try { if ((await BarcodeDetector.getSupportedFormats()).includes("qr_code")) this.detector = new BarcodeDetector({ formats: ["qr_code"] }); } catch { /* fall back */ }
    }
    this.canvas = document.createElement("canvas");
    this.running = true;
    this.loop();
  }
  async read() {
    const v = this.video;
    if (v.readyState < 2) return null;
    if (this.detector) { const r = await this.detector.detect(v); return r[0]?.rawValue || null; }
    const scale = Math.min(1, 800 / v.videoWidth);
    const w = Math.round(v.videoWidth * scale), h = Math.round(v.videoHeight * scale);
    this.canvas.width = w; this.canvas.height = h;
    const ctx = this.canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(v, 0, 0, w, h);
    const code = globalThis.jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: "dontInvert" });
    return code?.data || null;
  }
  async loop() {
    while (this.running) {
      let text = null;
      try { text = await this.read(); } catch { /* a bad frame: keep going */ }
      if (text && text !== this.last) { this.last = text; this.reads++; await this.onText(text); }
      await sleep(this.detector ? 50 : 20);
    }
  }
  stop() {
    this.running = false;
    this.stream?.getTracks().forEach((t) => t.stop());
    this.stream = null;
    this.video.srcObject = null;
    this.msgEl.hidden = false;
  }
}

// ---------------------------------------------------------------- home & contacts

async function renderHome() {
  $("meName").textContent = me.name;
  $("meFp").textContent = await A.fingerprint(me.signPub);
  const n = (await S.getPeers()).length;
  $("contactCount").textContent = n ? `${n} paired device${n > 1 ? "s" : ""}` : "No contacts yet";
}
async function renderContacts() {
  const peers = await S.getPeers(), list = $("contactList");
  list.innerHTML = "";
  if (!peers.length) list.innerHTML = `<li><span class="muted">No contacts yet. Pair with another device first.</span></li>`;
  for (const p of peers) {
    const li = document.createElement("li");
    li.innerHTML = `<div><b></b><span class="fp"></span></div><button class="btn quiet">Remove</button>`;
    li.querySelector("b").textContent = p.name;
    li.querySelector(".fp").textContent = p.fp;
    li.querySelector("button").onclick = async () => {
      if (!confirm(`Remove ${p.name}? You will need to pair again to exchange files.`)) return;
      await S.savePeers(peers.filter((x) => x !== p)); renderContacts();
    };
    list.appendChild(li);
  }
}

// ---------------------------------------------------------------- pairing

let pairScanner = null, foundCard = null;
async function renderPair() {
  drawQr($("myCardQr"), makeQr(A.b45encode(await A.makeCard(me))));
  $("pairMyFp").textContent = await A.fingerprint(me.signPub);
  $("pairFound").hidden = true; $("pairMsg").textContent = ""; $("pairScan").hidden = false;
}
$("pairScan").onclick = async () => {
  $("pairMsg").textContent = ""; $("pairMsg").className = "msg";
  pairScanner = new Scanner($("pairVideo"), $("pairCamMsg"), async (text) => {
    let card;
    try { card = await A.parseCard(A.b45decode(text)); } catch { return; } // some other QR code
    if (A.equalBytes(card.signPub, me.signPub)) { $("pairMsg").textContent = "That's this device's own code. Scan the OTHER device."; return; }
    pairScanner.stop();
    foundCard = card;
    $("foundName").textContent = card.name; $("foundFp").textContent = card.fingerprint; $("foundSaveAs").value = card.name;
    $("pairFound").hidden = false; $("pairScan").hidden = true;
  });
  try { await pairScanner.start(); $("pairScan").hidden = true; }
  catch (e) { $("pairMsg").textContent = cameraError(e); $("pairMsg").className = "msg bad"; }
};
$("pairYes").onclick = async () => {
  const peers = await S.getPeers();
  const name = ($("foundSaveAs").value.trim() || foundCard.name).slice(0, 40);
  const same = peers.find((p) => A.equalBytes(p.signPub, foundCard.signPub));
  const clash = peers.find((p) => p.name === name && !A.equalBytes(p.signPub, foundCard.signPub));
  if (clash) { $("pairMsg").textContent = `You already have a contact called “${name}” with a DIFFERENT key. Remove it first if this is intentional.`; $("pairMsg").className = "msg bad"; return; }
  const entry = { name, signPub: foundCard.signPub, recvPub: foundCard.recvPub, fp: foundCard.fingerprint };
  await S.savePeers(same ? peers.map((p) => (p === same ? entry : p)) : [...peers, entry]);
  $("pairFound").hidden = true; $("pairScan").hidden = false;
  $("pairMsg").textContent = `✓ Paired with ${name}. Make sure they scan your code too.`; $("pairMsg").className = "msg ok";
};
$("pairNo").onclick = () => {
  foundCard = null; $("pairFound").hidden = true; $("pairScan").hidden = false;
  $("pairMsg").textContent = "Not saved. If the fingerprints differ, someone may be interfering: don't pair."; $("pairMsg").className = "msg bad";
};
function cameraError(e) {
  if (e?.name === "NotAllowedError") return "Camera permission was denied. Allow camera access for this app in the browser settings.";
  if (e?.name === "NotFoundError") return "No camera found on this device.";
  return `Camera problem: ${e?.message || e}`;
}

// ---------------------------------------------------------------- send

async function renderSend() {
  const peers = await S.getPeers();
  $("sendNoContacts").hidden = peers.length > 0; $("sendForm").hidden = peers.length === 0;
  const sel = $("sendTo"); sel.innerHTML = "";
  peers.forEach((p, i) => { const o = document.createElement("option"); o.value = i; o.textContent = p.name; sel.appendChild(o); });
  $("sendMsg").textContent = "";
}
$("sendStart").onclick = async () => {
  const peers = await S.getPeers();
  const peer = peers[Number($("sendTo").value)];
  const file = $("sendFile").files[0];
  const text = $("sendText").value;
  let name, data;
  if (file) { name = file.name; data = new Uint8Array(await file.arrayBuffer()); }
  else if (text.trim()) { name = "message.txt"; data = new TextEncoder().encode(text); }
  else { $("sendMsg").textContent = "Choose a file or type a message first."; $("sendMsg").className = "msg bad"; return; }
  if (data.length > 200 * 1024) { $("sendMsg").textContent = "That file is large: it would need thousands of codes. Try something under 20 KB."; $("sendMsg").className = "msg bad"; return; }
  $("sendMsg").textContent = "Locking and sealing…"; $("sendMsg").className = "msg";
  const { seal, session } = await A.createSeal(me, peer);
  const packets = [seal, ...(await A.buildTransfer(me, session, name, data))];
  startPlayer(packets.map((p) => makeQr(A.b45encode(p))), A.formatSas(session.sas), peer.name, name);
};

let playTimer = null, wakeLock = null, codesPerSecond = 4;
async function startPlayer(qrs, code, toName, fileName) {
  $("player").hidden = false;
  $("playCode").textContent = code;
  $("playTo").textContent = `to ${toName} · ${fileName}`;
  try { wakeLock = await navigator.wakeLock?.request("screen"); } catch { /* not supported: fine */ }
  let i = 0;
  const tick = () => {
    drawQr($("playQr"), qrs[i]);
    $("playCount").textContent = `code ${i + 1} of ${qrs.length} · ${codesPerSecond}/s`;
    i = (i + 1) % qrs.length; // loops: a missed code comes round again
    playTimer = setTimeout(tick, 1000 / codesPerSecond);
  };
  tick();
}
function stopPlayer() { clearTimeout(playTimer); playTimer = null; $("player").hidden = true; wakeLock?.release?.(); wakeLock = null; }
$("playStop").onclick = stopPlayer;
$("slower").onclick = () => { codesPerSecond = Math.max(1, codesPerSecond - 1); };
$("faster").onclick = () => { codesPerSecond = Math.min(10, codesPerSecond + 1); };

// ---------------------------------------------------------------- receive

let rx = null; // { scanner, session, reasm, pending[], seal, done }
function step(kind, text) {
  const li = document.createElement("li"); li.className = kind;
  li.innerHTML = `<span class="ic">${{ ok: "✓", bad: "✗", ask: "?", info: "•" }[kind]}</span><span></span>`;
  li.lastChild.textContent = text;
  $("recvSteps").appendChild(li);
}
function resetReceive() {
  $("recvSteps").innerHTML = ""; $("recvResult").innerHTML = ""; $("recvConfirm").hidden = true;
  $("recvBar").style.width = "0"; $("recvCount").textContent = "Not started";
  $("recvStart").disabled = false; $("recvStop").disabled = true;
  step("info", "Press Start, then point the camera at the sender's screen.");
}
function stopReceive(withMessage = true) {
  if (!rx) return;
  rx.scanner?.stop(); rx.reasm?.discard();
  if (withMessage && !rx.done) step("bad", "Stopped. Nothing was saved.");
  rx = null;
  $("recvStart").disabled = false; $("recvStop").disabled = true;
}
function failReceive(e) {
  step("bad", friendly(e));
  const div = document.createElement("div"); div.className = "banner bad"; div.textContent = "✗ " + friendly(e);
  $("recvResult").replaceChildren(div);
  if (rx) rx.done = true;
  stopReceive(false);
}
async function handlePacketText(text) {
  if (!rx || rx.done) return;
  let bytes;
  try { bytes = A.b45decode(text); } catch { return; } // a QR code that isn't ours
  if (!rx.session) {
    if (rx.scanner && rx.scanner.reads === 1) step("info", "First QR code read. Looking for the seal (frame 0)…");
    let pkt;
    try { pkt = A.decodePacket(bytes); } catch { return; }
    if (pkt.type !== A.PacketType.SEAL) { if (rx.pending.length < 4096) rx.pending.push(bytes); return; }
    try { rx.session = await A.openSeal(me, await S.getPeers(), bytes, S.isUsed); }
    catch (e) { failReceive(e); return; }
    const who = rx.session.peerName;
    step("ok", `From ${who}: a paired contact.`);
    step("ok", `${who}'s signature is valid: nobody altered the seal.`);
    step("ok", "Fresh, and never received before (not a replay).");
    step("ok", "Secret key computed. Only this device can unlock the file.");
    rx.reasm = new A.Reassembler(rx.session);
    for (const p of rx.pending) await feed(p);
    rx.pending = [];
  } else {
    await feed(bytes);
  }
  if (rx?.reasm?.complete && !rx.done) await finishReceive();
}
async function feed(bytes) {
  try { await rx.reasm.feed(bytes); } catch (e) { failReceive(e); return; }
  const r = rx.reasm;
  if (r.total) {
    $("recvBar").style.width = `${Math.round((100 * r.received) / r.total)}%`;
    $("recvCount").textContent = `${r.received} of ${r.total} pieces · ${rx.scanner?.reads ?? 0} QR reads`;
  }
}
async function finishReceive() {
  rx.done = true;
  rx.scanner?.stop();
  let file;
  try { file = await rx.reasm.finalize(); } catch (e) { rx.done = false; failReceive(e); return; }
  step("ok", "Every piece passed its integrity check, and the whole file matches its signed fingerprint.");
  step("ask", "Last check, by a person: compare the code with the sender's screen.");
  $("recvCode").textContent = A.formatSas(rx.session.sas);
  $("recvConfirm").hidden = false;
  const session = rx.session;
  $("recvYes").onclick = async () => {
    $("recvConfirm").hidden = true;
    await S.markUsed(A.toHex(session.sid), session.timestamp); // a second playback is now a replay
    showFile(file, session.peerName);
    rx?.reasm?.discard(); rx = null;
    $("recvStart").disabled = false; $("recvStop").disabled = true;
  };
  $("recvNo").onclick = () => {
    $("recvConfirm").hidden = true;
    step("bad", "You said the codes differ, so the file was discarded. Someone may be in the middle.");
    rx?.reasm?.discard(); rx = null;
    $("recvStart").disabled = false; $("recvStop").disabled = true;
  };
}
function showFile(file, from) {
  const blob = new Blob([file.data]);
  const url = URL.createObjectURL(blob);
  const box = document.createElement("div"); box.className = "banner ok";
  box.innerHTML = `<div></div><div class="row"><a class="btn ok">Save file</a></div>`;
  box.firstChild.textContent = `✓ Received “${file.filename}” (${file.data.length} bytes) from ${from}, verified.`;
  const a = box.querySelector("a"); a.href = url; a.download = file.filename;
  if (navigator.canShare?.({ files: [new File([blob], file.filename)] })) {
    const share = document.createElement("button"); share.className = "btn quiet"; share.textContent = "Share / open…";
    share.onclick = () => navigator.share({ files: [new File([blob], file.filename)] }).catch(() => {});
    box.querySelector(".row").appendChild(share);
  }
  try { // show small text files right away
    const text = new TextDecoder("utf-8", { fatal: true }).decode(file.data);
    if (file.data.length < 20000) { const pre = document.createElement("div"); pre.className = "preview"; pre.textContent = text; box.appendChild(pre); }
  } catch { /* binary: no preview */ }
  $("recvResult").replaceChildren(box);
}
$("recvStart").onclick = async () => {
  resetReceive();
  $("recvSteps").innerHTML = "";
  rx = { pending: [], done: false };
  rx.scanner = new Scanner($("recvVideo"), $("recvCamMsg"), handlePacketText);
  step("info", "Camera on. Point it at the sender's screen, 20–40 cm away.");
  try { await rx.scanner.start(); } catch (e) { failReceive({ message: cameraError(e) }); return; }
  $("recvStart").disabled = true; $("recvStop").disabled = false;
};
$("recvStop").onclick = () => stopReceive(true);

// ---------------------------------------------------------------- setup & start

$("createIdentity").onclick = async () => {
  const name = $("deviceName").value.trim() || ($("deviceName").placeholder.replace(/^e\.g\. /, ""));
  $("createIdentity").disabled = true;
  me = await A.generateIdentity(name.slice(0, 40));
  await S.saveIdentity(me);
  go("home", { push: false });
};
$("wipe").onclick = async () => {
  if (!confirm("Delete this device's keys and contacts? Other devices will need to pair with it again.")) return;
  await S.wipe(); location.reload();
};

async function start() {
  const missing = await A.checkSupport();
  if (missing.length) { $("missing").textContent = missing.join(", "); go("unsupported", { push: false }); return; }
  me = await S.getIdentity();
  if (!me) {
    $("deviceName").placeholder = /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent) ? "e.g. My phone" : "e.g. My laptop";
    go("setup", { push: false });
  } else go("home", { push: false });
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").then(() => navigator.serviceWorker.ready).then(() => ($("offline").hidden = false)).catch(() => {});
  }
  if (new URLSearchParams(location.search).has("debug")) {
    // Test hook (only with ?debug in the URL): feed QR texts without a camera.
    globalThis.airlockDebug = {
      feed: async (text) => { rx ??= { pending: [], done: false }; await handlePacketText(text); },
      transferTexts: async (peerIndex, name, text) => {
        const peer = (await S.getPeers())[peerIndex];
        const { seal, session } = await A.createSeal(me, peer);
        const packets = [seal, ...(await A.buildTransfer(me, session, name, new TextEncoder().encode(text)))];
        return { code: A.formatSas(session.sas), texts: packets.map(A.b45encode) };
      },
      cardText: async () => A.b45encode(await A.makeCard(me)),
      addPeerFromCardText: async (text) => { const c = await A.parseCard(A.b45decode(text)); await S.savePeers([...(await S.getPeers()), { name: c.name, signPub: c.signPub, recvPub: c.recvPub, fp: c.fingerprint }]); },
    };
  }
}
start();
