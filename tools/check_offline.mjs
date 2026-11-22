// Real-browser offline test for the web app, using Chrome's DevTools Protocol.
//   1. open the app online and wait for its service worker to cache everything;
//   2. cut the network completely (offline emulation + the server is unreachable);
//   3. reload and check the app still starts and its crypto still works.
// Usage: node tools/check_offline.mjs http://127.0.0.1:8800/
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const url = process.argv[2] || "http://127.0.0.1:8800/";
const port = 9333;
const profile = mkdtempSync(join(tmpdir(), "airlock-chrome-"));
const chrome = spawn("google-chrome", ["--headless=new", "--disable-gpu", "--no-first-run", `--user-data-dir=${profile}`,
  `--remote-debugging-port=${port}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws, nextId = 0;
const pending = new Map();
function send(method, params = {}, sessionId) {
  const id = ++nextId;
  ws.send(JSON.stringify({ id, method, params, sessionId }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}
async function evaluate(sessionId, expression) {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || "evaluate failed");
  return r.result.value;
}

try {
  let info;
  for (let i = 0; i < 50 && !info; i++) { try { info = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); } catch { await sleep(200); } }
  ws = new WebSocket(info.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  ws.onmessage = (m) => { const msg = JSON.parse(m.data); if (msg.id && pending.has(msg.id)) { const p = pending.get(msg.id); pending.delete(msg.id); msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result); } };

  const { targetId } = await send("Target.createTarget", { url });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  await send("Runtime.enable", {}, sessionId);
  await send("Network.enable", {}, sessionId);

  // 1. Online: wait for the service worker and the "Works offline" badge.
  let ready = false;
  for (let i = 0; i < 60 && !ready; i++) { await sleep(250); ready = await evaluate(sessionId, `!document.getElementById("offline").hidden`).catch(() => false); }
  const cached = await evaluate(sessionId, `caches.keys().then(async ks => { const c = await caches.open(ks[0]); return (await c.keys()).length; })`);
  console.log(`online : service worker ready=${ready}, files cached=${cached}`);

  // 2. Offline: no network at all.
  await send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 }, sessionId);
  await send("Page.enable", {}, sessionId);
  await send("Page.reload", { ignoreCache: false }, sessionId);
  await sleep(2500);
  const screen = await evaluate(sessionId, `[...document.querySelectorAll("main > section")].find(s => !s.hidden)?.dataset.screen`);
  const cryptoOk = await evaluate(sessionId, `crypto.subtle.generateKey({name:"Ed25519"}, false, ["sign"]).then(() => true, () => false)`);
  const onLine = await evaluate(sessionId, "navigator.onLine");
  console.log(`offline: navigator.onLine=${onLine}, app screen="${screen}", Ed25519 works=${cryptoOk}`);
  const pass = ready && cached >= 10 && (screen === "setup" || screen === "home") && cryptoOk && onLine === false;
  console.log(pass ? "PASS: the app starts and works with the network switched off" : "FAIL");
  process.exitCode = pass ? 0 : 1;
} catch (e) {
  console.error("FAIL:", e.message);
  process.exitCode = 1;
} finally {
  ws?.close();
  chrome.kill();
}
