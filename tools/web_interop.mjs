// Interop helper driven by tests/test_web_interop.py: reads a JSON job on stdin,
// runs the JavaScript side of a transfer, and prints a JSON result.
import * as A from "../web/airlock-core.js";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const qrcode = require("../web/vendor/qrcode-generator-1.4.4.js");
const jsQR = require("../web/vendor/jsqr-1.4.0.js");

const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const job = JSON.parse(await new Promise((res) => { let d = ""; process.stdin.on("data", (c) => (d += c)); process.stdin.on("end", () => res(d)); }));

async function identity(j) {
  return A.importIdentity({ name: j.name, signPkcs8: b64(j.sign_pkcs8), signPub: b64(j.sign_pub), recvPkcs8: b64(j.recv_pkcs8), recvPub: b64(j.recv_pub) });
}
const peer = (j) => ({ name: j.name, signPub: b64(j.sign_pub), recvPub: b64(j.recv_pub) });

let out;
if (job.mode === "receive") {          // Python sent, JavaScript receives
  const me = await identity(job.me);
  const packets = job.packets.map(b64);
  const session = await A.openSeal(me, [peer(job.sender)], packets[0], async () => false);
  const r = new A.Reassembler(session);
  for (const p of packets.slice(1)) await r.feed(p);
  const file = await r.finalize();
  out = { sas: A.formatSas(session.sas), filename: file.filename, data: Buffer.from(file.data).toString("base64"), sender: session.peerName };
} else if (job.mode === "send") {      // JavaScript sends, Python receives
  const me = await identity(job.me);
  const { seal, session } = await A.createSeal(me, peer(job.recipient));
  const packets = await A.buildTransfer(me, session, job.filename, b64(job.data));
  out = { sas: A.formatSas(session.sas), packets: [seal, ...packets].map((p) => Buffer.from(p).toString("base64")) };
} else if (job.mode === "card") {      // JavaScript card, Python parses it
  out = { card: Buffer.from(await A.makeCard(await identity(job.me))).toString("base64"), fingerprint: await A.fingerprint(b64(job.me.sign_pub)) };
} else if (job.mode === "qr_text") {   // what a JS QR code carries for a packet
  out = { text: A.b45encode(b64(job.packet)) };
}
else if (job.mode === "qr_encode") { // the app's QR generator: return the module matrix
  const qr = qrcode(0, "M");
  qr.addData(job.text, "Alphanumeric");
  qr.make();
  const n = qr.getModuleCount();
  const rows = [];
  for (let r = 0; r < n; r++) { let row = ""; for (let c = 0; c < n; c++) row += qr.isDark(r, c) ? "1" : "0"; rows.push(row); }
  out = { rows };
} else if (job.mode === "qr_decode") { // the app's QR decoder on a grayscale image
  const g = b64(job.gray), rgba = new Uint8ClampedArray(g.length * 4);
  for (let i = 0; i < g.length; i++) { rgba[4 * i] = rgba[4 * i + 1] = rgba[4 * i + 2] = g[i]; rgba[4 * i + 3] = 255; }
  const code = jsQR(rgba, job.width, job.height);
  out = { text: code ? code.data : null };
}
process.stdout.write(JSON.stringify(out));
