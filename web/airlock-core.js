// AirLock protocol core for browsers (and Node 20+), wire-compatible with the Python package.
//
// Implements the one-way mode of docs/design.md sections 4, 8 and 10:
//   identities (Ed25519 signing + X25519 receiving), contact cards, the SEAL
//   handshake, HKDF key schedule, AES-256-GCM packets with the header as AAD,
//   the signed manifest, and a fail-closed reassembler.
//
// Every primitive comes from the platform's WebCrypto (crypto.subtle). No
// curve arithmetic or cipher is implemented here. Private keys are created
// NON-EXTRACTABLE: page scripts can use them but can never read their bytes.
//
// Byte-for-byte compatibility with Python is checked by tests/test_web_interop.py.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

export const PROTOCOL_VERSION = 1;
export const MAGIC = 0x414c; // "AL"
export const HEADER_SIZE = 30;
export const CRC_SIZE = 4;
export const MAX_PAYLOAD = 4096;
export const TAG_SIZE = 16;
export const QR_CHUNK_SIZE = 150;
export const MAX_FILE_SIZE = 16 * 1024 * 1024;
export const MAX_AEAD_FAILURES = 32;
export const MAX_AGE_SECONDS = 24 * 3600;
export const MAX_FUTURE_SKEW = 10 * 60;
export const PacketType = { HELLO: 1, REPLY: 2, FINISH: 3, MANIFEST: 4, DATA: 5, RECEIPT: 6, SEAL: 7, LAB_INSECURE: 8 };

const LABEL_SEAL = te.encode("airlock-seal");
const LABEL_MANIFEST = te.encode("airlock-manifest");
const LABEL_CARD = te.encode("airlock-card");
const KEYS_INFO = te.encode("airlock v1 keys");
const SAS_INFO = te.encode("airlock sas");
const CARD_MAGIC = te.encode("ALC1");

/** Error with a machine-readable code; the UI maps codes to plain-language messages. */
export class AirLockError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

// ---------------------------------------------------------------- byte helpers

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function u8(n) { return Uint8Array.of(n & 0xff); }
function u16(n) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n); return b; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; }
/** Compare without an early exit (public data mostly, but the habit is cheap). */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
export function randomBytes(n) { return globalThis.crypto.getRandomValues(new Uint8Array(n)); }

// ---------------------------------------------------------------- CRC32 (noise filter ONLY, not security)

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------- Base45 (RFC 9285): QR alphanumeric text

const B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
export function b45encode(bytes) {
  let out = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    let n = bytes[i] * 256 + bytes[i + 1];
    const c = n % 45; n = (n - c) / 45;
    const d = n % 45; const e = (n - d) / 45;
    out += B45[c] + B45[d] + B45[e];
  }
  if (bytes.length % 2) { const n = bytes[bytes.length - 1]; out += B45[n % 45] + B45[Math.floor(n / 45)]; }
  return out;
}
export function b45decode(text) {
  const v = Array.from(text, (ch) => { const i = B45.indexOf(ch); if (i < 0) throw new AirLockError("framing", "invalid Base45"); return i; });
  if (v.length % 3 === 1) throw new AirLockError("framing", "invalid Base45 length");
  const out = [];
  for (let i = 0; i + 2 < v.length; i += 3) {
    const n = v[i] + v[i + 1] * 45 + v[i + 2] * 2025;
    if (n > 0xffff) throw new AirLockError("framing", "invalid Base45 group");
    out.push(n >> 8, n & 0xff);
  }
  if (v.length % 3 === 2) {
    const n = v[v.length - 2] + v[v.length - 1] * 45;
    if (n > 0xff) throw new AirLockError("framing", "invalid Base45 group");
    out.push(n);
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------- framing (design §8.1)

export function headerBytes(type, sid, seq, total, length, version = PROTOCOL_VERSION) {
  if (sid.length !== 16) throw new AirLockError("framing", "session id must be 16 bytes");
  if (length > MAX_PAYLOAD) throw new AirLockError("framing", "payload too large");
  return concat(u16(MAGIC), u8(version), u8(type), sid, u32(seq), u32(total), u16(length));
}
export function encodePacket({ type, sid, seq, total, payload, version = PROTOCOL_VERSION }) {
  const body = concat(headerBytes(type, sid, seq, total, payload.length, version), payload);
  return concat(body, u32(crc32(body)));
}
export function decodePacket(raw) {
  if (raw.length < HEADER_SIZE + CRC_SIZE) throw new AirLockError("framing", "packet too short");
  if (raw.length > HEADER_SIZE + MAX_PAYLOAD + CRC_SIZE) throw new AirLockError("framing", "packet too large");
  const body = raw.subarray(0, raw.length - CRC_SIZE);
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  if (crc32(body) !== dv.getUint32(raw.length - CRC_SIZE)) throw new AirLockError("crc", "CRC mismatch");
  if (dv.getUint16(0) !== MAGIC) throw new AirLockError("framing", "bad magic");
  const version = raw[2];
  if (version !== PROTOCOL_VERSION) throw new AirLockError("version", `unsupported protocol version ${version}`);
  const type = raw[3];
  if (!Object.values(PacketType).includes(type)) throw new AirLockError("framing", "unknown packet type");
  const length = dv.getUint16(28);
  const payload = raw.slice(HEADER_SIZE, raw.length - CRC_SIZE);
  if (length !== payload.length) throw new AirLockError("framing", "length mismatch");
  return { type, version, sid: raw.slice(4, 20), seq: dv.getUint32(20), total: dv.getUint32(24), payload,
           header: raw.slice(0, HEADER_SIZE) };
}

// ---------------------------------------------------------------- hashing and key schedule (design §6, §7)

export async function sha256(bytes) { return new Uint8Array(await subtle.digest("SHA-256", bytes)); }
/** SHA-256 over 4-byte-length-prefixed parts: unambiguous, so ("ab","c") != ("a","bc"). */
export async function transcriptHash(...parts) {
  return sha256(concat(...parts.flatMap((p) => [u32(p.length), p])));
}
async function hkdf(ikm, salt, info, length) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
}
/** HKDF-Expand only (RFC 5869 §2.3), as used for the short verification code. */
async function hkdfExpand(prk, info, length) {
  const key = await subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const t1 = new Uint8Array(await subtle.sign("HMAC", key, concat(info, Uint8Array.of(1))));
  return t1.slice(0, length); // length <= 32, so one block is enough
}
export async function deriveSessionKeys(shared, sid, th) {
  const okm = await hkdf(shared, sid, concat(KEYS_INFO, th), 120);
  return { kIR: okm.slice(0, 32), kRI: okm.slice(32, 64), ivIR: okm.slice(64, 76), ivRI: okm.slice(76, 88), kSas: okm.slice(88, 120) };
}
export async function computeSas(keys) { return hkdfExpand(keys.kSas, SAS_INFO, 4); }
export function formatSas(sas) { const h = toHex(sas).toUpperCase(); return `${h.slice(0, 4)}-${h.slice(4)}`; }
/** nonce = iv XOR seq (TLS 1.3 style). seq < 2^32, so only the last 4 bytes change. */
export function makeNonce(iv, seq) {
  const n = iv.slice();
  const s = u32(seq);
  for (let i = 0; i < 4; i++) n[8 + i] ^= s[i];
  return n;
}

// ---------------------------------------------------------------- AEAD packets (design §8.2)

export class PacketSealer {
  constructor(keyBytes, iv, sid) { this.keyBytes = keyBytes; this.iv = iv; this.sid = sid; this.used = new Set(); }
  async seal(type, seq, total, plaintext) {
    if (this.used.has(seq)) throw new AirLockError("nonce", `seq ${seq} already used`); // never reuse a nonce
    const aad = headerBytes(type, this.sid, seq, total, plaintext.length + TAG_SIZE);
    this.key ??= await subtle.importKey("raw", this.keyBytes, "AES-GCM", false, ["encrypt"]);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: makeNonce(this.iv, seq), additionalData: aad, tagLength: 128 }, this.key, plaintext));
    this.used.add(seq);
    return encodePacket({ type, sid: this.sid, seq, total, payload: ct });
  }
}
export class PacketOpener {
  constructor(keyBytes, iv, sid) { this.keyBytes = keyBytes; this.iv = iv; this.sid = sid; }
  async open(pkt) {
    if (!equalBytes(pkt.sid, this.sid)) throw new AirLockError("session", "packet belongs to another session");
    if (pkt.payload.length < TAG_SIZE) throw new AirLockError("aead", "ciphertext too short");
    this.key ??= await subtle.importKey("raw", this.keyBytes, "AES-GCM", false, ["decrypt"]);
    try {
      return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: makeNonce(this.iv, pkt.seq), additionalData: pkt.header, tagLength: 128 }, this.key, pkt.payload));
    } catch {
      throw new AirLockError("aead", "authentication tag mismatch");
    }
  }
}

// ---------------------------------------------------------------- identities and contact cards (design §4)

export async function fingerprint(signPub) {
  const h = toHex((await sha256(signPub)).slice(0, 20)).toUpperCase();
  return h.match(/.{4}/g).join(" ");
}
async function rawPublic(key) { return new Uint8Array(await subtle.exportKey("raw", key)); }

/** A device identity. The private keys are non-extractable CryptoKeys (storable in IndexedDB). */
export async function generateIdentity(name) {
  const sign = await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const recv = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  return { name, signPriv: sign.privateKey, signPub: await rawPublic(sign.publicKey),
           recvPriv: recv.privateKey, recvPub: await rawPublic(recv.publicKey) };
}
/** For tests and interop: build an identity from PKCS#8 private keys + raw public keys. */
export async function importIdentity({ name, signPkcs8, signPub, recvPkcs8, recvPub }) {
  return { name, signPub, recvPub,
           signPriv: await subtle.importKey("pkcs8", signPkcs8, { name: "Ed25519" }, false, ["sign"]),
           recvPriv: await subtle.importKey("pkcs8", recvPkcs8, { name: "X25519" }, false, ["deriveBits"]) };
}
async function signWith(identity, message) { return new Uint8Array(await subtle.sign({ name: "Ed25519" }, identity.signPriv, message)); }
export async function verifySignature(pub, sig, message) {
  if (pub.length !== 32 || sig.length !== 64) return false;
  try {
    const key = await subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, key, sig, message);
  } catch { return false; }
}
async function x25519(priv, peerPub) {
  let shared;
  try {
    const pub = await subtle.importKey("raw", peerPub, { name: "X25519" }, false, []);
    shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  } catch { throw new AirLockError("bad_key", "invalid ephemeral key (low-order point)"); }
  if (shared.every((b) => b === 0)) throw new AirLockError("bad_key", "all-zero shared secret");
  return shared;
}

/** Compact binary contact card for QR: "ALC1" | nameLen | name | sign(32) | recv(32) | sig(64).
 *  sig = Ed25519(sign, "airlock-card" || recv): the same binding as the Python JSON card. */
export async function makeCard(identity) {
  const name = te.encode(identity.name.slice(0, 40));
  const sig = await signWith(identity, concat(LABEL_CARD, identity.recvPub));
  return concat(CARD_MAGIC, u8(name.length), name, identity.signPub, identity.recvPub, sig);
}
export async function parseCard(bytes) {
  if (bytes.length < 5 || !equalBytes(bytes.subarray(0, 4), CARD_MAGIC)) throw new AirLockError("card", "not an AirLock contact card");
  const n = bytes[4];
  if (bytes.length !== 5 + n + 128) throw new AirLockError("card", "malformed contact card");
  const name = td.decode(bytes.subarray(5, 5 + n));
  const signPub = bytes.slice(5 + n, 37 + n), recvPub = bytes.slice(37 + n, 69 + n), sig = bytes.slice(69 + n);
  if (!(await verifySignature(signPub, sig, concat(LABEL_CARD, recvPub)))) throw new AirLockError("card", "contact card signature is invalid (card was altered)");
  return { name, signPub, recvPub, fingerprint: await fingerprint(signPub) };
}

// ---------------------------------------------------------------- one-way SEAL handshake (design §10)

async function sealSignedInput(sid, unsigned) {
  return concat(LABEL_SEAL, await transcriptHash(Uint8Array.of(PROTOCOL_VERSION), sid, unsigned));
}

/** Sender: build the SEAL for `peer` ({name, signPub, recvPub}). Returns {seal, session}. */
export async function createSeal(identity, peer, now = Date.now() / 1000) {
  const sid = randomBytes(16);
  const eph = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]); // fresh per transfer
  const ePub = await rawPublic(eph.publicKey);
  const unsigned = concat(u64(Math.floor(now)), peer.recvPub, ePub, identity.signPub);
  const sig = await signWith(identity, await sealSignedInput(sid, unsigned));
  const seal = encodePacket({ type: PacketType.SEAL, sid, seq: 0, total: 0, payload: concat(unsigned, sig) });
  const shared = await x25519(eph.privateKey, peer.recvPub);
  const keys = await deriveSessionKeys(shared, sid, await transcriptHash(seal));
  return { seal, session: { sid, keys, sas: await computeSas(keys), peerName: peer.name, role: "sender" } };
}

/** Receiver: verify a SEAL. `peers` = [{name, signPub, recvPub}], `isUsed(sidHex)` = replay store. */
export async function openSeal(identity, peers, raw, isUsed, now = Date.now() / 1000, maxAge = MAX_AGE_SECONDS) {
  const pkt = decodePacket(raw);
  if (pkt.type !== PacketType.SEAL || pkt.seq !== 0 || pkt.total !== 0) throw new AirLockError("framing", "not a SEAL packet");
  if (pkt.payload.length !== 168) throw new AirLockError("framing", "SEAL has the wrong length");
  const p = pkt.payload;
  const ts = Number(new DataView(p.buffer, p.byteOffset).getBigUint64(0));
  const recipient = p.subarray(8, 40), ePub = p.slice(40, 72), senderSign = p.slice(72, 104), sig = p.slice(104);
  if (!equalBytes(recipient, identity.recvPub)) throw new AirLockError("not_for_me", "this transfer is addressed to someone else");
  const peer = peers.find((x) => equalBytes(x.signPub, senderSign));
  if (!peer) throw new AirLockError("untrusted", "sender identity is not in the trust store");
  if (!(await verifySignature(senderSign, sig, await sealSignedInput(pkt.sid, p.subarray(0, 104))))) throw new AirLockError("bad_signature", "sender signature is invalid");
  if (ts > now + MAX_FUTURE_SKEW) throw new AirLockError("future", "SEAL timestamp is in the future");
  if (now - ts > maxAge) throw new AirLockError("too_old", "SEAL is too old: possible replay");
  if (await isUsed(toHex(pkt.sid))) throw new AirLockError("replay", "this session was already received (replay)");
  const shared = await x25519(identity.recvPriv, ePub);
  const keys = await deriveSessionKeys(shared, pkt.sid, await transcriptHash(raw));
  return { sid: pkt.sid, keys, sas: await computeSas(keys), peerName: peer.name, peerSign: senderSign, timestamp: ts, role: "receiver" };
}

// ---------------------------------------------------------------- manifest and transfer (design §8.3)

const WIN_RESERVED = new Set(["CON", "PRN", "AUX", "NUL", ...[1, 2, 3, 4, 5, 6, 7, 8, 9].flatMap((i) => [`COM${i}`, `LPT${i}`])]);
/** Same rules as Python's sanitize_filename: basename only, no control or Windows-forbidden characters. */
export function sanitizeFilename(name) {
  let base = name.replace(/\\/g, "/").split("/").pop();
  base = Array.from(base).filter((ch) => !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(ch) && !'<>:"/\\|?*'.includes(ch)).join("");
  base = base.replace(/^[ .]+|[ .]+$/g, "");
  if (!base) base = "received.bin";
  if (WIN_RESERVED.has(base.split(".")[0].toUpperCase())) base = "_" + base;
  while (te.encode(base).length > 255) base = base.slice(0, -1);
  return base;
}
function manifestFields(m) {
  const name = te.encode(m.filename);
  return concat(u16(name.length), name, u64(m.size), m.sha256, u32(m.chunkCount));
}
function parseManifest(b) {
  try {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const n = dv.getUint16(0);
    if (n > 255) throw new Error();
    const filename = td.decode(b.subarray(2, 2 + n));
    let o = 2 + n;
    const size = Number(dv.getBigUint64(o)); o += 8;
    const sha = b.slice(o, o + 32); o += 32;
    const chunkCount = dv.getUint32(o); o += 4;
    const signature = b.slice(o);
    if (sha.length !== 32 || signature.length !== 64) throw new Error();
    return { filename, size, sha256: sha, chunkCount, signature, fieldsEnd: o };
  } catch { throw new AirLockError("manifest", "malformed manifest"); }
}

/** Sender: encrypt a file into [manifest, chunk_1..N] for an existing session (SEAL goes first). */
export async function buildTransfer(identity, session, filename, data, chunkSize = QR_CHUNK_SIZE) {
  const chunks = [];
  for (let i = 0; i < data.length; i += chunkSize) chunks.push(data.subarray(i, i + chunkSize));
  const total = chunks.length + 1;
  const m = { filename: sanitizeFilename(filename), size: data.length, sha256: await sha256(data), chunkCount: chunks.length };
  const fields = manifestFields(m);
  const sig = await signWith(identity, concat(LABEL_MANIFEST, session.sid, fields)); // bound to this session
  const sealer = new PacketSealer(session.keys.kIR, session.keys.ivIR, session.sid);
  const packets = [await sealer.seal(PacketType.MANIFEST, 0, total, concat(fields, sig))];
  for (let i = 0; i < chunks.length; i++) packets.push(await sealer.seal(PacketType.DATA, i + 1, total, chunks[i]));
  return packets;
}

/** Receiver: collects authenticated chunks IN MEMORY ONLY. Mirrors Python's Reassembler. */
export class Reassembler {
  constructor(session, { maxFileSize = MAX_FILE_SIZE, maxFailures = MAX_AEAD_FAILURES } = {}) {
    this.s = session;
    this.opener = new PacketOpener(session.keys.kIR, session.keys.ivIR, session.sid);
    this.maxFileSize = maxFileSize; this.maxFailures = maxFailures;
    this.total = null; this.manifest = null; this.chunks = new Map(); this.buffered = 0;
    this.stats = { accepted: 0, duplicates: 0, crc: 0, rejected: 0, aead: 0 };
  }
  get received() { return this.chunks.size + (this.manifest ? 1 : 0); }
  get complete() { return this.total !== null && this.received === this.total; }

  /** Returns true if the packet was new and authentic. Throws only when the transfer must abort. */
  async feed(raw) {
    let pkt;
    try { pkt = decodePacket(raw); } catch (e) {
      if (e.code === "crc") this.stats.crc++; else this.stats.rejected++;
      return false;
    }
    if (pkt.type !== PacketType.MANIFEST && pkt.type !== PacketType.DATA) { this.stats.rejected++; return false; }
    if (!equalBytes(pkt.sid, this.s.sid)) { this.stats.rejected++; return false; } // another (old) session
    if (pkt.total < 1 || pkt.seq >= pkt.total || (pkt.seq === 0) !== (pkt.type === PacketType.MANIFEST)) { this.stats.rejected++; return false; }
    if (this.total !== null && pkt.total !== this.total) { this.stats.rejected++; return false; }
    if (this.chunks.has(pkt.seq) || (pkt.seq === 0 && this.manifest)) { this.stats.duplicates++; return false; }
    let pt;
    try { pt = await this.opener.open(pkt); } catch {
      this.stats.aead++;
      if (this.stats.aead >= this.maxFailures) throw new AirLockError("tampering", `${this.stats.aead} packets failed authentication: active tampering suspected`);
      return false;
    }
    this.total ??= pkt.total;
    if (pkt.seq === 0) {
      const m = parseManifest(pt);
      const ok = await verifySignature(this.s.peerSign, m.signature, concat(LABEL_MANIFEST, this.s.sid, pt.subarray(0, m.fieldsEnd)));
      if (!ok) throw new AirLockError("bad_signature", "manifest signature is invalid");
      if (m.chunkCount + 1 !== pkt.total) throw new AirLockError("manifest", "manifest chunk count disagrees with packet total");
      if (m.size > this.maxFileSize) throw new AirLockError("too_big", "file is larger than the limit");
      this.manifest = m;
    } else {
      this.buffered += pt.length;
      if (this.buffered > this.maxFileSize) throw new AirLockError("too_big", "received data exceeds the size limit");
      this.chunks.set(pkt.seq, pt);
    }
    this.stats.accepted++;
    return true;
  }

  /** The plaintext, only after the end-to-end checks. Throws if anything is missing or wrong. */
  async finalize() {
    if (!this.complete) throw new AirLockError("incomplete", `incomplete transfer: ${this.received} of ${this.total ?? "?"} packets`);
    const parts = [];
    for (let i = 1; i < this.total; i++) parts.push(this.chunks.get(i));
    const data = concat(...parts);
    if (data.length !== this.manifest.size) throw new AirLockError("hash", "size does not match the manifest");
    if (!equalBytes(await sha256(data), this.manifest.sha256)) throw new AirLockError("hash", "SHA-256 does not match the manifest");
    return { filename: sanitizeFilename(this.manifest.filename), data };
  }
  discard() { this.chunks.clear(); this.buffered = 0; }
}

// ---------------------------------------------------------------- ATTACK LAB (demo only, never used for real transfers)
//
// LAB_INSECURE packets encrypt WITHOUT integrity: AES-CTR, no tag, no signed
// manifest, no hash. They exist only to demonstrate live that "encrypted" does
// not mean "unchangeable": CTR ciphertext is malleable, so an attacker who
// cannot read the message can still flip chosen bits of it. The real protocol
// (AES-GCM + signed manifest + SHA-256) rejects the identical edit.
// The Python package does not accept this packet type, and neither does the
// app unless the receiver explicitly ticks "accept insecure demo transfers".

async function labCounter(iv) { return concat(makeNonce(iv, 1), u32(1)); } // 16-byte CTR block

/** Sender, insecure demo: one LAB_INSECURE packet holding `data`, encrypted but NOT authenticated. */
export async function labInsecurePacket(session, data) {
  if (data.length > 1000) throw new AirLockError("lab", "insecure demo is for short messages only");
  const key = await subtle.importKey("raw", session.keys.kIR, "AES-CTR", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CTR", counter: await labCounter(session.keys.ivIR), length: 32 }, key, data));
  return encodePacket({ type: PacketType.LAB_INSECURE, sid: session.sid, seq: 1, total: 1, payload: ct });
}

/** Receiver, insecure demo: decrypts with no integrity check whatsoever (that is the point). */
export async function labOpenInsecure(session, pkt) {
  if (!equalBytes(pkt.sid, session.sid)) throw new AirLockError("session", "packet belongs to another session");
  const key = await subtle.importKey("raw", session.keys.kIR, "AES-CTR", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-CTR", counter: await labCounter(session.keys.ivIR), length: 32 }, key, pkt.payload));
}

/** Attacker: XOR (before ^ after) into the ciphertext at a plaintext offset, then fix the CRC.
 *  Works on both CTR and GCM packets because both are counter-mode underneath; only GCM notices. */
export function malleate(raw, offset, before, after) {
  const pkt = decodePacket(raw);
  const payload = pkt.payload.slice();
  for (let i = 0; i < before.length && offset + i < payload.length; i++) payload[offset + i] ^= before[i] ^ after[i];
  return encodePacket({ type: pkt.type, sid: pkt.sid, seq: pkt.seq, total: pkt.total, payload });
}

/** Attacker: flip one random byte of a packet's ciphertext and recompute the CRC (CRC is not security). */
export function corruptPacket(raw) {
  const pkt = decodePacket(raw);
  const payload = pkt.payload.slice();
  payload[Math.floor(Math.random() * payload.length)] ^= 1 + Math.floor(Math.random() * 255);
  return encodePacket({ type: pkt.type, sid: pkt.sid, seq: pkt.seq, total: pkt.total, payload });
}

/** Attacker: a forged data packet for a session (right header, random ciphertext). */
export function forgedPacket(sid, total) {
  const seq = 1 + Math.floor(Math.random() * Math.max(1, total - 1));
  return encodePacket({ type: PacketType.DATA, sid, seq, total, payload: randomBytes(166) });
}

/** Startup check: does this browser have everything AirLock needs? */
export async function checkSupport() {
  const missing = [];
  if (!globalThis.crypto?.subtle) missing.push("secure context (HTTPS)");
  else {
    for (const alg of ["Ed25519", "X25519"]) {
      try { await subtle.generateKey({ name: alg }, false, alg === "Ed25519" ? ["sign"] : ["deriveBits"]); }
      catch { missing.push(alg); }
    }
  }
  return missing;
}
