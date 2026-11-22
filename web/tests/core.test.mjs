// Unit tests for the JavaScript protocol core. Run: node --test web/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import * as A from "../airlock-core.js";

const te = new TextEncoder();
const peerOf = (id) => ({ name: id.name, signPub: id.signPub, recvPub: id.recvPub });
const notUsed = async () => false;

async function transfer(sender, receiver, data, name = "notes.txt") {
  const { seal, session } = await A.createSeal(sender, peerOf(receiver));
  return { seal, session, packets: await A.buildTransfer(sender, session, name, data) };
}
async function receive(receiver, senders, seal, packets) {
  const session = await A.openSeal(receiver, senders.map(peerOf), seal, notUsed);
  const r = new A.Reassembler(session);
  for (const p of packets) await r.feed(p);
  return { session, r, out: await r.finalize() };
}

test("RFC 9285 Base45 vectors", () => {
  assert.equal(A.b45encode(te.encode("AB")), "BB8");
  assert.equal(A.b45encode(te.encode("Hello!!")), "%69 VD92EX0");
  assert.equal(A.b45encode(te.encode("base-45")), "UJCLQE7W581");
  assert.deepEqual(A.b45decode("QED8WEX0"), te.encode("ietf!"));
  for (const bad of ["A", "GGW", "abc"]) assert.throws(() => A.b45decode(bad));
});

test("CRC32 check value", () => assert.equal(A.crc32(te.encode("123456789")), 0xcbf43926));

test("full one-way transfer between two JS identities", async () => {
  const alice = await A.generateIdentity("Alice"), bob = await A.generateIdentity("Bob");
  const data = A.randomBytes(2000);
  const { seal, session, packets } = await transfer(alice, bob, data);
  const { session: got, out } = await receive(bob, [alice], seal, [...packets].reverse());
  assert.deepEqual(out.data, data);
  assert.equal(A.formatSas(got.sas), A.formatSas(session.sas));
  assert.equal(got.peerName, "Alice");
});

test("untrusted sender, wrong recipient, replay and expiry are rejected", async () => {
  const alice = await A.generateIdentity("Alice"), bob = await A.generateIdentity("Bob"), eve = await A.generateIdentity("Eve");
  const { seal } = await transfer(alice, bob, te.encode("hi"));
  await assert.rejects(A.openSeal(bob, [], seal, notUsed), { code: "untrusted" });
  await assert.rejects(A.openSeal(eve, [peerOf(alice)], seal, notUsed), { code: "not_for_me" });
  await assert.rejects(A.openSeal(bob, [peerOf(alice)], seal, async () => true), { code: "replay" });
  const old = await A.createSeal(alice, peerOf(bob), Date.now() / 1000 - 2 * A.MAX_AGE_SECONDS);
  await assert.rejects(A.openSeal(bob, [peerOf(alice)], old.seal, notUsed), { code: "too_old" });
});

test("tampered SEAL and tampered chunks are rejected", async () => {
  const alice = await A.generateIdentity("Alice"), bob = await A.generateIdentity("Bob");
  const { seal, packets } = await transfer(alice, bob, A.randomBytes(600));
  const p = A.decodePacket(seal);
  const payload = p.payload.slice(); payload[50] ^= 1; // inside e_S
  const forged = A.encodePacket({ type: p.type, sid: p.sid, seq: 0, total: 0, payload });
  await assert.rejects(A.openSeal(bob, [peerOf(alice)], forged, notUsed), { code: "bad_signature" });

  const session = await A.openSeal(bob, [peerOf(alice)], seal, notUsed);
  const r = new A.Reassembler(session);
  const d = A.decodePacket(packets[1]);
  const ct = d.payload.slice(); ct[3] ^= 1;
  assert.equal(await r.feed(A.encodePacket({ ...d, payload: ct })), false); // valid CRC, bad tag
  assert.equal(r.stats.aead, 1);
});

test("truncated transfer cannot be finalized", async () => {
  const alice = await A.generateIdentity("Alice"), bob = await A.generateIdentity("Bob");
  const { seal, packets } = await transfer(alice, bob, A.randomBytes(900));
  const session = await A.openSeal(bob, [peerOf(alice)], seal, notUsed);
  const r = new A.Reassembler(session);
  for (const p of packets.slice(0, -1)) await r.feed(p);
  await assert.rejects(r.finalize(), { code: "incomplete" });
});

test("contact card round trip and tamper detection", async () => {
  const alice = await A.generateIdentity("Alice");
  const card = await A.makeCard(alice);
  const parsed = await A.parseCard(A.b45decode(A.b45encode(card)));
  assert.deepEqual(parsed.recvPub, alice.recvPub);
  assert.equal(parsed.fingerprint, await A.fingerprint(alice.signPub));
  const bad = card.slice(); bad[bad.length - 70] ^= 1; // inside the receiving key
  await assert.rejects(A.parseCard(bad), { code: "card" });
});

test("filenames are sanitised like the Python version", () => {
  assert.equal(A.sanitizeFilename("../../.bashrc"), "bashrc");
  assert.equal(A.sanitizeFilename("..\\..\\evil.dll"), "evil.dll");
  assert.equal(A.sanitizeFilename("CON.txt"), "_CON.txt");
  assert.equal(A.sanitizeFilename(""), "received.bin");
});
