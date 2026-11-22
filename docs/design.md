# AirLock: Protocol Design

Status: **specification for Phase 2.** Section 9 lists what is built so far.
Section numbers are referenced from `threat_model.md` and from code comments.

---

## 1. Goals and non-goals

**Goals**

1. Confidentiality and integrity of a file sent over a channel the attacker can
   fully observe and modify: sound, a screen filmed by a camera, or light.
2. Mutual authentication of the two endpoints using long-term identity keys
   whose fingerprints were compared once, in person.
3. Forward secrecy: if an identity key is stolen later, past sessions stay
   unreadable.
4. Fail closed: nothing reaches disk unless the whole file has been verified.
5. Transport independence. The crypto is written once and runs unchanged over
   every channel.

**Non-goals** (details in `limitations.md`)

- Hiding *that* a transfer is happening. Blinking screens and chirping
  speakers are obvious.
- Protecting against a compromised endpoint (malware, a stolen unlocked
  laptop).
- High throughput. These channels carry bytes to a few kilobytes per second.

---

## 2. Architecture

```
 +--------------------------------------------------------------+
 |  cli.py         keygen | send | receive | verify             |
 +--------------------------------------------------------------+
 |  core/session.py   runs handshake -> manifest -> chunks      |
 |  core/handshake.py SIGMA-style signed X25519 handshake       |
 |  core/crypto.py    HKDF key schedule, AES-256-GCM, SAS       |
 |  core/framing.py   packet encode/decode, CRC32               |
 |  core/identity.py  Ed25519 keys, fingerprints, trust store   |
 +--------------------------------------------------------------+
 |  Transport interface:  send(data: bytes) -> None             |
 |                        receive() -> bytes                    |
 +---------+---------+-----------+-------------+----------------+
 | loopback|   tcp   | qr (video)| audio (FSK) | light (blink)  |
 +---------+---------+-----------+-------------+----------------+
```

The transport delivers *datagrams*: one `send()` call produces at most one
`receive()` result. A transport may drop, duplicate, reorder or corrupt
datagrams. It must not be trusted for anything else. Everything
security-relevant happens above the line.

**Why this split matters for the viva:** the same unit tests and attack demos
run over loopback, TCP and QR. That shows the security properties come from
the protocol and not from the physics of the channel ("nobody can hear
ultrasound" is not a security argument).

---

## 3. Cryptographic primitives

All primitives come from the Python `cryptography` package (pyca), which wraps
OpenSSL. No curve arithmetic, cipher or MAC is implemented by hand.

| Purpose              | Primitive          | Why this one                                                  |
|----------------------|--------------------|---------------------------------------------------------------|
| Identity signatures  | Ed25519            | Deterministic (no nonce to get wrong), small keys and signatures, fast |
| Key agreement        | X25519 (ephemeral) | Forward secrecy, 32-byte public keys fit in an audio burst     |
| Key derivation       | HKDF-SHA256        | Standard extract-then-expand KDF (RFC 5869)                   |
| Bulk encryption      | AES-256-GCM        | AEAD: one primitive gives confidentiality and integrity        |
| File digest          | SHA-256            | End-to-end check over the reassembled plaintext                |
| Transcript hash      | SHA-256            | Binds the keys to every handshake byte                        |
| Channel error check  | CRC32              | **Not a security mechanism.** Detects noise early so the transport can request or wait for a retransmission |

---

## 4. Identities

- Each user runs `airlock keygen` once. This creates an Ed25519 private key
  (PEM, encrypted with a passphrase) and a public key file.
- **Fingerprint** = `SHA-256(raw 32-byte public key)`. It is shown as
  10 groups of 4 hex characters (the first 160 bits), for example
  `3F2A 9C1D ...`.
- Users compare fingerprints once, in person, and mark the peer as trusted.
  The trust store is a small JSON file mapping a name to a public key.
- In a session, the peer's identity key must match a trusted entry exactly.
  Otherwise the session aborts.

---

## 5. Handshake (3 messages, commit-then-reveal, SIGMA-style)

Notation: `I` = initiator (sender), `R` = responder (receiver).
`e_I`, `e_R` = ephemeral X25519 key pairs. `s_I`, `s_R` = identity Ed25519
key pairs. `H` = SHA-256. `||` = concatenation. `TH(a, b, ...)` = SHA-256
over the parts, each prefixed with its 4-byte length, so `TH("ab","c")` is
not `TH("a","bc")` (`crypto.transcript_hash`). `M1`, `M2`, `M3` mean the
full encoded packets as they were sent.

```
M1  I -> R : HELLO   version, session_id (16 random bytes),
                     commit_I = H("airlock-commit" || e_I.pub)
M2  R -> I : REPLY   session_id, e_R.pub, s_R.pub,
                     sig_R = Sign(s_R, "airlock-R" || TH(M1, e_R.pub, s_R.pub))
M3  I -> R : FINISH  session_id, e_I.pub, s_I.pub,
                     sig_I = Sign(s_I, "airlock-I" || TH(M1, M2, e_I.pub, s_I.pub))
```

Checks (any failure aborts the session and discards all state):

- R, on M3: `H("airlock-commit" || e_I.pub) == commit_I`; `s_I.pub` is
  trusted; `sig_I` verifies.
- I, on M2: `s_R.pub` is trusted; `sig_R` verifies.
- Both: the session_id matches, the version is supported, and the X25519
  shared secret is not all zeros (this rejects low-order points).

**Why each piece exists**

- **Ephemeral X25519** gives forward secrecy. The ephemeral private keys are
  never stored on disk.
- **Signatures over the transcript hash, not only over the sender's own
  ephemeral key.** Each side signs everything seen so far, including the
  peer's values. This stops a MITM from splicing two honest half-handshakes
  together. It is the core idea of SIGMA, which is used by IKE and TLS 1.3.
- **Role labels** ("airlock-I" and "airlock-R") stop a signature made in one
  role from being reflected back as the other role.
- **Commit-then-reveal of `e_I`** matters only for the short verification
  code (section 7). Without it, a MITM who could somehow bypass the
  signatures could try millions of its own ephemeral keys offline until the
  short code collided. With the commitment, the MITM must fix its key before
  it sees the honest party's key. One try then has about a 2^-32 chance.
  ZRTP uses the same trick.
- **A fresh random session_id** chosen by I, plus a fresh `e_R` from R, means
  a replayed old M1 or M3 cannot complete a new session.
- **Retransmission on lossy channels:** if R receives the *identical* M1
  again, it resends the same M2, and I does the same for M3. Any other
  second message is an error. This lets audio and QR resend handshake
  frames without opening a replay hole.

---

## 6. Key schedule

```
shared   = X25519(e_I.priv, e_R.pub)          (= X25519(e_R.priv, e_I.pub))
th       = TH(M1, M2, M3)                     # full transcript hash
okm      = HKDF-SHA256(ikm = shared,
                       salt = session_id,
                       info = "airlock v1 keys" || th,
                       length = 32 + 32 + 12 + 12 + 32)
k_IR, k_RI, iv_IR, iv_RI, k_sas = split(okm)
```

- **One key per direction** (`k_IR`, `k_RI`). The two sides then never
  encrypt under the same key, so their sequence numbers cannot produce the
  same nonce.
- **The transcript goes into `info`**, so the keys are bound to this exact
  handshake. A tampered or replayed handshake gives different keys, and
  decryption then fails.
- After derivation, `shared` and the ephemeral private keys are dropped.
  Python cannot guarantee that memory is zeroed. This is listed in
  `limitations.md`.

---

## 7. Short authentication string (cross-channel verification)

```
sas = HKDF-Expand(k_sas, info = "airlock sas", length = 4)  -> 32 bits
```

- Both sides compute the SAS. The sender transmits it over the **light**
  channel: the screen blinks, the receiver's webcam reads it. The receiver
  compares it with its own value. A mismatch aborts the session and the file
  is discarded.
- It is also shown as 8 hex characters, so a human can compare it by eye
  when the light channel is unavailable.
- **Threat it covers:** a MITM sitting on the main channel. It does not
  cover an attacker who controls both channels. The independence of the
  channels is an assumption, and it is stated as one in the threat model.
- With the signatures working, the SAS is defense in depth. Demo 3 shows the
  SAS catching a MITM in a build where signature checking is deliberately
  turned off.

---

## 8. Data phase

### 8.1 Packet format (big-endian)

| Offset | Size | Field        | Notes                                        |
|-------:|-----:|--------------|----------------------------------------------|
| 0      | 2    | magic        | `0x414C` ("AL")                              |
| 2      | 1    | version      | `0x01`                                       |
| 3      | 1    | type         | 1 HELLO, 2 REPLY, 3 FINISH, 4 MANIFEST, 5 DATA, 6 RECEIPT |
| 4      | 16   | session_id   |                                              |
| 20     | 4    | seq          | 0 = manifest, 1..N = data chunks             |
| 24     | 4    | total        | N + 1 (manifest included)                    |
| 28     | 2    | length       | length of ciphertext + tag                   |
| 30     | var  | ciphertext   | AES-256-GCM output, 16-byte tag at the end   |
| end-4  | 4    | crc32        | over every preceding byte                    |

The prompt's format did not have a `type` byte. I added one so handshake
packets and data packets share one parser and one replay check. It is
covered by the AEAD associated data like the rest of the header.

### 8.2 Encryption of one packet

```
header = bytes[0:30]                         # magic .. length
nonce  = iv_dir XOR (seq as 12-byte big-endian integer)
ct     = AES-256-GCM(k_dir).encrypt(nonce, plaintext_chunk, aad = header)
```

- **Nonce uniqueness:** `seq` never repeats within a session, and each
  session has new keys and IVs. So a (key, nonce) pair is never reused. This
  is the TLS 1.3 per-record nonce construction. Here session_id is mixed in
  through the key derivation (it is the HKDF salt).
- **The header is the AAD.** Changing `seq`, `total` or `session_id`, or
  moving a packet into another session, breaks the tag.
- **CRC32 is checked first, but only as a cheap filter for noise.** Anyone
  can recompute a CRC, so a valid CRC proves nothing. The GCM tag is the
  real integrity check.

### 8.3 Manifest (seq 0)

The manifest is encrypted like any other packet. Its plaintext is:

```
filename (UTF-8, length-prefixed, path components stripped) ||
size (8 bytes) || sha256(plaintext file) (32 bytes) || chunk_count (4 bytes) ||
sig = Sign(s_I, "airlock-manifest" || session_id || all previous fields)
```

The signature ties the file metadata to the sender's identity and to this
session. The AEAD already authenticates it under the session key. The extra
signature means the manifest could be checked on its own later, for example
in a log. The filename is sanitised (basename only, no `..`, no NUL) to
prevent path traversal on the receiver.

### 8.4 Receiver rules (fail closed)

1. Drop any packet whose CRC is wrong. This is noise, not an attack, so the
   transfer continues.
2. Drop any packet with an unknown session_id, a seq outside `[0, total)`,
   or a `total` that differs from the first authenticated one.
3. Drop duplicates of a seq that was already accepted. Duplicates are normal
   in looping QR mode.
4. If AEAD decryption fails, count it and drop the packet. Above a
   threshold (default 32 failures), abort the session, because someone is
   actively injecting.
5. Keep chunks **in memory only** (size cap, default 16 MiB).
6. When every seq has arrived: reassemble, check that the size matches and
   that the SHA-256 matches the manifest, and check the manifest signature
   and the SAS. Only then write to a temp file in the target directory,
   `fsync` it, and `os.replace()` it to the final name. The rename is atomic.
7. On abort, timeout or Ctrl-C: drop the buffers. Nothing was ever written.

### 8.5 Replay and reorder

- **Within a session:** the accepted-seq set rejects duplicates. Reordering
  is allowed, because QR looping and fountain codes produce it naturally.
- **Across sessions:** keys are per session, so an old packet fails AEAD
  under the new keys. Its session_id also does not match. The responder also
  keeps a cache of recent session_ids and rejects an M1 that reuses one.

### 8.6 Receipt (optional, needs a return channel)

After writing the file, R sends one `RECEIPT` packet (seq 0, total 1),
encrypted under `k_RI`, whose plaintext is the SHA-256 of the file. I
decrypts it and compares. The sender then knows the right file arrived
intact. One-way channels, such as a QR video played from a phone, skip it.

### 8.7 Order of the receiver's final checks

All packets → size == manifest → SHA-256 == manifest → user confirms the SAS
→ atomic write → receipt. A "no" at the SAS prompt discards the file.

---

## 9. Implementation status

| Component                 | Phase | Status            |
|---------------------------|:-----:|-------------------|
| Threat model, design docs | 1     | written           |
| Project skeleton          | 1     | done              |
| Loopback + TCP transports, CLI | 2 | done        |
| Core crypto + tests       | 2     | done; TCP transfer verified between two processes |
| One-way mode (section 10) | 2b    | done              |
| QR transport (section 11) | 3     | done: verified from video files; **live phone-to-webcam not yet tested** |
| Attack demos              | 4     | done: 6/6 pass (`python -m airlock.demos.all`) |
| Audio transport           | 5     | dropped (future work) |
| Light transport + SAS     | 6     | dropped: the code is compared by eye |
| Benchmarks                | 7     | done: crypto + QR robustness measured; live phone runs pending (`docs/results.md`) |
| README, report            | 8     | not started       |

---

## 10. One-way mode (no return channel)

**Why it exists.** With a phone as a plain display, data flows only from
the phone screen to the laptop webcam. The interactive handshake (section 5)
needs replies, so it cannot run there. In one-way mode the sender encrypts
to the receiver's pinned long-term **X25519 receiving key**, so the whole
handshake fits in one packet. The idea is the same as HPKE, the Noise "K/X"
patterns, and the `age` tool.

**Keys.** Every identity now has two keys: Ed25519 for signing and X25519
for receiving. They are never used for each other's job. The receiving key
reaches peers on a **contact card** (`identity.card`) that the Ed25519 key
signs. The fingerprint that people compare in person therefore
authenticates both keys.

**SEAL packet** (type 7, seq 0, total 0; 168-byte payload):

```
timestamp(8) | recipient_receive_key(32) | e_S.pub(32) | s_S.pub(32) |
sig = Sign(s_S, "airlock-seal" || TH(version, session_id, all fields above))

shared = X25519(e_S, R_recv)
keys   = HKDF(shared, salt = session_id, info = "airlock v1 keys" || TH(SEAL))
```

The manifest and chunks after the SEAL are the interactive-mode packets,
unchanged (section 8), and the sender uses `k_IR`. The `Reassembler`,
AEAD, size limits and fail-closed rules are reused as they are.

**Receiver checks, in order:**
1. The packet is well formed.
2. `recipient_receive_key` is its own key ("addressed to me").
3. The sender is pinned.
4. The signature is valid.
5. The timestamp is between now − 24 h and now + 10 min.
6. The session_id is not in the persistent `used_sessions.json`.
7. The X25519 shared secret is not all zeros.

Any failure aborts the session.

**Replay protection.** The receiver adds no fresh randomness here, so the
interactive defence (a fresh `e_R`) is not available. Two checks replace it:
- the **signed timestamp window**
- the **persistent store of used session ids**

The store records a session only after a successful write. A failed
attempt (the camera moved away, or the user said "no") can therefore be
retried with the same video, and that attempt wrote nothing. Entries older
than the window are pruned, because the timestamp check already rejects
those SEALs.

**Trade-offs compared with interactive mode**

| Property | Interactive (section 5) | One-way |
|---|---|---|
| Return channel needed | yes | **no** |
| Mutual authentication | both sign | the sender signs; only the pinned recipient can decrypt |
| Forward secrecy if the sender's key leaks | yes | yes |
| Forward secrecy if the receiver's key leaks | yes | **no**: recorded videos become decryptable (T19) |
| Replay defence | fresh `e_R` | timestamp window + persistent used-session store |
| Receipt to the sender | yes | no |

Frames seen before the SEAL are buffered (still encrypted, at most 4096)
and processed once the SEAL arrives. This lets the camera start in the
middle of a loop.

---

## 11. QR transport

- **One packet per QR code.** Packets are Base45-encoded (RFC 9285).
  Base45's alphabet is exactly the QR alphanumeric set, so the overhead is
  about 3%. Binary byte mode would not work, because OpenCV's decoder
  returns text and would corrupt arbitrary bytes.
- **QR settings.** Error-correction level M. Data chunks are 150 bytes, so
  each packet is about 200 bytes and fits a version-10 code (57×57 modules).
- **Video.** Each QR is on a 1080 px canvas with a label strip, shown for
  8 frames at 30 fps (3.75 codes/s). The whole sequence loops 4 times. The
  codec is MPEG-4 Part 2 (`mp4v`); H.264 is not available in the
  opencv-python wheels on this machine.
- **Self-check.** After rendering, the sender decodes one frame per packet
  from the written video and reports `N/N readable`. A codec that blurred
  the codes is caught before the video reaches the phone.
- **HTML fallback.** `--render out.html` writes a page with lossless PNG
  frames that loops forever in any phone browser.
- **Decoder.** `QRCodeDetectorAruco` runs first, then the classic
  `QRCodeDetector`. Measured on 300 random packets with clean images: the
  classic detector missed 18, Aruco missed 0.
- **Receiver.** `QrReceiver` returns each newly decoded code once
  (consecutive repeats are skipped). Repeats from later loops are counted
  as duplicates by the `Reassembler`. It is receive-only, and `send()`
  raises an error.

---

## 12. The web app (any device)

`web/` re-implements the one-way mode (section 10) in JavaScript, so phones,
tablets and laptops can all act as sender and receiver.

- **Crypto:** the browser's WebCrypto API only (Ed25519, X25519, HKDF,
  AES-256-GCM, SHA-256). No JavaScript crypto library. Private keys are
  created **non-extractable** and stored in IndexedDB, so page scripts can
  use them but never read them out.
- **Contact card for QR:** a compact binary card,
  `"ALC1" | name_len | name | sign_key | receive_key | Sign("airlock-card" || receive_key)`,
  Base45-encoded into one QR code. Python accepts it as well
  (`identity.parse_compact_card`).
- **QR:** codes are drawn with `qrcode-generator` 1.4.4 and read with
  `jsQR` 1.4.0, or with the platform's built-in `BarcodeDetector` where
  available. Both libraries are vendored at pinned versions.
- **Offline:** a service worker caches every file at first visit and
  serves them cache-first. Checked with `tools/check_offline.mjs`: real
  Chrome, network switched off, the app still starts and its crypto works.
- **No network use at all:** the Content Security Policy is
  `connect-src 'self'` and the app makes no requests itself.
- **Interop proof:** `tests/test_web_interop.py` runs real transfers in
  both directions between the Python and JavaScript implementations, and
  checks that each side decodes the other's QR codes.
- **Replay store:** IndexedDB (`used` store), with the same 24-hour window
  and pruning as Python.
