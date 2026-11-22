# AirLock: Threat Model

Method: assets, then trust boundaries, then attacker model, then STRIDE.
Each threat is mapped to the defense and to the test or demo that checks it.
Every test and demo named here exists and passes: `pytest` (138 tests)
and `python -m airlock.demos.all` (6/6 demos). Each demo is also run as a
test (`tests/test_attacks.py`).

Wording rule for the whole project: AirLock is **tested against the attacks
listed here**. It is not "proven secure".

---

## 1. System overview

Two endpoints, Alice (sender) and Bob (receiver), exchange a file without
Wi-Fi, Bluetooth, NFC or mobile data. The channels are:

| Channel           | Direction                | Carries                        | Rough capacity    |
|-------------------|--------------------------|--------------------------------|-------------------|
| Animated QR       | screen to camera (one-way) | SEAL + manifest + encrypted chunks | ~0.5 KB/s at the default 3.75 codes/s (estimate) |
| Human eyes        | screen to person         | 32-bit verification code       | n/a               |
| Loopback / TCP    | both directions          | everything (testing only)      | fast              |

The capacities are **estimates**. Phase 7 replaces them with measured
numbers.

## 2. Assets

| ID | Asset                                    | Property needed                  |
|----|------------------------------------------|----------------------------------|
| A1 | File contents                            | Confidentiality, integrity       |
| A2 | File metadata (name, size, hash)         | Integrity; name confidentiality  |
| A3 | Long-term identity private keys          | Confidentiality                  |
| A4 | Session keys (k_IR, k_RI, k_sas)         | Confidentiality, freshness       |
| A5 | Receiver's file system                   | Integrity (no partial or attacker-chosen writes) |
| A6 | Trust store (pinned peer public keys)    | Integrity                        |

## 3. Trust boundaries

```
 [ Alice's device ] ===(air: sound / light / screen pixels)=== [ Bob's device ]
        trusted                      UNTRUSTED                       trusted
```

- Everything that crosses the air gap is attacker-controlled.
- Each device, its OS and the Python runtime are trusted (see out of scope).
- The one-time, in-person fingerprint comparison is trusted. It is the root
  of authentication.

## 4. Attacker model

The attacker **can**:

- **Record** all audio with a microphone. **Film** the sender's screen and
  any blinking light from a distance, with better optics than the honest
  receiver.
- **Inject** signals: play their own audio, or hold up their own screen
  showing QR frames or blinking patterns.
- **Replay** anything recorded earlier, in the same session or in a later
  one.
- **Modify / block**: jam the audio, cover the camera, or add noise. In the
  MITM model they relay and change messages in both directions.
- Know the full protocol and the source code (Kerckhoffs's principle).
- Do offline computation at the level of a powerful PC: millions of
  X25519 operations, but not 2^128 work.

The attacker **cannot** (assumptions):

- Break X25519, Ed25519, AES-256-GCM, SHA-256 or HKDF.
- Read either endpoint's memory or disk.
- Change the fingerprint comparison that was done in person.
- Control both the QR channel and what the user sees on the sender's
  screen. This assumption applies to the verification-code check only. If
  it does not hold, the signatures still protect the session.

## 5. STRIDE analysis

| # | STRIDE | Threat | Defense | Verified by |
|---|---|---|---|---|
| T1 | **S**poofing | Mallory pretends to be Alice and sends Bob a file | Ed25519 signature over the transcript; peer key must be in the trust store (design §4, §5) | `tests/test_handshake.py::test_untrusted_identity_rejected`, `tests/test_cli.py::test_cli_untrusted_sender_rejected` |
| T2 | **S**poofing | MITM runs a separate handshake with each side and relays | Transcript-bound signatures; trust store; signed manifest; verification code compared by eye (design §5, §7, §10) | Demo 3 `airlock/demos/mitm_airlock.py` (scenarios A–C); contrast with demo 2 `mitm_insecure.py`, where the same attack **succeeds**; `tests/test_handshake.py::test_mitm_key_substitution_fails`, `tests/test_attacks.py::test_mitm_fails` |
| T3 | **S**poofing | MITM bypasses signatures (simulated bug) and grinds ephemeral keys until the short SAS collides | Commit-then-reveal of `e_I` (design §5); 32-bit SAS | Demo 3 scenario D (handshake signature check patched out: the signed manifest still stops it) and E (all signature checks patched out: the codes differ and the user aborts); `tests/test_handshake.py::test_commitment_binds_initiator_key` |
| T4 | **T**ampering | Bit flips or a changed ciphertext/header in a data packet | AES-GCM tag with the header as AAD (design §8.2) | Demo 5 `airlock/demos/tamper.py` (with and without a recomputed CRC, moved seq, flood); `tests/test_crypto.py::test_tamper_detected` |
| T5 | **T**ampering | Swap the manifest (different filename/hash) | Manifest encrypted + AEAD + Ed25519 signature; SHA-256 checked after reassembly (design §8.3) | `tests/test_session.py::test_manifest_tamper_rejected`, `test_hash_mismatch_rejected` |
| T6 | **T**ampering | Path traversal through a filename such as `../../.bashrc` | Basename-only sanitisation; written only inside the chosen output directory (design §8.3) | `tests/test_session.py::test_filename_sanitised` (9 hostile names), `test_sender_path_traversal_lands_inside_out_dir` |
| T7 | **T**ampering | Replay old-session packets into a new session | Per-session keys; session_id in the AAD; recent-session_id cache (design §8.5) | `tests/test_handshake.py::test_replayed_hello_rejected`, `test_replayed_old_finish_fails_in_new_session`, `tests/test_session.py::test_other_session_packets_ignored`; one-way: `tests/test_oneway.py::test_oneway_replay_rejected`, `test_seal_expired_and_future_rejected`, `test_seal_timestamp_is_signed`, `tests/test_cli.py::test_cli_demo_oneway_qr_flow`; demo 4 `airlock/demos/replay.py` |
| T8 | **T**ampering | Reorder or duplicate packets within a session | Accepted-seq set; seq and total authenticated (design §8.4, §8.5) | `tests/test_session.py::test_duplicates_and_reorder` |
| T9 | **R**epudiation | Alice later denies having sent the file | Signed manifest. *Partial only*: the signature is bound to a session transcript, which is not strong non-repudiation evidence for a third party | Documented limitation (`limitations.md`) |
| T10 | **I**nformation disclosure | Eavesdropper films the QR frames or records the TCP traffic | AES-256-GCM under X25519-derived keys; the filename is encrypted too | Demo 1 `airlock/demos/eavesdrop.py` (no plaintext or filename in any frame; ciphertext entropy about 7.96 bits/byte; a wrong key fails; also runs on a real video with `--video`) |
| T11 | **I**nformation disclosure | Identity key stolen later; recorded sessions decrypted | Ephemeral X25519 gives forward secrecy; ephemeral keys never written to disk | `tests/test_handshake.py::test_forward_secrecy_keys_ephemeral` (checks that keys are fresh and dropped; it cannot prove memory was wiped) |
| T12 | **I**nformation disclosure | Nonce reuse reveals the XOR of plaintexts and breaks the GCM tag | Direction-separated keys; nonce = iv XOR seq; seq never reused (design §6, §8.2) | `tests/test_crypto.py::test_nonce_unique`, `test_sealer_refuses_nonce_reuse` |
| T19 | **I**nformation disclosure | One-way mode: the receiver's X25519 receiving key is stolen later, and every recorded SEAL video addressed to it is decrypted | **Not defended in one-way mode** (inherent with no return channel). Use interactive mode for forward secrecy on both sides; rotate the receiving key (new `keygen`, new card) | `tests/test_oneway.py::test_receiver_key_compromise_breaks_old_sessions` shows the weakness is real |
| T20 | **S**poofing | A swapped receiving key on a contact card, so the sender encrypts to the attacker | The card is signed by the Ed25519 key whose fingerprint was checked in person | `tests/test_oneway.py::test_card_with_swapped_receive_key_rejected` |
| T21 | **T**ampering | Web app: whoever controls the hosting server swaps in malicious JavaScript (the classic "hosted crypto" problem) | Install once and run cache-first from the device (the service worker); pinned, vendored libraries; CSP blocks contacting other servers. **Residual risk:** the first install trusts the server, and so does every deliberate update | Documented in `limitations.md`; `tools/check_offline.mjs` proves the installed copy runs without the server |
| T13 | **I**nformation disclosure | Metadata: file size and timing visible from the packet count | **Not defended.** Padding is out of scope | `limitations.md` |
| T14 | **D**enial of service | Jamming, noise, covering the camera | **Not preventable** on a physical channel. Detected: CRC drops, timeouts, clear error message | Phase 7 noise benchmark measures how much the channel degrades |
| T15 | **D**enial of service | Flood of forged packets to burn CPU or memory | CRC pre-filter; AEAD-failure threshold aborts; in-memory size cap (design §8.4) | `tests/test_session.py::test_aead_failure_threshold`, `test_size_limit` |
| T16 | **E**levation of privilege | Malformed packet crashes the parser or causes huge allocations | Strict length checks; max packet size; `length` validated against the actual buffer (design §8.1) | `tests/test_framing.py::test_malformed_rejected`, `test_fuzz_random_bytes_only_raise_framing_error`, `tests/test_transports.py::test_tcp_rejects_oversized_frame` |
| T17 | **T**ampering | Truncation: the transfer is cut off and a partial file is left on disk | Chunks kept in memory; write only after the full hash check; atomic rename (design §8.4) | `tests/test_session.py::test_no_partial_write`, `tests/test_cli.py::test_cli_sas_refused_writes_nothing`; demo 6 `airlock/demos/truncate.py` |
| T18 | **T**ampering | Downgrade: attacker forces an older or weaker protocol version | A single version byte, covered by the transcript hash and the AAD; unknown versions are rejected, with no fallback | `tests/test_handshake.py::test_version_mismatch_rejected`, `tests/test_framing.py::test_version_mismatch_rejected` |

## 6. Out of scope

These are stated explicitly so nobody assumes they are covered:

1. **Compromised endpoints**: malware, keyloggers, a modified AirLock
   binary, a stolen unlocked device.
2. **Physical attacks on the devices**: cold-boot attacks, hardware
   implants.
3. **Side channels** in OpenSSL or Python: timing, power, EM, acoustic
   emanation from the CPU.
4. **Covertness**: hiding that a transfer happens at all.
5. **The fingerprint exchange itself**: we assume users really compare the
   fingerprints. Skipping that step removes the authentication.
6. **Long-term key storage beyond passphrase-encrypted PEM**: no TPM or HSM.
7. **Post-quantum attackers**: X25519 and Ed25519 are not PQ-secure. A
   recorded session could be decrypted by a future quantum computer.

## 7. Residual risks (honest list)

- The verification-code check depends on the user really comparing the two
  codes. An attacker standing between the screen and the camera could
  control the QR channel, but not the user's view of both screens.
- One-way mode has no forward secrecy against theft of the receiver's key
  (T19).
- The "phone as a display" demo setup (see `limitations.md`) runs both
  protocol endpoints on one laptop. Two Python processes are still isolated
  by the protocol, but the physical separation in that setup is weaker than
  with two real devices.
- Python cannot reliably wipe secrets from memory.
- No external security audit has been done.
