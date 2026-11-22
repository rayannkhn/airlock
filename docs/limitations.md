# AirLock: Known Limitations

This list is kept up to date as phases are completed. Each entry says
whether it is a design choice, a hardware constraint or an untested area.

## Security

| Limitation | Type | Notes |
|---|---|---|
| Not proven secure | Scope | Tested against the attacks in `threat_model.md` only. No formal verification, no audit. |
| Not post-quantum | Design choice | X25519/Ed25519. A "harvest now, decrypt later" attacker with a future quantum computer could read recorded sessions. |
| Secrets stay in Python memory | Platform | Python `bytes` are immutable and can be copied by the GC. Ephemeral keys cannot be reliably zeroed. |
| Metadata leaks | Design choice | File size (packet count) and transfer timing are visible to an observer. No padding. |
| Weak non-repudiation | Design choice | The manifest signature is bound to a session transcript. It is not a standalone, timestamped signature a court would accept. |
| SAS needs channel independence | Assumption | The light-channel check only helps if the attacker cannot control both the light channel and the main channel. |
| Trust-on-first-comparison | Assumption | Authentication depends entirely on the users comparing fingerprints in person, once. |

## Hardware and demo setup

**Current setup:** one Ubuntu 25.10 laptop (webcam, microphone, speaker) and
one Android phone that is used only as a **display and speaker**. It runs
no AirLock code.

How the demo works with this hardware:

- **Main path: one-way QR** (`design.md` section 10). The sender (demo
  user "alice") encrypts on the laptop and renders an MP4 or HTML file. The
  file goes to the phone **over a USB cable**, which is outside the
  threat model's air channel. The phone plays it, and the receiver (demo
  user "bob") decodes it from the laptop webcam. No reply is ever needed.
- Both demo users live on one laptop (`airlock demo-setup`). The
  in-person fingerprint comparison is simulated, and the protocol is
  exercised exactly as it would run between two devices.
- **Interactive handshake** (forward secrecy on both sides, a receipt) is
  shown over TCP only. Interactive QR in both directions would need a second
  laptop, and it was cut from the scope.
- **Verification code:** compared by eye. The light and audio channels were
  dropped to fit the schedule and are future work.

## Portability ("works on any device")

- The core is pure Python plus `cryptography`, and uses only standard
  library modules for files and sockets. Paths go through `pathlib`; output
  is ASCII-only, so Windows consoles cannot choke on it; the TCP listener
  uses `SO_EXCLUSIVEADDRUSE` on Windows; file writes use `os.replace`,
  which is atomic on both POSIX and NTFS.
- **Tested only on Ubuntu 25.10 / Python 3.13.** Windows and macOS are
  expected to work but have not been run. Run `pytest` on each machine
  before a demo.
- On Windows, `chmod 600` on the private key has no effect. Protection then
  depends on the passphrase and the user profile's ACLs.
- The Android phone runs no AirLock code (see above). Running the protocol
  *on* the phone would need Termux (Python on Android) or a port to
  another language. That is not planned.

## Tested so far

- 128 automated tests: every core module, the one-way mode, the Base45
  codec, video rendering and decoding, and the full CLI demo flow
  (`demo-setup` → `send --render` → `receive --video` → replay rejected).
- Measured on this laptop: a 4800-byte file becomes 34 QR codes. The video
  is 36 s (4 loops) and 27.6 MB. The self-check decoded 34/34. Decoding
  from the video file took about 7 s.
- The webcam opens, and `receive --camera 0` times out cleanly when no
  codes are shown.
- The TCP transport uses the network, so it is a test harness. It is not
  the air-gapped scenario.

## Web app

- **Trust in the hosting server (T21):** the first install, and every
  update, runs whatever code the server delivers. Mitigation: install once,
  then use the cached copy offline. A future version could publish a hash
  of the release so users can check it.
- **Tested so far:** the protocol in Node (Python cross-tests, both
  directions); the UI and the full pair → send → receive → replay flow in
  Chromium; offline start in headless Chrome. **Not yet tested:** real
  phone cameras, Safari on iOS, Firefox.
- **Browser requirement:** WebCrypto Ed25519 and X25519 (current Chrome,
  Edge, Safari and Firefox). Older browsers show an "unsupported" screen
  rather than failing silently.
- **One-way mode only**, so the receiver-key forward-secrecy caveat (T19)
  applies to the app as well.

## Benchmark caveats

- The QR robustness numbers use real codes and the real decoder, but
  *simulated* blur, noise, compression and damage (`docs/results.md` §2).
- The goodput figures are for a perfect channel (decoded from the video
  file). The live-camera numbers are pending.
- All timings come from one laptop and are medians. Other hardware will
  differ.

## Not tested yet

- **The live path: phone screen to webcam.** It depends on the phone's
  brightness and refresh rate, the webcam (640×480 by default here, 720p
  requested), glare and distance. If codes are missed, try in this order:
  1. a higher `--hold` (slower codes)
  2. more `--loops`
  3. `--render out.html` (lossless) instead of MP4
  4. full phone brightness and a 20–40 cm distance
- **Whether the phone's player supports `mp4v`** (MPEG-4 Part 2). Android's
  built-in decoders support it. If the gallery app refuses, use VLC or the
  `.html` render.
- Decoding takes about 125 ms per frame (Aruco detector) on this laptop, so
  the receiver reads roughly 8 frames/s. That is why the default rate is
  3.75 codes/s.
- Long transfers near the 16 MiB limit. A file that size would take hours
  over the optical channels anyway.
- The `ReplayCache` lives in memory only, so it is empty again after a
  receiver restart. Replays across restarts still fail, because the keys
  are new (`test_replayed_old_finish_fails_in_new_session`), but the early
  rejection does not survive a restart.
