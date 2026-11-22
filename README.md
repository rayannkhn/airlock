# AirLock

Secure file transfer with no Wi-Fi, Bluetooth, NFC or mobile data. It uses
sound, animated QR codes and light as transports, all protected by one
threat-modeled protocol (Ed25519 identities, signed X25519 handshake,
HKDF-SHA256, AES-256-GCM).

> Status: the secure core, the one-way mode, the QR transport, the attack demos
> and the benchmarks work (161 tests, 6/6 demos). Still to do: live phone
> benchmark runs, the final report.

## Install (Linux)

```bash
sudo apt install libportaudio2      # needed by sounddevice
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
.venv/bin/python -m pytest -v       # environment checks
```

## The AirLock app: any device to any device

`web/` is an installable app (a PWA) that runs on **phones, tablets and
laptops**. Any two devices can pair, send and receive in either direction,
using only the screen and the camera. Open it once, use "Add to Home
Screen" or "Install", and it works **fully offline** from then on.

- **Pair:** each device scans the other's code; compare fingerprints.
- **Send:** pick a file or type a message; the screen plays QR codes.
- **Receive:** point the camera; the checks tick off; compare the code; save.

It uses the same protocol as the Python package, byte for byte. The
cross-tests in `tests/test_web_interop.py` cover both directions (Python
encrypts and JavaScript decrypts, and the reverse). Private keys are
non-extractable WebCrypto keys, and a Content Security Policy blocks the app
from contacting any server.

Run it locally (`localhost` counts as secure, so the camera works):
```bash
cd web && python3 -m http.server 8800      # then open http://127.0.0.1:8800/
```

## Laptop-only demo page (Python)

```bash
airlock ui
```

The page opens in your browser with four tabs: **How it works · 1 Send ·
2 Receive · 3 Attacks**. Each action is one button, and a plain-English
checklist explains every step as it happens. See
[docs/demo_script.md](docs/demo_script.md).

## Command-line demo: phone screen to laptop webcam (one-way QR)

```bash
airlock demo-setup                          # once: creates alice and bob, who trust each other
airlock send notes.txt --render out.gif     # acts as alice; prints the verification code
# copy out.gif to the phone with a USB cable and open it fullscreen (it loops by itself)
airlock receive --camera 0                  # acts as bob; type y if the codes match
```

- Playing the same video again gives `ABORTED: ... (replay)`.
- No phone handy? `airlock receive --video out.mp4` decodes the file directly.
- Phone can't play the MP4? Use `--render out.html` and open it in the
  phone's browser.

## Attack demos (a few seconds, no camera)

```bash
python -m airlock.demos.all             # full narration
python -m airlock.demos.all --summary   # one line per demo
```

| # | Demo | Expected result |
|---|---|---|
| 1 | `eavesdrop` | the captured frames are unreadable ciphertext |
| 2 | `mitm_insecure` | the attack **succeeds** against a variant without authentication (the baseline) |
| 3 | `mitm_airlock` | rejected by signatures, the trust store, the signed manifest and the verification code |
| 4 | `replay` | old recordings, stale timestamps and old packets are all rejected |
| 5 | `tamper` | every modified packet is rejected; a flood aborts the session |
| 6 | `truncate` | an interrupted transfer never leaves a partial file |

Run one demo with `python -m airlock.demos.<name>`.
`python -m airlock.demos.eavesdrop --video out.mp4` analyses a real rendered video.

## Benchmarks (real runs only)

```bash
python -m airlock.bench.benchmark all     # about 4 minutes: CSVs in results/, charts in results/charts/
```

Headline numbers (this laptop; details and caveats in [docs/results.md](docs/results.md)):

| | AirLock (X25519 + Ed25519) | RSA-3072 with forward secrecy |
|---|---|---|
| Handshake time (both sides) | 0.93 ms | 339 ms |
| Handshake bytes on the channel | 390 B (2 QR codes) | 2552 B (13 QR codes) |

The QR channel delivers about 500 B/s of file data at the default 3.75
codes/s on a perfect channel, and needs at least about 4 camera pixels per
QR module to decode reliably.

## Quick start (two terminals; TCP test transport)

```bash
# Once per user. Prompts for a passphrase; --no-passphrase is for testing only.
airlock --home ~/alice keygen
airlock --home ~/bob keygen

# Exchange .pub files, compare fingerprints IN PERSON, then pin them:
airlock --home ~/alice trust add bob ~/bob/identity.pub
airlock --home ~/bob   trust add alice ~/alice/identity.pub

# Terminal 1 (receiver)
airlock --home ~/bob receive --listen 127.0.0.1:9000 --out received/
# Terminal 2 (sender)
airlock --home ~/alice send myfile.pdf --to 127.0.0.1:9000
```

Both sides print the same verification code (e.g. `E90C-8C97`). The
receiver types `y` only if the codes match. To use two machines, run
`--listen 0.0.0.0:9000` on the receiver and `--to <receiver-ip>:9000` on the
sender. With no `--home`, state goes to `~/.airlock`.

On Windows, use `.venv\Scripts\pip` and `.venv\Scripts\airlock` instead.

## Documents

- [docs/threat_model.md](docs/threat_model.md): assets, attacker model, STRIDE
- [docs/design.md](docs/design.md): protocol specification
- [docs/limitations.md](docs/limitations.md): known limitations
