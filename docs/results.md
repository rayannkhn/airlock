# AirLock: Measured Results

Every number below was produced by `python -m airlock.bench.benchmark all`
on the machine described in `results/environment.txt` (Ubuntu 25.10,
x86_64, Python 3.13.7, cryptography 50.0.2, OpenCV 5.0.0). The raw data is
in `results/*.csv`, and the charts in `results/charts/` are drawn only from
those files. Re-running the command regenerates everything. Timings will
differ on other hardware.

Three kinds of evidence, labelled throughout:
- **Measured**: real operations timed, or real transfers decoded.
- **Real decoder, synthetic degradation**: real AirLock QR codes and the
  real decoder, but the blur, noise, compression and damage are simulated.
- **Live**: phone screen to webcam. *Not yet run*; see section 4.

---

## 1. Elliptic curves vs RSA (measured)

### Primitives (median of 500 runs for the elliptic curves; 50 for RSA operations; 10 for RSA key generation)

| Operation | X25519 / Ed25519 | RSA-2048 | RSA-3072 |
|---|---|---|---|
| Key generation | 0.056 ms | 83 ms | 358 ms |
| Key agreement / decrypt 32 B | 0.065 ms (X25519) | 1.17 ms (OAEP) | 3.67 ms |
| Sign | 0.056 ms (Ed25519) | 1.17 ms (PSS) | 3.69 ms |
| Verify | 0.182 ms | 0.050 ms | 0.092 ms |
| Public key size | 32 B | 294 B (DER) | 422 B |
| Signature size | 64 B | 256 B | 384 B |
| Security level (NIST SP 800-57) | 128-bit | 112-bit | 128-bit |

RSA verification is faster than Ed25519 verification, because RSA uses a
small public exponent. Every other operation favours the elliptic curves,
key generation by more than 1000×.

### Whole handshake (`crypto_handshake_time.png`, `crypto_handshake_bytes.png`)

| Handshake (both sides) | Median time | Bytes on the channel | QR codes | Forward secrecy |
|---|---|---|---|---|
| **AirLock interactive** (X25519 + Ed25519) | **0.93 ms** | **390 B** | 2 | yes |
| **AirLock one-way** (X25519 + Ed25519) | **0.58 ms** | **202 B** | 2 | sender side only |
| RSA-2048 analogue, with forward secrecy | 76 ms | 1784 B | 9 | yes |
| RSA-2048 analogue, no forward secrecy | 3.9 ms | 1490 B | 8 | no |
| RSA-3072 analogue, with forward secrecy | 339 ms | 2552 B | 13 | yes |
| RSA-3072 analogue, no forward secrecy | 12 ms | 2130 B | 11 | no |

The RSA analogue follows the same message structure with real operations:
RSA-PSS transcript signatures, and RSA-OAEP transport of a 32-byte secret.
Forward secrecy with RSA needs a fresh key pair every session, and RSA key
generation is the cost that dominates.

**Takeaway for the report:** at the same 128-bit security level, AirLock's
handshake is about **360× faster** (0.93 ms against 339 ms) and **6.5×
smaller** (390 B against 2552 B) than an RSA-3072 design with forward
secrecy. On an optical channel that moves a few hundred bytes per second,
size matters more than CPU time: 2 QR codes against 13.

## 2. QR channel robustness (real decoder, synthetic degradation)

Each point is 40 real AirLock-sized QR codes (200-byte packets, Base45,
error-correction level M), placed in a simulated 640×480 camera frame with
optical blur and sensor noise.

**Apparent size** (`qr_size.png`). This is the factor distance controls.

| Camera pixels per QR module | 2.0 | 2.5 | 3.1 | 4.0 | 5.2+ |
|---|---|---|---|---|---|
| Codes decoded | 5% | 0% | 75% | 97.5% | 100% |

→ **Rule of thumb: the QR must cover at least about 4 camera pixels per
module** (about 260 px of the 640 px frame for AirLock's 65-module codes).
This explains why the phone has to be held close.

**Noise and compression** (`qr_conditions.png`, QR 300 px wide). Decoding
stays at 82–98% up to a noise standard deviation of 30 grey levels. It
falls to 65% at 45 and 0% at 80. JPEG compression from quality 95 down to
quality 5 has **no clear effect**: every quality level decodes 85–100%. So
video compression is not the bottleneck.

*Anomaly, reported as measured:* zero noise decoded *lower* (82.5%) than a
little noise (97.5% at σ = 10). The likely cause is the decoder's
binarisation step behaving differently on perfectly flat images. It has not
been investigated further.

**Error-correction level** (`qr_ecc.png`). Random damage applied only to
data modules (the layout patterns are spared):

| Damaged modules | 1% | 1.5% | 2% | 2.5% | 3% |
|---|---|---|---|---|---|
| L (version 9, 53×53) | 65% | 8% | 0% | 0% | 0% |
| **M (version 10, 57×57)**, AirLock's choice | 100% | 88% | 35% | 10% | 0% |
| Q (version 13, 69×69) | 100% | 95% | 78% | 40% | 5% |
| H (version 15, 77×77) | 100% | 92% | 88% | 32% | 10% |

The cliff matches theory. A codeword is 8 modules, so 2% damaged modules
corrupts 1 − 0.98⁸ ≈ 15% of codewords, which is exactly level M's
correction limit. Q and H survive more damage, but they need bigger codes
(69–77 modules a side against 57). By the size result above, a bigger code
needs more camera pixels, so the phone must be held closer. **M is the
trade-off chosen.** Q is the fallback if the live test shows damage (glare)
rather than size is the limiting factor.

## 3. End-to-end goodput on a perfect channel (measured)

A real 2000-byte one-way transfer becomes 16 packets (3073 bytes on the
channel: the SEAL, the signed manifest, and AES-GCM tags and headers). It
was rendered to MP4 and decoded from the file (`qr_pipeline.png`):

| QR codes per second | 7.5 | 5 | **3.75 (default)** | 2.5 |
|---|---|---|---|---|
| Goodput (file bytes/s) | 984 | 659 | **496** | 332 |

The protocol overhead is 54% for a 2 KB file. It is mostly fixed
per-transfer cost: the 202-byte SEAL and the manifest. Per chunk, the cost
is a 30-byte header, a 16-byte tag and a 4-byte CRC on 150 bytes of data.
These numbers are an **upper bound**: a live camera will miss codes, and
missed codes cost a full loop.

## 4. Live: phone screen to webcam (not yet run)

The live benchmark is built and has been tested on a video file. It still
needs the phone:

```bash
python -m airlock.bench.benchmark live-video      # makes results/live/bench.mp4 (and bench.html)
# copy results/live/bench.mp4 to the phone with a USB cable
python -m airlock.bench.benchmark live --distance-cm 20 --runs 3 --label "room light"
python -m airlock.bench.benchmark live --distance-cm 35 --runs 3 --label "room light"
python -m airlock.bench.benchmark live --distance-cm 50 --runs 3 --label "room light"
```

Each run is a complete, verified transfer. Failures are recorded as rows
too. `results/charts/qr_live.png` (success rate and goodput against
distance) appears automatically once data exists. **Until it is run, the
report must not claim any distance figure.**

## 5. How to cite these in the report

- Quote medians, and say they are medians, from this machine.
- For section 2, say "simulated degradation, real decoder".
- Section 3 is a best case (perfect channel). Section 4 is the real-world
  number.
