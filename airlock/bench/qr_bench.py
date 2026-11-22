"""Benchmark: how robust is the QR channel? Every number comes from real decodes.

Distance itself needs a person holding a phone (see ``live_bench.py``). This
benchmark measures the *factors* that distance and conditions change, by
degrading real AirLock-sized QR codes inside a simulated 640x480 camera
frame and running the same decoder the receiver uses:

- ``qr_size.csv``     success vs QR width in camera pixels (more distance = smaller)
- ``qr_noise.csv``    success vs sensor noise (dark rooms are noisier)
- ``qr_jpeg.csv``     success vs compression (like video encoding)
- ``qr_ecc.csv``      success vs damaged modules for error-correction levels L/M/Q/H
- ``qr_pipeline.csv`` end-to-end goodput of a real transfer decoded from a real MP4

The degradations are synthetic and labelled as such. The decoder, the QR
codes and the packets are the real ones.
"""

from __future__ import annotations

import csv
import os
import random
import statistics
import tempfile
import time
from pathlib import Path

import cv2
import numpy as np
import qrcode
from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q

from airlock.core.identity import Identity, TrustStore
from airlock.core.oneway import SessionStore
from airlock.core.session import build_oneway_transfer, receive_file_oneway
from airlock.transports.qr import DEFAULT_FPS, QrDecoder, QrReceiver, b45encode, render_video

PACKET_BYTES = 200  # a real data packet with the QR chunk size (30 + 150 + 16 + 4)
FRAME_W, FRAME_H = 640, 480  # this laptop's webcam delivers 640x480 by default
LEVELS = {"L": ERROR_CORRECT_L, "M": ERROR_CORRECT_M, "Q": ERROR_CORRECT_Q, "H": ERROR_CORRECT_H}


def _matrix(packet: bytes, level: int) -> np.ndarray:
    """Boolean module matrix (True = dark), including the 4-module quiet zone."""
    qr = qrcode.QRCode(error_correction=level, border=4)
    qr.add_data(b45encode(packet))
    qr.make(fit=True)
    return np.array(qr.get_matrix(), dtype=bool)


def _to_image(matrix: np.ndarray, size: int) -> np.ndarray:
    img = np.where(matrix, 0, 255).astype(np.uint8)
    return cv2.resize(img, (size, size), interpolation=cv2.INTER_NEAREST)


def _scene(
    qr_img: np.ndarray,
    width_px: int,
    rng: np.random.Generator,
    *,
    blur_sigma: float = 0.8,
    noise_sigma: float = 6.0,
    jpeg_quality: int | None = None,
) -> np.ndarray:
    """Put the QR into a camera-sized frame and add optics blur, sensor noise and compression."""
    width_px = min(width_px, FRAME_H - 10)
    small = cv2.resize(qr_img, (width_px, width_px), interpolation=cv2.INTER_AREA)
    frame = np.full((FRAME_H, FRAME_W), 60, dtype=np.float32)  # darker surroundings
    y, x = (FRAME_H - width_px) // 2, (FRAME_W - width_px) // 2
    frame[y : y + width_px, x : x + width_px] = small
    if blur_sigma > 0:
        frame = cv2.GaussianBlur(frame, (0, 0), blur_sigma)
    if noise_sigma > 0:
        frame += rng.normal(0, noise_sigma, frame.shape)
    out = np.clip(frame, 0, 255).astype(np.uint8)
    if jpeg_quality is not None:
        ok, enc = cv2.imencode(".jpg", out, [cv2.IMWRITE_JPEG_QUALITY, jpeg_quality])
        out = cv2.imdecode(enc, cv2.IMREAD_GRAYSCALE) if ok else out
    return out


def _function_mask(version: int, n: int) -> np.ndarray:
    """True where a module belongs to a QR *function pattern* (layout, not data).

    Covers finder patterns plus separators, timing lines, format information,
    version information (version 7 and above) and alignment patterns. The
    decoder needs these to locate and read the code at all. Error
    correction protects only the data and ECC codewords, so damage is
    applied to those modules only.
    """
    from qrcode.util import pattern_position

    mask = np.zeros((n, n), dtype=bool)
    for r0, c0 in ((0, 0), (0, n - 8), (n - 8, 0)):  # finders + separators
        mask[max(r0 - 1, 0) : r0 + 9, max(c0 - 1, 0) : c0 + 9] = True
    mask[6, :] = mask[:, 6] = True  # timing patterns
    mask[8, :9] = mask[:9, 8] = mask[8, n - 8 :] = mask[n - 8 :, 8] = True  # format info
    if version >= 7:  # version information blocks
        mask[:6, n - 11 : n - 8] = mask[n - 11 : n - 8, :6] = True
    centres = pattern_position(version)
    for r in centres:
        for c in centres:
            if not mask[r, c]:  # alignment patterns that do not overlap a finder
                mask[r - 2 : r + 3, c - 2 : c + 3] = True
    return mask


def _damage(matrix: np.ndarray, rate: float, rng: np.random.Generator) -> np.ndarray:
    """Flip a fraction ``rate`` of the DATA modules (function patterns and quiet zone untouched)."""
    border = 4
    n = matrix.shape[0] - 2 * border
    version = (n - 17) // 4
    data_area = ~_function_mask(version, n)
    m = matrix.copy()
    symbol = m[border : border + n, border : border + n]
    flips = (rng.random(symbol.shape) < rate) & data_area
    symbol[flips] = ~symbol[flips]
    return m


def _success_rate(frames_and_packets: list[tuple[np.ndarray, bytes]], decoder: QrDecoder) -> tuple[float, float]:
    ok, times = 0, []
    for frame, packet in frames_and_packets:
        start = time.perf_counter()
        ok += decoder.decode(frame) == packet
        times.append((time.perf_counter() - start) * 1000)
    return ok / len(frames_and_packets), statistics.median(times)


def bench_size(samples: int, rng: np.random.Generator, decoder: QrDecoder) -> list[dict[str, object]]:
    packets = [os.urandom(PACKET_BYTES) for _ in range(samples)]
    images = [(_to_image(_matrix(p, ERROR_CORRECT_M), 1080), p) for p in packets]
    modules = _matrix(packets[0], ERROR_CORRECT_M).shape[0]  # symbol + quiet zone
    rows = []
    for width in (70, 85, 100, 115, 130, 160, 200, 260, 340, 440):
        frames = [(_scene(img, width, rng), p) for img, p in images]
        rate, ms = _success_rate(frames, decoder)
        rows.append({"qr_width_px": width, "px_per_module": round(width / modules, 2),
                     "samples": samples, "success_rate": round(rate, 4), "median_decode_ms": round(ms, 2)})
        print(f"  size {width:>3} px ({width / modules:.2f} px/module): {rate:6.1%}")
    return rows


def bench_noise(samples: int, rng: np.random.Generator, decoder: QrDecoder) -> list[dict[str, object]]:
    packets = [os.urandom(PACKET_BYTES) for _ in range(samples)]
    images = [(_to_image(_matrix(p, ERROR_CORRECT_M), 1080), p) for p in packets]
    rows = []
    for sigma in (0, 10, 20, 30, 45, 60, 80, 100):
        frames = [(_scene(img, 300, rng, noise_sigma=sigma), p) for img, p in images]
        rate, _ = _success_rate(frames, decoder)
        rows.append({"noise_sigma": sigma, "qr_width_px": 300, "samples": samples, "success_rate": round(rate, 4)})
        print(f"  noise sigma {sigma:>3}: {rate:6.1%}")
    return rows


def bench_jpeg(samples: int, rng: np.random.Generator, decoder: QrDecoder) -> list[dict[str, object]]:
    packets = [os.urandom(PACKET_BYTES) for _ in range(samples)]
    images = [(_to_image(_matrix(p, ERROR_CORRECT_M), 1080), p) for p in packets]
    rows = []
    for quality in (95, 75, 50, 30, 20, 10, 5):
        frames = [(_scene(img, 300, rng, jpeg_quality=quality), p) for img, p in images]
        rate, _ = _success_rate(frames, decoder)
        rows.append({"jpeg_quality": quality, "qr_width_px": 300, "samples": samples, "success_rate": round(rate, 4)})
        print(f"  JPEG quality {quality:>3}: {rate:6.1%}")
    return rows


def bench_ecc(samples: int, rng: np.random.Generator, decoder: QrDecoder) -> list[dict[str, object]]:
    packets = [os.urandom(PACKET_BYTES) for _ in range(samples)]
    rows = []
    for name, level in LEVELS.items():
        matrices = [(_matrix(p, level), p) for p in packets]
        modules = matrices[0][0].shape[0] - 8
        version = (modules - 17) // 4
        for pct in (0, 0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 5):
            frames = [(_scene(_to_image(_damage(m, pct / 100, rng), 1080), 360, rng), p)
                      for m, p in matrices]
            rate, _ = _success_rate(frames, decoder)
            rows.append({"ecc_level": name, "qr_version": version, "modules_per_side": modules,
                         "damaged_modules_pct": pct,
                         # each codeword is 8 modules: P(codeword hit) = 1 - (1 - p)^8
                         "codeword_error_pct": round(100 * (1 - (1 - pct / 100) ** 8), 1),
                         "samples": samples, "success_rate": round(rate, 4)})
        print(f"  ECC {name} (version {version}, {modules}x{modules}): "
              + " ".join(f"{r['damaged_modules_pct']}%={r['success_rate']:.0%}"
                         for r in rows if r["ecc_level"] == name))
    return rows


def bench_pipeline(file_bytes: int) -> list[dict[str, object]]:
    """Real transfer -> real MP4 -> real decode. Measures goodput on a perfect channel."""
    alice, bob = Identity.generate(), Identity.generate()
    a_trust, b_trust = TrustStore(), TrustStore()
    a_trust.add("bob", bob.public_key, bob.receive_public_key)
    b_trust.add("alice", alice.public_key, alice.receive_public_key)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "payload.bin"
        src.write_bytes(os.urandom(file_bytes))
        for hold in (4, 6, 8, 12):
            packets, _ = build_oneway_transfer(alice, a_trust, "bob", src, chunk_size=150)
            video = Path(tmp) / f"h{hold}.mp4"
            render_video(packets, video, hold=hold, loops=3)
            with QrReceiver.open_video(video) as rx:
                report = receive_file_oneway(rx, bob, b_trust, Path(tmp) / f"out{hold}", SessionStore())
                frames = rx.frames_read
            assert report.path.read_bytes() == src.read_bytes()
            seconds = frames / DEFAULT_FPS
            one_pass = len(packets) * hold / DEFAULT_FPS
            rows.append({
                "hold_frames": hold,
                "codes_per_second": round(DEFAULT_FPS / hold, 2),
                "file_bytes": file_bytes,
                "packets": len(packets),
                "wire_bytes": sum(map(len, packets)),
                "overhead_pct": round(100 * (sum(map(len, packets)) / file_bytes - 1), 1),
                "one_pass_seconds": round(one_pass, 2),
                "video_seconds_to_complete": round(seconds, 2),
                "goodput_bytes_per_s": round(file_bytes / seconds, 1),
                "video_mb_per_loop": round(video.stat().st_size / 1e6 / 3, 2),
            })
            print(f"  hold {hold:>2} ({DEFAULT_FPS / hold:.2f} codes/s): complete after "
                  f"{seconds:.1f} s of video -> {file_bytes / seconds:.0f} B/s goodput")
    return rows


def _write(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(out_dir: Path, quick: bool = False, seed: int = 2026) -> list[Path]:
    samples = 6 if quick else 40
    random.seed(seed)
    rng = np.random.default_rng(seed)  # fixed seed: the same degradations every run
    decoder = QrDecoder()
    outputs = []
    for name, func in (("qr_size", bench_size), ("qr_noise", bench_noise),
                       ("qr_jpeg", bench_jpeg), ("qr_ecc", bench_ecc)):
        print(f"qr: {name} ({samples} codes per condition)")
        path = out_dir / f"{name}.csv"
        _write(path, func(samples, rng, decoder))
        outputs.append(path)
    print("qr: end-to-end pipeline from real MP4 files")
    path = out_dir / "qr_pipeline.csv"
    _write(path, bench_pipeline(600 if quick else 2000))
    outputs.append(path)
    return outputs
