"""Smoke tests for the benchmarks: they run, write well-formed CSVs and charts, and record failures."""

from __future__ import annotations

import csv
from pathlib import Path

import numpy as np

from airlock.bench import crypto_bench, live_bench, plots, qr_bench
from airlock.transports.qr import QrDecoder


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_crypto_bench_quick(tmp_path: Path) -> None:
    crypto_bench.run(tmp_path, quick=True)
    handshakes = {r["scheme"]: r for r in _rows(tmp_path / "crypto_handshake.csv")}
    assert int(handshakes["AirLock interactive (X25519 + Ed25519)"]["wire_bytes"]) == 390
    assert int(handshakes["AirLock one-way (X25519 + Ed25519)"]["wire_bytes"]) == 202
    rsa = handshakes["RSA-3072 analogue, with forward secrecy"]
    assert int(rsa["wire_bytes"]) > 390 and float(rsa["median_ms"]) > 0
    sizes = {r["scheme"]: r for r in _rows(tmp_path / "crypto_sizes.csv")}
    assert int(sizes["RSA-2048"]["signature_bytes"]) == 256


def test_damage_spares_function_patterns() -> None:
    """Even 100% damage leaves finder, timing and format modules untouched."""
    rng = np.random.default_rng(0)
    m = qr_bench._matrix(b"\x00" * 200, 1)
    damaged = qr_bench._damage(m, 1.0, rng)
    n = m.shape[0] - 8
    mask = qr_bench._function_mask((n - 17) // 4, n)
    inner, inner_d = m[4:-4, 4:-4], damaged[4:-4, 4:-4]
    assert (inner[mask] == inner_d[mask]).all() and (inner[~mask] != inner_d[~mask]).all()


def test_clean_qr_scene_decodes() -> None:
    rng = np.random.default_rng(0)
    packet = bytes(range(200))
    img = qr_bench._to_image(qr_bench._matrix(packet, 0), 1080)
    assert QrDecoder().decode(qr_bench._scene(img, 400, rng)) == packet


def test_live_bench_dry_run_with_video_file(tmp_path: Path) -> None:
    """The live benchmark reads a video file instead of the camera and appends real rows."""
    video = live_bench.make_video(tmp_path, hold=4, loops=2)
    rows = live_bench.run_live(tmp_path, distance_cm=0, runs=1, label="dry run",
                               camera=0, video=video, timeout=10)
    assert rows[0]["success"] == 1 and float(rows[0]["goodput_bytes_per_s"]) > 0
    assert len(_rows(tmp_path / "qr_live.csv")) == 1


def test_plots_from_csvs(tmp_path: Path) -> None:
    crypto_bench.run(tmp_path, quick=True)
    (tmp_path / "qr_live.csv").write_text(
        "recorded_at,distance_cm,label,run,source,success,failure_reason,seconds_first_code_to_done,"
        "file_bytes,goodput_bytes_per_s,packets,codes_decoded,duplicates,crc_errors,camera_fps_processed\n"
        "t,20,x,1,camera 0,1,,10,2000,200,16,30,10,0,8\n"
        "t,60,x,1,camera 0,0,timeout,,2000,,16,3,,,8\n", encoding="utf-8")
    charts = plots.make_all(tmp_path)
    names = {p.name for p in charts}
    assert {"crypto_handshake_time.png", "crypto_handshake_bytes.png", "qr_live.png"} <= names
    assert all(p.stat().st_size > 10_000 for p in charts)
