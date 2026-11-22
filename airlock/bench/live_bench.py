"""Live benchmark: the real phone screen and the real webcam, at distances you choose.

This is the only benchmark that needs a person. Usage:

    python -m airlock.bench.benchmark live-video                  # once: makes results/live/bench.mp4
    # copy results/live/bench.gif to the phone (USB), then for each distance:
    python -m airlock.bench.benchmark live --distance-cm 20 --runs 3
    python -m airlock.bench.benchmark live --distance-cm 40 --runs 3
    python -m airlock.bench.benchmark live --distance-cm 60 --runs 3

Each run is a complete, verified AirLock transfer (SEAL check, decryption,
SHA-256) from the phone to the webcam. A row is appended to
``results/qr_live.csv`` whatever the outcome, so failures are recorded too.

Benchmark-specific relaxations (documented, not hidden):
- each run uses a fresh in-memory session store, so the same video can be
  received repeatedly (in normal use the second playback is a replay and is
  rejected);
- the timestamp window is 365 days, so the benchmark video does not expire
  between sessions.
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from airlock.core.handshake import HandshakeError
from airlock.core.identity import Identity, TrustStore, card_path_for, load_peer_keys
from airlock.core.oneway import SessionStore
from airlock.core.session import TransferError, build_oneway_transfer, receive_file_oneway
from airlock.transports.base import Transport, TransportError
from airlock.transports.qr import (
    DEFAULT_FPS,
    DEFAULT_HOLD,
    QrReceiver,
    render_gif,
    render_html,
    render_video,
    verify_video,
)

LIVE_FILE_BYTES = 2000
LIVE_LOOPS = 8
BENCH_MAX_AGE = 365 * 24 * 3600


class TimingTransport(Transport):
    """Pass-through wrapper that records when the first QR code was decoded."""

    def __init__(self, inner: QrReceiver) -> None:
        self.inner = inner
        self.first_code_at: float | None = None
        self.codes = 0

    def send(self, data: bytes) -> None:
        self.inner.send(data)

    def receive(self, timeout: float | None = None) -> bytes:
        packet = self.inner.receive(timeout)
        if self.first_code_at is None:
            self.first_code_at = time.perf_counter()
        self.codes += 1
        return packet

    def close(self) -> None:
        self.inner.close()


def _live_dir(out_dir: Path) -> Path:
    return out_dir / "live"


def make_video(out_dir: Path, hold: int = DEFAULT_HOLD, loops: int = LIVE_LOOPS) -> Path:
    """Create benchmark keys, a 2000-byte payload and the transfer video (plus an HTML fallback)."""
    live = _live_dir(out_dir)
    alice, bob = Identity.generate(), Identity.generate()
    alice.save(live / "keys" / "alice.key", None, overwrite=True)
    bob.save(live / "keys" / "bob.key", None, overwrite=True)
    trust = TrustStore()
    trust.add("bob", bob.public_key, bob.receive_public_key)
    payload = live / "payload.bin"
    payload.write_bytes(os.urandom(LIVE_FILE_BYTES))
    packets, _ = build_oneway_transfer(alice, trust, "bob", payload, chunk_size=150)
    video = live / "bench.mp4"
    seconds = render_video(packets, video, hold=hold, loops=loops)
    render_html(packets, live / "bench.html")
    render_gif(packets, live / "bench.gif", codes_per_second=DEFAULT_FPS / hold)
    readable = verify_video(video, packets, hold=hold)
    (live / "meta.json").write_text(json.dumps({
        "file_bytes": LIVE_FILE_BYTES,
        "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
        "packets": len(packets),
        "hold": hold,
        "loops": loops,
        "video_seconds": seconds,
        "created": dt.datetime.now().isoformat(timespec="seconds"),
    }, indent=2), encoding="utf-8")
    print(f"Wrote {video} ({len(packets)} codes x {loops} loops, {seconds:.0f} s); "
          f"self-check {readable}/{len(packets)}")
    print(f"For the phone (plays everywhere): {live / 'bench.gif'}   (fallback: {live / 'bench.html'})")
    return video


def _append(path: Path, row: dict[str, object]) -> None:
    new = not path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        if new:
            writer.writeheader()
        writer.writerow(row)


def run_live(
    out_dir: Path,
    *,
    distance_cm: float,
    runs: int,
    label: str,
    camera: int,
    video: Path | None,
    timeout: float,
) -> list[dict[str, object]]:
    live = _live_dir(out_dir)
    if not (live / "meta.json").exists():
        raise SystemExit("Run 'python -m airlock.bench.benchmark live-video' first.")
    meta = json.loads((live / "meta.json").read_text(encoding="utf-8"))
    bob = Identity.load(live / "keys" / "bob.key")
    alice_sign, alice_recv = load_peer_keys(card_path_for(live / "keys" / "alice.key"))
    trust = TrustStore()
    trust.add("alice", alice_sign, alice_recv)

    rows = []
    for run in range(1, runs + 1):
        if video is None:
            input(f"\nRun {run}/{runs} at {distance_cm:g} cm: start bench.mp4 on the phone, "
                  "hold it in front of the webcam, then press Enter ... ")
            source = QrReceiver.open_camera(camera, preview=True)
        else:
            source = QrReceiver.open_video(video, frame_step=1)
        timer = TimingTransport(source)
        started = time.perf_counter()
        success, reason, stats = False, "", None
        with tempfile.TemporaryDirectory() as tmp:
            try:
                report = receive_file_oneway(timer, bob, trust, Path(tmp), SessionStore(),
                                             timeout=timeout, max_age=BENCH_MAX_AGE)
                ok = hashlib.sha256(report.path.read_bytes()).hexdigest() == meta["sha256"]
                success, reason, stats = ok, "" if ok else "hash mismatch", report.stats
            except (TransportError, TransferError, HandshakeError) as exc:
                reason = str(exc)
            finally:
                timer.close()
        finished = time.perf_counter()
        seconds = finished - (timer.first_code_at or started)
        elapsed = finished - started
        row = {
            "recorded_at": dt.datetime.now().isoformat(timespec="seconds"),
            "distance_cm": distance_cm,
            "label": label,
            "run": run,
            "source": "video file" if video else f"camera {camera}",
            "success": int(success),
            "failure_reason": reason,
            "seconds_first_code_to_done": round(seconds, 2) if success else "",
            "file_bytes": meta["file_bytes"],
            "goodput_bytes_per_s": round(meta["file_bytes"] / seconds, 1) if success else "",
            "packets": meta["packets"],
            "codes_decoded": timer.codes,
            "duplicates": stats.duplicates if stats else "",
            "crc_errors": stats.crc_errors if stats else "",
            "camera_fps_processed": round(source.frames_read / elapsed, 1) if elapsed > 0 else "",
        }
        _append(out_dir / "qr_live.csv", row)
        rows.append(row)
        verdict = "OK" if success else f"FAILED ({reason})"
        print(f"run {run}: {verdict}; {timer.codes} codes decoded"
              + (f"; {seconds:.1f} s -> {row['goodput_bytes_per_s']} B/s" if success else ""))
    return rows
