"""Benchmark entry point. Every number comes from real runs on this machine; nothing is fabricated.

    python -m airlock.bench.benchmark all             # crypto + QR robustness + charts (~2 min)
    python -m airlock.bench.benchmark all --quick     # fewer repetitions, for a smoke test
    python -m airlock.bench.benchmark crypto
    python -m airlock.bench.benchmark qr
    python -m airlock.bench.benchmark live-video      # make the phone benchmark video
    python -m airlock.bench.benchmark live --distance-cm 30 --runs 3

CSV files go to ``results/``; charts go to ``results/charts/`` (see plots.py).
"""

from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

DEFAULT_OUT = Path("results")


def _environment(out: Path) -> None:
    """Record the machine the numbers came from, for the report's methodology section."""
    import cryptography
    import cv2

    out.mkdir(parents=True, exist_ok=True)
    (out / "environment.txt").write_text(
        f"python {sys.version.split()[0]}\n"
        f"platform {platform.platform()}\n"
        f"processor {platform.processor() or platform.machine()}\n"
        f"cryptography {cryptography.__version__}\n"
        f"opencv {cv2.__version__}\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="results directory")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("all", "crypto", "qr"):
        p = sub.add_parser(name)
        p.add_argument("--quick", action="store_true", help="fewer repetitions (smoke test)")
    sub.add_parser("live-video", help="create results/live/bench.mp4 for the phone")
    p = sub.add_parser("live", help="time real transfers from the phone to the webcam")
    p.add_argument("--distance-cm", type=float, required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--label", default="", help="free text, e.g. 'room light, full brightness'")
    p.add_argument("--camera", type=int, default=0)
    p.add_argument("--video", type=Path, help="dry run: read a video file instead of the camera")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds without a new code before a run fails")
    args = parser.parse_args(argv)

    from airlock.bench import crypto_bench, live_bench, plots, qr_bench

    _environment(args.out)
    if args.command in ("all", "crypto"):
        crypto_bench.run(args.out, quick=args.quick)
    if args.command in ("all", "qr"):
        qr_bench.run(args.out, quick=args.quick)
    if args.command == "live-video":
        live_bench.make_video(args.out)
    if args.command == "live":
        live_bench.run_live(args.out, distance_cm=args.distance_cm, runs=args.runs, label=args.label,
                            camera=args.camera, video=args.video, timeout=args.timeout)
    written = plots.make_all(args.out)
    for path in written:
        print(f"chart: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
