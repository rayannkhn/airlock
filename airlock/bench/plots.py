"""Charts for the report, drawn only from the CSV files the benchmarks wrote.

    python -m airlock.bench.plots            # reads results/*.csv, writes results/charts/*.png

Style: one y-scale per chart (two measures go in separate panels), thin
marks, a faint grid, a legend whenever there are two or more series, and
direct value labels in text colour. Series colours come from a validated
colour-blind-safe palette, assigned in a fixed order.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")  # files only: works on machines without a display
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # blue, orange, aqua, yellow (fixed order)
PERCENT = FuncFormatter(lambda v, _: f"{v:.0%}")


def _style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.labelcolor": TEXT_2, "axes.titlecolor": TEXT,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
        "axes.labelsize": 10, "font.size": 10, "text.color": TEXT,
        "xtick.color": TEXT_2, "ytick.color": TEXT_2, "xtick.labelsize": 9, "ytick.labelsize": 9,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
        "axes.spines.top": False, "axes.spines.right": False,
        "lines.linewidth": 1.6, "lines.markersize": 6,
        "legend.frameon": False, "legend.fontsize": 9,
    })


def _title(fig: plt.Figure, text: str) -> None:
    """Figure-level title, left-aligned to the figure edge so long y-labels never push it off-canvas."""
    fig.suptitle(text, x=0.01, ha="left", fontsize=12, fontweight="bold", color=TEXT)


GROUP_LEGEND = {"AirLock (X25519 + Ed25519)": SERIES[0], "RSA analogue (OAEP + PSS)": SERIES[1]}


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _save(fig: plt.Figure, path: Path, source: str) -> Path:
    fig.text(0.01, 0.01, f"Source: {source}", fontsize=7.5, color=TEXT_2)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path


def chart_handshake_time(results: Path, charts: Path) -> Path | None:
    src = results / "crypto_handshake.csv"
    if not src.exists():
        return None
    rows = _read(src)[::-1]  # top-to-bottom in the order measured
    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    ys = range(len(rows))
    for y, row in zip(ys, rows):
        colour = SERIES[0] if row["scheme"].startswith("AirLock") else SERIES[1]
        value = float(row["median_ms"])
        ax.plot([value], [y], "o", color=colour, markeredgecolor=SURFACE, markeredgewidth=1.5)
        ax.annotate(f"{value:.2f} ms" if value < 10 else f"{value:.0f} ms", (value, y),
                    xytext=(8, 0), textcoords="offset points", va="center", fontsize=9, color=TEXT)
    ax.set_yticks(list(ys), [r["scheme"] for r in rows])
    ax.set_xscale("log")
    ax.set_xlim(0.1, max(float(r["median_ms"]) for r in rows) * 6)
    ax.set_xlabel("median time per handshake, both sides (ms, log scale)")
    _title(fig, "Handshake time: AirLock vs an RSA version of the same protocol")
    ax.grid(axis="y", visible=False)
    ax.legend(handles=[Line2D([], [], marker="o", linestyle="", color=c, label=n)
                       for n, c in GROUP_LEGEND.items()],
              loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2)
    return _save(fig, charts / "crypto_handshake_time.png", "crypto_handshake.csv (real timings)")


def chart_handshake_bytes(results: Path, charts: Path) -> Path | None:
    src = results / "crypto_handshake.csv"
    if not src.exists():
        return None
    rows = _read(src)[::-1]
    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    for y, row in enumerate(rows):
        colour = SERIES[0] if row["scheme"].startswith("AirLock") else SERIES[1]
        value = int(row["wire_bytes"])
        ax.barh(y, value, height=0.6, color=colour, edgecolor=SURFACE, linewidth=2)
        ax.annotate(f"{value} B  ({row['qr_codes']} QR codes)", (value, y), xytext=(6, 0),
                    textcoords="offset points", va="center", fontsize=9, color=TEXT)
    ax.set_yticks(range(len(rows)), [r["scheme"] for r in rows])
    ax.set_xlim(0, max(int(r["wire_bytes"]) for r in rows) * 1.5)
    ax.set_xlabel("handshake bytes on the channel")
    _title(fig, "Handshake size: bytes that must cross the optical channel")
    ax.grid(axis="y", visible=False)
    ax.legend(handles=[Patch(color=c, label=n) for n, c in GROUP_LEGEND.items()],
              loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2)
    return _save(fig, charts / "crypto_handshake_bytes.png", "crypto_handshake.csv")


def chart_qr_size(results: Path, charts: Path) -> Path | None:
    src = results / "qr_size.csv"
    if not src.exists():
        return None
    rows = _read(src)
    x = [float(r["px_per_module"]) for r in rows]
    y = [float(r["success_rate"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.plot(x, y, "-o", color=SERIES[0], markeredgecolor=SURFACE, markeredgewidth=1.5)
    for xi, yi, r in zip(x, y, rows):
        if r is rows[0] or r is rows[-1] or 0 < yi < 1:
            ax.annotate(f"{yi:.0%}", (xi, yi), xytext=(0, 9), textcoords="offset points",
                        ha="center", fontsize=8.5, color=TEXT)
    ax.set_ylim(-0.05, 1.12)
    ax.yaxis.set_major_formatter(PERCENT)
    ax.set_xlabel("camera pixels per QR module (smaller = farther away)")
    ax.set_ylabel("codes decoded")
    _title(fig, "QR decoding vs apparent size in a 640x480 camera frame (level M)")
    samples = rows[0]["samples"]
    return _save(fig, charts / "qr_size.png", f"qr_size.csv ({samples} real decodes per point; simulated blur + noise)")


def chart_qr_ecc(results: Path, charts: Path) -> Path | None:
    src = results / "qr_ecc.csv"
    if not src.exists():
        return None
    by_level: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in _read(src):
        by_level[r["ecc_level"]].append(r)
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    crossings: list[tuple[float, str]] = []
    for colour, (level, rows) in zip(SERIES, by_level.items()):
        x = [float(r["damaged_modules_pct"]) for r in rows]
        y = [float(r["success_rate"]) for r in rows]
        tag = f"{level} (version {rows[0]['qr_version']}, {rows[0]['modules_per_side']}x{rows[0]['modules_per_side']})"
        ax.plot(x, y, "-o", color=colour, label=tag, markeredgecolor=SURFACE, markeredgewidth=1.5)
        crossing = next(((x[i] + (x[i + 1] - x[i]) * (y[i] - 0.5) / (y[i] - y[i + 1]))
                         for i in range(len(y) - 1) if y[i] >= 0.5 > y[i + 1]), None)
        if crossing is not None:
            crossings.append((crossing, level))
    # Direct labels where each line crosses 50%: to the right by default; two lines crossing
    # within 0.2 percentage points get staggered (first above-left, second below-right).
    crossings.sort()
    for i, (cx, level) in enumerate(crossings):
        near_next = i + 1 < len(crossings) and crossings[i + 1][0] - cx < 0.2
        near_prev = i > 0 and cx - crossings[i - 1][0] < 0.2
        offset, ha = ((-8, 10), "right") if near_next else (((8, -10), "left") if near_prev else ((8, 0), "left"))
        ax.annotate(level, (cx, 0.5), xytext=offset, textcoords="offset points", ha=ha,
                    va="center", fontsize=9, fontweight="bold", color=TEXT)
    ax.set_ylim(-0.05, 1.1)
    ax.yaxis.set_major_formatter(PERCENT)
    ax.set_xlabel("data modules damaged (%)")
    ax.set_ylabel("codes decoded")
    ax.axhline(0.5, color=GRID, linewidth=0.8, zorder=0)
    _title(fig, "Error-correction level vs damage (AirLock uses M)")
    ax.legend(title="level", title_fontsize=9, loc="upper right")
    return _save(fig, charts / "qr_ecc.png", "qr_ecc.csv (real decodes; synthetic module damage)")


def chart_qr_conditions(results: Path, charts: Path) -> Path | None:
    noise, jpeg = results / "qr_noise.csv", results / "qr_jpeg.csv"
    if not (noise.exists() and jpeg.exists()):
        return None
    fig, (left, right) = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    n_rows, j_rows = _read(noise), _read(jpeg)
    left.plot([int(r["noise_sigma"]) for r in n_rows], [float(r["success_rate"]) for r in n_rows],
              "-o", color=SERIES[0], markeredgecolor=SURFACE, markeredgewidth=1.5)
    left.set_xlabel("sensor noise (std. dev., grey levels)")
    left.set_ylabel("codes decoded")
    left.set_title("Noise")
    right.plot([int(r["jpeg_quality"]) for r in j_rows], [float(r["success_rate"]) for r in j_rows],
               "-o", color=SERIES[0], markeredgecolor=SURFACE, markeredgewidth=1.5)
    right.invert_xaxis()  # left to right = more compression
    right.set_xlabel("JPEG quality (lower = more compression)")
    right.set_title("Compression")
    left.set_ylim(-0.05, 1.1)
    left.yaxis.set_major_formatter(PERCENT)
    _title(fig, "QR decoding under noise and compression (QR 300 px wide, level M)")
    return _save(fig, charts / "qr_conditions.png", "qr_noise.csv, qr_jpeg.csv (real decodes; synthetic degradation)")


def chart_qr_pipeline(results: Path, charts: Path) -> Path | None:
    src = results / "qr_pipeline.csv"
    if not src.exists():
        return None
    rows = _read(src)
    fig, ax = plt.subplots(figsize=(7, 3.4))
    labels = [f"{float(r['codes_per_second']):g}/s" for r in rows]
    values = [float(r["goodput_bytes_per_s"]) for r in rows]
    ax.bar(labels, values, width=0.6, color=SERIES[0], edgecolor=SURFACE, linewidth=2)
    for i, v in enumerate(values):
        ax.annotate(f"{v:.0f} B/s", (i, v), xytext=(0, 4), textcoords="offset points",
                    ha="center", fontsize=9, color=TEXT)
    ax.set_ylim(0, max(values) * 1.2)
    ax.set_xlabel("QR codes shown per second")
    ax.set_ylabel("file bytes delivered per second")
    _title(fig, f"Goodput of a real {rows[0]['file_bytes']}-byte transfer decoded from MP4")
    ax.grid(axis="x", visible=False)
    return _save(fig, charts / "qr_pipeline.png", "qr_pipeline.csv (perfect channel: decoded straight from the video file)")


def chart_qr_live(results: Path, charts: Path) -> Path | None:
    src = results / "qr_live.csv"
    if not src.exists():
        return None
    rows = [r for r in _read(src) if r["source"].startswith("camera")]
    if not rows:
        return None
    by_distance: dict[float, list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        by_distance[float(r["distance_cm"])].append(r)
    distances = sorted(by_distance)
    success = [sum(int(r["success"]) for r in by_distance[d]) / len(by_distance[d]) for d in distances]
    goodput = [median([float(r["goodput_bytes_per_s"]) for r in by_distance[d] if r["success"] == "1"] or [0])
               for d in distances]
    runs = [len(by_distance[d]) for d in distances]
    fig, (left, right) = plt.subplots(1, 2, figsize=(9, 3.4))
    left.plot(distances, success, "-o", color=SERIES[0], markeredgecolor=SURFACE, markeredgewidth=1.5)
    for d, s, n in zip(distances, success, runs):
        left.annotate(f"{s:.0%} of {n}", (d, s), xytext=(0, 8), textcoords="offset points",
                      ha="center", fontsize=8.5, color=TEXT)
    left.set_ylim(-0.05, 1.15)
    left.yaxis.set_major_formatter(PERCENT)
    left.set_xlabel("phone-to-webcam distance (cm)")
    left.set_title("Transfers completed")
    right.plot(distances, goodput, "-o", color=SERIES[0], markeredgecolor=SURFACE, markeredgewidth=1.5)
    right.set_ylim(0, max(goodput + [1]) * 1.25)
    right.set_xlabel("phone-to-webcam distance (cm)")
    right.set_title("Median goodput (B/s, successful runs)")
    _title(fig, "Live: phone screen to laptop webcam")
    return _save(fig, charts / "qr_live.png", "qr_live.csv (real runs with the phone)")


def make_all(results: Path) -> list[Path]:
    _style()
    charts = results / "charts"
    makers = (chart_handshake_time, chart_handshake_bytes, chart_qr_size, chart_qr_ecc,
              chart_qr_conditions, chart_qr_pipeline, chart_qr_live)
    return [p for p in (m(results, charts) for m in makers) if p is not None]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("results"))
    args = parser.parse_args()
    for path in make_all(args.out):
        print(f"chart: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
