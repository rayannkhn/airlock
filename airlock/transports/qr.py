"""Animated-QR transport: screen (phone or monitor) -> camera.

Sender side: every packet becomes one QR code, and the codes are written to
an MP4 video or a self-contained HTML page that loops through them.
Receiver side: :class:`QrReceiver` reads frames from a webcam or a video file
and returns each newly decoded packet. It is a one-way (receive-only)
transport.

Encoding: packets are binary, but OpenCV's QR decoder returns text, which
would corrupt arbitrary bytes. Packets are therefore encoded with Base45
(RFC 9285). Its alphabet is exactly the QR "alphanumeric" character set, so
the QR stays compact (about 3% overhead, against 33% for Base64 in byte mode).

Like every transport, this one is untrusted. The QR layer adds no security;
the packets it carries are already encrypted and authenticated.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Sequence

import cv2
import numpy as np
import qrcode
from qrcode.constants import ERROR_CORRECT_M

from airlock.transports.base import Transport, TransportClosed, TransportError, TransportTimeout

B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_INDEX = {ch: i for i, ch in enumerate(B45_ALPHABET)}

DEFAULT_FPS = 30
DEFAULT_HOLD = 8  # video frames per QR code: 30 fps / 8 = 3.75 codes per second
DEFAULT_LOOPS = 4
DEFAULT_SIZE = 1080  # pixels; square QR area
LABEL_HEIGHT = 90


# ----------------------------------------------------------------- Base45


def b45encode(data: bytes) -> str:
    """RFC 9285 Base45: every 2 bytes become 3 alphanumeric characters."""
    out: list[str] = []
    for i in range(0, len(data) - 1, 2):
        n = data[i] * 256 + data[i + 1]
        n, c = divmod(n, 45)
        e, d = divmod(n, 45)
        out += [B45_ALPHABET[c], B45_ALPHABET[d], B45_ALPHABET[e]]
    if len(data) % 2:
        d, c = divmod(data[-1], 45)
        out += [B45_ALPHABET[c], B45_ALPHABET[d]]
    return "".join(out)


def b45decode(text: str) -> bytes:
    """Inverse of :func:`b45encode`. Raises ValueError on any invalid input."""
    try:
        values = [_B45_INDEX[ch] for ch in text]
    except KeyError as exc:
        raise ValueError("invalid Base45 character") from exc
    if len(values) % 3 == 1:
        raise ValueError("invalid Base45 length")
    out = bytearray()
    for i in range(0, len(values) - 2, 3):
        n = values[i] + values[i + 1] * 45 + values[i + 2] * 2025
        if n > 0xFFFF:
            raise ValueError("invalid Base45 group")
        out += bytes((n >> 8, n & 0xFF))
    if len(values) % 3 == 2:
        n = values[-2] + values[-1] * 45
        if n > 0xFF:
            raise ValueError("invalid Base45 group")
        out.append(n)
    return bytes(out)


# ----------------------------------------------------------------- sender side


def qr_image(
    packet: bytes, size: int = DEFAULT_SIZE, error_correction: int = ERROR_CORRECT_M
) -> np.ndarray:
    """One packet -> a square grayscale QR image (uint8, white background).

    Level M (the default) tolerates about 15% damage. The benchmark compares
    it with L (7%), Q (25%) and H (30%).
    """
    qr = qrcode.QRCode(error_correction=error_correction, border=4)
    qr.add_data(b45encode(packet))  # alphanumeric mode
    qr.make(fit=True)
    matrix = np.array(qr.get_matrix(), dtype=bool)  # True = dark module
    img = np.where(matrix, 0, 255).astype(np.uint8)
    # INTER_NEAREST keeps module edges perfectly sharp (no blur from scaling).
    return cv2.resize(img, (size, size), interpolation=cv2.INTER_NEAREST)


def _frame(packet: bytes, label: str, size: int) -> np.ndarray:
    """QR plus a small human-readable label strip underneath (BGR)."""
    canvas = np.full((size + LABEL_HEIGHT, size), 255, dtype=np.uint8)
    canvas[:size, :] = qr_image(packet, size)
    cv2.putText(canvas, label, (24, size + 60), cv2.FONT_HERSHEY_SIMPLEX, 1.6, 0, 3, cv2.LINE_AA)
    return cv2.cvtColor(canvas, cv2.COLOR_GRAY2BGR)


def render_video(
    packets: Sequence[bytes],
    path: Path,
    *,
    fps: int = DEFAULT_FPS,
    hold: int = DEFAULT_HOLD,
    loops: int = DEFAULT_LOOPS,
    size: int = DEFAULT_SIZE,
) -> float:
    """Write the looping QR video. Returns its duration in seconds.

    OpenCV's pip build can only write MPEG-4 Part 2 ('mp4v'), which many
    phone players refuse. If ffmpeg is installed, the file is re-encoded to
    H.264 (baseline profile, yuv420p), which every phone plays. Without
    ffmpeg, use :func:`render_gif` for phones instead.
    """
    if not packets:
        raise ValueError("nothing to render")
    frames = [_frame(p, f"AirLock  {i + 1}/{len(packets)}", size) for i, p in enumerate(packets)]
    height, width = frames[0].shape[:2]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), fps, (width, height))
    if not writer.isOpened():
        raise TransportError(f"cannot write video {path} (no MP4 encoder available)")
    try:
        for _ in range(loops):
            for frame in frames:
                for _ in range(hold):
                    writer.write(frame)
    finally:
        writer.release()
    to_h264(path)
    return loops * len(frames) * hold / fps


def to_h264(path: Path) -> bool:
    """Re-encode ``path`` to H.264 in place if ffmpeg is available. Returns True if it did.

    Settings chosen for compatibility and sharp QR edges: baseline profile,
    yuv420p, high quality (CRF 18), 'stillimage' tuning, and the moov atom at
    the start (faststart) so phones can open it immediately.
    """
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        return False
    path = Path(path)
    tmp = path.with_name(path.stem + ".h264.mp4")
    result = subprocess.run(
        [ffmpeg, "-y", "-loglevel", "error", "-i", str(path), "-c:v", "libx264",
         "-profile:v", "baseline", "-pix_fmt", "yuv420p", "-crf", "18", "-tune", "stillimage",
         "-movflags", "+faststart", str(tmp)],
        capture_output=True, check=False,
    )
    if result.returncode != 0 or not tmp.exists():
        tmp.unlink(missing_ok=True)
        return False
    tmp.replace(path)
    return True


def render_gif(
    packets: Sequence[bytes],
    path: Path,
    *,
    codes_per_second: float = DEFAULT_FPS / DEFAULT_HOLD,
    size: int = 720,
) -> float:
    """Write a looping animated GIF: the format every phone gallery and browser plays.

    For black-and-white QR codes a GIF is lossless (2 colours, no video
    compression), and it repeats forever by itself. Returns the seconds per loop.
    """
    from PIL import Image

    if not packets:
        raise ValueError("nothing to render")
    frames = [Image.fromarray(cv2.cvtColor(_frame(p, f"AirLock  {i + 1}/{len(packets)}", size),
                                           cv2.COLOR_BGR2GRAY)).convert("1")
              for i, p in enumerate(packets)]
    # GIF timing is in 10 ms units; round to the nearest valid duration.
    duration_ms = max(20, int(round(1000 / codes_per_second / 10)) * 10)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=duration_ms,
                   loop=0, optimize=False, disposal=1)
    return len(frames) * duration_ms / 1000


def gif_frames(path: Path) -> list[np.ndarray]:
    """All frames of a GIF as BGR arrays (used for the self-check and for receiving)."""
    from PIL import Image, ImageSequence

    with Image.open(path) as gif:
        return [cv2.cvtColor(np.array(f.convert("L")), cv2.COLOR_GRAY2BGR)
                for f in ImageSequence.Iterator(gif)]


def verify_gif(path: Path, packets: Sequence[bytes]) -> int:
    """Decode every GIF frame and count how many packets come back exactly."""
    decoder = QrDecoder()
    found = {decoder.decode(frame) for frame in gif_frames(path)}
    return sum(1 for p in packets if p in found)


def render_html(
    packets: Sequence[bytes],
    path: Path,
    *,
    codes_per_second: float = DEFAULT_FPS / DEFAULT_HOLD,
    size: int = 720,
) -> None:
    """Write a self-contained HTML page that cycles through the QR codes forever.

    This is the fallback when a phone cannot play the MP4. It is lossless
    (PNG, no video compression) and works offline in any browser.
    """
    if not packets:
        raise ValueError("nothing to render")
    images = []
    for packet in packets:
        ok, png = cv2.imencode(".png", qr_image(packet, size))
        if not ok:
            raise TransportError("PNG encoding failed")
        images.append("data:image/png;base64," + base64.b64encode(png.tobytes()).decode("ascii"))
    period_ms = max(50, int(1000 / codes_per_second))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AirLock transfer</title>
<style>
  html, body {{ margin: 0; height: 100%; background: #fff; color: #000;
               font-family: sans-serif; }}
  body {{ display: flex; flex-direction: column; align-items: center;
          justify-content: center; }}
  img {{ width: 96vmin; height: 96vmin; image-rendering: pixelated; }}
  #label {{ font-size: 5vmin; margin-top: 1vmin; }}
</style></head>
<body onclick="document.documentElement.requestFullscreen && document.documentElement.requestFullscreen()">
<img id="qr" alt="AirLock QR frame">
<div id="label"></div>
<script>
  const frames = {json.dumps(images)};
  let i = 0;
  const img = document.getElementById("qr"), label = document.getElementById("label");
  function show() {{
    img.src = frames[i];
    label.textContent = "AirLock " + (i + 1) + "/" + frames.length + "  (tap for fullscreen)";
    i = (i + 1) % frames.length;
  }}
  show();
  setInterval(show, {period_ms});
</script></body></html>
"""
    Path(path).write_text(page, encoding="utf-8")


def verify_video(path: Path, packets: Sequence[bytes], hold: int = DEFAULT_HOLD) -> int:
    """Decode one frame per packet from the written video. Returns how many decode exactly.

    Catches a codec that blurred the QR codes on the laptop, before the
    video ever reaches the phone.
    """
    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        raise TransportError(f"cannot open {path} for verification")
    decoder = QrDecoder()
    good = 0
    try:
        for index, packet in enumerate(packets):
            capture.set(cv2.CAP_PROP_POS_FRAMES, index * hold + hold // 2)
            ok, frame = capture.read()
            if ok and decoder.decode(frame) == packet:
                good += 1
    finally:
        capture.release()
    return good


# ----------------------------------------------------------------- receiver side


class QrDecoder:
    """Frame -> packet bytes (or None). Wraps OpenCV's QR detectors.

    Measured on this project (300 random packets, perfect images): the classic
    ``QRCodeDetector`` missed 18 of 300, and ``QRCodeDetectorAruco`` missed
    none. So the Aruco detector runs first, and the classic one is a fallback.
    """

    def __init__(self) -> None:
        self._detectors: list[cv2.QRCodeDetector] = []
        if hasattr(cv2, "QRCodeDetectorAruco"):
            self._detectors.append(cv2.QRCodeDetectorAruco())
        self._detectors.append(cv2.QRCodeDetector())

    def decode(self, frame: np.ndarray) -> bytes | None:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if frame.ndim == 3 else frame
        for detector in self._detectors:
            try:
                text, _points, _ = detector.detectAndDecode(gray)
            except cv2.error:
                continue
            if text:
                try:
                    return b45decode(text)
                except ValueError:
                    return None  # a QR code that is not ours: ignore
        return None


class QrReceiver(Transport):
    """Receive-only transport that reads QR packets from a camera or a video file.

    ``receive()`` returns the next *newly seen* packet. The same code shown
    on several consecutive frames is returned once. Repeats from later loops
    are returned again, and the Reassembler counts them as duplicates.
    """

    def __init__(
        self,
        capture: cv2.VideoCapture,
        *,
        source_name: str,
        is_file: bool,
        preview: bool = False,
        frame_step: int = 1,
    ) -> None:
        if not capture.isOpened():
            raise TransportError(f"cannot open {source_name}")
        self._capture = capture
        self._decoder = QrDecoder()
        self._is_file = is_file
        self._preview = preview
        self._frame_step = max(1, frame_step)
        self._last: bytes | None = None
        self._closed = False
        self.source_name = source_name
        self.status = "waiting for QR codes"  # shown in the preview window
        self.frames_read = 0
        self.codes_decoded = 0
        self.last_frame: np.ndarray | None = None  # latest camera frame, for a UI preview

    @classmethod
    def open_camera(cls, index: int = 0, *, preview: bool = True) -> QrReceiver:
        capture = cv2.VideoCapture(index)
        # Ask for 720p. More pixels per QR module helps; the camera may refuse.
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        return cls(capture, source_name=f"camera {index}", is_file=False, preview=preview)

    @classmethod
    def open_video(cls, path: Path, *, frame_step: int = 1, preview: bool = False) -> QrReceiver:
        if not Path(path).is_file():
            raise TransportError(f"video file not found: {path}")
        if Path(path).suffix.lower() == ".gif":
            frame_step = 1  # a GIF shows each code exactly once: skipping frames would lose codes
        return cls(
            cv2.VideoCapture(str(path)),
            source_name=str(path),
            is_file=True,
            preview=preview,
            frame_step=frame_step,
        )

    def send(self, data: bytes) -> None:
        raise TransportError("the QR receiver is one-way: it cannot send")

    def _show(self, frame: np.ndarray) -> None:
        if not self._preview:
            return
        view = frame.copy()
        cv2.putText(view, self.status, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 160, 0), 2)
        try:
            cv2.imshow("AirLock receiver (press q to abort)", view)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                raise KeyboardInterrupt
        except cv2.error:
            self._preview = False  # no display available: carry on without the window

    def receive(self, timeout: float | None = None) -> bytes:
        if self._closed:
            raise TransportError("transport is closed")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if deadline is not None and time.monotonic() > deadline:
                raise TransportTimeout(f"no new QR code within {timeout:.0f}s")
            if self._is_file and self._frame_step > 1:
                for _ in range(self._frame_step - 1):
                    if not self._capture.grab():
                        raise TransportClosed("end of video")
            ok, frame = self._capture.read()
            if not ok:
                if self._is_file:
                    raise TransportClosed("end of video")
                raise TransportError(f"{self.source_name} stopped delivering frames")
            self.frames_read += 1
            self.last_frame = frame
            self._show(frame)
            packet = self._decoder.decode(frame)
            if packet is None or packet == self._last:
                continue
            self._last = packet
            self.codes_decoded += 1
            return packet

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._capture.release()
        if self._preview:
            try:
                cv2.destroyAllWindows()
            except cv2.error:
                pass
