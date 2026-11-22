"""AirLock demo UI: a local web page with three buttons (Send, Receive, Attacks).

    airlock ui            # opens http://127.0.0.1:8765 in the browser

It drives exactly the same code as the CLI. It only adds plain-language
step-by-step explanations, so the protocol can be presented in a few
minutes.

Security of the UI itself (worth a sentence in the viva):
- it listens on 127.0.0.1 only, so nothing on the network can reach it;
- every state-changing request must carry an ``X-AirLock`` header. A
  malicious website cannot add custom headers to cross-site requests
  without a CORS preflight, which this server never approves (CSRF);
- the ``Host`` header must be localhost, which blocks DNS-rebinding attacks.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import shutil
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlparse

import cv2

from airlock.core.handshake import HandshakeError
from airlock.core.identity import IdentityError
from airlock.core.oneway import SessionStore
from airlock.core.session import (
    TransferError,
    build_oneway_transfer,
    receive_file_oneway,
    sanitize_filename,
)
from airlock.demo_users import demo_users_exist, load_demo_user, setup_demo_users
from airlock.transports.base import Transport, TransportClosed, TransportError, TransportTimeout
from airlock.transports.qr import (
    DEFAULT_FPS,
    DEFAULT_HOLD,
    QrReceiver,
    qr_image,
    render_gif,
    render_html,
    render_video,
)

STATIC = Path(__file__).parent / "static"
MAX_UPLOAD = 16 * 1024 * 1024
QR_CHUNK = 150
IDLE_TIMEOUT = 90.0  # seconds without a new QR code before a receive gives up


# --------------------------------------------------------------------- plain-language errors

def friendly_error(exc: BaseException) -> str:
    """Turn a protocol error into one sentence a non-specialist audience understands."""
    text = str(exc)
    table = [
        ("replay", "Rejected: this exact transfer was already received. Someone is replaying an old recording."),
        ("too old", "Rejected: this transfer is more than 24 hours old, so it could be a replayed recording."),
        ("future", "Rejected: the transfer's timestamp is in the future. Check that the clocks are right."),
        ("not in the trust store", "Rejected: the sender is not on Bob's trusted list. It could be an impostor."),
        ("signature", "Rejected: the digital signature does not match. The data was altered or forged."),
        ("addressed to someone else", "Rejected: this transfer was locked for a different receiver."),
        ("tampering", "Aborted: many packets failed their integrity check. Someone is injecting fake data."),
        ("verification code rejected", "Discarded: you said the codes did not match, so nothing was saved."),
        ("no new QR code", "Stopped: no QR code seen for a while. Hold the phone closer and steadier, then try again."),
        ("end of video", "Stopped: the video ended before every piece arrived, so nothing was saved."),
        ("stopped by user", "Stopped. Nothing was saved."),
        ("SHA-256", "Rejected: the reassembled file does not match its fingerprint."),
    ]
    for needle, message in table:
        if needle in text:
            return message
    return f"Stopped: {text}. Nothing was saved."


# --------------------------------------------------------------------- receive job

class _StoppableTransport(Transport):
    """Wraps the QR receiver: polls in short slices so the UI's Stop button works."""

    def __init__(self, inner: QrReceiver, job: "ReceiveJob") -> None:
        self.inner = inner
        self.job = job

    def send(self, data: bytes) -> None:
        self.inner.send(data)

    def receive(self, timeout: float | None = None) -> bytes:
        deadline = time.monotonic() + (timeout if timeout is not None else IDLE_TIMEOUT)
        while True:
            if self.job.stop_requested.is_set():
                raise TransportError("stopped by user")
            try:
                packet = self.inner.receive(timeout=0.4)
            except TransportTimeout:
                if time.monotonic() > deadline:
                    raise TransportTimeout(f"no new QR code within {timeout or IDLE_TIMEOUT:.0f}s") from None
                continue
            self.job.on_code()
            return packet

    def close(self) -> None:
        self.inner.close()


class ReceiveJob(threading.Thread):
    """One receive attempt, running in the background; the page polls its status."""

    def __init__(self, app: "AirLockApp", source: QrReceiver, source_label: str) -> None:
        super().__init__(daemon=True)
        self.app = app
        self.source = source
        self.source_label = source_label
        self.stop_requested = threading.Event()
        self.confirm_event = threading.Event()
        self.confirm_answer = False
        self.lock = threading.Lock()
        self.phase = "waiting"  # waiting -> checking -> receiving -> confirm -> saved | failed
        self.steps: list[dict[str, str]] = []
        self.received = 0
        self.total = 0
        self.codes_seen = 0
        self.sender = ""
        self.code = ""
        self.saved_as = ""
        self.error = ""
        self._add("info", f"Watching {source_label}. Waiting for the first QR code...")

    # -- status helpers
    def _add(self, kind: str, text: str) -> None:
        with self.lock:
            self.steps.append({"kind": kind, "text": text})

    def status(self) -> dict[str, object]:
        with self.lock:
            return {
                "phase": self.phase, "steps": list(self.steps), "received": self.received,
                "total": self.total, "codes_seen": self.codes_seen, "sender": self.sender,
                "code": self.code, "saved_as": self.saved_as, "error": self.error,
                "source": self.source_label,
            }

    def on_code(self) -> None:
        with self.lock:
            self.codes_seen += 1
            first = self.codes_seen == 1
        if first:
            self._add("info", "First QR code read. Looking for frame 0, the 'seal' that starts the transfer...")

    # -- protocol callbacks
    def _authenticated(self, peer: str) -> None:
        name = peer.capitalize()
        self.sender = name
        self._add("ok", f"Sender is {name}: this key is on Bob's trusted list.")
        self._add("ok", f"{name}'s digital signature is valid: nobody altered the seal.")
        self._add("ok", "Fresh: sent within the last 24 hours.")
        self._add("ok", "Not a replay: Bob has never received this transfer before.")
        self._add("ok", "Secret key computed. Only Bob's private key can do this, so only Bob can read the file.")
        with self.lock:
            self.phase = "receiving"

    def _progress(self, done: int, total: int) -> None:
        with self.lock:
            self.received, self.total = done, total

    def _confirm(self, peer: str, code: str) -> bool:
        self._add("ok", "Every piece decrypted and passed its integrity check (AES-GCM).")
        self._add("ok", "The whole file matches its signed fingerprint (SHA-256).")
        self._add("ask", "Last check, done by a person: compare this code with the one on the sender's screen.")
        with self.lock:
            self.code, self.phase = code, "confirm"
        while not self.confirm_event.wait(0.2):
            if self.stop_requested.is_set():
                return False
        return self.confirm_answer

    def run(self) -> None:
        transport = _StoppableTransport(self.source, self)
        bob = self.app.bob()
        try:
            report = receive_file_oneway(
                transport, bob.identity, bob.trust, self.app.received_dir,
                SessionStore.load(bob.home / "used_sessions.json"),
                timeout=IDLE_TIMEOUT, confirm_sas=self._confirm,
                on_authenticated=self._authenticated, on_progress=self._progress,
            )
            with self.lock:
                self.phase, self.saved_as = "saved", report.path.name
            self._add("ok", f"Saved as {report.path.name} ({report.size} bytes). "
                            "The file only appears now, complete and verified.")
        except (HandshakeError, TransferError, TransportError, IdentityError) as exc:
            message = friendly_error(exc)
            with self.lock:
                self.phase, self.error = "failed", message
            self._add("bad", message)
        finally:
            transport.close()

    def preview_jpeg(self) -> bytes | None:
        frame = self.source.last_frame
        if frame is None:
            return None
        ok, jpg = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
        return jpg.tobytes() if ok else None


# --------------------------------------------------------------------- application state

class AirLockApp:
    def __init__(self, base: Path, camera: int = 0) -> None:
        self.base = Path(base)
        self.camera = camera
        self.received_dir = self.base / "ui" / "received"
        self.work = self.base / "ui"
        self.lock = threading.Lock()
        self.job: ReceiveJob | None = None
        self.last_send: dict[str, object] | None = None
        self._packets: list[bytes] = []
        if not demo_users_exist(self.base):
            setup_demo_users(self.base, force=True)

    def alice(self):
        return load_demo_user(self.base, "alice")

    def bob(self):
        return load_demo_user(self.base, "bob")

    def overview(self) -> dict[str, object]:
        alice, bob = self.alice(), self.bob()
        return {
            "alice": alice.identity.fingerprint,
            "bob": bob.identity.fingerprint,
            "received_dir": str(self.received_dir),
            "received": sorted(p.name for p in self.received_dir.glob("*") if p.is_file())
            if self.received_dir.exists() else [],
        }

    def reset(self) -> None:
        """New demo users and an empty replay store: a clean slate before presenting."""
        self.stop_receive()
        setup_demo_users(self.base, force=True)
        shutil.rmtree(self.work, ignore_errors=True)
        self.last_send, self._packets = None, []

    # -- send
    def send(self, filename: str, data: bytes) -> dict[str, object]:
        alice = self.alice()
        name = sanitize_filename(filename)
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / name
            src.write_bytes(data)
            packets, result = build_oneway_transfer(alice.identity, alice.trust, "bob", src,
                                                    chunk_size=QR_CHUNK)
        frames = []
        for packet in packets:
            ok, png = cv2.imencode(".png", qr_image(packet, 540))
            frames.append("data:image/png;base64," + base64.b64encode(png.tobytes()).decode("ascii"))
        self._packets = packets
        for stale in ("transfer.mp4", "transfer.html", "transfer.gif"):
            (self.work / stale).unlink(missing_ok=True)
        self.last_send = {
            "filename": name, "size": len(data), "code": result.sas_text,
            "packets": len(packets), "chunks": len(packets) - 2, "frames": frames,
            "codes_per_second": DEFAULT_FPS / DEFAULT_HOLD,
        }
        return self.last_send

    def download(self, kind: str) -> Path:
        if not self._packets:
            raise TransferError("nothing prepared yet: send a file first")
        self.work.mkdir(parents=True, exist_ok=True)
        if kind == "gif":
            path = self.work / "transfer.gif"
            if not path.exists():
                render_gif(self._packets, path)
        elif kind == "mp4":
            path = self.work / "transfer.mp4"
            if not path.exists():
                render_video(self._packets, path)
        else:
            path = self.work / "transfer.html"
            if not path.exists():
                render_html(self._packets, path)
        return path

    # -- receive
    def start_receive(self, video: bytes | None = None) -> None:
        self.stop_receive()
        if video is not None:
            self.work.mkdir(parents=True, exist_ok=True)
            # Keep the real format: a GIF must be read frame by frame, without skipping.
            path = self.work / ("uploaded.gif" if video[:4] == b"GIF8" else "uploaded.mp4")
            path.write_bytes(video)
            source, label = QrReceiver.open_video(path, frame_step=2), "the uploaded video"
        else:
            source, label = QrReceiver.open_camera(self.camera, preview=False), f"camera {self.camera}"
        with self.lock:
            self.job = ReceiveJob(self, source, label)
            self.job.start()

    def stop_receive(self) -> None:
        with self.lock:
            job = self.job
        if job is not None and job.is_alive():
            job.stop_requested.set()
            job.join(5)

    def confirm(self, answer: bool) -> None:
        if self.job is not None:
            self.job.confirm_answer = answer
            self.job.confirm_event.set()

    # -- attacks
    def run_attacks(self) -> list[dict[str, object]]:
        from airlock.demos import eavesdrop, mitm_airlock, mitm_insecure, replay, tamper, truncate

        results = []
        for key, module in (("eavesdrop", eavesdrop), ("mitm_insecure", mitm_insecure),
                            ("mitm_airlock", mitm_airlock), ("replay", replay),
                            ("tamper", tamper), ("truncate", truncate)):
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                passed = module.run()
            results.append({"key": key, "passed": passed, "log": buffer.getvalue().strip()})
        return results


# --------------------------------------------------------------------- HTTP layer

def make_handler(app: AirLockApp, port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "AirLockUI"

        def log_message(self, fmt: str, *args: object) -> None:  # keep the terminal quiet
            pass

        # -- helpers
        def _send(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: object, code: int = 200) -> None:
            self._send(code, json.dumps(payload).encode(), "application/json")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts  # blocks DNS rebinding

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_UPLOAD:
                raise TransferError("file too large for the demo (16 MB max)")
            return self.rfile.read(length)

        # -- routes
        def do_GET(self) -> None:
            if not self._host_ok():
                return self._send(403, b"forbidden host", "text/plain")
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            if path == "/api/overview":
                return self._json(app.overview())
            if path == "/api/receive/status":
                job = app.job
                return self._json(job.status() if job else {"phase": "idle", "steps": []})
            if path == "/api/receive/frame.jpg":
                jpg = app.job.preview_jpeg() if app.job else None
                return self._send(200, jpg, "image/jpeg") if jpg else self._send(204, b"", "image/jpeg")
            if path in ("/api/download/mp4", "/api/download/html", "/api/download/gif"):
                try:
                    file = app.download(path.rsplit("/", 1)[-1])
                except TransferError as exc:
                    return self._json({"error": str(exc)}, 400)
                name = "airlock_transfer" + file.suffix
                ctype = {".mp4": "video/mp4", ".gif": "image/gif"}.get(file.suffix, "text/html")
                return self._send(200, file.read_bytes(), ctype,
                                  {"Content-Disposition": f'attachment; filename="{name}"'})
            return self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:
            if not self._host_ok() or self.headers.get("X-AirLock") != "1":
                return self._send(403, b"forbidden", "text/plain")  # CSRF / rebinding guard
            path = urlparse(self.path).path
            try:
                if path == "/api/send":
                    filename = unquote(self.headers.get("X-Filename", "file.bin"))
                    return self._json(app.send(filename, self._body()))
                if path == "/api/receive/camera":
                    app.start_receive()
                    return self._json({"ok": True})
                if path == "/api/receive/video":
                    app.start_receive(video=self._body())
                    return self._json({"ok": True})
                if path == "/api/receive/stop":
                    app.stop_receive()
                    return self._json({"ok": True})
                if path in ("/api/receive/yes", "/api/receive/no"):
                    app.confirm(path.endswith("yes"))
                    return self._json({"ok": True})
                if path == "/api/attacks":
                    return self._json(app.run_attacks())
                if path == "/api/reset":
                    app.reset()
                    return self._json({"ok": True})
            except (TransferError, TransportError, IdentityError, HandshakeError, OSError) as exc:
                return self._json({"error": friendly_error(exc)}, 400)
            return self._send(404, b"not found", "text/plain")

    return Handler


def create_server(base: Path, port: int = 8765, camera: int = 0) -> tuple[ThreadingHTTPServer, AirLockApp, str]:
    """Bind to 127.0.0.1 (port 0 = any free port) and return (server, app, url)."""
    app = AirLockApp(base, camera)
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, actual)
    return server, app, f"http://127.0.0.1:{actual}/"


def serve(base: Path, port: int = 8765, camera: int = 0, open_browser: bool = True) -> None:
    server, app, url = create_server(base, port, camera)
    print(f"AirLock UI running at {url}  (Ctrl-C to stop)", flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop_receive()
        server.server_close()
