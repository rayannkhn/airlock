"""Tests for the demo UI: its local-only protections and a full send -> receive -> replay flow."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from airlock.transports.qr import render_video
from airlock.ui.server import create_server, friendly_error


@pytest.fixture
def ui(tmp_path: Path):
    server, app, url = create_server(tmp_path / "home", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield url, app, tmp_path
    app.stop_receive()
    server.shutdown()
    server.server_close()


def _req(url: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None,
         method: str | None = None):
    req = urllib.request.Request(url.rstrip("/") + path, data=body, headers=headers or {},
                                 method=method or ("POST" if body is not None else "GET"))
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if resp.headers.get_content_type() == "application/json" else raw)


H = {"X-AirLock": "1"}


def test_page_and_overview(ui) -> None:
    url, _, _ = ui
    status, page = _req(url, "/")
    assert status == 200 and b"AirLock" in page
    status, info = _req(url, "/api/overview")
    assert len(info["alice"].split()) == 10 and info["alice"] != info["bob"]


def test_post_without_header_is_refused(ui) -> None:
    """CSRF guard: a cross-site form post cannot add the custom header."""
    url, _, _ = ui
    with pytest.raises(urllib.error.HTTPError) as err:
        _req(url, "/api/reset", body=b"")
    assert err.value.code == 403


def test_foreign_host_header_is_refused(ui) -> None:
    """DNS-rebinding guard: requests naming another host are refused."""
    url, _, _ = ui
    with pytest.raises(urllib.error.HTTPError) as err:
        _req(url, "/api/overview", headers={"Host": "evil.example:80"})
    assert err.value.code == 403


def _wait(url: str, phases: set[str], seconds: float = 90) -> dict:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        _, status = _req(url, "/api/receive/status")
        if status["phase"] in phases:
            return status
        time.sleep(0.2)
    raise AssertionError(f"timed out; last status {status}")


def test_full_flow_send_receive_replay(ui) -> None:
    url, app, tmp = ui
    status, sent = _req(url, "/api/send", body=b"hello from alice " * 40,
                        headers={**H, "X-Filename": "notes.txt"})
    assert status == 200 and len(sent["code"]) == 9 and len(sent["frames"]) == sent["packets"]

    # Stand in for the phone: render the prepared packets to a short video, then upload it.
    video = tmp / "phone.mp4"
    render_video(app._packets, video, hold=4, loops=2, size=720)
    _req(url, "/api/receive/video", body=video.read_bytes(), headers=H)
    waiting = _wait(url, {"confirm", "failed"})
    assert waiting["phase"] == "confirm" and waiting["code"] == sent["code"]
    assert any("trusted list" in s["text"] for s in waiting["steps"])
    _req(url, "/api/receive/yes", body=b"", headers=H)
    done = _wait(url, {"saved", "failed"})
    assert done["phase"] == "saved"
    assert (app.received_dir / "notes.txt").read_bytes() == b"hello from alice " * 40

    # Playing the same recording again is a replay.
    _req(url, "/api/receive/video", body=video.read_bytes(), headers=H)
    again = _wait(url, {"failed", "confirm", "saved"})
    assert again["phase"] == "failed" and "already received" in again["error"]


def test_answering_no_saves_nothing(ui) -> None:
    url, app, tmp = ui
    _req(url, "/api/send", body=b"secret", headers={**H, "X-Filename": "s.txt"})
    video = tmp / "phone.mp4"
    render_video(app._packets, video, hold=4, loops=2, size=720)
    _req(url, "/api/receive/video", body=video.read_bytes(), headers=H)
    _wait(url, {"confirm"})
    _req(url, "/api/receive/no", body=b"", headers=H)
    done = _wait(url, {"saved", "failed"})
    assert done["phase"] == "failed" and not app.received_dir.exists()


def test_attacks_endpoint(ui) -> None:
    url, _, _ = ui
    _, results = _req(url, "/api/attacks", body=b"", headers=H)
    assert len(results) == 6 and all(r["passed"] for r in results)


def test_download_video(ui) -> None:
    url, _, _ = ui
    _req(url, "/api/send", body=b"x" * 300, headers={**H, "X-Filename": "x.bin"})
    status, data = _req(url, "/api/download/html")
    assert status == 200 and b"data:image/png;base64," in data


def test_friendly_errors_are_plain_language() -> None:
    assert "replaying" in friendly_error(Exception("this session was already received (replay)"))
    assert "impostor" in friendly_error(Exception("sender identity is not in the trust store"))


def test_gif_download_then_receive_it(ui) -> None:
    """What a user does with a phone: download the GIF, and later receive from it."""
    url, app, _ = ui
    _req(url, "/api/send", body=b"phone friendly " * 50, headers={**H, "X-Filename": "p.txt"})
    status, gif = _req(url, "/api/download/gif")
    assert status == 200 and gif[:4] == b"GIF8"
    _req(url, "/api/receive/video", body=gif, headers=H)
    _wait(url, {"confirm"})
    _req(url, "/api/receive/yes", body=b"", headers=H)
    assert _wait(url, {"saved", "failed"})["phase"] == "saved"
    assert (app.received_dir / "p.txt").read_bytes() == b"phone friendly " * 50
