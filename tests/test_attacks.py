"""Every attack demo must pass. The demos double as integration tests (threats T2-T4, T7, T10, T15, T17)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from airlock.demos import eavesdrop, mitm_airlock, mitm_insecure, replay, tamper, truncate
from airlock.demos.common import Demo


@pytest.mark.parametrize(
    "demo",
    [eavesdrop, mitm_insecure, mitm_airlock, replay, tamper, truncate],
    ids=lambda m: m.__name__.rsplit(".", 1)[-1],
)
def test_demo_passes(demo) -> None:
    assert demo.run(quiet=True) is True


def test_mitm_fails(capsys) -> None:
    """The MITM is stopped, and both verification codes are shown (and differ) in scenario E."""
    assert mitm_airlock.run() is True
    out = capsys.readouterr().out
    alice = out.split("Alice's screen shows  : ")[1][:9]
    bob = out.split("Bob's screen shows    : ")[1][:9]
    assert alice != bob


def test_demo_reports_fail_honestly() -> None:
    """A demo whose check fails must report FAIL, never PASS."""
    demo = Demo(0, "self-test", quiet=True)
    demo.check("this check fails", False)
    assert demo.finish("should not print") is False


def test_eavesdrop_on_a_real_video(tmp_path) -> None:
    """The eavesdropper analysis also works on frames decoded from a rendered MP4."""
    from airlock.core.session import build_oneway_transfer
    from airlock.demos.common import make_users
    from airlock.transports.qr import render_video

    users = make_users()
    src = tmp_path / "secret.txt"
    src.write_bytes(b"CONFIDENTIAL " * 30)
    packets, _ = build_oneway_transfer(users.alice, users.alice_trust, "bob", src, chunk_size=150)
    video = tmp_path / "out.mp4"
    render_video(packets, video, hold=4, loops=1, size=720)
    assert eavesdrop.run(quiet=True, video=video) is True


def test_run_all_cli() -> None:
    res = subprocess.run([sys.executable, "-m", "airlock.demos.all", "--summary"],
                         capture_output=True, text=True, timeout=120, check=False)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.count("[PASS]") == 6 and "6/6 demos passed" in res.stdout
