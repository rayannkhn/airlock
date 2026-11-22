"""End-to-end CLI test: two real processes, keygen, trust, send and receive over TCP."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PY = [sys.executable, "-m", "airlock"]


def _run(home: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*PY, "--home", str(home), *args],
        input=stdin, capture_output=True, text=True, timeout=60, check=False,
    )


def _setup(tmp_path: Path) -> tuple[Path, Path]:
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    for home in (alice, bob):
        res = _run(home, "keygen", "--no-passphrase")
        assert res.returncode == 0, res.stderr
        assert "Fingerprint" in res.stdout
    assert _run(alice, "trust", "add", "bob", str(bob / "identity.pub"), "--yes").returncode == 0
    assert _run(bob, "trust", "add", "alice", str(alice / "identity.pub"), "--yes").returncode == 0
    return alice, bob


def _start_receiver(bob: Path, out: Path, *extra: str) -> tuple[subprocess.Popen[str], int]:
    proc = subprocess.Popen(
        [*PY, "--home", str(bob), "receive", "--listen", "127.0.0.1:0", "--out", str(out),
         "--timeout", "20", *extra],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert proc.stdout is not None
    for line in proc.stdout:  # wait for the "Listening on host:port" line
        if line.startswith("Listening on"):
            return proc, int(line.split(":")[-1].split()[0])
    raise AssertionError(f"receiver did not start: {proc.stderr.read() if proc.stderr else ''}")


def test_cli_end_to_end(tmp_path: Path) -> None:
    alice, bob = _setup(tmp_path)
    src = tmp_path / "secret plan.txt"
    src.write_bytes(os.urandom(3000))
    out = tmp_path / "received"

    receiver, port = _start_receiver(bob, out)
    assert receiver.stdin is not None
    receiver.stdin.write("y\n")  # answers the "same code?" prompt
    receiver.stdin.flush()
    sender = _run(alice, "send", str(src), "--to", f"127.0.0.1:{port}")
    r_out, r_err = receiver.communicate(timeout=30)

    assert sender.returncode == 0, sender.stderr
    assert receiver.returncode == 0, r_err
    assert "SUCCESS" in sender.stdout and "SUCCESS" in r_out
    sas_sender = sender.stdout.split("Verification code  : ")[1][:9]
    assert f"Verification code  : {sas_sender}" in r_out  # both sides show the same code
    assert (out / "secret plan.txt").read_bytes() == src.read_bytes()


def test_cli_sas_refused_writes_nothing(tmp_path: Path) -> None:
    alice, bob = _setup(tmp_path)
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    out = tmp_path / "received"
    receiver, port = _start_receiver(bob, out)
    assert receiver.stdin is not None
    receiver.stdin.write("n\n")
    receiver.stdin.flush()
    sender = _run(alice, "send", str(src), "--to", f"127.0.0.1:{port}")
    _, r_err = receiver.communicate(timeout=30)
    assert receiver.returncode == 1 and "ABORTED" in r_err and "Nothing was written" in r_err
    assert sender.returncode == 1
    assert not out.exists() or not any(out.iterdir())


def test_cli_untrusted_sender_rejected(tmp_path: Path) -> None:
    _, bob = _setup(tmp_path)
    mallory = tmp_path / "mallory"
    assert _run(mallory, "keygen", "--no-passphrase").returncode == 0
    _run(mallory, "trust", "add", "bob", str(bob / "identity.pub"), "--yes")
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    receiver, port = _start_receiver(bob, tmp_path / "received", "--accept-sas")
    sender = _run(mallory, "send", str(src), "--to", f"127.0.0.1:{port}")
    _, r_err = receiver.communicate(timeout=30)
    assert receiver.returncode == 1 and "not in the trust store" in r_err
    assert sender.returncode == 1


def test_cli_passphrase_protected_key(tmp_path: Path) -> None:
    env = {**os.environ, "AIRLOCK_PASSPHRASE": "correct horse battery"}
    home = tmp_path / "carol"
    res = subprocess.run([*PY, "--home", str(home), "keygen"], env=env,
                         capture_output=True, text=True, timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    assert b"ENCRYPTED" in (home / "identity.key").read_bytes()
    verify = _run(home, "verify")
    assert verify.returncode == 0 and "Fingerprint" in verify.stdout


def test_cli_demo_oneway_qr_flow(tmp_path: Path) -> None:
    """The exact demo: demo-setup, send --render, receive --video, then replay is rejected."""
    home = tmp_path / "home"
    setup = _run(home, "demo-setup")
    assert setup.returncode == 0 and "alice trusts bob" in setup.stdout, setup.stderr

    src = tmp_path / "notes.txt"
    src.write_bytes(os.urandom(900))
    video = tmp_path / "out.mp4"
    send = _run(home, "send", str(src), "--render", str(video), "--loops", "2", "--hold", "4")
    assert send.returncode == 0, send.stderr
    assert "acting as 'alice'" in send.stdout and "Self-check" in send.stdout
    sas = send.stdout.split("Verification code: ")[1][:9]

    out = tmp_path / "received"
    recv = _run(home, "receive", "--video", str(video), "--out", str(out), stdin="y\n")
    assert recv.returncode == 0, recv.stderr
    assert "acting as 'bob'" in recv.stdout and sas in recv.stdout and "SUCCESS" in recv.stdout
    assert (out / "notes.txt").read_bytes() == src.read_bytes()

    replay = _run(home, "receive", "--video", str(video), "--out", str(out), stdin="y\n")
    assert replay.returncode == 1 and "replay" in replay.stderr
    assert sorted(p.name for p in out.iterdir()) == ["notes.txt"]


def test_cli_demo_setup_refuses_overwrite(tmp_path: Path) -> None:
    home = tmp_path / "home"
    assert _run(home, "demo-setup").returncode == 0
    again = _run(home, "demo-setup")
    assert again.returncode == 1 and "--force" in again.stderr
    assert _run(home, "demo-setup", "--force").returncode == 0


def test_cli_send_needs_a_mode(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _run(home, "demo-setup")
    src = tmp_path / "f.txt"
    src.write_bytes(b"x")
    res = _run(home, "send", str(src))
    assert res.returncode == 2 and "--render" in res.stderr


def test_cli_render_gif(tmp_path: Path) -> None:
    home = tmp_path / "home"
    _run(home, "demo-setup")
    src = tmp_path / "notes.txt"
    src.write_bytes(os.urandom(700))
    gif = tmp_path / "out.gif"
    send = _run(home, "send", str(src), "--render", str(gif))
    assert send.returncode == 0, send.stderr
    assert "readable from the GIF" in send.stdout and gif.read_bytes()[:4] == b"GIF8"
    recv = _run(home, "receive", "--video", str(gif), "--out", str(tmp_path / "r"), stdin="y\n")
    assert recv.returncode == 0, recv.stderr
    assert (tmp_path / "r" / "notes.txt").read_bytes() == src.read_bytes()
