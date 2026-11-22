"""Transport tests and full sessions over loopback and real TCP sockets."""

from __future__ import annotations

import os
import struct
import threading
from pathlib import Path

import pytest

from airlock.core.handshake import HandshakeError
from airlock.core.identity import Identity, TrustStore
from airlock.core.session import TransferError, receive_file, send_file
from airlock.transports.base import TransportClosed, TransportError, TransportTimeout
from airlock.transports.loopback import make_loopback_pair
from airlock.transports.tcp import MAX_FRAME, TcpTransport, parse_endpoint


def test_loopback_pair() -> None:
    a, b = make_loopback_pair()
    a.send(b"ping")
    assert b.receive(1) == b"ping"
    b.send(b"pong")
    assert a.receive(1) == b"pong"
    with pytest.raises(TransportTimeout):
        a.receive(0.05)
    b.close()
    with pytest.raises(TransportClosed):
        a.receive(1)


def _tcp_pair() -> tuple[TcpTransport, TcpTransport]:
    ready = threading.Event()
    port: list[int] = []
    server: list[TcpTransport] = []

    def serve() -> None:
        def on_listening(_h: str, p: int) -> None:
            port.append(p)
            ready.set()

        server.append(TcpTransport.listen("127.0.0.1", 0, accept_timeout=5, on_listening=on_listening))

    thread = threading.Thread(target=serve)
    thread.start()
    assert ready.wait(5)
    client = TcpTransport.connect("127.0.0.1", port[0])
    thread.join(5)
    return client, server[0]


def test_tcp_roundtrip_and_framing() -> None:
    client, server = _tcp_pair()
    with client, server:
        for size in (0, 1, 1000, MAX_FRAME):
            payload = os.urandom(size)
            client.send(payload)
            assert server.receive(5) == payload
        with pytest.raises(TransportTimeout):
            server.receive(0.05)
        client.send(b"after timeout")  # stream must not be desynced by the timeout
        assert server.receive(5) == b"after timeout"


def test_tcp_rejects_oversized_frame() -> None:
    client, server = _tcp_pair()
    with client, server:
        with pytest.raises(TransportError):
            client.send(b"x" * (MAX_FRAME + 1))
        # A hostile peer announcing a 1 GiB frame is refused before allocation.
        client._sock.sendall(struct.pack(">I", 1 << 30))
        with pytest.raises(TransportError, match="refusing"):
            server.receive(5)


def test_tcp_peer_close_detected() -> None:
    client, server = _tcp_pair()
    client.close()
    with pytest.raises(TransportClosed):
        server.receive(5)
    server.close()


@pytest.mark.parametrize(
    ("text", "expected"),
    [("127.0.0.1:9000", ("127.0.0.1", 9000)), (":9001", ("127.0.0.1", 9001)),
     ("9002", ("127.0.0.1", 9002)), ("[::1]:9003", ("::1", 9003))],
)
def test_parse_endpoint(text: str, expected: tuple[str, int]) -> None:
    assert parse_endpoint(text) == expected


def test_parse_endpoint_invalid() -> None:
    with pytest.raises(ValueError):
        parse_endpoint("host:notaport")


def _identities() -> tuple[Identity, TrustStore, Identity, TrustStore]:
    alice, bob = Identity.generate(), Identity.generate()
    return alice, TrustStore({"bob": bob.public_key}), bob, TrustStore({"alice": alice.public_key})


def _run_pair(sender_t, receiver_t, src: Path, out: Path, **receive_kwargs):
    alice, a_trust, bob, b_trust = _identities()
    outcome: dict[str, object] = {}

    def receiver() -> None:
        try:
            outcome["recv"] = receive_file(receiver_t, bob, b_trust, out, timeout=10, **receive_kwargs)
        except Exception as exc:  # noqa: BLE001 - reported to the main thread
            outcome["recv_error"] = exc
            receiver_t.close()

    thread = threading.Thread(target=receiver)
    thread.start()
    try:
        outcome["send"] = send_file(sender_t, alice, a_trust, src, timeout=10, receipt_timeout=10)
    except Exception as exc:  # noqa: BLE001
        outcome["send_error"] = exc
    thread.join(15)
    return outcome


@pytest.mark.parametrize("kind", ["loopback", "tcp"])
def test_full_session(kind: str, tmp_path: Path) -> None:
    src = tmp_path / "photo.jpg"
    src.write_bytes(os.urandom(20_000))
    sender_t, receiver_t = make_loopback_pair() if kind == "loopback" else _tcp_pair()
    outcome = _run_pair(sender_t, receiver_t, src, tmp_path / "out")
    sender_t.close()
    receiver_t.close()
    assert "send_error" not in outcome and "recv_error" not in outcome, outcome
    written = tmp_path / "out" / "photo.jpg"
    assert written.read_bytes() == src.read_bytes()
    assert outcome["send"].receipt_verified  # type: ignore[union-attr]


def test_full_session_sas_rejected_writes_nothing(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_bytes(b"confidential")
    sender_t, receiver_t = make_loopback_pair()
    outcome = _run_pair(
        sender_t, receiver_t, src, tmp_path / "out", confirm_sas=lambda _p, _s: False
    )
    assert isinstance(outcome.get("recv_error"), TransferError)
    assert isinstance(outcome.get("send_error"), TransportError)  # no receipt arrives
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())


def test_untrusted_sender_over_tcp(tmp_path: Path) -> None:
    """An unknown identity is refused by a receiver on a real socket."""
    src = tmp_path / "x.bin"
    src.write_bytes(b"x")
    client, server = _tcp_pair()
    mallory = Identity.generate()
    bob = Identity.generate()
    errors: list[Exception] = []

    def receiver() -> None:
        try:
            receive_file(server, bob, TrustStore({"alice": Identity.generate().public_key}),
                         tmp_path / "out", timeout=5)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            server.close()

    thread = threading.Thread(target=receiver)
    thread.start()
    with pytest.raises((TransportError, HandshakeError)):
        send_file(client, mallory, TrustStore({"bob": bob.public_key}), src, timeout=5)
    thread.join(10)
    client.close()
    assert isinstance(errors[0], HandshakeError)
    assert not (tmp_path / "out").exists()

