"""Demo 4: replay attacks. Old recordings are played back and rejected.

    A. one-way: the same QR recording is played twice     -> second time rejected
    B. one-way: a recording older than the window         -> rejected as too old
    C. one-way: Mallory edits the old timestamp to "now"  -> signature breaks
    D. interactive: old data packets injected into a new session -> all dropped
    E. interactive: old handshake messages replayed       -> rejected

Threat: T7. Run:
    python -m airlock.demos.replay
"""

from __future__ import annotations

import struct
import tempfile
import time
from pathlib import Path

from airlock.core.framing import Packet, PacketType, decode
from airlock.core.handshake import HandshakeError, Responder
from airlock.core.oneway import DEFAULT_MAX_AGE, SessionStore, create_seal, open_seal
from airlock.core.session import (
    Reassembler,
    build_oneway_transfer,
    build_transfer_packets,
    receive_file_oneway,
)
from airlock.demos.common import SECRET_TEXT, Demo, make_users, run_interactive_handshake
from airlock.transports.loopback import make_loopback_pair


def _play(packets: list[bytes]):
    tx, rx = make_loopback_pair()
    for p in packets:
        tx.send(p)
    tx.close()
    return rx


def run(quiet: bool = False) -> bool:
    demo = Demo(4, "Replay attacks", quiet)
    u = make_users()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        src = tmp_path / "payment.txt"
        src.write_bytes(SECRET_TEXT)
        store = SessionStore(tmp_path / "used_sessions.json")  # Bob's persistent store
        out = tmp_path / "received"

        demo.step("A. Bob receives a QR transfer; Mallory recorded it and plays it again later")
        recording, _ = build_oneway_transfer(u.alice, u.alice_trust, "bob", src)
        receive_file_oneway(_play(recording), u.bob, u.bob_trust, out, store, timeout=5)
        demo.note("first playback: accepted, payment.txt written")
        try:
            receive_file_oneway(_play(recording), u.bob, u.bob_trust, out,
                                SessionStore.load(tmp_path / "used_sessions.json"), timeout=5)
            rejected = False
        except HandshakeError as exc:
            demo.note(f"second playback: {exc}")
            rejected = True
        demo.check("the replayed recording is rejected, even after reloading the store from disk",
                   rejected)
        demo.check("still only ONE copy of the file on disk",
                   [p.name for p in out.iterdir()] == ["payment.txt"])

    demo.step("B. Mallory replays a recording made 25 hours ago (never received by Bob)")
    old_seal, _ = create_seal(u.alice, u.alice_trust, "bob",
                              now=time.time() - DEFAULT_MAX_AGE - 3600)
    try:
        open_seal(u.bob, u.bob_trust, old_seal, SessionStore())
        demo.check("the stale recording is rejected", False)
    except HandshakeError as exc:
        demo.note(f"Bob: {exc}")
        demo.check("the stale recording is rejected by the signed timestamp window", True)

    demo.step("C. Mallory rewrites that old timestamp to 'now' to get past the window")
    pkt = decode(old_seal)
    payload = struct.pack(">Q", int(time.time())) + pkt.payload[8:]
    try:
        open_seal(u.bob, u.bob_trust,
                  Packet(PacketType.SEAL, pkt.session_id, 0, 0, payload).encode(), SessionStore())
        demo.check("the edited timestamp is detected", False)
    except HandshakeError as exc:
        demo.note(f"Bob: {exc}")
        demo.check("the edited timestamp is detected (the timestamp is signed)", True)

    demo.step("D. Interactive: Mallory injects every packet of an OLD session into a NEW one")
    old_i, _, old_handshake = run_interactive_handshake(u)
    old_packets = build_transfer_packets(old_i, u.alice, "old.txt", SECRET_TEXT * 20)
    _, new_r, _ = run_interactive_handshake(u)
    reasm = Reassembler(new_r)
    accepted = sum(reasm.feed(raw) for raw in old_packets)
    demo.note(f"{len(old_packets)} old packets injected, {accepted} accepted, "
              f"{reasm.stats.rejected} rejected (wrong session id)")
    demo.check("none of the old packets is accepted", accepted == 0)

    demo.step("E. Interactive: Mallory replays the old HELLO and FINISH to Bob")
    m1, _, m3 = old_handshake
    fresh = Responder(u.bob, u.bob_trust)
    fresh.on_hello(m1)  # Bob answers with a NEW ephemeral key
    try:
        fresh.on_finish(m3)
        demo.check("the old FINISH is rejected", False)
    except HandshakeError as exc:
        demo.note(f"Bob: {exc}")
        demo.check("the old FINISH is rejected (it signs Bob's OLD ephemeral key, not the new one)",
                   True)

    return demo.finish("every replay was rejected")


def main() -> int:
    return 0 if run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
