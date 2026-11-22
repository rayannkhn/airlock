"""Demo 6: truncation. The transfer is cut off, and no partial file ever appears.

    A. one-way: the video stops at 50%                  -> abort, output folder empty
    B. one-way: everything except the last chunk        -> abort, nothing written
    C. interactive: the sender disconnects mid-transfer -> abort, nothing written
    D. after A, the full video plays                    -> accepted (a failed try is not "used")

Threat: T17. Run:
    python -m airlock.demos.truncate
"""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from airlock.core.session import (
    build_oneway_transfer,
    build_transfer_packets,
    receive_file,
    receive_file_oneway,
)
from airlock.core.handshake import Initiator
from airlock.core.oneway import SessionStore
from airlock.demos.common import SECRET_TEXT, Demo, make_users
from airlock.transports.base import TransportError
from airlock.transports.loopback import make_loopback_pair


def _play(packets: list[bytes]):
    tx, rx = make_loopback_pair()
    for p in packets:
        tx.send(p)
    tx.close()  # the video ends here
    return rx


def _leftovers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


def run(quiet: bool = False) -> bool:
    demo = Demo(6, "Truncation: the transfer is cut off", quiet)
    u = make_users()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        src = tmp_path / "answers.txt"
        src.write_bytes(SECRET_TEXT * 20)
        out = tmp_path / "received"
        store = SessionStore(tmp_path / "used_sessions.json")
        packets, _ = build_oneway_transfer(u.alice, u.alice_trust, "bob", src)

        demo.step(f"A. the phone video stops after {len(packets) // 2} of {len(packets)} packets")
        try:
            receive_file_oneway(_play(packets[: len(packets) // 2]), u.bob, u.bob_trust, out,
                                store, timeout=5)
        except TransportError as exc:
            demo.note(f"Bob: ABORTED, the video ended before every packet arrived ({exc})")
        demo.check("nothing written, not even a temporary file", _leftovers(out) == [])

        demo.step("B. everything arrives except the very last chunk")
        try:
            receive_file_oneway(_play(packets[:-1]), u.bob, u.bob_trust, out, store, timeout=5)
        except TransportError as exc:
            demo.note(f"Bob: ABORTED ({exc})")
        demo.check("nothing written: 99% of a file is still no file", _leftovers(out) == [])

        demo.step("C. interactive: Alice's connection drops halfway through the data")
        a_end, b_end = make_loopback_pair()
        errors: list[Exception] = []

        def bob_side() -> None:
            try:
                receive_file(b_end, u.bob, u.bob_trust, out, timeout=5)
            except Exception as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        thread = threading.Thread(target=bob_side)
        thread.start()
        initiator = Initiator(u.alice, u.alice_trust)
        a_end.send(initiator.start())
        a_end.send(initiator.on_reply(a_end.receive(5)))
        assert initiator.result is not None
        data = build_transfer_packets(initiator.result, u.alice, "answers.txt", SECRET_TEXT * 20)
        for raw in data[: len(data) // 2]:
            a_end.send(raw)
        a_end.close()  # connection lost
        thread.join(10)
        if errors:
            demo.note(f"Bob: ABORTED ({errors[0]})")
        demo.check("Bob aborts and writes nothing",
                   len(errors) == 1 and _leftovers(out) == [])

        demo.step("D. the full video is played again after the failed attempts")
        report = receive_file_oneway(_play(packets), u.bob, u.bob_trust, out, store, timeout=5)
        demo.check("the complete transfer is accepted and matches the original exactly",
                   report.path.read_bytes() == src.read_bytes())
        demo.check("the output folder holds exactly one finished file, with no leftovers",
                   _leftovers(out) == ["answers.txt"])

    return demo.finish("no partial file was ever written")


def main() -> int:
    return 0 if run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
