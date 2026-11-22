"""Demo 5: tampering. Mallory flips bits in packets on the channel.

    A. bits flipped and the CRC NOT fixed    -> treated as noise, dropped
    B. bits flipped and the CRC recomputed   -> AES-GCM tag fails, dropped
    C. header edited (seq), CRC recomputed   -> AES-GCM tag fails (the header is AAD)
    D. the honest copy arrives later          -> the file is still exactly right
    E. a flood of forged packets              -> the session aborts, nothing written

Threats: T4, T15. Run:
    python -m airlock.demos.tamper
"""

from __future__ import annotations

import os
import struct
import tempfile
import zlib
from pathlib import Path

from airlock.core.framing import HEADER_SIZE, Packet, PacketType, decode
from airlock.core.oneway import SessionStore, open_seal
from airlock.core.session import Reassembler, TransferError, build_oneway_transfer
from airlock.demos.common import SECRET_TEXT, Demo, make_users


def _flip(raw: bytes, offset: int, fix_crc: bool) -> bytes:
    out = bytearray(raw)
    out[offset] ^= 0x01
    if fix_crc:  # an attacker can always do this: CRC32 is not a security mechanism
        out[-4:] = struct.pack(">I", zlib.crc32(bytes(out[:-4])))
    return bytes(out)


def run(quiet: bool = False) -> bool:
    demo = Demo(5, "Tampering with packets in transit", quiet)
    u = make_users()
    secret = SECRET_TEXT * 20
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "answers.txt"
        src.write_bytes(secret)
        packets, _ = build_oneway_transfer(u.alice, u.alice_trust, "bob", src)
    seal, data_packets = packets[0], packets[1:]
    result = open_seal(u.bob, u.bob_trust, seal, SessionStore())
    reasm = Reassembler(result)

    demo.step(f"Mallory corrupts every one of the {len(data_packets)} packets before Bob sees them")
    noisy = [_flip(p, HEADER_SIZE + 5, fix_crc=False) for p in data_packets]
    for raw in noisy:
        reasm.feed(raw)
    demo.check(f"A. bit flips without a CRC fix are dropped as noise "
               f"({reasm.stats.crc_errors} CRC errors, 0 accepted)",
               reasm.stats.crc_errors == len(data_packets) and reasm.stats.accepted == 0)

    forged = [_flip(p, HEADER_SIZE + 5, fix_crc=True) for p in data_packets]
    for raw in forged:
        reasm.feed(raw)
    demo.check(f"B. ciphertext bit flips WITH a valid CRC fail authentication "
               f"({reasm.stats.aead_failures} AES-GCM tag failures, 0 accepted)",
               reasm.stats.aead_failures == len(forged) and reasm.stats.accepted == 0)

    target = decode(data_packets[3])
    moved = Packet(target.ptype, target.session_id, target.seq + 1, target.total,
                   target.payload).encode()  # Mallory tries to reorder content
    before = reasm.stats.aead_failures
    reasm.feed(moved)
    demo.check("C. moving a chunk to another seq number fails authentication "
               "(the header is associated data)", reasm.stats.aead_failures == before + 1)

    demo.step("D. the honest packets get through on the next loop of the video")
    for raw in data_packets:
        reasm.feed(raw)
    _, received = reasm.finalize()
    demo.check("the file is reassembled exactly; no tampered byte made it in", received == secret)

    demo.step("E. Mallory floods Bob with forged packets")
    flood = Reassembler(result)
    try:
        for seq in range(1, 1000):
            flood.feed(Packet(PacketType.DATA, result.session_id, seq, 1000, os.urandom(60)).encode())
        demo.check("the session aborts under a flood", False)
    except TransferError as exc:
        demo.note(f"Bob: {exc}")
        demo.check(f"the session aborts after {flood.stats.aead_failures} forgeries "
                   "instead of running forever", True)

    return demo.finish("every tampered packet was detected and dropped")


def main() -> int:
    return 0 if run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
