"""Demo 1: an eavesdropper films every QR frame and records the TCP traffic.

Threats covered: T10 (passive disclosure). Run:
    python -m airlock.demos.eavesdrop
    python -m airlock.demos.eavesdrop --video out.mp4   # analyse frames filmed from a real video
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from airlock.core.crypto import DecryptError, PacketOpener, derive_session_keys, transcript_hash
from airlock.core.framing import FramingError, PacketType, decode
from airlock.core.identity import Identity, IdentityError
from airlock.core.session import build_oneway_transfer, build_transfer_packets
from airlock.demos.common import (
    SECRET_TEXT,
    Demo,
    make_users,
    run_interactive_handshake,
    shannon_entropy,
)


def _captured_from_video(path: Path) -> list[bytes]:
    from airlock.transports.base import TransportClosed
    from airlock.transports.qr import QrReceiver

    frames: list[bytes] = []
    with QrReceiver.open_video(path, frame_step=2) as rx:
        try:
            while True:
                packet = rx.receive(timeout=30)
                if packet not in frames:
                    frames.append(packet)
        except TransportClosed:
            pass
    return frames


def run(quiet: bool = False, video: Path | None = None) -> bool:
    demo = Demo(1, "Eavesdropper records everything", quiet)
    users = make_users()
    secret = SECRET_TEXT * 40  # about 4.5 KB of very guessable text

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "exam_answers.txt"
        src.write_bytes(secret)
        packets, _ = build_oneway_transfer(users.alice, users.alice_trust, "bob", src)

    if video is not None:
        demo.step(f"Eve films the phone screen: decoding every QR frame in {video}")
        captured = _captured_from_video(video)
        demo.note(f"captured {len(captured)} distinct packets from the video")
    else:
        demo.step("Eve films the phone screen and decodes every QR frame of a transfer")
        captured = list(packets)
        demo.note(f"captured {len(captured)} packets ({sum(map(len, captured))} bytes)")

    wire = b"".join(captured)
    sample = decode(captured[-1]).payload[:24].hex(" ")
    demo.note(f"what a data frame looks like to Eve: {sample} ...")

    if video is None:
        demo.check("the plaintext does not appear anywhere in the captured frames",
                   b"CONFIDENTIAL" not in wire and b"PK-1234" not in wire)
        demo.check("the filename is hidden too (it is inside the encrypted manifest)",
                   b"exam_answers" not in wire)
        payload = b"".join(decode(p).payload for p in captured if decode(p).ptype is PacketType.DATA)
        h_cipher, h_plain = shannon_entropy(payload), shannon_entropy(secret)
        demo.note(f"entropy: plaintext {h_plain:.2f} bits/byte, ciphertext {h_cipher:.2f} bits/byte")
        demo.check("the ciphertext is statistically indistinguishable from random (> 7.9 bits/byte)",
                   h_cipher > 7.9)
    else:
        demo.check("no frame contains readable text",
                   all(b"CONFIDENTIAL" not in p for p in captured))

    # Eve has everything that is public: both contact cards and every frame.
    # Her best try is to run the key agreement with a key she controls.
    demo.step("Eve tries to derive the session key using only public information")
    seal = next(p for p in captured if decode(p).ptype is PacketType.SEAL)
    seal_pkt = decode(seal)
    eve = Identity.generate()
    try:
        shared = eve.receive_exchange(seal_pkt.payload[40:72])
        keys = derive_session_keys(shared, seal_pkt.session_id, transcript_hash(seal))
        manifest = next(p for p in captured if decode(p).ptype is PacketType.MANIFEST)
        PacketOpener(keys.k_ir, keys.iv_ir, seal_pkt.session_id).open(decode(manifest))
        broke_it = True
    except (DecryptError, IdentityError, FramingError, StopIteration):
        broke_it = False
    demo.check("decrypting with any key other than Bob's receiving key fails "
               "(AES-GCM tag mismatch)", not broke_it)

    demo.step("Eve also records an interactive (TCP) session: handshake and data")
    i_res, r_res, transcript = run_interactive_handshake(users)
    data_packets = build_transfer_packets(i_res, users.alice, "exam_answers.txt", secret)
    recorded = b"".join(transcript) + b"".join(data_packets)
    demo.check("the interactive session leaks no plaintext either", b"CONFIDENTIAL" not in recorded)
    demo.note("the handshake carries only public keys and signatures; the session key "
              "comes from two ephemeral secrets Eve never sees")
    demo.check("Alice and Bob derived the same key, which never crossed the channel",
               i_res.keys.k_ir == r_res.keys.k_ir and i_res.keys.k_ir not in recorded)

    return demo.finish("captured traffic is unreadable ciphertext")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--video", type=Path, help="analyse a rendered AirLock video instead")
    args = parser.parse_args()
    return 0 if run(video=args.video) else 1


if __name__ == "__main__":
    raise SystemExit(main())
