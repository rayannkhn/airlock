"""Demo 3: the same man-in-the-middle against AirLock. The attack FAILS, at several layers.

    A. Mallory swaps in her own ephemeral key            -> bad signature
    B. Mallory uses her own identity                     -> not in the trust store
    C. one-way mode: Mallory alters Alice's SEAL         -> bad signature
    D. "what if the handshake signature check had a bug?" -> the signed manifest still catches it
    E. "what if ALL signature checks were disabled?"     -> the verification codes differ, and the user aborts

Threats: T1, T2, T3. Run:
    python -m airlock.demos.mitm_airlock
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from airlock.core.framing import Packet, PacketType, decode
from airlock.core.handshake import HandshakeError, Initiator, Responder
from airlock.core.identity import Identity, TrustStore
from airlock.core.oneway import SessionStore, create_seal, open_seal
from airlock.core.session import (
    Reassembler,
    TransferError,
    build_transfer_packets,
    write_file_atomic,
)
from airlock.demos.common import SECRET_TEXT, Demo, Users, make_users


class Impersonator:
    """Mallory claiming someone else's public key. She cannot make their signatures."""

    def __init__(self, victim_public_key: bytes) -> None:
        self.public_key = victim_public_key

    def sign(self, message: bytes) -> bytes:
        return b"\x00" * 64  # the best Mallory can do without the private key


def _new_ephemeral() -> bytes:
    return X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _scenario_key_swap(demo: Demo, u: Users) -> None:
    demo.step("A. Mallory replaces Bob's ephemeral key in M2 with her own")
    alice = Initiator(u.alice, u.alice_trust)
    m2 = decode(Responder(u.bob, u.bob_trust).on_hello(alice.start()))
    forged = Packet(m2.ptype, m2.session_id, 0, 0, _new_ephemeral() + m2.payload[32:]).encode()
    try:
        alice.on_reply(forged)
        demo.check("Alice rejects the swapped key", False)
    except HandshakeError as exc:
        demo.note(f"Alice: {exc}")
        demo.check("Alice rejects the swapped key (Bob's signature no longer matches)", True)


def _scenario_own_identity(demo: Demo, u: Users) -> None:
    demo.step("B. Mallory answers Alice with her own identity and a valid signature")
    mallory = Identity.generate()
    alice = Initiator(u.alice, u.alice_trust)
    m2 = Responder(mallory, TrustStore({"alice": u.alice.public_key})).on_hello(alice.start())
    try:
        alice.on_reply(m2)
        demo.check("Alice rejects Mallory's identity", False)
    except HandshakeError as exc:
        demo.note(f"Alice: {exc}")
        demo.check("Alice rejects Mallory's identity (not pinned)", True)


def _scenario_oneway(demo: Demo, u: Users) -> None:
    demo.step("C. One-way mode: Mallory swaps the ephemeral key inside Alice's SEAL frame")
    seal, _ = create_seal(u.alice, u.alice_trust, "bob")
    pkt = decode(seal)
    payload = pkt.payload[:40] + _new_ephemeral() + pkt.payload[72:]
    forged = Packet(PacketType.SEAL, pkt.session_id, 0, 0, payload).encode()
    try:
        open_seal(u.bob, u.bob_trust, forged, SessionStore())
        demo.check("Bob rejects the altered SEAL", False)
    except HandshakeError as exc:
        demo.note(f"Bob: {exc}")
        demo.check("Bob rejects the altered SEAL (Alice's signature covers e_S)", True)


def _relay_with_bug(u: Users):
    """Mallory runs two separate handshakes, impersonating each side to the other.

    Only works because signature checks are patched out by the caller.
    Returns (alice_result, mallory_facing_alice, mallory_facing_bob, bob_result).
    """
    alice = Initiator(u.alice, u.alice_trust)
    m_resp = Responder(Impersonator(u.bob.public_key), TrustStore({"alice": u.alice.public_key}))  # type: ignore[arg-type]
    m1 = alice.start()
    m3_from_alice = alice.on_reply(m_resp.on_hello(m1))
    m_resp_result = m_resp.on_finish(m3_from_alice)

    m_init = Initiator(Impersonator(u.alice.public_key), TrustStore({"bob": u.bob.public_key}),  # type: ignore[arg-type]
                       session_id=alice.session_id)
    bob = Responder(u.bob, u.bob_trust)
    bob_result = bob.on_finish(m_init.on_reply(bob.on_hello(m_init.start())))
    assert alice.result is not None and m_init.result is not None
    return alice.result, m_resp_result, m_init.result, bob_result


def _scenario_handshake_bug(demo: Demo, u: Users) -> None:
    demo.step("D. Simulated bug: the HANDSHAKE signature check is disabled; Mallory relays")
    with mock.patch("airlock.core.handshake._check_signature", lambda *a, **k: None):
        a_res, m_a, m_b, b_res = _relay_with_bug(u)
    demo.note("both handshakes complete. Mallory decrypts Alice's file and re-encrypts it for Bob")
    stolen = Reassembler(m_a)
    for raw in build_transfer_packets(a_res, u.alice, "answers.txt", SECRET_TEXT):
        stolen.feed(raw)
    _, plaintext = stolen.finalize()
    forged = build_transfer_packets(m_b, Impersonator(u.alice.public_key), "answers.txt",  # type: ignore[arg-type]
                                    plaintext.replace(b"100", b"999"))
    try:
        reasm = Reassembler(b_res)
        for raw in forged:
            reasm.feed(raw)
        demo.check("Bob rejects the relayed file", False)
    except TransferError as exc:
        demo.note(f"Bob: {exc}")
        demo.check("defense in depth: Bob rejects it (Mallory cannot sign the manifest as Alice)",
                   True)


def _scenario_all_signatures_off(demo: Demo, u: Users) -> None:
    demo.step("E. Worst case: EVERY signature check is disabled. Only the verification code is left")
    with mock.patch("airlock.core.handshake._check_signature", lambda *a, **k: None), \
         mock.patch("airlock.core.session.verify_signature", lambda *a, **k: None):
        a_res, m_a, m_b, b_res = _relay_with_bug(u)
        stolen = Reassembler(m_a)
        for raw in build_transfer_packets(a_res, u.alice, "answers.txt", SECRET_TEXT):
            stolen.feed(raw)
        _, plaintext = stolen.finalize()
        reasm = Reassembler(b_res)
        for raw in build_transfer_packets(m_b, Impersonator(u.alice.public_key), "answers.txt",  # type: ignore[arg-type]
                                          plaintext.replace(b"100", b"999")):
            reasm.feed(raw)
        manifest, data = reasm.finalize()
    demo.note(f"Alice's screen shows  : {a_res.sas_text}")
    demo.note(f"Bob's screen shows    : {b_res.sas_text}")
    demo.check("the two verification codes DIFFER (each side shares keys with Mallory, not each other)",
               a_res.sas != b_res.sas)
    demo.note("the commitment in M1 stops Mallory from grinding keys until the codes collide")

    def user_compares(_peer: str, code: str) -> bool:
        return code == a_res.sas_text  # Bob reads Alice's code off her screen

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        written = False
        if user_compares("alice", b_res.sas_text):
            write_file_atomic(out, manifest.filename, data)
            written = True
        demo.check("Bob answers 'no' at the code prompt, so the forged file is never written",
                   not written and not out.exists())


def run(quiet: bool = False) -> bool:
    demo = Demo(3, "MITM vs AirLock (expected: attack FAILS)", quiet)
    users = make_users()
    _scenario_key_swap(demo, users)
    _scenario_own_identity(demo, users)
    _scenario_oneway(demo, users)
    _scenario_handshake_bug(demo, users)
    _scenario_all_signatures_off(demo, users)
    return demo.finish("MITM blocked by signatures, the trust store, the signed manifest and the verification code")


def main() -> int:
    return 0 if run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
