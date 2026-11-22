"""Demo 2: man-in-the-middle against airlock-insecure (no authentication). The attack SUCCEEDS.

This is the baseline. It shows that encryption without authentication does
not protect anyone: Mallory reads AND rewrites the message, and both victims
see "success". Demo 3 runs the same attack against AirLock. Run:
    python -m airlock.demos.mitm_insecure
"""

from __future__ import annotations

from airlock.core.crypto import Role
from airlock.demos.common import Demo
from airlock.demos.insecure import InsecurePeer

ORIGINAL = b"Transfer 100 USD to account PK-1234."
FORGED = b"Transfer 9999 USD to account PK-6666."


def run(quiet: bool = False) -> bool:
    demo = Demo(2, "MITM vs airlock-insecure (expected: attack SUCCEEDS)", quiet)
    alice, bob = InsecurePeer(Role.INITIATOR), InsecurePeer(Role.RESPONDER)
    # Mallory runs one fake responder (facing Alice) and one fake initiator (facing Bob).
    m_to_alice, m_to_bob = InsecurePeer(Role.RESPONDER), InsecurePeer(Role.INITIATOR)

    demo.step("Alice sends HELLO; Mallory intercepts it and opens her own session with Bob")
    hello = alice.hello()
    reply_to_alice = m_to_alice.on_hello(hello)  # Mallory answers Alice with HER key
    m_to_bob.session_id = hello[:16]
    reply_from_bob = bob.on_hello(m_to_bob.session_id + m_to_bob.public)
    m_to_bob.on_reply(reply_from_bob)
    alice.on_reply(reply_to_alice)  # Alice cannot tell that this key is Mallory's
    demo.note("Alice now shares a key with Mallory, and Bob shares a different key with Mallory")
    demo.check("both handshakes 'succeed': no error on either side",
               alice.keys is not None and bob.keys is not None)

    demo.step(f"Alice encrypts: {ORIGINAL.decode()!r}")
    packets = alice.encrypt_message(ORIGINAL)
    stolen = m_to_alice.decrypt_message(packets)
    demo.note(f"Mallory decrypts it: {stolen.decode()!r}")
    demo.check("Mallory READ the confidential message", stolen == ORIGINAL)

    demo.step(f"Mallory re-encrypts a forged message for Bob: {FORGED.decode()!r}")
    received = bob.decrypt_message(m_to_bob.encrypt_message(FORGED))
    demo.note(f"Bob receives: {received.decode()!r}  (decryption and integrity check OK)")
    demo.check("Bob accepted Mallory's forged message as genuine", received == FORGED)

    demo.note("lesson: AES-GCM only proves the message came from 'whoever holds the key';")
    demo.note("without authenticating the key exchange, that 'whoever' can be Mallory")
    return demo.finish("attack succeeded against the insecure variant, as expected")


def main() -> int:
    return 0 if run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
