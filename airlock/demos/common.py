"""Shared helpers for the attack demos: two trusting users, a sample file, PASS/FAIL output.

Each demo answers one question: "does the defense hold?". PASS means the
*expected* outcome happened. For the deliberately insecure variant, the
expected outcome is that the attack succeeds.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from airlock.core.handshake import HandshakeResult, Initiator, Responder
from airlock.core.identity import Identity, TrustStore

SECRET_TEXT = (
    b"CONFIDENTIAL: exam answers for Information Security, Q1-Q10. "
    b"Transfer 100 USD to account PK-1234 before Friday.\n"
)


@dataclass
class Users:
    """Alice (sender) and Bob (receiver), each pinning the other's keys."""

    alice: Identity
    alice_trust: TrustStore
    bob: Identity
    bob_trust: TrustStore


def make_users() -> Users:
    alice, bob = Identity.generate(), Identity.generate()
    alice_trust, bob_trust = TrustStore(), TrustStore()
    alice_trust.add("bob", bob.public_key, bob.receive_public_key)
    bob_trust.add("alice", alice.public_key, alice.receive_public_key)
    return Users(alice, alice_trust, bob, bob_trust)


def run_interactive_handshake(
    users: Users,
) -> tuple[HandshakeResult, HandshakeResult, list[bytes]]:
    """Honest 3-message handshake. Returns both results and the recorded messages."""
    initiator = Initiator(users.alice, users.alice_trust)
    responder = Responder(users.bob, users.bob_trust)
    m1 = initiator.start()
    m2 = responder.on_hello(m1)
    m3 = initiator.on_reply(m2)
    r_result = responder.on_finish(m3)
    assert initiator.result is not None
    return initiator.result, r_result, [m1, m2, m3]


def shannon_entropy(data: bytes) -> float:
    """Bits per byte. Random bytes are about 8; English text is about 4-5."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass
class Demo:
    """Collects checks and prints them in a uniform format."""

    number: int
    title: str
    quiet: bool = False
    checks: list[tuple[str, bool]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._print(f"\n=== Demo {self.number}: {self.title} ===")

    def _print(self, text: str) -> None:
        if not self.quiet:
            print(text, flush=True)

    def step(self, text: str) -> None:
        """Narrate what the attacker or the users are doing."""
        self._print(f"  > {text}")

    def note(self, text: str) -> None:
        self._print(f"      {text}")

    def check(self, label: str, ok: bool) -> bool:
        self.checks.append((label, ok))
        self._print(f"  [{'ok' if ok else 'XX'}] {label}")
        return ok

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(ok for _, ok in self.checks)

    def finish(self, pass_message: str) -> bool:
        if self.passed:
            self._print(f"  RESULT: PASS ({pass_message})")
        else:
            failed = [label for label, ok in self.checks if not ok]
            self._print(f"  RESULT: FAIL ({len(failed)} check(s) failed: {failed[0]})")
        return self.passed
