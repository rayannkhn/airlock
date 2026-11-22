"""The two demo users, alice (sender) and bob (receiver), shared by the CLI and the UI.

``setup_demo_users`` stands in for the one-time in-person meeting where two
people compare fingerprints and pin each other's keys. Both users live in
one state directory, because the demo runs on a single laptop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from airlock.core.identity import Identity, IdentityError, TrustStore, parse_card

DEMO_FILE = "demo.json"
DEMO_USERS = ("alice", "bob")


@dataclass
class DemoUser:
    name: str
    identity: Identity
    trust: TrustStore
    home: Path


def demo_users_exist(base: Path) -> bool:
    return all((Path(base) / name / "identity.key").exists() for name in DEMO_USERS)


def setup_demo_users(base: Path, force: bool = False) -> dict[str, Identity]:
    """Create alice and bob, each pinning the other's keys. Clears their replay stores."""
    base = Path(base)
    if not force:
        for name in DEMO_USERS:
            if (base / name / "identity.key").exists():
                raise IdentityError(
                    f"demo user '{name}' already exists in {base} (use --force to recreate)"
                )
    identities = {name: Identity.generate() for name in DEMO_USERS}
    for name, ident in identities.items():
        ident.save(base / name / "identity.key", None, overwrite=force)
        (base / name / "used_sessions.json").unlink(missing_ok=True)
    for me, peer in (("alice", "bob"), ("bob", "alice")):
        store = TrustStore(path=base / me / "trusted_peers.json")
        sign_key, receive_key = parse_card(identities[peer].card())  # verifies the card
        store.add(peer, sign_key, receive_key)
        store.save()
    (base / DEMO_FILE).write_text(
        json.dumps({"sender": "alice", "receiver": "bob"}, indent=2) + "\n", encoding="utf-8"
    )
    return identities


def load_demo_user(base: Path, name: str) -> DemoUser:
    home = Path(base) / name
    return DemoUser(
        name=name,
        identity=Identity.load(home / "identity.key"),
        trust=TrustStore.load(home / "trusted_peers.json"),
        home=home,
    )
