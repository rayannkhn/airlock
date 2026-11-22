"""Tests for airlock.core.identity (threat T1 and key-file handling)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from airlock.core.identity import (
    Identity,
    IdentityError,
    PassphraseRequired,
    TrustStore,
    fingerprint,
    load_public_key,
    verify_signature,
)


def test_fingerprint_format_and_stability() -> None:
    ident = Identity.generate()
    fp = fingerprint(ident.public_key)
    groups = fp.split(" ")
    assert len(groups) == 10 and all(len(g) == 4 for g in groups)
    assert fp == ident.fingerprint == fingerprint(ident.public_key)
    assert fp != Identity.generate().fingerprint


def test_save_and_load_with_passphrase(tmp_path: Path) -> None:
    ident = Identity.generate()
    pub_path = ident.save(tmp_path / "id.key", b"correct horse")
    assert load_public_key(pub_path) == ident.public_key
    loaded = Identity.load(tmp_path / "id.key", b"correct horse")
    assert loaded.public_key == ident.public_key


def test_encrypted_key_needs_correct_passphrase(tmp_path: Path) -> None:
    Identity.generate().save(tmp_path / "id.key", b"correct horse")
    with pytest.raises(PassphraseRequired):
        Identity.load(tmp_path / "id.key")
    with pytest.raises(IdentityError):
        Identity.load(tmp_path / "id.key", b"wrong")


def test_private_key_is_encrypted_on_disk(tmp_path: Path) -> None:
    Identity.generate().save(tmp_path / "id.key", b"correct horse")
    assert b"ENCRYPTED PRIVATE KEY" in (tmp_path / "id.key").read_bytes()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_private_key_file_permissions(tmp_path: Path) -> None:
    Identity.generate().save(tmp_path / "id.key", None)
    assert (os.stat(tmp_path / "id.key").st_mode & 0o777) == 0o600


def test_save_refuses_to_overwrite(tmp_path: Path) -> None:
    Identity.generate().save(tmp_path / "id.key", None)
    with pytest.raises(IdentityError):
        Identity.generate().save(tmp_path / "id.key", None)
    Identity.generate().save(tmp_path / "id.key", None, overwrite=True)


def test_signature_verification() -> None:
    ident = Identity.generate()
    sig = ident.sign(b"msg")
    verify_signature(ident.public_key, sig, b"msg")
    with pytest.raises(InvalidSignature):
        verify_signature(ident.public_key, sig, b"other")
    with pytest.raises(InvalidSignature):
        verify_signature(Identity.generate().public_key, sig, b"msg")
    with pytest.raises(InvalidSignature):
        verify_signature(ident.public_key, sig[:-1], b"msg")


def test_trust_store_roundtrip(tmp_path: Path) -> None:
    bob = Identity.generate()
    store = TrustStore(path=tmp_path / "trust.json")
    store.add("bob", bob.public_key)
    store.save()
    again = TrustStore.load(tmp_path / "trust.json")
    assert again.name_for(bob.public_key) == "bob"
    assert again.name_for(Identity.generate().public_key) is None


def test_trust_store_refuses_silent_key_change() -> None:
    store = TrustStore({"bob": Identity.generate().public_key})
    with pytest.raises(IdentityError, match="DIFFERENT"):
        store.add("bob", Identity.generate().public_key)


def test_trust_store_rejects_corrupt_file(tmp_path: Path) -> None:
    (tmp_path / "trust.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(IdentityError):
        TrustStore.load(tmp_path / "trust.json")


def test_missing_trust_store_is_empty(tmp_path: Path) -> None:
    assert len(TrustStore.load(tmp_path / "nope.json")) == 0


def test_repr_does_not_leak_key() -> None:
    ident = Identity.generate()
    assert "PRIVATE" not in repr(ident) and ident.fingerprint in repr(ident)
