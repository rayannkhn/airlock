"""Swappable transports. Each one moves opaque datagrams and is untrusted.

Every transport implements :class:`airlock.transports.base.Transport`:
``send(data: bytes) -> None`` and ``receive(timeout=None) -> bytes``.
"""
