"""In-process transport: two queues. Used to test the protocol with no physics involved."""

from __future__ import annotations

import queue

from airlock.transports.base import Transport, TransportClosed, TransportError, TransportTimeout

_CLOSED = object()  # sentinel the peer sees when this end closes


class LoopbackTransport(Transport):
    """One end of an in-memory datagram pipe. Thread-safe."""

    def __init__(self, inbox: queue.Queue[object], outbox: queue.Queue[object]) -> None:
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False

    def send(self, data: bytes) -> None:
        if self._closed:
            raise TransportError("transport is closed")
        self._outbox.put(bytes(data))  # copy: the caller may reuse its buffer

    def receive(self, timeout: float | None = None) -> bytes:
        if self._closed:
            raise TransportError("transport is closed")
        try:
            item = self._inbox.get(timeout=timeout)
        except queue.Empty as exc:
            raise TransportTimeout(f"no data within {timeout}s") from exc
        if item is _CLOSED:
            raise TransportClosed("peer closed the loopback")
        assert isinstance(item, bytes)
        return item

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._outbox.put(_CLOSED)


def make_loopback_pair() -> tuple[LoopbackTransport, LoopbackTransport]:
    """Return two connected ends (a, b): what a sends, b receives, and vice versa."""
    a_to_b: queue.Queue[object] = queue.Queue()
    b_to_a: queue.Queue[object] = queue.Queue()
    return LoopbackTransport(b_to_a, a_to_b), LoopbackTransport(a_to_b, b_to_a)
