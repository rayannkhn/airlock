"""The transport interface every channel implements.

A transport moves opaque datagrams. It is *untrusted*: it may drop,
duplicate, reorder or corrupt them, and an attacker may control it fully.
No security decision is ever made here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType


class TransportError(Exception):
    """The channel failed (closed, broken, or a frame was too large)."""


class TransportTimeout(TransportError):
    """No datagram arrived within the timeout."""


class TransportClosed(TransportError):
    """The peer closed the channel."""


class Transport(ABC):
    """``send(data) -> None`` and ``receive() -> bytes``. That is the whole contract."""

    @abstractmethod
    def send(self, data: bytes) -> None:
        """Transmit one datagram."""

    @abstractmethod
    def receive(self, timeout: float | None = None) -> bytes:
        """Return the next datagram. Raises TransportTimeout or TransportClosed."""

    def close(self) -> None:
        """Release resources. Safe to call more than once."""

    def __enter__(self) -> Transport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
