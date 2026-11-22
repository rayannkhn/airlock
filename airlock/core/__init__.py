"""Secure core: identities, handshake, key schedule, AEAD framing, sessions.

This package must never import from :mod:`airlock.transports`. Security
properties must hold regardless of which transport carries the bytes.
"""
