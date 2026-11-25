"""Key-layer STUB (Week 1 Day 2). Other members code against this.

Returns correctly SIZED dummy data and one fixed dummy 32-byte secret.
NOT SECURE. Replace with the real module on integration day (Week 2 Day 4).
"""
from __future__ import annotations

import hashlib

from .interface import FIPS203_SIZES, KeyLayerError, check_level, derive_keys  # noqa: F401

DUMMY_SS = hashlib.sha256(b"key-layer stub dummy secret").digest()  # 32 B
BACKEND_NAME = "stub (NOT a real KEM)"


def _fill(tag: bytes, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(tag + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:n]


def keygen(level: int = 768):
    check_level(level)
    ek_n, dk_n, _, _ = FIPS203_SIZES[level]
    return _fill(b"ek%d" % level, ek_n), _fill(b"dk%d" % level, dk_n)


def encaps(ek: bytes):
    level = next((l for l, s in FIPS203_SIZES.items() if s[0] == len(ek)), None)
    if level is None:
        raise KeyLayerError("encapsulation key has an unknown length")
    return _fill(b"ct%d" % level, FIPS203_SIZES[level][2]), DUMMY_SS


def decaps(dk: bytes, ct: bytes):
    level = next((l for l, s in FIPS203_SIZES.items() if s[1] == len(dk)), None)
    if level is None or len(ct) != FIPS203_SIZES[level][2]:
        raise KeyLayerError("decapsulation key or ciphertext has a wrong length")
    return DUMMY_SS
