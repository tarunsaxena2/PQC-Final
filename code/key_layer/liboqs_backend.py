"""Real ML-KEM through liboqs-python (headline back-end). Day 3 demo uses it."""
from __future__ import annotations

from .interface import KeyLayerError, check_level

BACKEND_NAME = "liboqs"


def _oqs():
    try:
        import oqs  # type: ignore
    except Exception as exc:  # import or DLL problem
        raise KeyLayerError(f"liboqs-python is not available: {exc.__class__.__name__}") from None
    return oqs


def keygen(level: int = 768):
    check_level(level)
    oqs = _oqs()
    with oqs.KeyEncapsulation(f"ML-KEM-{level}") as kem:
        ek = kem.generate_keypair()
        dk = kem.export_secret_key()
    return bytes(ek), bytes(dk)


def encaps(ek: bytes):
    oqs = _oqs()
    level = {800: 512, 1184: 768, 1568: 1024}.get(len(ek))
    if level is None:
        raise KeyLayerError("encapsulation key has an unknown length")
    with oqs.KeyEncapsulation(f"ML-KEM-{level}") as kem:
        ct, ss = kem.encap_secret(ek)
    return bytes(ct), bytes(ss)


def decaps(dk: bytes, ct: bytes):
    oqs = _oqs()
    level = {1632: 512, 2400: 768, 3168: 1024}.get(len(dk))
    if level is None:
        raise KeyLayerError("decapsulation key has an unknown length")
    with oqs.KeyEncapsulation(f"ML-KEM-{level}", dk) as kem:
        return bytes(kem.decap_secret(ct))
