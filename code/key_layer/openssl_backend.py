"""ML-KEM through the cryptography wheel (OpenSSL). Only 768 and 1024 exist there.

dk here is the 64-byte seed (cryptography exposes the seed form, not the
expanded 2,400 B key), so it is NOT interchangeable with liboqs dk bytes.
Cross-back-end checks therefore swap ek / ct, not dk.
"""
from __future__ import annotations

from .interface import KeyLayerError

BACKEND_NAME = "OpenSSL (cryptography wheel)"
SUPPORTED = (768, 1024)


def available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401
        mlkem.MLKEM768PrivateKey.generate()
        return True
    except Exception:
        return False


def _cls(level):
    from cryptography.hazmat.primitives.asymmetric import mlkem
    if level == 768:
        return mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey
    if level == 1024:
        return mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey
    raise KeyLayerError("OpenSSL back-end supports ML-KEM-768 and ML-KEM-1024 only")


def keygen(level: int = 768):
    priv_cls, _ = _cls(level)
    sk = priv_cls.generate()
    return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()  # ek, 64 B seed


def encaps(ek: bytes):
    level = {1184: 768, 1568: 1024}.get(len(ek))
    if level is None:
        raise KeyLayerError("OpenSSL back-end: ek length not 768/1024")
    _, pub_cls = _cls(level)
    ss, ct = pub_cls.from_public_bytes(ek).encapsulate()  # order: (secret, ciphertext)
    return bytes(ct), bytes(ss)


def decaps(dk_seed: bytes, ct: bytes):
    level = {1088: 768, 1568: 1024}.get(len(ct))
    if level is None:
        raise KeyLayerError("OpenSSL back-end: ciphertext length not 768/1024")
    priv_cls, _ = _cls(level)
    return bytes(priv_cls.from_seed_bytes(dk_seed).decapsulate(ct))
