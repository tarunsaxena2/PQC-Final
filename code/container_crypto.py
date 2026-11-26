"""container_crypto.py - body encryption + integrity (encrypt-then-MAC).

Default: AES-128-CBC (PKCS7) + HMAC-SHA256 over header + IV + ciphertext.
Option : AES-128-GCM with the header as AAD.
keys = 64 B from derive_keys(ss): K_AES[0:16] + K_perm[16:32] + K_MAC[32:64]. This layer uses K_AES and K_MAC only.
Body bytes: CBC = IV(16) + ciphertext + tag(32); GCM = nonce(12) + ciphertext + tag(16).
"""
import hashlib
import hmac
import os

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from container_header import ContainerError, header_encode

KEYS_LEN = 64
IV_LEN, MAC_LEN = 16, 32
NONCE_LEN, GCM_TAG_LEN = 12, 16
_AUTH_FAIL = "authentication failed (wrong key or damaged data)"   # one message for every failure


def zeroise(*buffers):
    """Best effort: overwrite bytearrays in place. Python may keep other copies, so this is not a guarantee."""
    for b in buffers:
        if isinstance(b, bytearray):
            b[:] = bytes(len(b))


def body_length(n_plain, gcm=False):
    """Body size in bytes for an n_plain-byte file."""
    if gcm:
        return NONCE_LEN + n_plain + GCM_TAG_LEN
    return IV_LEN + (n_plain // 16 + 1) * 16 + MAC_LEN


def _split(keys):
    if len(keys) != KEYS_LEN:
        raise ContainerError("bad key material")
    return bytearray(keys[0:16]), bytearray(keys[32:64])    # K_AES, K_MAC (copies we can wipe)


def pack(file_bytes, keys, header):
    """File bytes -> body bits (uint8 array of 0/1). The header is authenticated but is not part of the body."""
    if header.body_len != body_length(len(file_bytes), header.gcm):
        raise ContainerError("header body length does not match the payload")
    aad = header_encode(header)
    k_aes, k_mac = _split(keys)
    padded = bytearray()
    try:
        if header.gcm:
            nonce = os.urandom(NONCE_LEN)
            body = nonce + AESGCM(k_aes).encrypt(nonce, bytes(file_bytes), aad)
        else:
            iv = os.urandom(IV_LEN)
            padder = padding.PKCS7(128).padder()
            padded = bytearray(padder.update(bytes(file_bytes)) + padder.finalize())
            enc = Cipher(algorithms.AES(k_aes), modes.CBC(iv)).encryptor()
            ct = enc.update(padded) + enc.finalize()
            tag = hmac.new(k_mac, aad + iv + ct, hashlib.sha256).digest()
            body = iv + ct + tag
    finally:
        zeroise(k_aes, k_mac, padded)
    return np.unpackbits(np.frombuffer(body, dtype=np.uint8))


def unpack(body_bits, keys, header):
    """Body bits -> file bytes, or ContainerError. The MAC / tag is verified before anything is decrypted."""
    n = header.body_len
    min_len = NONCE_LEN + GCM_TAG_LEN if header.gcm else IV_LEN + 16 + MAC_LEN
    if len(body_bits) != 8 * n or n < min_len or (not header.gcm and (n - IV_LEN - MAC_LEN) % 16):
        raise ContainerError(_AUTH_FAIL)
    body = np.packbits(np.asarray(body_bits, dtype=np.uint8)).tobytes()
    aad = header_encode(header)
    k_aes, k_mac = _split(keys)
    padded = bytearray()
    try:
        if header.gcm:
            try:
                return AESGCM(k_aes).decrypt(body[:NONCE_LEN], body[NONCE_LEN:], aad)
            except InvalidTag:
                raise ContainerError(_AUTH_FAIL) from None
        iv, ct, tag = body[:IV_LEN], body[IV_LEN:-MAC_LEN], body[-MAC_LEN:]
        expect = hmac.new(k_mac, aad + iv + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):
            raise ContainerError(_AUTH_FAIL)
        dec = Cipher(algorithms.AES(k_aes), modes.CBC(iv)).decryptor()
        padded = bytearray(dec.update(ct) + dec.finalize())
        try:
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            raise ContainerError(_AUTH_FAIL) from None
    finally:
        zeroise(k_aes, k_mac, padded)
