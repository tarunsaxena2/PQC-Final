import hmac, hashlib, os, sys
from pathlib import Path
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER = b"PQCS" + bytes([1, 3, 0])  # dummy: magic, version, level, mode byte

def pack(plain, k_aes, k_mac, header):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(k_aes), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    tag = hmac.new(k_mac, header + iv + ct, hashlib.sha256).digest()
    return iv + ct + tag

def unpack(blob, k_aes, k_mac, header):
    iv, ct, tag = blob[:16], blob[16:-32], blob[-32:]
    expect = hmac.new(k_mac, header + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):  # MAC first, then decrypt
        raise ValueError("MAC check failed")
    dec = Cipher(algorithms.AES(k_aes), modes.CBC(iv)).decryptor()
    data = dec.update(ct) + dec.finalize()
    unp = padding.PKCS7(128).unpadder()
    return unp.update(data) + unp.finalize()

if __name__ == "__main__":
    src = Path(sys.argv[1])
    plain = src.read_bytes()
    k_aes, k_mac = os.urandom(16), os.urandom(32)  # stand-ins for HKDF output
    blob = pack(plain, k_aes, k_mac, HEADER)
    assert unpack(blob, k_aes, k_mac, HEADER) == plain
    print(f"round trip OK, plain={len(plain)} B, blob={len(blob)} B (overhead {len(blob)-len(plain)} B)")

    bad = bytearray(blob)
    bad[20] ^= 1  # flip one ciphertext bit
    try:
        unpack(bytes(bad), k_aes, k_mac, HEADER)
        print("FAIL: tampering not detected")
    except ValueError as e:
        print("tamper rejected:", e)
