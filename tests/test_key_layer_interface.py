"""Week 1 Day 2 checks for the frozen key-layer interface and stub."""
import pytest
from key_layer import (FIPS203_SIZES, KeyLayerError, QkdKeyFileError, derive_keys,
                       read_qkd_keyfile, split_keys, write_qkd_keyfile, zeroise)
from key_layer import stub


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_stub_sizes_and_agreement(level):
    ek, dk = stub.keygen(level)
    ct, ss = stub.encaps(ek)
    assert (len(ek), len(dk), len(ct), len(ss)) == FIPS203_SIZES[level]
    assert stub.decaps(dk, ct) == ss


def test_stub_rejects_bad_level_and_lengths():
    with pytest.raises(KeyLayerError):
        stub.keygen(999)
    with pytest.raises(KeyLayerError):
        stub.encaps(b"short")
    ek, dk = stub.keygen(768)
    with pytest.raises(KeyLayerError):
        stub.decaps(dk, b"short")


def test_derive_keys_64_bytes_and_split():
    okm = derive_keys(b"\x01" * 32)
    assert len(okm) == 64
    k_aes, k_perm, k_mac = split_keys(okm)
    assert (len(k_aes), len(k_perm), len(k_mac)) == (16, 16, 32)
    assert k_aes + k_perm + k_mac == okm


def test_derive_keys_deterministic_and_separated():
    ss = b"\x02" * 32
    assert derive_keys(ss) == derive_keys(ss)
    assert derive_keys(ss) != derive_keys(b"\x03" * 32)
    k_aes, k_perm, k_mac = split_keys(derive_keys(ss))
    assert len({k_aes, k_perm, k_mac[:16]}) == 3


def test_hybrid_input_changes_output():
    ss = b"\x04" * 32
    assert derive_keys(ss, k_qkd=b"\x05" * 32) != derive_keys(ss)


def test_derive_keys_rejects_wrong_length():
    with pytest.raises(KeyLayerError):
        derive_keys(b"short")


def test_zeroise():
    b = bytearray(b"secret")
    assert zeroise(b) is True and b == bytearray(6)
    assert zeroise(b"immutable") is False


def test_qkd_keyfile_roundtrip_and_errors(tmp_path):
    p = tmp_path / "sim_qkd.key"
    write_qkd_keyfile(p)
    key = read_qkd_keyfile(p)
    assert len(key) == 16                      # matches the BB84 simulator's 128-bit key
    p32 = tmp_path / "sim32.key"
    write_qkd_keyfile(p32, b"\x07" * 32)
    assert read_qkd_keyfile(p32) == b"\x07" * 32
    with pytest.raises(QkdKeyFileError):
        write_qkd_keyfile(tmp_path / "bad.key", b"x" * 20)
    assert read_qkd_keyfile(p) == key
    with pytest.raises(QkdKeyFileError):
        read_qkd_keyfile(tmp_path / "missing.key")
    raw = bytearray(p.read_bytes()); raw[10] ^= 1; p.write_bytes(bytes(raw))
    with pytest.raises(QkdKeyFileError):
        read_qkd_keyfile(p)
    p.write_bytes(b"garbage")
    with pytest.raises(QkdKeyFileError):
        read_qkd_keyfile(p)


def test_first_32_bytes_match_old_benchmark_hkdf():
    """New 64 B output starts with the old 32 B (K_AES || K_perm) from the benchmark script."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ss = bytes(range(32))
    old = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pqc-stego-v1").derive(ss)
    assert derive_keys(ss)[:32] == old
