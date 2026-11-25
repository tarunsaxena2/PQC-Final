"""Pure-Python ML-KEM: sizes, round trip, implicit rejection, and agreement with OpenSSL."""
import pytest
from key_layer import FIPS203_SIZES
from key_layer import pure_backend as P
from key_layer import openssl_backend as O


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_pure_sizes_and_roundtrip(level):
    ek, dk = P.keygen(level)
    ct, ss = P.encaps(ek)
    assert (len(ek), len(dk), len(ct), len(ss)) == FIPS203_SIZES[level]
    assert P.decaps(dk, ct) == ss


def test_pure_implicit_rejection():
    ek, dk = P.keygen(768)
    ct, ss = P.encaps(ek)
    bad = bytearray(ct); bad[5] ^= 1
    ss2 = P.decaps(dk, bytes(bad))
    assert ss2 != ss and len(ss2) == 32


@pytest.mark.skipif(not O.available(), reason="cryptography wheel has no ML-KEM")
@pytest.mark.parametrize("level", [768, 1024])
def test_same_seed_same_public_key_and_cross_decaps(level):
    d, z = bytes(range(32)), bytes(range(32, 64))
    ek_p, dk_p = P.pure_keygen(level, d, z)
    ek_o, _ = None, None
    from cryptography.hazmat.primitives.asymmetric import mlkem
    cls = mlkem.MLKEM768PrivateKey if level == 768 else mlkem.MLKEM1024PrivateKey
    sk = cls.from_seed_bytes(d + z)
    assert sk.public_key().public_bytes_raw() == ek_p          # T2: same pk from same 64 B seed
    ct, ss = P.encaps(ek_p)                                     # pure encaps -> OpenSSL decaps
    assert bytes(sk.decapsulate(ct)) == ss
    ss2, ct2 = sk.public_key().encapsulate()                    # OpenSSL encaps -> pure decaps
    assert P.decaps(dk_p, bytes(ct2)) == bytes(ss2)
