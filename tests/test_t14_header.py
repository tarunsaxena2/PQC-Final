import os
import pytest
import container as c


@pytest.mark.parametrize("gcm", [False, True])
@pytest.mark.parametrize("mode", [c.MODE_PQC, c.MODE_HYBRID_X25519, c.MODE_HYBRID_QKDSIM])
@pytest.mark.parametrize("level", [1, 2, 3])
def test_round_trip(level, mode, gcm):
    h = c.Header(level=level, mode=mode, kem_ct=os.urandom(c.CT_LEN[level]), body_len=12345, gcm=gcm)
    raw = c.header_encode(h)
    assert len(raw) == c.header_len(level) == 7 + c.CT_LEN[level] + 4
    assert c.peek_header_len(raw[:c.PREFIX_LEN]) == len(raw)
    assert c.header_decode(raw) == h


def test_level2_header_is_1099_bytes():
    assert c.header_len(2) == 1099


def test_decode_rejects_bad_input():
    h = c.Header(level=2, mode=0, kem_ct=bytes(1088), body_len=1)
    raw = bytearray(c.header_encode(h))
    for bad in (b"", raw[:10], raw[:-1], b"XXXX" + raw[4:]):
        with pytest.raises(c.ContainerError):
            c.header_decode(bytes(bad))
    reserved = bytearray(raw)
    reserved[6] |= 0x40
    with pytest.raises(c.ContainerError):
        c.header_decode(bytes(reserved))
    unknown = bytearray(raw)
    unknown[6] = 7
    with pytest.raises(c.ContainerError):
        c.header_decode(bytes(unknown))
