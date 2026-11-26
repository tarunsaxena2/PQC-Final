import sys, os
sys.path.insert(0, "code")
import container as c

def test_header_round_trip():
    h = c.Header(level=2, mode=c.MODE_HYBRID_QKDSIM, kem_ct=os.urandom(1088), body_len=123, gcm=True)
    raw = c.header_encode(h)
    assert len(raw) == 1099
    assert c.header_decode(raw) == h

def test_stub_pass_through():
    data = b"hello"
    h = c.Header(level=2, mode=0, kem_ct=bytes(1088), body_len=len(data))
    assert c.unpack(c.pack(data, bytes(64), h), bytes(64), h) == data
