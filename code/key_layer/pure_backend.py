"""Pure-Python ML-KEM (FIPS 203) back-end: VALIDATION ONLY, never a headline result.

Core algorithm copied from the team's pqc_stego_benchmark.py (sections 1).
NOT constant-time. Label every result from it as 'pure-Python'.
dk is the full FIPS 203 decapsulation key (same layout as liboqs).
"""
from __future__ import annotations

import hashlib
import os

from .interface import FIPS203_SIZES, KeyLayerError, check_level

BACKEND_NAME = "pure-Python (NOT constant-time, validation only)"

Q = 3329
PARAMS = {  # level: (k, eta1, eta2, du, dv)
    512: (2, 3, 2, 10, 4),
    768: (3, 2, 2, 10, 4),
    1024: (4, 2, 2, 11, 5),
}
SIZES = {  # FIPS 203 sizes in bytes: (encaps key, decaps key, ciphertext, shared secret)
    512: (800, 1632, 768, 32),
    768: (1184, 2400, 1088, 32),
    1024: (1568, 3168, 1568, 32),
}


def _brv7(i):
    return int(format(i, "07b")[::-1], 2)


_ZETAS = [pow(17, _brv7(i), Q) for i in range(128)]
_GAMMAS = [pow(17, 2 * _brv7(i) + 1, Q) for i in range(128)]


def _ntt(f):
    f = list(f)
    i, ln = 1, 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            z = _ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def _intt(f):
    f = list(f)
    i, ln = 127, 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            z = _ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln *= 2
    return [x * 3303 % Q for x in f]


def _mul(f, g):
    h = [0] * 256
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % Q * _GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _sample_ntt(rho, i, j):
    seed = rho + bytes([j, i])
    n_bytes = 672
    while True:
        stream = hashlib.shake_128(seed).digest(n_bytes)
        out = []
        p = 0
        while p + 3 <= len(stream) and len(out) < 256:
            b0, b1, b2 = stream[p], stream[p + 1], stream[p + 2]
            d1 = b0 + 256 * (b1 % 16)
            d2 = (b1 >> 4) + 16 * b2
            if d1 < Q:
                out.append(d1)
            if d2 < Q and len(out) < 256:
                out.append(d2)
            p += 3
        if len(out) == 256:
            return out
        n_bytes *= 2


def _cbd(b, eta):
    x = int.from_bytes(b, "little")
    mask = (1 << eta) - 1
    f = []
    for i in range(256):
        chunk = (x >> (2 * eta * i)) & ((1 << (2 * eta)) - 1)
        f.append((bin(chunk & mask).count("1") - bin(chunk >> eta).count("1")) % Q)
    return f


def _prf(s, b, eta):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def _enc(f, d):
    acc = 0
    for i, c in enumerate(f):
        acc |= c << (d * i)
    return acc.to_bytes(32 * d, "little")


def _dec(b, d):
    acc = int.from_bytes(b, "little")
    m = (1 << d) - 1
    f = [(acc >> (d * i)) & m for i in range(256)]
    return [x % Q for x in f] if d == 12 else f


def _compress(f, d):
    return [((x << d) + Q // 2) // Q % (1 << d) for x in f]


def _decompress(f, d):
    return [(y * Q + (1 << (d - 1))) >> d for y in f]


def _matrix(rho, k):
    return [[_sample_ntt(rho, i, j) for j in range(k)] for i in range(k)]


def _pke_keygen(d, level):
    k, eta1, _, _, _ = PARAMS[level]
    g = hashlib.sha3_512(d + bytes([k])).digest()
    rho, sigma = g[:32], g[32:]
    A = _matrix(rho, k)
    n = 0
    s, e = [], []
    for _ in range(k):
        s.append(_ntt(_cbd(_prf(sigma, n, eta1), eta1)))
        n += 1
    for _ in range(k):
        e.append(_ntt(_cbd(_prf(sigma, n, eta1), eta1)))
        n += 1
    t = []
    for i in range(k):
        acc = e[i]
        for j in range(k):
            acc = _add(acc, _mul(A[i][j], s[j]))
        t.append(acc)
    ek = b"".join(_enc(x, 12) for x in t) + rho
    dk = b"".join(_enc(x, 12) for x in s)
    return ek, dk


def _pke_encrypt(ek, m, r, level):
    k, eta1, eta2, du, dv = PARAMS[level]
    t = [_dec(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:]
    A = _matrix(rho, k)
    n = 0
    y, e1 = [], []
    for _ in range(k):
        y.append(_ntt(_cbd(_prf(r, n, eta1), eta1)))
        n += 1
    for _ in range(k):
        e1.append(_cbd(_prf(r, n, eta2), eta2))
        n += 1
    e2 = _cbd(_prf(r, n, eta2), eta2)
    u = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = _add(acc, _mul(A[j][i], y[j]))
        u.append(_add(_intt(acc), e1[i]))
    mu = _decompress(_dec(m, 1), 1)
    acc = [0] * 256
    for i in range(k):
        acc = _add(acc, _mul(t[i], y[i]))
    v = _add(_add(_intt(acc), e2), mu)
    c1 = b"".join(_enc(_compress(x, du), du) for x in u)
    c2 = _enc(_compress(v, dv), dv)
    return c1 + c2


def _pke_decrypt(dk, c, level):
    k, _, _, du, dv = PARAMS[level]
    c1, c2 = c[:32 * du * k], c[32 * du * k:]
    u = [_decompress(_dec(c1[32 * du * i:32 * du * (i + 1)], du), du) for i in range(k)]
    v = _decompress(_dec(c2, dv), dv)
    s = [_dec(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
    acc = [0] * 256
    for i in range(k):
        acc = _add(acc, _mul(s[i], _ntt(u[i])))
    w = [(a - b) % Q for a, b in zip(v, _intt(acc))]
    return _enc(_compress(w, 1), 1)


def pure_keygen(level, d=None, z=None):
    d = d or os.urandom(32)
    z = z or os.urandom(32)
    ek, dkp = _pke_keygen(d, level)
    dk = dkp + ek + hashlib.sha3_256(ek).digest() + z
    return ek, dk


def pure_encaps(ek, level, m=None):
    m = m or os.urandom(32)
    g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    K, r = g[:32], g[32:]
    return _pke_encrypt(ek, m, r, level), K


def pure_decaps(dk, c, level):
    k = PARAMS[level][0]
    dkp = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m2 = _pke_decrypt(dkp, c, level)
    g = hashlib.sha3_512(m2 + h).digest()
    K2, r2 = g[:32], g[32:]
    Kbar = hashlib.shake_256(z + c).digest(32)
    return K2 if _pke_encrypt(ek, m2, r2, level) == c else Kbar




# ---- key-layer interface wrapper -------------------------------------------
def keygen(level: int = 768):
    check_level(level)
    return pure_keygen(level)


def _level_from(length, index, what):
    level = next((l for l, s in FIPS203_SIZES.items() if s[index] == length), None)
    if level is None:
        raise KeyLayerError(f"{what} has an unknown length")
    return level


def encaps(ek: bytes):
    level = _level_from(len(ek), 0, "encapsulation key")
    ct, ss = pure_encaps(bytes(ek), level)
    return ct, ss


def decaps(dk: bytes, ct: bytes):
    level = _level_from(len(dk), 1, "decapsulation key")
    if len(ct) != FIPS203_SIZES[level][2]:
        raise KeyLayerError("ciphertext has a wrong length")
    return pure_decaps(bytes(dk), bytes(ct), level)
