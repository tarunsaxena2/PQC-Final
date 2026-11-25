#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pqc_stego_benchmark.py
======================
Project 5 - Post-Quantum Cryptography (ML-KEM / Kyber) alternative for
classical-channel key exchange in a hybrid audio-steganography tool.

What this program does
----------------------
1. Key exchange back-ends being compared
     * BB84 QKD *software simulation* (sifting, QBER estimation, Cascade-style
       reconciliation, SHA-256 privacy amplification)
     * ML-KEM-512 / 768 / 1024 (FIPS 203) through the first back-end that works:
         a) liboqs-python  (import oqs)            <- recommended
         b) cryptography >= 47 (OpenSSL ML-KEM)     <- native fallback
         c) built-in pure-Python reference ML-KEM   <- always available (slow)
     * Hybrid:  HKDF( ss_ML-KEM || K_BB84 )
2. Secret-key hierarchy: HKDF-SHA256 -> 128-bit AES key + 128-bit permutation key
3. Steganography: AES-128-CBC ciphertext hidden by quantisation-index
   modulation (QIM) in mid-band DCT coefficients of a 16-bit PCM signal, at
   positions given by a key-driven pseudorandom permutation (AES-CTR argsort).
4. Benchmarks: speed, key/ciphertext size overhead, memory, imperceptibility
   (SNR/PSNR), BER, ablation, QBER sweep.
5. Results are written to an Excel workbook (with native, editable charts).

Usage
-----
  GUI :  python pqc_stego_benchmark.py
  CLI :  python pqc_stego_benchmark.py --cli --trials 10 --out results.xlsx
         python pqc_stego_benchmark.py --cli --quick           (fast smoke test)
         python pqc_stego_benchmark.py --selftest              (ML-KEM checks)

Install:  pip install numpy scipy cryptography openpyxl matplotlib
Optional: pip install liboqs-python   (needs the liboqs C library)
          (GUI needs tkinter, which ships with the python.org installers)
"""
import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import threading
import time
import tracemalloc
import queue
from datetime import datetime

import numpy as np
from scipy.fft import dct, idct
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------
# Optional native ML-KEM back-ends
# --------------------------------------------------------------------------
try:
    import oqs  # liboqs-python
    HAVE_OQS = True
except Exception:
    oqs = None
    HAVE_OQS = False

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem
    HAVE_OPENSSL_MLKEM = True
except Exception:
    _mlkem = None
    HAVE_OPENSSL_MLKEM = False

# ==========================================================================
# 1.  PURE-PYTHON ML-KEM (FIPS 203) - reference / fallback implementation
#     NOT constant-time. For benchmarking/education only.
# ==========================================================================
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


# ==========================================================================
# 2.  Uniform KEM wrapper
# ==========================================================================
class KEM:
    """keygen() -> (pk, sk); encaps(pk) -> (ct, ss); decaps(sk, ct) -> ss"""

    def __init__(self, level, backend):
        self.level, self.backend = level, backend
        self.name = f"ML-KEM-{level}"
        self.pk_size, self.sk_size, self.ct_size, self.ss_size = SIZES[level]
        if backend == "liboqs":
            self._alg = None
            for cand in (f"ML-KEM-{level}", f"Kyber{level}"):
                try:
                    oqs.KeyEncapsulation(cand).free()
                    self._alg = cand
                    break
                except Exception:
                    continue
            if self._alg is None:
                raise RuntimeError("liboqs lacks ML-KEM-%d" % level)
        elif backend == "openssl":
            if level not in (768, 1024) or not HAVE_OPENSSL_MLKEM:
                raise RuntimeError("openssl back-end unavailable for level %d" % level)
            self._priv = getattr(_mlkem, f"MLKEM{level}PrivateKey")
            self._pub = getattr(_mlkem, f"MLKEM{level}PublicKey")
        elif backend != "pure":
            raise ValueError(backend)

    def keygen(self):
        if self.backend == "liboqs":
            kem = oqs.KeyEncapsulation(self._alg)
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            kem.free()
            return pk, sk
        if self.backend == "openssl":
            sk = self._priv.generate()
            pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw)
            return pk, sk
        return pure_keygen(self.level)

    def encaps(self, pk):
        if self.backend == "liboqs":
            kem = oqs.KeyEncapsulation(self._alg)
            ct, ss = kem.encap_secret(pk)
            kem.free()
            return ct, ss
        if self.backend == "openssl":
            ss, ct = self._pub.from_public_bytes(pk).encapsulate()
            return ct, ss
        return pure_encaps(pk, self.level)

    def decaps(self, sk, ct):
        if self.backend == "liboqs":
            kem = oqs.KeyEncapsulation(self._alg, secret_key=sk)
            ss = kem.decap_secret(ct)
            kem.free()
            return ss
        if self.backend == "openssl":
            return sk.decapsulate(ct)
        return pure_decaps(sk, ct, self.level)


def available_backends(level):
    out = []
    if HAVE_OQS:
        try:
            KEM(level, "liboqs")
            out.append("liboqs")
        except Exception:
            pass
    if HAVE_OPENSSL_MLKEM and level in (768, 1024):
        out.append("openssl")
    out.append("pure")
    return out


def best_native_backend(level):
    return available_backends(level)[0]


def selftest(log=print):
    """Round-trip, implicit-rejection and (if available) OpenSSL cross-validation."""
    ok_all = True
    for lvl in (512, 768, 1024):
        pk, sk = pure_keygen(lvl)
        ct, ss = pure_encaps(pk, lvl)
        ss2 = pure_decaps(sk, ct, lvl)
        bad = bytearray(ct)
        bad[0] ^= 1
        ss3 = pure_decaps(sk, bytes(bad), lvl)
        sizes_ok = (len(pk), len(sk), len(ct)) == SIZES[lvl][:3]
        ok = ss == ss2 and ss3 != ss and sizes_ok
        ok_all &= ok
        log(f"[pure ML-KEM-{lvl}] round-trip+implicit-rejection+sizes: {'PASS' if ok else 'FAIL'}")
    if HAVE_OPENSSL_MLKEM:
        for lvl in (768, 1024):
            seed = os.urandom(64)
            sk_o = getattr(_mlkem, f"MLKEM{lvl}PrivateKey").from_seed_bytes(seed)
            pk_o = sk_o.public_key().public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw)
            pk_p, sk_p = pure_keygen(lvl, d=seed[:32], z=seed[32:])
            same_key = pk_p == pk_o
            ct, ss = pure_encaps(pk_o, lvl)
            x1 = sk_o.decapsulate(ct) == ss
            ss_o, ct_o = getattr(_mlkem, f"MLKEM{lvl}PublicKey").from_public_bytes(pk_o).encapsulate()
            x2 = pure_decaps(sk_p, ct_o, lvl) == ss_o
            ok = same_key and x1 and x2
            ok_all &= ok
            log(f"[pure vs OpenSSL ML-KEM-{lvl}] identical keygen from seed={same_key}, "
                f"cross-decaps={x1 and x2}: {'PASS' if ok else 'FAIL'}")
    else:
        log("[cross-validation] OpenSSL ML-KEM not available - skipped")
    return ok_all


# ==========================================================================
# 3.  BB84 QKD software simulation
# ==========================================================================
def _par(a, idx):
    return int(a[idx].sum() & 1)


def bb84_session(n, qber, rng, sample_frac=0.25, abort_q=0.11, passes=6):
    a_bits = rng.integers(0, 2, n, dtype=np.int8)
    a_bas = rng.integers(0, 2, n, dtype=np.int8)
    b_bas = rng.integers(0, 2, n, dtype=np.int8)
    flips = (rng.random(n) < qber).astype(np.int8)
    rnd = rng.integers(0, 2, n, dtype=np.int8)
    match = a_bas == b_bas
    b_bits = np.where(match, a_bits ^ flips, rnd).astype(np.int8)
    idx = np.flatnonzero(match)
    A, B = a_bits[idx], b_bits[idx]
    m = len(idx)
    ns = int(m * sample_frac)
    perm = rng.permutation(m)
    samp, rest = perm[:ns], np.sort(perm[ns:])
    q_est = float(np.mean(A[samp] != B[samp])) if ns else 0.0
    st = dict(qubits=n, sifted=m, sample=ns, qber_est=q_est, leaked=0,
              classical_bytes=0, ok=False, aborted=False, key=None)
    st["classical_bytes"] = 2 * (n // 8) + ns // 8 + 1
    if q_est > abort_q:
        st["aborted"] = True
        return st
    A, B = A[rest].copy(), B[rest].copy()
    L = len(A)
    leaked = 0
    q_use = max(q_est, 0.005)
    k1 = max(4, int(0.73 / q_use))
    for p in range(passes):
        k = min(L, k1 * (2 ** (p % 4)))
        order = np.arange(L) if p == 0 else rng.permutation(L)
        for s in range(0, L, k):
            blk = order[s:s + k]
            leaked += 1
            if _par(A, blk) != _par(B, blk):
                lo = blk
                while len(lo) > 1:
                    h = len(lo) // 2
                    leaked += 1
                    if _par(A, lo[:h]) != _par(B, lo[:h]):
                        lo = lo[:h]
                    else:
                        lo = lo[h:]
                B[lo[0]] ^= 1
    leaked += 32  # verification tag
    tag_ok = hashlib.sha256(A.tobytes()).digest()[:4] == hashlib.sha256(B.tobytes()).digest()[:4]
    final_bits = L - leaked - 64
    st["leaked"] = leaked
    st["classical_bytes"] += (leaked + 7) // 8
    st["final_bits"] = max(0, final_bits)
    if tag_ok and final_bits >= 128:
        st["ok"] = True
        st["key"] = hashlib.sha256(np.packbits(A).tobytes()).digest()[:16]
    return st


def bb84_exchange(n=2048, qber=0.02, rng=None, max_sessions=6):
    rng = rng or np.random.default_rng()
    tot_bytes, tot_q, sessions = 0, 0, 0
    last = None
    for _ in range(max_sessions):
        sessions += 1
        last = bb84_session(n, qber, rng)
        tot_bytes += last["classical_bytes"]
        tot_q += n
        if last["ok"]:
            break
    last = dict(last)
    last.update(classical_bytes=tot_bytes, qubits=tot_q, sessions=sessions)
    return last["key"], last


# ==========================================================================
# 4.  Key derivation, AES-128-CBC, permutation, DCT/QIM steganography
# ==========================================================================
def derive_keys(ikm, info=b"pqc-stego-v1"):
    okm = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)
    return okm[:16], okm[16:]  # K_aes, K_perm


def aes_cbc_encrypt(key, iv, pt):
    pad = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pad.update(pt) + pad.finalize()) + enc.finalize()


def aes_cbc_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(dec.update(ct) + dec.finalize()) + unpad.finalize()


def perm_from_key(k_perm, M):
    """pi = argsort( AES-128-CTR_{K_perm}(0) interpreted as M x uint64 )"""
    enc = Cipher(algorithms.AES(k_perm), modes.CTR(b"\x00" * 16)).encryptor()
    ks = enc.update(bytes(8 * M))
    r = np.frombuffer(ks, dtype=np.uint64)
    return np.argsort(r, kind="stable")


FRAME, LO, HI, DELTA = 1024, 32, 512, 6.0
_DITHER = np.random.default_rng(12345)


def make_synthetic_audio(seconds=20, fs=44100, seed=1):
    rng = np.random.default_rng(seed)
    t = np.arange(int(seconds * fs)) / fs
    sig = np.zeros_like(t)
    for f0, a in [(220, .30), (440, .22), (660, .15), (1320, .08), (2640, .05)]:
        sig += a * np.sin(2 * np.pi * f0 * t + rng.random() * 6.28)
    sig *= 0.6 + 0.4 * np.sin(2 * np.pi * 0.25 * t)
    noise = rng.normal(0, 1, t.size)
    noise = np.convolve(noise, np.ones(8) / 8, mode="same") * 0.05
    sig = (sig + noise) / 1.2
    return np.clip(sig * 0.6 * 32767, -32768, 32767).astype(np.int16)


def load_audio(path):
    from scipy.io import wavfile
    fs, x = wavfile.read(path)
    if x.ndim > 1:
        x = x[:, 0]
    if x.dtype != np.int16:
        x = (x.astype(np.float64) / (np.abs(x).max() or 1) * 0.6 * 32767).astype(np.int16)
    return x


def capacity_bits(n_samples):
    return (n_samples // FRAME) * (HI - LO)


def embed_bits(audio, bits, k_perm, sequential=False):
    F = len(audio) // FRAME
    X = dct(audio[:F * FRAME].reshape(F, FRAME).astype(np.float64), type=2, norm="ortho", axis=1)
    flat = X[:, LO:HI].reshape(-1).copy()
    if len(bits) > flat.size:
        raise ValueError("payload exceeds capacity")
    pos = np.arange(len(bits)) if sequential else perm_from_key(k_perm, flat.size)[:len(bits)]
    v = flat[pos] / DELTA
    q = np.rint(v)
    wrong = (q % 2).astype(np.int8) != bits
    q = np.where(wrong, q + np.where(v >= q, 1.0, -1.0), q)
    flat[pos] = q * DELTA
    X[:, LO:HI] = flat.reshape(F, HI - LO)
    y = idct(X, type=2, norm="ortho", axis=1)
    # Sub-LSB dither: de-correlates the int16 rounding error from the (tiny) embedding
    # change so the receiver sees a zero-mean coefficient error of std ~0.41 << DELTA/2.
    y = y + _DITHER.uniform(-0.5, 0.5, y.shape)
    out = audio.copy()
    out[:F * FRAME] = np.clip(np.rint(y), -32768, 32767).astype(np.int16).reshape(-1)
    return out, pos


def extract_body(stego, k_perm, sequential=False):
    F = len(stego) // FRAME
    X = dct(stego[:F * FRAME].reshape(F, FRAME).astype(np.float64), type=2, norm="ortho", axis=1)
    flat = X[:, LO:HI].reshape(-1)
    perm = np.arange(flat.size) if sequential else perm_from_key(k_perm, flat.size)
    rd = lambda p: (np.rint(flat[p] / DELTA) % 2).astype(np.uint8)
    n_body = int.from_bytes(np.packbits(rd(perm[:32])).tobytes(), "big")
    bits = rd(perm[32:32 + 8 * n_body])
    return np.packbits(bits).tobytes()


def build_bits(body):
    return np.unpackbits(np.frombuffer(len(body).to_bytes(4, "big") + body, dtype=np.uint8))


def snr_db(x, y):
    x, y = x.astype(np.float64), y.astype(np.float64)
    num, den = np.sum(x ** 2), np.sum((x - y) ** 2)
    return float("inf") if den == 0 else 10 * np.log10(num / den)


def psnr_db(x, y):
    mse = np.mean((x.astype(np.float64) - y.astype(np.float64)) ** 2)
    return float("inf") if mse == 0 else 10 * np.log10(32767.0 ** 2 / mse)


def byte_entropy(b):
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(np.float64)
    p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())


def make_payload(n, seed=7):
    rng = np.random.default_rng(seed)
    words = [b"secret", b"report", b"quantum", b"lattice", b"audio", b"key", b"the",
             b"of", b"and", b"stego", b"data", b"channel", b"cipher", b"file"]
    out = b""
    while len(out) < n:
        out += words[rng.integers(0, len(words))] + b" "
    return out[:n]


# ==========================================================================
# 5.  End-to-end pipeline
# ==========================================================================
def tm(fn, *a):
    t = time.perf_counter()
    r = fn(*a)
    return r, (time.perf_counter() - t) * 1e3


def scheme_label(scheme, level):
    return {"QKD": "QKD (BB84-sim)", "PQC": f"PQC (ML-KEM-{level})",
            "HYBRID": f"Hybrid (ML-KEM-{level} + BB84-sim)"}[scheme]


def key_exchange(scheme, level, backend, cfg, rng):
    """Returns (ikm, wire_bytes, t_ms, detail)"""
    parts, wire, t_ms, det = [], 0, 0.0, {}
    if scheme in ("PQC", "HYBRID"):
        kem = KEM(level, backend)
        (pk, sk), t1 = tm(kem.keygen)
        (ct, ss), t2 = tm(kem.encaps, pk)
        ss2, t3 = tm(kem.decaps, sk, ct)
        assert ss == ss2, "KEM shared-secret mismatch"
        parts.append(ss)
        wire += len(pk) + len(ct)
        t_ms += t1 + t2 + t3
        det.update(keygen_ms=t1, encaps_ms=t2, decaps_ms=t3)
    if scheme in ("QKD", "HYBRID"):
        (k, st), t4 = tm(bb84_exchange, cfg["qkd_qubits"], cfg["qber"], rng)
        if k is None:
            raise RuntimeError("BB84 failed (QBER too high)")
        parts.append(k)
        wire += st["classical_bytes"]
        t_ms += t4
        det.update(qkd_ms=t4, qubits=st["qubits"], sessions=st["sessions"])
    return b"".join(parts), wire, t_ms, det


def run_pipeline_once(audio, payload, scheme, level, backend, cfg, rng,
                      encrypt=True, permute=True):
    ikm, wire, t_kx, det = key_exchange(scheme, level, backend, cfg, rng)
    (k_aes, k_perm), t_kdf = tm(derive_keys, ikm)
    iv = os.urandom(16)
    if encrypt:
        ct, t_enc = tm(aes_cbc_encrypt, k_aes, iv, payload)
    else:
        ct, t_enc = payload, 0.0
    body = iv + ct
    bits = build_bits(body)
    (stego, _), t_emb = tm(embed_bits, audio, bits, k_perm, not permute)
    rec, t_ext = tm(extract_body, stego, k_perm, not permute)
    if encrypt:
        pt, t_dec = tm(aes_cbc_decrypt, k_aes, rec[:16], rec[16:])
    else:
        pt, t_dec = rec[16:], 0.0
    ok = pt == payload
    rb = np.unpackbits(np.frombuffer(rec, dtype=np.uint8))
    sb = np.unpackbits(np.frombuffer(body, dtype=np.uint8))
    ber = float(np.mean(rb[:len(sb)] != sb)) if len(rb) >= len(sb) else 1.0
    return dict(
        scheme=scheme_label(scheme, level), backend=backend if scheme != "QKD" else "simulation",
        payload_bytes=len(payload), embedded_bits=len(bits),
        capacity_bits=capacity_bits(len(audio)), wire_bytes=wire,
        t_kx_ms=t_kx, t_kdf_ms=t_kdf, t_aes_ms=t_enc + t_dec, t_embed_ms=t_emb,
        t_extract_ms=t_ext, t_total_ms=t_kx + t_kdf + t_enc + t_dec + t_emb + t_ext,
        snr_db=snr_db(audio, stego), psnr_db=psnr_db(audio, stego), ber=ber, ok=bool(ok),
        entropy_bits_per_byte=byte_entropy(ct), **det), stego, bits


def locality(pos, per_frame=HI - LO):
    fr = pos // per_frame
    return float(np.mean(fr[1:] == fr[:-1])) if len(fr) > 1 else 1.0


def mean_std(vals):
    vals = [float(v) for v in vals]
    return (statistics.fmean(vals), statistics.pstdev(vals) if len(vals) > 1 else 0.0)


def peak_mem_kib(fn, *a):
    tracemalloc.start()
    tracemalloc.reset_peak()
    fn(*a)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return peak / 1024.0


# ==========================================================================
# 6.  Experiments
# ==========================================================================
def run_all(cfg, log=print, progress=lambda f: None, stop=lambda: False):
    rng = np.random.default_rng(cfg.get("seed", 2026))
    res = dict(meta={}, kex=[], pipeline_raw=[], pipeline=[], ablation=[], qber=[], selftest="")
    res["meta"] = dict(
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), python=platform.python_version(),
        platform=platform.platform(), cpu=platform.processor() or platform.machine(),
        numpy=np.__version__, liboqs=HAVE_OQS, openssl_mlkem=HAVE_OPENSSL_MLKEM,
        config={k: v for k, v in cfg.items() if k != "audio_path"})
    audio = load_audio(cfg["audio_path"]) if cfg.get("audio_path") else make_synthetic_audio(cfg["seconds"])
    cap = capacity_bits(len(audio))
    res["meta"]["audio_samples"] = int(len(audio))
    res["meta"]["capacity_bytes"] = int(cap // 8) - 8
    log(f"Audio: {len(audio)} samples, capacity {cap // 8} bytes")
    res["selftest"] = "PASS" if selftest(log) else "FAIL"

    T = cfg["trials"]
    levels = [512, 768, 1024]
    jobs = (len(levels) * 3 + 1) + 4 * len(cfg["payload_kb"]) + 4 + len(cfg["qber_sweep"])
    done = [0]

    def tick():
        done[0] += 1
        progress(min(1.0, done[0] / jobs))

    # ---- E1: key-exchange micro-benchmark ------------------------------
    log("E1: key-exchange benchmark")
    for lvl in levels:
        for be in available_backends(lvl):
            if stop():
                return res
            if be == "pure" and cfg.get("skip_pure"):
                continue
            kem = KEM(lvl, be)
            kem.encaps(kem.keygen()[0])  # warm-up
            kg, en, de = [], [], []
            for _ in range(T if be != "pure" else max(3, T // 3)):
                (pk, sk), a = tm(kem.keygen)
                (ct, ss), b = tm(kem.encaps, pk)
                ss2, c = tm(kem.decaps, sk, ct)
                assert ss == ss2
                kg.append(a); en.append(b); de.append(c)
            mem = peak_mem_kib(lambda: kem.decaps(*(lambda p, s: (s, kem.encaps(p)[0]))(*kem.keygen())))
            tot = [x + y + z for x, y, z in zip(kg, en, de)]
            res["kex"].append(dict(
                scheme=f"ML-KEM-{lvl}", backend=be, pk_bytes=SIZES[lvl][0], sk_bytes=SIZES[lvl][1],
                ct_bytes=SIZES[lvl][2], wire_bytes=SIZES[lvl][0] + SIZES[lvl][2], ss_bytes=32,
                keygen_ms=mean_std(kg)[0], encaps_ms=mean_std(en)[0], decaps_ms=mean_std(de)[0],
                total_ms=mean_std(tot)[0], total_std_ms=mean_std(tot)[1], peak_mem_kib=mem,
                trials=len(tot)))
            log(f"  ML-KEM-{lvl:<4} [{be:7}] total {mean_std(tot)[0]:9.3f} ms")
            tick()
    qt, qb, qs = [], [], []
    for _ in range(T):
        (k, st), t = tm(bb84_exchange, cfg["qkd_qubits"], cfg["qber"], rng)
        qt.append(t); qb.append(st["classical_bytes"]); qs.append(st["sessions"])
    qmem = peak_mem_kib(bb84_exchange, cfg["qkd_qubits"], cfg["qber"], rng)
    res["kex"].insert(0, dict(
        scheme="BB84-sim", backend="simulation", pk_bytes=0, sk_bytes=0, ct_bytes=0,
        wire_bytes=int(statistics.fmean(qb)), ss_bytes=16, keygen_ms=0.0, encaps_ms=0.0,
        decaps_ms=0.0, total_ms=mean_std(qt)[0], total_std_ms=mean_std(qt)[1],
        peak_mem_kib=qmem, trials=T, qubits=cfg["qkd_qubits"],
        sessions=statistics.fmean(qs)))
    log(f"  BB84-sim ({cfg['qkd_qubits']} qubits)    total {mean_std(qt)[0]:9.3f} ms, "
        f"classical {statistics.fmean(qb):.0f} B")
    tick()

    # ---- E2: end-to-end pipeline ---------------------------------------
    log("E2: end-to-end steganography pipeline")
    nat768, nat1024 = best_native_backend(768), best_native_backend(1024)
    schemes = [("QKD", 768, "simulation"), ("PQC", 768, nat768),
               ("PQC", 1024, nat1024), ("HYBRID", 768, nat768)]
    pipe_mem = {}
    for kb in cfg["payload_kb"]:
        payload = make_payload(kb * 1024)
        if (len(payload) + 40) * 8 > cap:
            log(f"  skip {kb} KB (exceeds capacity)")
            continue
        for sch, lvl, be in schemes:
            if stop():
                return res
            run_pipeline_once(audio, payload, sch, lvl, be, cfg, rng)  # warm-up
            rows = []
            for _ in range(cfg["pipe_trials"]):
                r, _, _ = run_pipeline_once(audio, payload, sch, lvl, be, cfg, rng)
                rows.append(r)
                res["pipeline_raw"].append(dict(r, trial=len(rows)))
            agg = dict(rows[0])
            for key in ("t_kx_ms", "t_kdf_ms", "t_aes_ms", "t_embed_ms", "t_extract_ms",
                        "t_total_ms", "snr_db", "psnr_db", "ber", "wire_bytes"):
                agg[key] = mean_std([r[key] for r in rows])[0]
            agg["t_total_std_ms"] = mean_std([r["t_total_ms"] for r in rows])[1]
            agg["ok"] = all(r["ok"] for r in rows)
            agg["util_pct"] = 100.0 * agg["embedded_bits"] / agg["capacity_bits"]
            if kb == cfg["payload_kb"][min(2, len(cfg["payload_kb"]) - 1)]:
                key = (sch, lvl)
                pipe_mem[key] = peak_mem_kib(run_pipeline_once, audio, payload, sch, lvl, be, cfg, rng) / 1024.0
            agg["pipeline_peak_mib"] = pipe_mem.get((sch, lvl), None)
            res["pipeline"].append(agg)
            log(f"  {kb:>3} KB  {agg['scheme']:<34} total {agg['t_total_ms']:8.1f} ms  "
                f"PSNR {agg['psnr_db']:.1f} dB  BER {agg['ber']:.0e}  ok={agg['ok']}")
            tick()
    for row in res["pipeline"]:  # back-fill memory for all rows of same scheme
        for (sch, lvl), mib in pipe_mem.items():
            if row["scheme"] == scheme_label(sch, lvl):
                row["pipeline_peak_mib"] = mib

    # ---- E3: ablation --------------------------------------------------
    log("E3: ablation (encryption / permutation)")
    kb = cfg["payload_kb"][min(2, len(cfg["payload_kb"]) - 1)]
    payload = make_payload(kb * 1024)
    variants = [("A0  Plain + sequential QIM", False, False), ("A1  Plain + permuted QIM", False, True),
                ("A2  AES-CBC + sequential QIM", True, False), ("A3  AES-CBC + permuted QIM (proposed)", True, True)]
    for name, enc, perm in variants:
        ts, ps, ents, locs, oks = [], [], [], [], []
        for _ in range(cfg["pipe_trials"]):
            r, stego, bits = run_pipeline_once(audio, payload, "PQC", 768, nat768, cfg, rng,
                                               encrypt=enc, permute=perm)
            ts.append(r["t_total_ms"]); ps.append(r["psnr_db"]); oks.append(r["ok"])
            ents.append(r["entropy_bits_per_byte"] if enc else byte_entropy(payload))
            k_perm = derive_keys(os.urandom(32))[1]
            _, pos = embed_bits(audio, bits, k_perm, sequential=not perm)
            locs.append(locality(pos))
        res["ablation"].append(dict(
            variant=name, encrypt=enc, permute=perm, total_ms=mean_std(ts)[0],
            psnr_db=mean_std(ps)[0], entropy=mean_std(ents)[0], locality=mean_std(locs)[0],
            ok=all(oks)))
        log(f"  {name:<40} PSNR {mean_std(ps)[0]:.2f}  H={mean_std(ents)[0]:.3f}  loc={mean_std(locs)[0]:.4f}")
        tick()

    # ---- E4: QBER sweep -------------------------------------------------
    log("E4: BB84 QBER sweep")
    for qb_ in cfg["qber_sweep"]:
        if stop():
            return res
        rows = []
        for _ in range(max(3, T // 2)):
            (k, st), t = tm(bb84_exchange, cfg["qber_sweep_qubits"], qb_, rng)
            rows.append((t, st))
        okr = sum(1 for _, s in rows if s["ok"]) / len(rows)
        res["qber"].append(dict(
            qber_pct=100 * qb_, time_ms=statistics.fmean(t for t, _ in rows),
            sifted=statistics.fmean(s["sifted"] for _, s in rows),
            leaked=statistics.fmean(s["leaked"] for _, s in rows),
            classical_bytes=statistics.fmean(s["classical_bytes"] for _, s in rows),
            sessions=statistics.fmean(s["sessions"] for _, s in rows), success_rate=okr))
        log(f"  QBER {100 * qb_:4.1f}%: {res['qber'][-1]['time_ms']:.1f} ms, success {okr:.0%}")
        tick()
    progress(1.0)
    return res


DEFAULT_CFG = dict(seconds=20, audio_path=None, trials=10, pipe_trials=5, payload_kb=[1, 4, 8, 16, 32],
                   qkd_qubits=2048, qber=0.02, qber_sweep=[0.005, 0.01, 0.02, 0.03, 0.05, 0.07, 0.09, 0.11],
                   qber_sweep_qubits=8192, seed=2026, skip_pure=False)


# ==========================================================================
# 7.  Excel export (native charts)
# ==========================================================================
def save_excel(res, path):
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, LineChart, Reference
    from openpyxl.styles import Alignment, Font, PatternFill
    wb = Workbook()
    hdr_fill = PatternFill("solid", fgColor="1F3864")
    hdr_font = Font(bold=True, color="FFFFFF")

    def table(ws, rows, headers, r0=1, c0=1):
        for j, h in enumerate(headers):
            c = ws.cell(r0, c0 + j, h)
            c.fill, c.font = hdr_fill, hdr_font
            c.alignment = Alignment(horizontal="center", wrap_text=True)
        for i, row in enumerate(rows, 1):
            for j, h in enumerate(headers):
                v = row.get(h, "")
                if isinstance(v, float):
                    v = round(v, 4)
                ws.cell(r0 + i, c0 + j, v)
        for j, h in enumerate(headers):
            ws.column_dimensions[ws.cell(1, c0 + j).column_letter].width = max(13, min(34, len(h) + 4))
        return r0 + len(rows)

    # Summary
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = "Project 5: ML-KEM (Kyber) vs BB84-QKD-simulated key exchange for audio steganography"
    ws["A1"].font = Font(bold=True, size=13)
    r = 3
    m = res["meta"]
    for k in ("date", "python", "platform", "cpu", "numpy", "liboqs", "openssl_mlkem",
              "audio_samples", "capacity_bytes"):
        ws.cell(r, 1, k); ws.cell(r, 2, str(m.get(k))); r += 1
    for k, v in m["config"].items():
        ws.cell(r, 1, "cfg." + k); ws.cell(r, 2, str(v)); r += 1
    ws.cell(r, 1, "ML-KEM self-test"); ws.cell(r, 2, res["selftest"]); r += 2
    kx = {(x["scheme"], x["backend"]): x for x in res["kex"]}
    qkd = kx.get(("BB84-sim", "simulation"))
    best = [x for x in res["kex"] if x["scheme"] == "ML-KEM-768" and x["backend"] != "pure"] or \
           [x for x in res["kex"] if x["scheme"] == "ML-KEM-768"]
    if qkd and best:
        b = best[0]
        ws.cell(r, 1, "Headline comparison (ML-KEM-768 vs BB84-sim)").font = Font(bold=True); r += 1
        ws.cell(r, 1, "Key-exchange time speed-up (x)"); ws.cell(r, 2, round(qkd["total_ms"] / b["total_ms"], 1)); r += 1
        ws.cell(r, 1, "Wire bytes: BB84 classical channel"); ws.cell(r, 2, qkd["wire_bytes"]); r += 1
        ws.cell(r, 1, "Wire bytes: ML-KEM-768 (ek+ct)"); ws.cell(r, 2, b["wire_bytes"]); r += 1
        ws.cell(r, 1, "Note: BB84 row is classical post-processing only; real QKD also needs a dedicated quantum link.")
    ws.column_dimensions["A"].width = 52
    ws.column_dimensions["B"].width = 60

    # KeyExchange
    ws = wb.create_sheet("KeyExchange")
    H = ["scheme", "backend", "pk_bytes", "sk_bytes", "ct_bytes", "wire_bytes", "ss_bytes", "keygen_ms",
         "encaps_ms", "decaps_ms", "total_ms", "total_std_ms", "peak_mem_kib", "trials"]
    for x in res["kex"]:
        x["label"] = f"{x['scheme']} [{x['backend']}]"
    H2 = ["label"] + H
    last = table(ws, res["kex"], H2)
    for ttl, col, anchor in (("Key-exchange time (ms, log scale)", 12, "Q2"),
                             ("Bytes on the classical channel", 7, "Q20")):
        ch = BarChart(); ch.type = "col"; ch.title = ttl
        ch.add_data(Reference(ws, min_col=col, min_row=1, max_row=last), titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=last))
        ch.y_axis.title = "ms" if col == 12 else "bytes"; ch.x_axis.title = "Scheme"
        if col == 12:
            ch.y_axis.scaling.logBase = 10
        ch.x_axis.delete = False; ch.y_axis.delete = False
        ch.height, ch.width = 9, 18
        ws.add_chart(ch, anchor)

    # Pipeline + pivots
    ws = wb.create_sheet("Pipeline")
    PH = ["scheme", "backend", "payload_bytes", "embedded_bits", "capacity_bits", "util_pct", "wire_bytes",
          "t_kx_ms", "t_kdf_ms", "t_aes_ms", "t_embed_ms", "t_extract_ms", "t_total_ms", "t_total_std_ms",
          "snr_db", "psnr_db", "ber", "ok", "pipeline_peak_mib"]
    table(ws, res["pipeline"], PH)
    ws2 = wb.create_sheet("Pipeline_Pivot")
    schemes = list(dict.fromkeys(p["scheme"] for p in res["pipeline"]))
    kbs = sorted(set(p["payload_bytes"] for p in res["pipeline"]))
    for title, key, r0, anchor, ytitle in (
            ("Total latency vs payload size", "t_total_ms", 1, "H1", "ms"),
            ("Key-exchange latency vs payload size", "t_kx_ms", len(kbs) + 4, "H20", "ms"),
            ("PSNR vs payload size", "psnr_db", 2 * len(kbs) + 7, "H39", "dB")):
        ws2.cell(r0, 1, title).font = Font(bold=True)
        ws2.cell(r0 + 1, 1, "payload (KiB)")
        for j, s in enumerate(schemes):
            ws2.cell(r0 + 1, 2 + j, s)
        for i, b in enumerate(kbs):
            ws2.cell(r0 + 2 + i, 1, b // 1024)
            for j, s in enumerate(schemes):
                v = next((p[key] for p in res["pipeline"] if p["scheme"] == s and p["payload_bytes"] == b), None)
                ws2.cell(r0 + 2 + i, 2 + j, round(v, 4) if v is not None else None)
        ch = LineChart(); ch.title = title; ch.y_axis.title = ytitle; ch.x_axis.title = "Payload (KiB)"
        ch.add_data(Reference(ws2, min_col=2, max_col=1 + len(schemes), min_row=r0 + 1, max_row=r0 + 1 + len(kbs)),
                    titles_from_data=True)
        ch.set_categories(Reference(ws2, min_col=1, min_row=r0 + 2, max_row=r0 + 1 + len(kbs)))
        for s_ in ch.series:
            s_.marker.symbol = "circle"
        ch.x_axis.delete = False; ch.y_axis.delete = False
        ch.height, ch.width = 9, 18
        ws2.add_chart(ch, anchor)
    ws2.column_dimensions["A"].width = 16
    for j in range(len(schemes)):
        ws2.column_dimensions[chr(66 + j)].width = 30

    # Ablation
    ws = wb.create_sheet("Ablation")
    AH = ["variant", "encrypt", "permute", "total_ms", "psnr_db", "entropy", "locality", "ok"]
    last = table(ws, res["ablation"], AH)
    for ttl, col, anchor in (("Entropy of embedded payload (bits/byte)", 6, "J2"),
                             ("Embedding locality (adjacent bits in same frame)", 7, "J20")):
        ch = BarChart(); ch.type = "col"; ch.title = ttl
        ch.add_data(Reference(ws, min_col=col, min_row=1, max_row=last), titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=last))
        ch.x_axis.delete = False; ch.y_axis.delete = False
        ch.height, ch.width = 9, 18
        ws.add_chart(ch, anchor)

    # QBER sweep
    ws = wb.create_sheet("QBER_Sweep")
    QH = ["qber_pct", "time_ms", "sifted", "leaked", "classical_bytes", "sessions", "success_rate"]
    last = table(ws, res["qber"], QH)
    for ttl, col, anchor in (("BB84 post-processing time vs QBER", 2, "J2"),
                             ("Disclosed (leaked) bits vs QBER", 4, "J20")):
        ch = LineChart(); ch.title = ttl; ch.x_axis.title = "QBER (%)"
        ch.add_data(Reference(ws, min_col=col, min_row=1, max_row=last), titles_from_data=True)
        ch.set_categories(Reference(ws, min_col=1, min_row=2, max_row=last))
        ch.series[0].marker.symbol = "circle"
        ch.x_axis.delete = False; ch.y_axis.delete = False
        ch.height, ch.width = 9, 18
        ws.add_chart(ch, anchor)

    ws = wb.create_sheet("Raw_Pipeline_Trials")
    table(ws, res["pipeline_raw"], PH + ["trial"])
    wb.save(path)


# ==========================================================================
# 8.  Plots (used by the GUI)
# ==========================================================================
def make_figure(res):
    from matplotlib.figure import Figure
    fig = Figure(figsize=(11, 7), dpi=100)
    a1, a2, a3, a4 = (fig.add_subplot(2, 2, i) for i in range(1, 5))
    kx = res["kex"]
    a1.bar([f"{x['scheme']}\n{x['backend']}" for x in kx], [x["total_ms"] for x in kx], color="#2F5597")
    a1.set_yscale("log"); a1.set_ylabel("ms"); a1.set_title("Key-exchange time"); a1.tick_params(labelsize=6)
    a2.bar([f"{x['scheme']}" for x in kx], [x["wire_bytes"] for x in kx], color="#C55A11")
    a2.set_ylabel("bytes"); a2.set_title("Wire overhead"); a2.tick_params(labelsize=6)
    schemes = list(dict.fromkeys(p["scheme"] for p in res["pipeline"]))
    for s in schemes:
        rows = [p for p in res["pipeline"] if p["scheme"] == s]
        a3.plot([p["payload_bytes"] / 1024 for p in rows], [p["t_total_ms"] for p in rows], "o-", label=s)
        a4.plot([p["payload_bytes"] / 1024 for p in rows], [p["psnr_db"] for p in rows], "s-", label=s)
    a3.set_xlabel("payload (KiB)"); a3.set_ylabel("ms"); a3.set_title("End-to-end latency"); a3.legend(fontsize=6)
    a4.set_xlabel("payload (KiB)"); a4.set_ylabel("dB"); a4.set_title("PSNR"); a4.legend(fontsize=6)
    fig.tight_layout()
    return fig


# ==========================================================================
# 9.  GUI (tkinter)
# ==========================================================================
def run_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except Exception:
        print("tkinter is not available - use --cli instead.")
        return
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    root = tk.Tk()
    root.title("PQC (ML-KEM) vs QKD-Sim Steganography Benchmark")
    root.geometry("1250x820")
    q = queue.Queue()
    state = dict(stop=False, res=None, canvas=None)

    left = ttk.Frame(root, padding=8)
    left.pack(side="left", fill="y")
    right = ttk.Frame(root, padding=8)
    right.pack(side="right", fill="both", expand=True)

    vars_ = dict(
        audio=tk.StringVar(value=""), seconds=tk.StringVar(value="20"), trials=tk.StringVar(value="10"),
        ptrials=tk.StringVar(value="5"), payload=tk.StringVar(value="1,4,8,16,32"),
        qubits=tk.StringVar(value="2048"), qber=tk.StringVar(value="2.0"),
        out=tk.StringVar(value=os.path.abspath("pqc_stego_results.xlsx")),
        skip_pure=tk.BooleanVar(value=False))

    def row(label, key, r, browse=None):
        ttk.Label(left, text=label).grid(row=r, column=0, sticky="w", pady=2)
        ttk.Entry(left, textvariable=vars_[key], width=26).grid(row=r, column=1, pady=2)
        if browse:
            ttk.Button(left, text="...", width=3, command=browse).grid(row=r, column=2)

    def pick_audio():
        p = filedialog.askopenfilename(filetypes=[("WAV", "*.wav")])
        if p:
            vars_["audio"].set(p)

    def pick_out():
        p = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if p:
            vars_["out"].set(p)

    ttk.Label(left, text="Configuration", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=3, sticky="w")
    row("Cover WAV (blank = synthetic)", "audio", 1, pick_audio)
    row("Synthetic length (s)", "seconds", 2)
    row("KEM trials", "trials", 3)
    row("Pipeline trials", "ptrials", 4)
    row("Payload sizes (KiB, comma)", "payload", 5)
    row("BB84 qubits", "qubits", 6)
    row("BB84 QBER (%)", "qber", 7)
    row("Excel output", "out", 8, pick_out)
    ttk.Checkbutton(left, text="Skip pure-Python ML-KEM (faster)", variable=vars_["skip_pure"]).grid(
        row=9, column=0, columnspan=3, sticky="w")
    be_txt = f"Back-ends: liboqs={'yes' if HAVE_OQS else 'no'}, OpenSSL ML-KEM={'yes' if HAVE_OPENSSL_MLKEM else 'no'}, pure=yes"
    ttk.Label(left, text=be_txt, wraplength=300, foreground="#444").grid(row=10, column=0, columnspan=3, sticky="w", pady=4)
    prog = ttk.Progressbar(left, length=300, mode="determinate", maximum=1.0)
    prog.grid(row=12, column=0, columnspan=3, pady=8)

    nb = ttk.Notebook(right)
    nb.pack(fill="both", expand=True)
    log_tab, res_tab, plot_tab = ttk.Frame(nb), ttk.Frame(nb), ttk.Frame(nb)
    nb.add(log_tab, text="Log"); nb.add(res_tab, text="Results"); nb.add(plot_tab, text="Plots")
    logbox = tk.Text(log_tab, wrap="word", font=("Consolas", 9))
    logbox.pack(fill="both", expand=True)
    cols = ("scheme", "backend", "wire B", "keygen ms", "encaps ms", "decaps ms", "total ms", "mem KiB")
    tree = ttk.Treeview(res_tab, columns=cols, show="headings", height=10)
    for c in cols:
        tree.heading(c, text=c); tree.column(c, width=105, anchor="center")
    tree.pack(fill="x")
    tree2 = ttk.Treeview(res_tab, columns=("scheme", "KiB", "total ms", "kx ms", "PSNR", "BER", "ok"), show="headings", height=14)
    for c in ("scheme", "KiB", "total ms", "kx ms", "PSNR", "BER", "ok"):
        tree2.heading(c, text=c); tree2.column(c, width=130, anchor="center")
    tree2.pack(fill="both", expand=True, pady=6)

    def log(msg):
        q.put(("log", msg))

    def worker(cfg):
        try:
            res = run_all(cfg, log=log, progress=lambda f: q.put(("prog", f)), stop=lambda: state["stop"])
            save_excel(res, cfg["out"])
            log(f"\nExcel written: {cfg['out']}")
            q.put(("done", res))
        except Exception as e:
            q.put(("err", repr(e)))

    def start():
        try:
            cfg = dict(DEFAULT_CFG)
            cfg.update(audio_path=vars_["audio"].get() or None, seconds=float(vars_["seconds"].get()),
                       trials=int(vars_["trials"].get()), pipe_trials=int(vars_["ptrials"].get()),
                       payload_kb=[int(x) for x in vars_["payload"].get().split(",") if x.strip()],
                       qkd_qubits=int(vars_["qubits"].get()), qber=float(vars_["qber"].get()) / 100.0,
                       skip_pure=vars_["skip_pure"].get(), out=vars_["out"].get())
        except ValueError:
            messagebox.showerror("Input error", "Please check the numeric fields.")
            return
        state["stop"] = False
        logbox.delete("1.0", "end"); prog["value"] = 0
        run_btn.config(state="disabled")
        threading.Thread(target=worker, args=(cfg,), daemon=True).start()

    def poll():
        try:
            while True:
                kind, val = q.get_nowait()
                if kind == "log":
                    logbox.insert("end", val + "\n"); logbox.see("end")
                elif kind == "prog":
                    prog["value"] = val
                elif kind == "err":
                    logbox.insert("end", "ERROR: " + val + "\n"); run_btn.config(state="normal")
                elif kind == "done":
                    res = val; state["res"] = res; run_btn.config(state="normal")
                    tree.delete(*tree.get_children()); tree2.delete(*tree2.get_children())
                    for x in res["kex"]:
                        tree.insert("", "end", values=(x["scheme"], x["backend"], x["wire_bytes"],
                                    f"{x['keygen_ms']:.3f}", f"{x['encaps_ms']:.3f}", f"{x['decaps_ms']:.3f}",
                                    f"{x['total_ms']:.3f}", f"{x['peak_mem_kib']:.1f}"))
                    for p in res["pipeline"]:
                        tree2.insert("", "end", values=(p["scheme"], p["payload_bytes"] // 1024,
                                     f"{p['t_total_ms']:.1f}", f"{p['t_kx_ms']:.2f}", f"{p['psnr_db']:.1f}",
                                     f"{p['ber']:.0e}", p["ok"]))
                    if state["canvas"]:
                        state["canvas"].get_tk_widget().destroy()
                    state["canvas"] = FigureCanvasTkAgg(make_figure(res), master=plot_tab)
                    state["canvas"].draw(); state["canvas"].get_tk_widget().pack(fill="both", expand=True)
                    messagebox.showinfo("Done", "Benchmark finished. Excel file saved:\n" + vars_["out"].get())
        except queue.Empty:
            pass
        root.after(100, poll)

    def run_selftest():
        logbox.delete("1.0", "end")
        ok = selftest(lambda m: logbox.insert("end", m + "\n"))
        logbox.insert("end", "SELF-TEST " + ("PASSED" if ok else "FAILED") + "\n")

    run_btn = ttk.Button(left, text="Run benchmark", command=start)
    run_btn.grid(row=11, column=0, pady=6, sticky="w")
    ttk.Button(left, text="Stop", command=lambda: state.update(stop=True)).grid(row=11, column=1, sticky="w")
    ttk.Button(left, text="ML-KEM self-test", command=run_selftest).grid(row=13, column=0, columnspan=2, sticky="w")
    poll()
    root.mainloop()


# ==========================================================================
# 10. Entry point
# ==========================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--trials", type=int, default=DEFAULT_CFG["trials"])
    ap.add_argument("--pipe-trials", type=int, default=DEFAULT_CFG["pipe_trials"])
    ap.add_argument("--audio", default=None)
    ap.add_argument("--out", default="pqc_stego_results.xlsx")
    ap.add_argument("--json", default=None)
    ap.add_argument("--skip-pure", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if not a.cli:
        run_gui()
        return
    cfg = dict(DEFAULT_CFG)
    cfg.update(trials=a.trials, pipe_trials=a.pipe_trials, audio_path=a.audio, skip_pure=a.skip_pure)
    if a.quick:
        cfg.update(trials=3, pipe_trials=2, payload_kb=[1, 4], seconds=8,
                   qber_sweep=[0.01, 0.03], qber_sweep_qubits=4096, skip_pure=True)
    res = run_all(cfg)
    save_excel(res, a.out)
    print("Excel written:", a.out)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=1, default=str)
        print("JSON written:", a.json)


if __name__ == "__main__":
    main()
