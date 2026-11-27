# Randomness audit (U9) - from git grep of HEAD, dev-vaibhav and tarun/tool-benchmark, 2026-11-27

| Source | File / line | Generator | Used for | Security-critical? | Finding / action |
|---|---|---|---|---|---|
| CBC IV | code/container_crypto.py:58 | os.urandom(16) | fresh IV per message | yes | OK: Windows system CSPRNG |
| GCM nonce | code/container_crypto.py:55 | os.urandom(12) | fresh nonce per message | yes | OK; key is fresh per message (new KEM secret) |
| ML-KEM randomness, liboqs | inside liboqs (C) | liboqs default RNG: system or OpenSSL RAND_bytes by build option | keygen, encaps | yes | Not visible in grep; confirm build flags with Vaibhav (liboqs 0.16.0) |
| ML-KEM randomness, OpenSSL back-end | key_layer/openssl_backend.py | library-internal | keygen, encaps | yes | Not visible in grep; library RNG |
| ML-KEM randomness, pure-Python | key_layer/pure_backend.py:209,210,217 | os.urandom(32) for d, z, m | keygen, encaps | yes | OK; same code duplicated in pqc_stego_benchmark.py:271-279, keep one copy |
| Simulated-QKD key file | key_layer/interface.py:96 | os.urandom(QKD_KEY_LEN) | K_QKD in hybrid-qkdsim | yes (it feeds the hybrid key) | OK; label as simulation in README and report |
| BB84-sim bits, bases, channel noise | pqc_stego_benchmark.py:427, 478 | NumPy default_rng (not cryptographic) | simulation | no (simulation only) | CONFIRM by reading the code; never called quantum security |
| Dither | pqc_stego_benchmark.py:522 | np.random.default_rng(12345), fixed seed, module-level | sub-LSB dither | no | Ask Yatharth what it is for; record seed 12345 |
| Keyed permutation | pqc_stego_benchmark.py:22 | AES-CTR argsort keyed by K_perm | embedding order | derived from K_perm | Deterministic, not an entropy source |
| Old CBC IV | pqc_stego_benchmark.py:658 | os.urandom(16) | pre-v7 CBC code | yes if still used | Confirm facade uses container.pack (HMAC) |
| Benchmark and test seeds | pqc_stego_benchmark.py:525, 606, 708, 860; tests | default_rng(seed) | reproducible data | no | Record seeds in the result sheets |
