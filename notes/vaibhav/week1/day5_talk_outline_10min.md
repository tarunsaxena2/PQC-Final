# 10-minute talk: key layer (Vaibhav)

1. (1 min) What the key layer owns: KEM back-ends, BB84-sim, hybrid combiner, HKDF, keygen, dk storage, zeroise.
2. (2 min) What a KEM is: keygen, encaps, decaps; sizes for ML-KEM-512/768/1024 (768: ek 1,184 B, ct 1,088 B, ss 32 B). Implicit rejection.
3. (2 min) Key hierarchy: ss -> HKDF-SHA256 -> 64 B = K_AES 16 + K_perm 16 + K_MAC 32. Why the receiver must read the header (ciphertext) first.
4. (2 min) The three modes: pqc, hybrid-x25519, hybrid-qkdsim (simulated key file, not quantum security).
5. (1 min) Back-ends: liboqs is the headline (installed: liboqs 0.16.0, liboqs-python 0.16.0.2, Python 3.14.5), OpenSSL via cryptography for 768/1024, pure-Python for validation only.
6. (1 min) Honest limits: PQC sends more bytes than BB84 classical traffic (2,272 B vs about 739 B), no authentication from the exchange alone, zeroise is best effort.
7. (1 min) Questions. Likely: why ML-KEM and not QKD (no special hardware, no distance limit, software deployable, NIST standard FIPS 203).
