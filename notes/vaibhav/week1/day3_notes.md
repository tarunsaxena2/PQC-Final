# Week 1 Day 3: kem_demo and back-end comparison

Run (venv active, project root):
```
python code/kem_demo.py --write
```
This prints and saves `notes/vaibhav/week1/day3_kem_demo_results.md` with: size table, round-trip result, back-end availability, cross-back-end agreement, and the OpenSSL ML-KEM availability note.

Already checked in my sandbox with cryptography 50.0.2: the wheel exposes `MLKEM768` and `MLKEM1024` (no 512). Confirm the same on your Windows machine from the generated file; write the answer in the OpenSSL note section.

Pure-Python back-end: now included (`code/key_layer/pure_backend.py`, core copied from the team benchmark script). `tests/test_pure_backend.py` checks sizes, round trip, implicit rejection, same public key from the same 64 B seed as OpenSSL, and cross-decapsulation both ways.
