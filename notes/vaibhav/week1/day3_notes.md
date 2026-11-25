# Week 1 Day 3: kem_demo and back-end comparison

Run (venv active, project root):
```
python code/kem_demo.py --write
```
This prints and saves `notes/vaibhav/week1/day3_kem_demo_results.md` with: size table, round-trip result, back-end availability, cross-back-end agreement, and the OpenSSL ML-KEM availability note.

Already checked in my sandbox with cryptography 50.0.2: the wheel exposes `MLKEM768` and `MLKEM1024` (no 512). Confirm the same on your Windows machine from the generated file; write the answer in the OpenSSL note section.

Pure-Python back-end: not written yet because the existing benchmark script is not in the repo. When it is, wrap its ML-KEM in `code/key_layer/pure_backend.py` (same four functions as `liboqs_backend.py`) and the demo will pick it up automatically.
