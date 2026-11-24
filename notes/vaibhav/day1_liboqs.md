\# Week 1 Day 1: liboqs setup (Vaibhav, Key Layer)



\## Environment

\- OS: Windows, Version 26H2 (OS Build 26300.9974)

\- Python: 3.14.5 (venv)

\- liboqs: 0.16.0

\- liboqs-python: 0.16.0.2

\- MSVC: 19.44.35230 (VS Build Tools 2022 17.14.45)

\- CMake: 4.4.4

\- Git: 2.53.0



\## Install method

`pip install liboqs-python`, run from the x64 Native Tools Command Prompt.

liboqs was built automatically on first `import oqs`.

No manual cmake flags were needed, so the manual build was not required.



\## Wheel check

Command: pip install --only-binary=:all: numpy scipy cryptography openpyxl matplotlib psutil pytest

Result: passed on Python 3.14.5 (all packages installed from wheels).

Key versions: cryptography 50.0.2, numpy 2.5.5, scipy 1.18.1, psutil 7.2.2,

matplotlib 3.11.2, openpyxl 3.1.5, pytest 9.2.0

Full list: versions\_day1.txt



\## Enabled algorithms

ML-KEM: \['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']

ML-DSA: \['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']

Screenshot: enabled\_kem\_list.png

Raw output: enabled\_algorithms.txt

(liboqs-python prints "faulthandler is disabled" on import; harmless.)



\## Round-trip check (ML-KEM-768)

CHECK: public key 1184 B, ciphertext 1088 B, secrets match: True

(update this line with the real output of the rerun)



\## Notes for the report

\- Old Table 4.2 and Appendix A say liboqs 0.16.0 with ML-KEM only. The version

&#x20; matches; ML-DSA-44/65/87 are also enabled and must be added there.

\- cryptography is 50.0.2, which matches the old report. The code docstring says

&#x20; cryptography >= 47; Tarun is tracking that mismatch.

\- Python 3.14.5 and the full wheel set work with no workaround.



\## Issues

None. The first round-trip attempt failed only because the venv was not active.

