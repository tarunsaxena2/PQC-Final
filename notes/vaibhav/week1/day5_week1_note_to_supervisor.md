Subject: PQC Hybrid Audio Steganography: Week 1 progress note

Respected Sir,

Week 1 status (Key layer, Vaibhav Gautam):

Done
- liboqs 0.16.0 and liboqs-python 0.16.0.2 installed and working on Windows with Python 3.14.5 (pip route, no manual build). ML-KEM-512/768/1024 and ML-DSA-44/65/87 are enabled; ML-KEM-768 round trip gives 1,184 B public key, 1,088 B ciphertext, matching secrets.
- Key-layer interface written and frozen with a working stub; HKDF key split (16 + 16 + 32 bytes) and simulated-QKD key file helpers implemented with tests.
- ML-KEM demo and back-end comparison (liboqs, OpenSSL through the cryptography package; pure-Python pending).
- References 1 to 9 verification and QKD note part A drafted.

In progress
- Pure-Python back-end wrapper; remaining reference checks.

Blockers
- None so far. (Add any new one here.)

Next week
- Back-end selector, keygen tool, hybrid combiner, tests T1 to T4, T16.

Please confirm
1. The names and designations of the Guide, Project Coordinator and HOD as printed in the report.
2. Preferred project title, whether slides are required, and the final deadline.
3. Scope: which Stretch items are in scope; whether AES-CBC + HMAC stays the default with AES-GCM as an option; whether a research paper is required.

Regards,
Vaibhav Gautam, on behalf of the team
