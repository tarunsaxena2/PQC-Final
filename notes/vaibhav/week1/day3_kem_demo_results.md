# Day 3 results: ML-KEM demo and back-end comparison

Python 3.14.5 on Windows-11-10.0.26300-SP0

liboqs 0.16.0, liboqs-python 0.16.0.2
cryptography 50.0.2

## Sizes and round trips (ek / dk / ct / ss in bytes; medians of 20 runs, ms, order of magnitude only)

| Back-end | Level | ek | dk | ct | ss | FIPS 203 sizes | Round trip | keygen ms | encaps ms | decaps ms |
|---|---|---|---|---|---|---|---|---|---|---|
| liboqs | 512 | 800 | 1632 | 768 | 32 | yes | True | 0.136 | 0.170 | 0.208 |
| liboqs | 768 | 1184 | 2400 | 1088 | 32 | yes | True | 0.211 | 0.249 | 0.296 |
| liboqs | 1024 | 1568 | 3168 | 1568 | 32 | yes | True | 0.305 | 0.347 | 0.403 |
| openssl | 512 | - | - | - | - | - | not supported | - | - | - |
| openssl | 768 | 1184 | 64 | 1088 | 32 | ek/ct yes; dk is 64 B seed | True | 0.172 | 0.056 | 0.199 |
| openssl | 1024 | 1568 | 64 | 1568 | 32 | ek/ct yes; dk is 64 B seed | True | 0.239 | 0.078 | 0.269 |
| pure-python | 512 | 800 | 1632 | 768 | 32 | yes | True | 1.626 | 2.241 | 3.146 |
| pure-python | 768 | 1184 | 2400 | 1088 | 32 | yes | True | 2.660 | 3.431 | 4.630 |
| pure-python | 1024 | 1568 | 3168 | 1568 | 32 | yes | True | 4.024 | 4.846 | 6.378 |

## Back-end availability

- liboqs: available
- openssl: available
- pure-python: available

## Cross-back-end agreement (swap ek / ct; each side decapsulates with its own dk)

- ML-KEM-768: liboqs encaps -> OpenSSL decaps True; OpenSSL encaps -> liboqs decaps True
- ML-KEM-1024: liboqs encaps -> OpenSSL decaps True; OpenSSL encaps -> liboqs decaps True

## OpenSSL ML-KEM availability note

- The cryptography wheel exposes ML-KEM-768 and ML-KEM-1024 (not 512), so OpenSSL can be a third back-end for those two levels.
- Only the speed ORDER of magnitude is recorded here; the real timing runs (E1) are in Week 3 on the frozen machine.
