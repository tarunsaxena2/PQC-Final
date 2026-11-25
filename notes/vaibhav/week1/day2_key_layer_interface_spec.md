# Week 1 Day 2: Key-layer interface spec (FROZEN after the 30-minute meeting)

Owner: Vaibhav Gautam. Code: `code/key_layer/`. Stub: `code/key_layer/stub.py`.
Changing anything here needs all four members to agree (team rule 5).

## Functions
| Call | Returns | Notes |
|---|---|---|
| `keygen(level)` | `(ek, dk)` bytes | level in {512, 768, 1024} |
| `encaps(ek)` | `(ct, ss)` bytes | ss is 32 B; ct is embedded in the header |
| `decaps(dk, ct)` | `ss` (32 B) | wrong or corrupted ct gives a different ss (implicit rejection), no exception |
| `derive_keys(ss, k_qkd=None)` | 64 B | HKDF-SHA256; hybrid modes pass `k_qkd`, input is `ss || k_qkd` |
| `split_keys(okm)` | `(K_AES, K_perm, K_MAC)` | 16 B + 16 B + 32 B |
| `zeroise(buf)` | bool | bytearray / writable memoryview only; best effort, see limit below |
| `write_qkd_keyfile(path, key=None)` | Path | simulated-QKD key file, hybrid-qkdsim only |
| `read_qkd_keyfile(path)` | 16 B `K_QKD` (32 B also accepted) | raises `QkdKeyFileError` with a plain message |

Errors: every failure raises `KeyLayerError` (or the subclass `QkdKeyFileError`) with a message that never contains secret bytes.

## FIPS 203 sizes (bytes)
| Level | ek | dk | ct | ss |
|---|---|---|---|---|
| 512 | 800 | 1632 | 768 | 32 |
| 768 | 1184 | 2400 | 1088 | 32 |
| 1024 | 1568 | 3168 | 1568 | 32 |

## Key hierarchy
`ss` (32 B) -> HKDF-SHA256 (info `pqc-stego-v1`, the same string as the team benchmark script, so the first 32 B equal the old K_AES and K_perm) -> 64 B = `K_AES` 16 B + `K_perm` 16 B + `K_MAC` 32 B.
Optional AES-256 (Uday) would use a 32 B `K_AES`; that changes the split and needs the group's agreement.
The symbol is `K_perm` everywhere (never K-pi).

## Modes (V7-3) as seen by the key layer
- `pqc`: input to HKDF is `ss`.
- `hybrid-x25519`: both public keys travel on the classical channel; input is the combined secret (combiner added in Week 2 Day 2).
- `hybrid-qkdsim`: input is `ss || K_QKD`, `K_QKD` read from the simulated-QKD key file shared out of band. This is a SIMULATION, not quantum security.

## Back-ends
`liboqs_backend` (headline), `openssl_backend` (cryptography wheel, 768 and 1024 only, dk is a 64 B seed), `pure_backend` (pure-Python, validation only, not constant-time). Every result states which back-end made it.

## Limits to state in the report
- `zeroise` cannot wipe immutable `bytes` or copies the interpreter made. Do not claim memory is wiped.
- The stub returns one fixed dummy secret and is NOT secure. It exists only so the other layers can code against correct sizes.

## Sign-off
- [ ] Presented in the 30-minute meeting
- [ ] Frozen on: ____ (date), agreed by Yatharth / Uday / Tarun
