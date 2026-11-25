# Receiver key-pair design note (Vaibhav, Week 1 Day 5)

## Who does what
- **Receiver** runs `keygen` once. It creates `receiver.ek` (public) and `receiver.dk.enc` (secret, encrypted).
- **Sender** needs only `receiver.ek`. It is shared in advance on any channel; it is public, but check its fingerprint or signature (see authentication below).
- Only the KEM ciphertext (1,088 B for ML-KEM-768) is embedded in the stego file, not the public key.

## File formats (all binary, `pathlib`, no text mode)
| File | Content |
|---|---|
| `receiver.ek` | magic `PQEK`, version 1 byte, level 2 bytes, raw ek |
| `receiver.dk.enc` | magic `PQDK`, version, level, scrypt salt (16 B), scrypt params (n, r, p), nonce (12 B), AES-GCM ciphertext of raw dk with its tag |
| `sim_qkd.key` | magic `SIMQKDv1`, length byte (16 or 32), key, 4 B check (simulation only). Default 16 B = the 128-bit key the BB84 simulator produces |

## dk storage on Windows (V7)
- Default: passphrase-encrypted with scrypt (cryptography `Scrypt`) and AES-GCM. No dependence on Unix file mode bits.
- Optional: restrict the file with `icacls receiver.dk.enc /inheritance:r /grant:r "%USERNAME%:R"`, or protect with Windows DPAPI.
- Never write dk, ss or derived keys to logs, Excel or JSON. Zeroise buffers after use (best effort in Python; state the limit).
- The passphrase is typed at the prompt or read from an environment variable the user sets; it is never stored.

## Simulated-QKD key file design (hybrid-qkdsim)
- One side writes `sim_qkd.key` once (`write_qkd_keyfile`); the file is delivered out of band to the other side.
- Both sides read it with `read_qkd_keyfile` and pass `K_QKD` (16 B) to `derive_keys(ss, k_qkd)`.
- Extract without the file fails cleanly (test T11). README and report must say the word "simulation".

## Authentication gap (feeds 6.12a)
A KEM exchange alone does not authenticate the receiver's ek. Fix: sign ek with ML-DSA (liboqs has ML-DSA-44/65/87 enabled) or compare a fingerprint over a trusted channel.
