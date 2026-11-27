4.4 Encryption and integrity of the container body

The payload is protected with AES-128 in CBC mode followed by an HMAC-SHA256 tag (encrypt-then-MAC).
For a payload P of n bytes, the sender pads P with PKCS#7 padding to P', draws a fresh 16-byte IV
and computes

    C_i = AES_K_AES( P'_i XOR C_(i-1) ),  C_0 = IV                       (4.x)
    T   = HMAC-SHA256( K_MAC, H || IV || C )                              (4.y)

where H is the container header (magic, version, security level, mode byte, KEM ciphertext, body
length). The body is IV || C || T and has 16 + 16(floor(n/16) + 1) + 32 bytes.

The receiver recomputes T and compares it with the received tag in constant time. Decryption is
performed only if the tags match. A wrong key, a modified header, IV, ciphertext or tag, and an
invalid length all give the same error message, and no partial output is produced.

Option: AES-128-GCM. (C, T) = AES-GCM( K_AES, N, P, AAD = H ) with a 12-byte nonce N and a 16-byte
tag. The body is N || C || T and has 12 + n + 16 bytes. CBC with HMAC is the default.

Keys: K_AES (16 B) and K_MAC (32 B) come from the 64-byte HKDF output together with K_perm (16 B).
Each hide operation encapsulates a new KEM secret (confirm this in the facade), so the keys are
fresh for every message.

Overhead (ML-KEM-768): header 1,099 B; body overhead 49 to 64 B (CBC, with padding) or 28 B (GCM);
about 2.2% of a 20 s clip's 51,652 B capacity. Quote the exact figures from scratch\overhead_table.py.
