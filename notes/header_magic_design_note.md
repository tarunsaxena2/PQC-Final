# Header / magic design note (container v1)

Decision: keep a 4-byte plaintext magic "PQCS" in v1.

Why: it lets extract() reject a non-stego or foreign WAV with a clear error, separately from
"wrong key" (MAC failure). It also carries the version for later format changes. The magic is
covered by the MAC, so it cannot be altered undetected.

Limitation (to be stated in 6.12b / 6.12c): the header sits at fixed positions and starts with a
known value, so anyone who can read the QIM positions can recognise a stego file. The KEM
ciphertext itself looks random. This is a detectability limitation, not a confidentiality one.

Alternative (future work): drop the magic and send the ciphertext as a separate file. Extraction
failure then cannot distinguish "no message" from "wrong key".
