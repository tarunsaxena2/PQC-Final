"""container.py - FROZEN INTERFACE v1 (real implementation). Owner: Uday, container and integrity layer."""
from container_header import (CT_LEN, FLAG_GCM, MAGIC, MODE_HYBRID_QKDSIM, MODE_HYBRID_X25519, MODE_NAMES,
                              MODE_PQC, PREFIX_LEN, VERSION, ContainerError, Header, header_decode,
                              header_encode, header_len, peek_header_len)
from container_crypto import body_length, pack, unpack, zeroise
