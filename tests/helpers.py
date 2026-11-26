import os
import container as c


def make_header(n, gcm=False, level=2, mode=c.MODE_PQC):
    return c.Header(level=level, mode=mode, kem_ct=os.urandom(c.CT_LEN[level]),
                    body_len=c.body_length(n, gcm), gcm=gcm)
