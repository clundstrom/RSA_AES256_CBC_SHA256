import hashlib


def int_to_bytes(i):
    i = int(i)
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


def asymm_handshake(payload: bytes):
    rsa_pk = payload[0:-32]
    rsa_pk_hash = payload[-32:]

    compare_hash = hashlib.sha256(rsa_pk).digest()
    return compare_hash == rsa_pk_hash
