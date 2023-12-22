from rsa_utils import *
from rsa_padding import *
from rsa_constant import KEY_SIZE


def rsa_encryption(master_key, public_key):

    master_key_bytes = bytearray(master_key)

    padded_master_key = pkcs1_v1_5_pad(master_key_bytes, KEY_SIZE // 8)

    mk_int = byte_to_integer(padded_master_key)
    e, n = public_key
    encrypted_message = pow(mk_int, e, n)

    return encrypted_message
