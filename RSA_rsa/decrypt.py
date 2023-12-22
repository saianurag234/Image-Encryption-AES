from rsa_utils import *
from rsa_padding import *
from rsa_constant import *


def rsa_decryption(encrypted_message, private_key):
    d, n = private_key

    m_int = pow(encrypted_message, d, n)

    decryption_res = integer_to_byte(m_int, KEY_SIZE // 8)

    upadded_decryption_res = pkcs1_v1_5_unpad(decryption_res)

    decrypted_message = bytearray_to_array(upadded_decryption_res)

    return decrypted_message
