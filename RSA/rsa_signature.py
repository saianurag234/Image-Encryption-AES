from RSA.encrypt import *
from RSA.decrypt import *
from RSA.sha256 import sha256
from RSA.rsa_utils import *
from RSA.rsa_padding import *
from RSA.rsa_constant import KEY_SIZE


def rsa_encrypt(master_key, private_key):

    mk_int = byte_to_integer(master_key)
    d, n = private_key
    encrypted_message = pow(mk_int, d, n)

    return encrypted_message


def rsa_decrypt(encrypted_message, public_key):
    e, n = public_key

    decrypted_message = pow(encrypted_message, e, n)

    bytes_decrypted_message = integer_to_byte(
        decrypted_message, KEY_SIZE // 32)

    return bytes_decrypted_message


def generate_signature(master_key, private_key):
    master_key_bytes = bytearray(master_key).hex()

    key_hash = sha256(master_key_bytes).to_bytes()

    signature = rsa_encrypt(key_hash, private_key)

    return signature, key_hash


def is_signature_valid(key_hash, signature, public_key):

    retrived_signature = rsa_decrypt(signature, public_key)

    if key_hash != retrived_signature:
        return False

    return True
