from ECC.sha256 import *
from ECC.sha512 import *
from ECC.AES import *
from ECC.curve import *
from ECC.ecc import *
from user_constant import *

def alice_encrypts(msg,alice,bob):
    curve = Secp521r1()
    weierstrass = Weierstrass(curve.p,curve.a,curve.b)

    a_shared_sec = weierstrass.multiply(bob.pub_k,alice.pri_k)[0]

    a_shared_sec = hkdf(a_shared_sec, hkdf_salt, HKDF_HASHF, HASHLEN, HASH_BLOCK_SIZE,hkdf_info,HKDF_SIZE,SHARED_KEY_SIZE)

    ecdsa = Ecdsa(curve)
    signature = ecdsa.gen_signature(msg, alice.pri_k)

    ecies = Ecies(SHARED_KEY_SIZE,ECIES_SYMM_ENC_ALG,CURVE)
    tag = ecies.gen_hmac(msg,a_shared_sec,ECIES_HMAC_HASHF, ECIES_HMAC_HASHF_BLOCK_SIZE)
    ciphertext = ecies.encrypt(msg,a_shared_sec)

    return ciphertext, tag, signature
