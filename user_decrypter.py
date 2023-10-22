from ECC.sha256 import *
from ECC.sha512 import *
from ECC.AES import *
from ECC.curve import *
from ECC.ecc import *
from user_constant import *

def alice_decrypts(ciphertext, tag, signature,alice,bob):
    curve = Secp521r1()
    weierstrass = Weierstrass(curve.p,curve.a,curve.b)

    b_shared_sec = weierstrass.multiply(alice.pub_k,bob.pri_k)[0]
    
    b_shared_sec = hkdf(b_shared_sec, hkdf_salt, HKDF_HASHF, HASHLEN,HASH_BLOCK_SIZE,hkdf_info,HKDF_SIZE,SHARED_KEY_SIZE)

    ecies = Ecies(SHARED_KEY_SIZE,ECIES_SYMM_ENC_ALG,CURVE)
    plaintext = ecies.decrypt(ciphertext,b_shared_sec)
    byte_array = bytearray(plaintext)
    master_key = list(byte_array)

    ecdsa = Ecdsa(curve)

    verify_tag = ecies.verify_hmac(plaintext,b_shared_sec,tag)

    m_hash = int(str(Sha512(plaintext).hexdigest()),16) % curve.n

    verify_sign = ecdsa.verify_signature(signature, m_hash,alice.pub_k)

    m_hash = int(str(Sha512(plaintext).hexdigest()),16) % curve.n

    recovered_a_pubk = ecdsa.recover_pubkey(m_hash, signature)

    return master_key,verify_tag,verify_sign,recovered_a_pubk