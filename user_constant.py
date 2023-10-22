from ECC.sha256 import Sha256
from ECC.sha512 import Sha512
from ECC.AES import AES256
from ECC.curve import Secp521r1

# Constants
HASHLEN = 32 
HASH_BLOCK_SIZE = 64 
HKDF_SIZE = 32 
HKDF_HASHF = Sha256 
SHARED_KEY_SIZE = 66 
MSG_SALT = "" 
CURVE = Secp521r1 
ECIES_SYMM_ENC_ALG = AES256 
ECIES_HMAC_HASHF = Sha512 
ECIES_HMAC_HASHF_BLOCK_SIZE = 128

hkdf_salt = b'p\xc3\xfc\xb7\xb4\xacY\xfeh.^o\xc5\xf4\x05\xc0w\x03\xb9}\x97C\xcf\xadI\x0c\x0f_\x8c\x82@\xe3'
hkdf_info = b"testing"
