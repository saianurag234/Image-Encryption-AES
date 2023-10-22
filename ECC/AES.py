from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes  

class AES256:
    def __init__(self) -> None:
        pass

    @staticmethod
    def encrypt(data_bytes: bytes, key: bytes, iv: bytes = None) -> bytes:

        if len(key) != 32: 
            raise ValueError("Invalid key length: expected 32 bytes for AES-256.")
        
        if iv is None:
            iv = get_random_bytes(16)
            
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
        return iv + ciphertext 

    @staticmethod
    def decrypt(iv_and_ciphertext: bytes,key: bytes) -> bytes:

        print(f"Key at start of decrypt method: {key}")
        print(f"Key length at start of decrypt method: {len(key)}")

        if len(key) != 32:  
            raise ValueError("Invalid key length: expected 32 bytes for AES-256.")
        
        iv, ciphertext = iv_and_ciphertext[:16], iv_and_ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)