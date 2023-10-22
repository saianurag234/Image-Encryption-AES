import hashlib

def Sha512(array):
    array_bytes = bytearray(array)
    hasher = hashlib.sha512()
    hasher.update(array_bytes)
    
    return hasher