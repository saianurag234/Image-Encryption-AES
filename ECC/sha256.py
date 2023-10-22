import hashlib

def Sha256(array):
    array_bytes = bytearray(array)
    hasher = hashlib.sha256()
    hasher.update(array_bytes)
    
    return hasher