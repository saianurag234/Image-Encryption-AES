def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return abs(a)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m


def pow(x, y, p):
    res = 1
    x = x % p
    while (y > 0):

        if ((y & 1) == 1):
            res = (res * x) % p

        y = y >> 1
        x = (x * x) % p

    return res


def byte_to_integer(byte_array):
    return int.from_bytes(byte_array, 'big')


def integer_to_byte(integer, length):
    return integer.to_bytes(length, 'big')


def bytearray_to_array(byte_array):
    return [byte for byte in byte_array]
