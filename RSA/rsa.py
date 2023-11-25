from encrypt import *
from decrypt import *
from RSA.rsa_utils import *
import random
from sympy import nextprime
from RSA.rsa_constant import e

# def get_e_val(phi):
#     random_start = random.getrandbits(1024)
#     e = nextprime(random_start)

#     while gcd(e, phi) != 1:
#         e = nextprime(e)

#     return e


def get_d_val(e, phi):
    d = modinv(e, phi)
    return d


def get_n_value(p, q):
    return p*q


def euler_phi(p, q):
    n = (p-1)*(q-1)

    return n


def public_key(e, n):
    return (e, n)


def private_key(d, n):
    return (d, n)
