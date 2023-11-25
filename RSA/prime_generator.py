import random


def fermat_test(n, k=11):
    for i in range(k):
        a = random.randrange(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True


# def miller_rabin_test(n, k=10):
#     if n in [2, 3]:
#         return True
#     if n <= 1 or n % 2 == 0:
#         return False

#     r, d = 0, n - 1
#     while d % 2 == 0:
#         r += 1
#         d //= 2

#     for _ in range(k):
#         a = random.randrange(2, n - 2)
#         x = pow(a, d, n)
#         if x == 1 or x == n - 1:
#             continue
#         for _ in range(r - 1):
#             x = pow(x, 2, n)
#             if x == n - 1:
#                 break
#         else:
#             return False
#     return True

def miller_rabin_test(number):
    num1 = number - 1
    num2 = 0
    while num1 % 2 == 0:
        num1 //= 2
        num2 += 1

    for i in range(5):
        random_num = random.randrange(2, number - 1)
        remainder = pow(random_num, num1, number)
        if remainder != 1:
            i = 0
            while remainder != (number - 1):
                if i == num2 - 1:
                    return False
                else:
                    i += 1
                    remainder = (remainder ** 2) % number
    return True


def generate_prime(keysize):
    while True:
        prime_number = random.getrandbits(keysize)
        prime_number |= 1
        if fermat_test(prime_number) and miller_rabin_test(prime_number):
            return prime_number
