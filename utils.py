import numpy as np
import cv2

def bytes_to_matrix(byte_data):
    byte_data = np.frombuffer(byte_data, dtype=np.uint8)
    return byte_data.reshape((-1, 4))


def matrix_to_bytes(matrix):
    return matrix.tobytes()


def xor(a, b):
    return np.bitwise_xor(a, b)


def read_image_split_channels(image):
    b, g, r = cv2.split(image)
        
    return (b,g,r)


def gf_multiplication(a, b):
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        carry = a & 0x80

        a <<= 1
        a &= 0xFF

        if carry:
            a ^= 0x1B

        b >>= 1

    return result

def reshape_for_image(arr_length:int):
    possible_shapes = []
    
    for i in range(1, int(arr_length**0.5) + 1):
        if arr_length % i == 0:
            possible_shapes.append((i, arr_length // i))
    
    best_shape = min(possible_shapes, key=lambda x: abs(x[0]-x[1]))
    
    return best_shape