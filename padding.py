import numpy as np

class PKCS7:
    def __init__(self, block_size) -> None:
        self.block_size = block_size

        if self.block_size <= 0:
            raise ValueError("Block size should be a positive integer.")

    @staticmethod
    def pkcs7_padding(data: np.array, block_size: int):
        data = data.flatten()

        if len(data) % 16 == 0:
            return data
        
        else:
            padding_size = block_size - (len(data) % block_size)
            padding = [padding_size] * padding_size
            padded_data = np.concatenate((data, padding))
            return padded_data

    @staticmethod
    def pkcs7_unpadding(data):
        padding_size = data[-1]
        
        if padding_size > len(data) or padding_size == 0:
            return data

        if not all(x == padding_size for x in data[-padding_size:]):
            return data

        return data[:-padding_size]