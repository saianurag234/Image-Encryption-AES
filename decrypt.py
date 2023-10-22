from constant import S_BOX,INV_S_BOX,BLOCK_SIZE,STATE_BLOCK_SIZE,KEY_SIZE_ROUND,R_CON,INV_MIX_COLUMN_MATRIX
from utils import gf_multiplication
from padding import PKCS7
import numpy as np
from entity import image_metadata
import cv2

class AES_decryption:
    def __init__(self,encrypted_image,master_key,image_metadata) -> None:
        self.image_data = encrypted_image
        self.master_key = master_key
        self.no_of_round = KEY_SIZE_ROUND
        self.image_metadata = image_metadata

    def add_round_key(self,state_block,round_key):
        return np.bitwise_xor(state_block, round_key)

    @staticmethod
    def _sub_word(word: np.ndarray) -> np.ndarray:
        return np.array([S_BOX[b//0x10][b%0x10] for b in word], dtype=np.uint8)
    
    '''
      Key Expansion function for AES-128

    '''

    # def expand_key(self) -> list:
    #     num_rounds = 10
    #     round_keys = [self.master_key]

    #     for i in range(num_rounds):
    #         previous_key = round_keys[-1]
    #         new_key = np.zeros((4, 4), dtype=np.uint8)

    #         word = np.roll(previous_key[:, 3], -1)
    #         word = self._sub_word(word)
    #         word[0] ^= R_CON[i * 4]

    #         new_key[:, 0] = word ^ previous_key[:, 0]

    #         for j in range(1, 4):
    #             new_key[:, j] = new_key[:, j-1] ^ previous_key[:, j]

    #         round_keys.append(new_key)

    #     return round_keys

    '''
      Key Expansion function for AES-256

    '''

    def expand_key(self) -> list:
        num_rounds = 14
        round_keys = [self.master_key]
    
        # Assuming the master key is a single 8x4 array
        words = [self.master_key[:, i] for i in range(8)]

        while len(words) < 4 * (num_rounds + 1):
            word = words[-1].copy()

            if len(words) % 8 == 0:
                word = np.roll(word, -1)
                word = self._sub_word(word)
                word[0] ^= R_CON[len(words) // 8]
            elif len(words) % 8 == 4:
                word = self._sub_word(word)
        
            word = word ^ words[-8]
            words.append(word)

        # Convert list of words into list of keys
        for i in range(0, len(words), 4):
            round_keys.append(np.column_stack(words[i:i+4]))

        return round_keys[1:]  # We don't want the master key in the round_keys
    
    def inverse_substitute_bytes(self, state_block):
        for i in range(4):
            for j in range(4):
                byte = state_block[i][j]
                row = byte // 16
                col = byte % 16
                state_block[i][j] = INV_S_BOX[row][col]
        return state_block
    
    def inverse_shift_rows(self, state_block):
        for i in range(1, STATE_BLOCK_SIZE):
            state_block[i] = np.roll(state_block[i], i)
        return state_block
    
    def inverse_mix_columns(self,state_block):
        
        for i in range(4):
            col = [state_block[x][i] for x in range(4)]
            
            for j in range(4):
                mix_col = INV_MIX_COLUMN_MATRIX[j]
                state_block[j][i] = gf_multiplication(mix_col[0], col[0]) ^ \
                          gf_multiplication(mix_col[1], col[1]) ^ \
                          gf_multiplication(mix_col[2], col[2]) ^ \
                          gf_multiplication(mix_col[3], col[3])

        return state_block
    
    def decrypt_block(self,state_block,round_keys):
        block = state_block
        
        for round_num in reversed(range(1,15)):
            block = self.add_round_key(block, round_keys[round_num])

            if round_num < KEY_SIZE_ROUND:
                block = self.inverse_mix_columns(block)

            block = self.inverse_shift_rows(block)

            block = self.inverse_substitute_bytes(block) 

        return block
    
    
    # def decrypt_image(self,image_array):
    #     round_keys = self.expand_key()

    #     cipher_image_blocks = []

    #     decrypted_image = []

    #     for i in range(0, len(image_array), BLOCK_SIZE):
    #         chunk = image_array[i:i + BLOCK_SIZE]
    #         state_block = np.array(chunk).reshape(4, 4)
    #         cipher_image_blocks.append(state_block)

    #     for i in range(0, len(cipher_image_blocks)):
    #         block = cipher_image_blocks[i]

    #         block = self.decrypt_block(block,round_keys)

    #         block = self.add_round_key(block,round_keys[0])

    #         decrypted_image.extend(block.reshape(-1))

    #     decrypted_data = PKCS7.pkcs7_unpadding(decrypted_image)

    #     decrypted_data = np.array(decrypted_data)

       
    #     decrypted_data = decrypted_data.reshape((self.image_metadata.image_height,self.image_metadata.image_width))

    #     return decrypted_data

    '''
      Optimized way of writing the above decrypt_image function 

    '''

    def decrypt_image(self, image_array):
        round_keys = self.expand_key()
        total_blocks = len(image_array) // BLOCK_SIZE
        cipher_image_blocks = image_array.reshape(total_blocks, 4, 4)
        
        decrypted_image = np.zeros_like(image_array)

        for idx in range(total_blocks):
            block = cipher_image_blocks[idx]
            block = self.decrypt_block(block, round_keys)
            block = self.add_round_key(block, round_keys[0])
            decrypted_image[idx * BLOCK_SIZE: (idx + 1) * BLOCK_SIZE] = block.flatten()

        decrypted_data = PKCS7.pkcs7_unpadding(decrypted_image)
        return decrypted_data.reshape((self.image_metadata.image_height, self.image_metadata.image_width))


    
    def aes_decryption(self):
        if not self.image_metadata.is_colour:
            decrypted_image = self.decrypt_image(self.image_data.flatten())
            return decrypted_image

        else:
            b,g,r = cv2.split(self.image_data)

            blue_channel_decrypted = self.decrypt_image(b.flatten())
            green_channel_decrypted = self.decrypt_image(g.flatten())
            red_channel_decrypted = self.decrypt_image(r.flatten())

            image = cv2.merge((blue_channel_decrypted,green_channel_decrypted,red_channel_decrypted))

            return image