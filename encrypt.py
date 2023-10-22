from constant import S_BOX,BLOCK_SIZE,STATE_BLOCK_SIZE,KEY_SIZE_ROUND,R_CON,MIX_COLUMN_MATRIX
from utils import gf_multiplication,reshape_for_image,read_image_split_channels
from padding import PKCS7
from entity import image_metadata
import numpy as np
import cv2

class AES_encryption:
    def __init__(self,image,master_key) -> None:
        self.image_data = image
        self.master_key = master_key
        self.no_of_round = KEY_SIZE_ROUND
        self.round_keys = self.expand_key()

        if len(self.image_data.shape) == 3:
            self.is_colour = True
            self.image_metadata_info = image_metadata(self.image_data.shape[0],self.image_data.shape[1],self.is_colour,self.image_data.shape[2])
        
        else:
            self.is_colour = False
            self.image_metadata_info = image_metadata(self.image_data.shape[0],self.image_data.shape[1],self.is_colour,0)

        

    @staticmethod
    def _sub_word(word: np.ndarray) -> np.ndarray:
        return np.array([S_BOX[b//0x10][b%0x10] for b in word], dtype=np.uint8)

    def expand_key(self) -> list:
        num_rounds = 10
        round_keys = [self.master_key]

        for i in range(num_rounds):
            previous_key = round_keys[-1]
            new_key = np.zeros((4, 4), dtype=np.uint8)

            word = np.roll(previous_key[:, 3], -1)
            word = self._sub_word(word)
            word[0] ^= R_CON[i * 4]

            new_key[:, 0] = word ^ previous_key[:, 0]

            for j in range(1, 4):
                new_key[:, j] = new_key[:, j-1] ^ previous_key[:, j]

            round_keys.append(new_key)

        return round_keys



    
    def xor_round_key(self,state_block, round_key):
        for i in range(0,STATE_BLOCK_SIZE):
            for j in range(0,STATE_BLOCK_SIZE):
                state_block[i][j] = state_block[i][j]^round_key[i][j]

        return state_block
    
    def substitute_bytes(self,state_block):
        for i in range(4):
            for j in range(4):
                byte = state_block[i][j]
                row = byte // 16
                col = byte % 16
                state_block[i][j] = S_BOX[row][col]
        return state_block
    

    def shift_rows(self,state_block):
        for i in range(1, STATE_BLOCK_SIZE):
            state_block[i] = np.roll(state_block[i], -i)

        return state_block
    

    def mix_col(self,state_block):
        
        for i in range(4):
            col = [state_block[x][i] for x in range(4)]
            
            for j in range(4):
                mix_col = MIX_COLUMN_MATRIX[j]
                state_block[j][i] = gf_multiplication(mix_col[0], col[0]) ^ \
                          gf_multiplication(mix_col[1], col[1]) ^ \
                          gf_multiplication(mix_col[2], col[2]) ^ \
                          gf_multiplication(mix_col[3], col[3])

        return state_block

    def add_round_key(self,state_block,round_key):
        return np.bitwise_xor(state_block, round_key)
    
    def encrypt_block(self,state_block,round_keys):
        block = state_block
        
        for round_num in range(1, 11):
            block = self.substitute_bytes(block)
            block = self.shift_rows(block)
            
            if round_num < KEY_SIZE_ROUND:
                block = self.mix_col(block)

            block = self.add_round_key(block, round_keys[round_num])

        return block
    


    def encrypt_image(self,image_array):
        state_array = []

        image_array = PKCS7.pkcs7_padding(image_array,BLOCK_SIZE)

        for i in range(0, len(image_array), BLOCK_SIZE):
            chunk = image_array[i:i + BLOCK_SIZE]
            state_block = np.array(chunk).reshape(4, 4)
            state_array.append(state_block)


        cipher_image = []

        for i in range(0, len(state_array)):
             block = state_array[i]

             block = self.add_round_key(block,self.round_keys[0])

             block = self.encrypt_block(block,self.round_keys)             

             cipher_image.extend(block.reshape(-1))

        cipher_image = np.array(cipher_image)

        cipher_image = cipher_image.reshape(reshape_for_image(len(cipher_image)))


        return cipher_image

    
    def aes_encryption(self):
        if not self.is_colour:
            encrypted_image = self.encrypt_image(self.image_data)

            return encrypted_image,self.image_metadata_info

        else:
            colour_channel = read_image_split_channels(self.image_data)

            blue_channel_encrypted = self.encrypt_image(colour_channel[0])
            green_channel_encrypted = self.encrypt_image(colour_channel[1])
            red_channel_encrypted = self.encrypt_image(colour_channel[2])

            image = cv2.merge((blue_channel_encrypted,green_channel_encrypted,red_channel_encrypted))

            return image,self.image_metadata_info