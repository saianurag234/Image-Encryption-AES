import os


def pkcs1_v1_5_pad(message, key_size):

    message_length = len(message)
    padding_length = key_size - message_length - 3

    if message_length > key_size - 11:
        raise ValueError("Message too long for the specified key size.")

    padding_string = os.urandom(padding_length).replace(b'\x00', b'\x01')

    return b'\x00\x02' + padding_string + b'\x00' + message


def pkcs1_v1_5_unpad(padded_message):

    if not (padded_message[0] == 0x00 and padded_message[1] == 0x02):
        raise ValueError("Invalid padding - incorrect header bytes.")

    separator_index = padded_message.find(b'\x00', 2)
    if separator_index == -1:
        raise ValueError("Invalid padding - separator byte not found.")

    return padded_message[separator_index + 1:]
