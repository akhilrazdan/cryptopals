import base64
import os

from set1.challenge_8 import detect_ecb
from set2.challenge_10 import encrypt_aes_ecb

key = os.urandom(16)

given_string = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                "YnkK")


def get_block_size(oracle):
    enc_text = oracle(b"")
    orig_len = len(enc_text)
    i = 0
    while True:
        plain_text = b'A' * i
        cipher_text_len = len(oracle(plain_text))
        diff = cipher_text_len - orig_len
        if diff > 0:
            return diff, orig_len - i
        i += 1


def encryption_oracle(plaintext: bytes) -> bytes:
    unknown_string = base64.b64decode(given_string)
    return encrypt_aes_ecb(plaintext + unknown_string, key)


def get_unknown_string(oracle):
    is_ecb = detect_ecb(b"YELLOW SUBMARINE" * 2)
    assert is_ecb

    block_size, unknown_str_len = get_block_size(oracle)

    unknown_string = bytearray()
    unknown_string_size_rounded = ((int(unknown_str_len / block_size) + 1) * block_size)
    print(unknown_string_size_rounded)
    for i in range(unknown_string_size_rounded -1, 0, -1):
        d1 = bytearray(b"A" * i)
        c1 = oracle(d1)[:unknown_string_size_rounded]
        print("d1 len = {} c1 len : {} unknown_string : {}".format(len(d1), len(c1), unknown_string))
        for c in range(0, 256):
            d2 = d1[:] + unknown_string + chr(c).encode()
            c2 = oracle(d2)[:unknown_string_size_rounded]
            if c1 == c2:
                unknown_string += chr(c).encode()
                break
    return unknown_string


if __name__ == "__main__":
    # 1. Determine block size
    block_size, unknown_str_len = get_block_size(encryption_oracle)
    print("Found block size {} and unknown str len : {}".format(block_size, unknown_str_len))
    # 2. See if it is ECB
    cipher_text = encryption_oracle(b"A" * 50)
    print("Checking if the encryption method used is ECB = {}".format(detect_ecb(cipher_text, 16)))
    # 3. See what the output is for 1 small block size
    cipher_text = encryption_oracle(b"A" * 15)
    print(get_unknown_string(encryption_oracle))
