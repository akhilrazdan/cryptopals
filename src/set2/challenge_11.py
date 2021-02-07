import os
import random

from Crypto.Cipher import AES

from set1.challenge_7 import encrypt_AES
from set1.challenge_8 import detect_ecb
from set2.challenge_10 import encrypt_cbc, encrypt_aes_ecb


def choose_mode_at_random():
    return [AES.MODE_ECB, AES.MODE_CBC].__getitem__(random.randint(0, 1))


def generate_random_key():
    return os.urandom(16)


def encryption_oracle(orig_text: bytes, mode) -> bytes:
    pre_pad = os.urandom(random.randint(5, 10))
    post_pad = os.urandom(random.randint(5, 10))
    key = generate_random_key()
    to_encrypt = pre_pad + orig_text + post_pad

    ## Append bytes
    if mode == AES.MODE_ECB:
        return encrypt_aes_ecb(to_encrypt, key)
    else:
        return encrypt_cbc(to_encrypt, key, iv=os.urandom(16))


if __name__ == "__main__":
    for _ in range(10):
        mode = choose_mode_at_random()
        cipher_text = encryption_oracle(b'A' * 50, mode)
        detected_mode = AES.MODE_ECB if detect_ecb(cipher_text, 16) else AES.MODE_CBC
        assert detected_mode == mode
