import base64

from Crypto.Cipher import AES

from set1.challenge_5 import repeating_key_xor_b
from set1.challenge_7 import encrypt_AES, decrypt_AES
from set2.challenge_9 import pkcs7_pad, pkcs7_unpad


def encrypt_cbc(plaintext: bytes, key: bytes, iv=b'\x00' * AES.block_size) -> bytes:
    cipher_text = b""
    prev_cipher_text = iv
    for i in range(0, len(plaintext), AES.block_size):
        orig_text_padded = pkcs7_pad(plaintext[i:i + AES.block_size], AES.block_size)

        comb = repeating_key_xor_b(orig_text_padded, prev_cipher_text)
        encrypted_block = encrypt_AES(comb, key)
        cipher_text += encrypted_block
        prev_cipher_text = encrypted_block
    return cipher_text


def decrypt_cbc(ciphertext: bytes, key: bytes, iv=b'\x00' * AES.block_size) -> bytes:
    plain_text = b""
    prev_block_input = iv
    for i in range(0, len(ciphertext), AES.block_size):
        encrypted_block = ciphertext[i:i+AES.block_size]

        # Decrypt the block
        decrypted_block = decrypt_AES(encrypted_block, key)
        orig_text = repeating_key_xor_b(prev_block_input, decrypted_block)
        prev_block_input = encrypted_block
        plain_text += orig_text
    return pkcs7_unpad(plain_text)

if __name__ == '__main__':
    with open("10.txt") as f:
        orig_text = base64.b64decode(''.join(f.read().strip().split('\n')))

    print(encrypt_cbc(b"This is a message", b"YELLOW SUBMARINE"))
    print(decrypt_cbc(b'\xfc\x96\xbb!<\\\x99T\xb9tJ\x00i;fF\xc6\xcc\x0f2f`Q\xb8/\rcQO(\x17\x9a', b"YELLOW SUBMARINE"))
