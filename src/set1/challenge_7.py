import base64

from Crypto.Cipher import AES


def encrypt_AES(plaintext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def decrypt_AES(ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    with open("7.txt") as f:
        ciphertext = base64.b64decode(''.join(f.read().strip().split('\n')))
    print(len(ciphertext))
    print(len(b"YELLOW SUBMARINE"))
    original_text = decrypt_AES(ciphertext, b"YELLOW SUBMARINE")
    print(original_text.decode())
