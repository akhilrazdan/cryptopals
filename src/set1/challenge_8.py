from Crypto.Cipher import AES


def detect_ecb(cipher_text: bytes, keysize=AES.block_size):
    assert len(cipher_text) % keysize == 0, "length of cipher text should be a multiple of blocksize"
    num_blocks = len(cipher_text) // keysize

    blocks = [cipher_text[(i * keysize): ((i + 1) * keysize)] for i in range(0, num_blocks)]
    return True if (len(blocks) != len(set(blocks))) else False


if __name__ == '__main__':
    with open("8.txt") as f:
        cipher_texts = f.read().strip().split('\n')

    hits = [ct for ct in cipher_texts if detect_ecb(bytes.fromhex(ct))]
    assert len(hits) == 1
    print(bytes.fromhex(hits[0]))
