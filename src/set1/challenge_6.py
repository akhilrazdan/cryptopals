import base64

# inspired from http://blog.joshuahaddad.com/cryptopals-challenges-6/
from set1.challenge_3 import find_encryption_key
from set1.challenge_5 import repeating_key_xor


def hamming_distance(input1: bytes, input2: bytes) -> int:
    """
    Is the number of differing bits between two strings.
    :return: Edit distance which is an int
    """
    if len(input1) != len(input2):
        raise ValueError("Hamming distance assumes the string lengths to be equal.")
    distance = 0
    for b1, b2 in zip(input1, input2):
        diff = b1 ^ b2
        distance += sum(1 for bit in bin(diff) if bit == '1')

    return distance


def find_norm_hamming_dist(cipher_text: bytes, keysize: int) -> float:
    chunks = [cipher_text[i:i + keysize] for i in range(0, len(cipher_text), keysize)]

    # Determine the normalized hamming distance, neighboring is fine, you could do
    # all combinations as well
    distances = []
    while True:
        try:
            inp1 = chunks[0]
            inp2 = chunks[1]

            dist = hamming_distance(inp1, inp2)
            distances.append(dist / keysize)

            del chunks[0]
            del chunks[1]
        # Once there are no more blocks, return the normalized distances
        except Exception as e:
            return sum(distances) / float(len(distances))


def find_keysize(ciphertext: bytes) -> int:
    KEYSIZE_MIN, KEYSIZE_MAX = 20, 40
    distances = []
    for keysize in range(KEYSIZE_MIN, KEYSIZE_MAX):
        distances.append((keysize, find_norm_hamming_dist(ciphertext, keysize)))
    return min(distances, key=lambda x: x[1])[0]


def find_cipher(cipher_text: bytes) -> str:
    keysize = find_keysize(cipher_text)
    sequences = [[] for _ in range(keysize)]
    for i in range(0, len(cipher_text)):
        sequences[i % keysize].append(cipher_text[i])

    key = ""
    for sequence in sequences:
        xor_key = find_encryption_key(bytes(sequence).hex())[2]
        key += chr(xor_key)

    return key


if __name__ == "__main__":
    print(hamming_distance(b"this is a test", b"wokka wokka!!!"))
    with open('6.txt') as f:
        ciphertext = base64.b64decode(''.join(f.read().strip().split('\n')))
    cipher = find_cipher(ciphertext)
    print(bytes.fromhex(repeating_key_xor(ciphertext,cipher)).decode())
