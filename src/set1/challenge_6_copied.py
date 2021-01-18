import unittest
from base64 import b64decode
from functools import reduce

from set1.challenge_3 import find_encryption_key


def hamming_distance(bs0, bs1):
    xored = bytes(map(lambda p: p[0] ^ p[1], zip(bs0, bs1)))
    return len(''.join(reduce(lambda acc, x: acc + bin(x)[2:], xored, '0b')[2:].split('0')))

with open('6.txt') as f:
    ciphertext = b64decode(''.join(f.read().strip().split('\n')))

print(len(ciphertext))
lst = []
for keysize in range(2, 40):
    chunks = []
    for i in range(0, len(ciphertext), keysize):
        chunks.append(ciphertext[i:keysize + i])

    distances = []
    from itertools import combinations
    for p in combinations(range(len(chunks)), r=2):
        distances.append(hamming_distance(chunks[p[0]], chunks[p[1]]) / keysize)
    average_distance = sum(distances) / len(distances)
    lst.append((average_distance, keysize))

lst.sort(key=lambda p: p[0])
keysize = lst[0][1]

chunks = []
for i in range(keysize):
    chunks.append([])

for i in range(len(ciphertext)):
    chunks[i % keysize].append(ciphertext[i])

assert len(chunks) == keysize

plaintext_chunks = []
for chunk in chunks:
    plaintext_chunks.append(chr(find_encryption_key(bytes(chunk).hex())[2]))

plaintext = []
for i in range(keysize):
    for j in range(len(plaintext_chunks)):
        plaintext.append(plaintext_chunks[j][i])

print(bytes(plaintext))

# class HammingDistanceTest(unittest.TestCase):
#     def test_hamming_distance(self):
#         self.assertEqual(hamming_distance(b'this is a test', b'wokka wokka!!!'), 37)

if __name__ == '__main__':
    #unittest.main()
    print("Hello")