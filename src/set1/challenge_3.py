# Solution inspired from : https://www.codementor.io/@arpitbhayani/deciphering-single-byte-xor-ciphertext-17mtwlzh30
from collections import Counter

occurence_english = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
}


def single_byte_xor(text: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in text])


def compute_fitting_quotient(text: bytes) -> float:
    counter = Counter(text)
    dist_text = [(counter.get(ord(c), 0) ) for c in occurence_english]
    dist_eng = list(occurence_english.values())
    return sum([abs(a - b) for a, b in zip(dist_eng, dist_text)]) / float(len(dist_text))


def find_encryption_key(encoded_hex: str):
    result = []
    for i in range(0, 256):
        orig_text = single_byte_xor(bytes.fromhex(encoded_hex), i)
        result.append((compute_fitting_quotient(orig_text.lower()), orig_text.lower(), i))
    answer = max(result, key=lambda x: x[0])
    return answer


if __name__ == "__main__":
    print(single_byte_xor("abcd".encode('utf-8'), 69))
    print(single_byte_xor(b"$'&!", 69))
    encoded_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    print(find_encryption_key(encoded_hex))
