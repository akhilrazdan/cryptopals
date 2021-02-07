import os

from Crypto.Cipher import AES

from set2.challenge_10 import encrypt_aes_ecb, decrypt_aes_ecb
from set2.challenge_10_external import pkcs7_pad_bytes
from set2.challenge_9 import pkcs7_pad


def get_dict_from_string(input_text: str) -> dict:
    d = {}
    for tup in input_text.strip().split("&"):
        k, v = tup.split("=")
        d[k] = v
    return d


def profile_for(email: str, uid="10", role="user") -> str:
    if any([c in ["&", "="] for c in email]):
        raise ValueError("email contains banned words")
    return "email=" + email + "&uid=" + uid + "&role=" + role


key = os.urandom(16)


def encrypted_profile(email) -> bytes:
    encoded_url = profile_for(email)
    return encrypt_aes_ecb(encoded_url.encode(), key=key)


if __name__ == "__main__":
    print(get_dict_from_string("foo=bar&baz=qux&zap=zazzle"))
    #print(encrypted_profile("akhilz@gmai.com"))

    # Generate encrypted profile for email=X&uid=10&role=user
    mandotory_string = "email=&uid=10&role="
    block_size = AES.block_size  # To get from AES - ECB breaking block size

    cipher_text_length = (int(len(mandotory_string.encode()) / AES.block_size) + 1) * AES.block_size
    email_len = cipher_text_length - len(mandotory_string.encode())
    email_prefix = "A" * email_len
    profile_prefix = encrypted_profile(email_prefix)[:cipher_text_length]

    # Part two : Generate email=admin to a perfect block length
    mandatory_string = "email="
    cipher_text_length = (int(len(mandotory_string.encode()) / AES.block_size) + 1) * AES.block_size
    email_len = cipher_text_length - len(mandatory_string.encode())
    email_prefix = "A" * email_len
    email = email_prefix + pkcs7_pad_bytes(b"admin",block_size).decode()
    print(email)
    print(len(email))
    profile_postfix = encrypted_profile(email)[cipher_text_length:cipher_text_length+block_size]
    print(decrypt_aes_ecb(profile_postfix, key))
    print(decrypt_aes_ecb(profile_prefix + profile_postfix, key))
