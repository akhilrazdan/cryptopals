def repeating_key_xor(orig_text: bytes, repeat_key: str) -> str:
    val = []
    for i, orig_byte in enumerate(orig_text):
        result = orig_byte ^ ord(repeat_key[i % len(repeat_key)])
        val.append(result)
    return bytes(val).hex()


if __name__ == '__main__':
    print(repeating_key_xor(b"This is a secret message", "MySecretPassword"))
    print(bytes.fromhex(repeating_key_xor(bytes.fromhex('19113a16431b165431410016141d17106d14361610130211'), "MySecretPassword")))
    assert repeating_key_xor(
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        "ICE") == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
