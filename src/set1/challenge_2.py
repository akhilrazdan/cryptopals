def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def xor(hex1: str, hex2: str):
    return byte_xor(bytes.fromhex(hex1), bytes.fromhex(hex2)).hex()


if __name__ == "__main__":
    assert "746865206b696420646f6e277420706c6179" == xor("1c0111001f010100061a024b53535009181c",
                                                         "686974207468652062756c6c277320657965")
    print(bytes(12))
    [print(type(a)) for a in bytes(12)]