# Inspired from https://joshfrogers.co.uk/cryptopals-set2-ex1/


def pkcs7_pad(input: bytes, padded_length: int) -> bytes:
    assert len(input) <= padded_length, "input should be <= padded len"
    difference_in_padding = (padded_length - len(input)) % padded_length
    output = b""
    output += input
    output += bytes((chr(difference_in_padding) * difference_in_padding).encode())

    return output


def pkcs7_unpad(input_bytes: bytes) -> bytes:
    padding = input_bytes[-input_bytes[-1]:]
    if not all(padding[byte] == len(padding) for byte in range(0, len(padding))):
        return input_bytes
    return input_bytes[:-input_bytes[-1]]


if __name__ == "__main__":
    padded = pkcs7_pad(b"YELLOW SUBMARINE", 50)
    print(padded)
    print(pkcs7_unpad(padded))
