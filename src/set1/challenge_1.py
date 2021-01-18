from base64 import b64encode


def convert_hex_to_base64(in_string: str):
    return b64encode(bytes.fromhex(in_string)).decode()


if __name__ == "__main__":
    result = convert_hex_to_base64(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    assert result == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
