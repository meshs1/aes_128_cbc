import binascii
import re

from tqdm import tqdm

from aes_128_cbc import cbc_encrypt, cbc_decrypt


def parse_rsp(file_path):
    with open(file_path, "r") as f:
        content = f.read()

    encrypt_section = re.search(r"\[ENCRYPT](.*?)\[DECRYPT]", content, re.S).group(1)
    decrypt_section = re.search(r"\[DECRYPT](.*)", content, re.S).group(1)

    def parse_section(section):
        cases = []
        entries = re.findall(
            r"COUNT\s*=\s*(\d+)\s*KEY\s*=\s*([0-9a-fA-F]+)\s*IV\s*=\s*([0-9a-fA-F]+)\s*(PLAINTEXT|CIPHERTEXT)\s*=\s*([0-9a-fA-F]+)\s*(CIPHERTEXT|PLAINTEXT)\s*=\s*([0-9a-fA-F]+)",
            section,
        )
        for _, key, iv, text_type1, text1, text_type2, text2 in entries:
            cases.append({
                "key": key,
                "iv": iv,
                "plaintext": text1 if text_type1 == "PLAINTEXT" else text2,
                "ciphertext": text1 if text_type1 == "CIPHERTEXT" else text2
            })
        return cases

    encrypt_cases = parse_section(encrypt_section)
    decrypt_cases = parse_section(decrypt_section)
    return encrypt_cases, decrypt_cases


def run_tests(encrypt_cases, decrypt_cases):
    for i, case in tqdm(enumerate(encrypt_cases), unit="case", desc="Encrypt tests", total=len(encrypt_cases)):
        key = binascii.unhexlify(case["key"])
        iv = binascii.unhexlify(case["iv"])
        plaintext = binascii.unhexlify(case["plaintext"])
        expected_ct = binascii.unhexlify(case["ciphertext"])

        ct = cbc_encrypt(plaintext, key, iv)

        if ct != expected_ct:
            tqdm.write(f"Encrypt FAIL at case {i}")
            tqdm.write(f"  Got:      {ct.hex()}")
            tqdm.write(f"  Expected: {expected_ct.hex()}")
        else:
            tqdm.write(f"Encrypt OK at case {i}")

    for i, case in tqdm(enumerate(decrypt_cases), unit="case", desc="Decrypt tests", total=len(decrypt_cases)):
        key = binascii.unhexlify(case["key"])
        iv = binascii.unhexlify(case["iv"])
        ciphertext = binascii.unhexlify(case["ciphertext"])
        expected_pt = binascii.unhexlify(case["plaintext"])

        pt = cbc_decrypt(ciphertext, key, iv)

        if pt != expected_pt:
            tqdm.write(f"Decrypt FAIL at case {i}")
            tqdm.write(f"  Got:      {pt.hex()}")
            tqdm.write(f"  Expected: {expected_pt.hex()}")
        else:
            tqdm.write(f"Decrypt OK at case {i}")


if __name__ == "__main__":
    encrypt_data, decrypt_data = parse_rsp("CBCKeySbox128.rsp")
    run_tests(encrypt_data, decrypt_data)
