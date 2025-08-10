import binascii
import re

from tqdm import trange, tqdm

from aes_128_cbc import aes_encrypt_block, xor_blocks, aes_decrypt_block


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


def mct_cbc_encrypt_128(key0, iv0, pt0):
    key = key0
    iv = iv0
    pt_start = pt0

    pt_j = pt_start
    for j in trange(1000, leave=False):
        if j == 0:
            ct_j = aes_encrypt_block(xor_blocks(pt_j, iv), key)
            pt_j_next = iv
        else:
            ct_j = aes_encrypt_block(xor_blocks(pt_j, ct_prev), key)
            pt_j_next = ct_prev
        ct_prev = ct_j
        pt_j = pt_j_next

    return ct_j


def mct_cbc_decrypt_128(key0, iv0, ct0):
    # TODO: Fix
    key = key0
    iv = iv0
    ct_start = ct0

    ct_j = ct_start
    for j in trange(1000, leave=False):
        if j == 0:
            pt_j = aes_decrypt_block(xor_blocks(ct_j, iv), key)
            ct_j_next = iv
        else:
            pt_j = aes_decrypt_block(xor_blocks(ct_j, pt_prev), key)
            ct_j_next = pt_prev
        pt_prev = pt_j
        ct_j = ct_j_next

    return pt_j

def run_tests(encrypt_cases, decrypt_cases):
    for i, case in tqdm(enumerate(encrypt_cases), unit="case", desc="Encrypt tests", total=len(encrypt_cases)):
        key = binascii.unhexlify(case["key"])
        iv = binascii.unhexlify(case["iv"])
        plaintext = binascii.unhexlify(case["plaintext"])
        expected_ct = binascii.unhexlify(case["ciphertext"])

        # ct = cbc_encrypt(plaintext, key, iv)
        ct = mct_cbc_encrypt_128(key, iv, plaintext)

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

        pt = mct_cbc_decrypt_128(key, iv, ciphertext)

        if pt != expected_pt:
            tqdm.write(f"Decrypt FAIL at case {i}")
            tqdm.write(f"  Got:      {pt.hex()}")
            tqdm.write(f"  Expected: {expected_pt.hex()}")
        else:
            tqdm.write(f"Decrypt OK at case {i}")


if __name__ == "__main__":
    encrypt_data, decrypt_data = parse_rsp("CBCMCT128.rsp")
    run_tests(encrypt_data, decrypt_data)
