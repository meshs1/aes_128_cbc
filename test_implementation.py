from aes_128_cbc import cbc_encrypt, cbc_decrypt

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

PLAINTEXT_BLOCKS = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"
]
FULL_PLAINTEXT = bytes.fromhex("".join(PLAINTEXT_BLOCKS))

EXPECTED_CIPHERTEXT_BLOCKS = [
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7"
]
EXPECTED_FULL_CIPHERTEXT = bytes.fromhex("".join(EXPECTED_CIPHERTEXT_BLOCKS))

CIPHERTEXT_BLOCKS = [
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7"
]
FULL_CIPHERTEXT = bytes.fromhex("".join(CIPHERTEXT_BLOCKS))

EXPECTED_FULL_PLAINTEXT = bytes.fromhex("".join(PLAINTEXT_BLOCKS))

print("Encryption:\n")

actual_ciphertext = cbc_encrypt(FULL_PLAINTEXT, KEY, IV, padding=False)

print(f"Expected ciphertext: {EXPECTED_FULL_CIPHERTEXT.hex()}")
print(f"Actual ciphertext:   {actual_ciphertext.hex()}")

if actual_ciphertext == EXPECTED_FULL_CIPHERTEXT:
    print("\nSUCCESS! The generated ciphertext matches the NIST specification.")
else:
    print("\nFAILURE! The generated ciphertext does not match the NIST specification.")

print("Decryption:\n")

actual_plaintext = cbc_decrypt(FULL_CIPHERTEXT, KEY, IV, padding=False)

print(f"Expected plaintext: {EXPECTED_FULL_PLAINTEXT.hex()}")
print(f"Actual plaintext:   {actual_plaintext.hex()}")

if actual_plaintext == EXPECTED_FULL_PLAINTEXT:
    print("\nSUCCESS! The generated ciphertext matches the NIST specification.")
else:
    print("\nFAILURE! The generated ciphertext does not match the NIST specification.")
