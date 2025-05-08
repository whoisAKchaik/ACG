from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding to ensure the plaintext is a multiple of the block size
    # The value of each added byte is the number of bytes added.
    # For example, if 5 bytes are added, each byte will have the value 0x05.
    # This allows the decryption process to know how many bytes to remove.
    padder = padding.PKCS7(128).padder()

    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # prepend IV for decryption. This is necessary because the IV is needed for decryption.
    return iv + ciphertext  

""" def decrypt_message(key, iv_and_ciphertext):
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext """

# Use a random 256-bit key (32 bytes)
# In practice, you should use a secure key management system to generate and store keys.
key = os.urandom(32)

plaintexts = [
    b"SHORT",
    b"MEDIUM MEDIUM MEDIUM",
    b"LONG LONG LONG LONG LONG LONG"
]

ciphertexts = []
for m in plaintexts:
    c = encrypt_message(key, m)
    ciphertexts.append(c)

# Print ciphertexts in hexadecimal
for c in ciphertexts:
    print("Ciphertext (hex):", c.hex())

# Optional: comment this out if you don't want to show decrypted output
# for c in ciphertexts:
#     print("Recovered:", decrypt_message(key, c).decode('utf-8'))
