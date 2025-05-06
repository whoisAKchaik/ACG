# NEVER USE: ECB is not secure!
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

# Shared AES key (128-bit / 16 bytes)
test_key = bytes.fromhex('00112233445566778899AABBCCDDEEFF')

# Set up the AES cipher in ECB mode
aesCipher = Cipher(
    algorithms.AES(test_key),
    modes.ECB(),
    backend=default_backend()
)
aesEncryptor = aesCipher.encryptor()

# Unoptimal padding function to pad the data to a multiple of 16 bytes.
# This is necessary for AES encryption because AES operates on blocks of 16 bytes.
# Note: This is a simple padding scheme and should not be used in production.
# In production, consider using PKCS#7 or another secure padding scheme.
def pad(data):
    """Pad data to a multiple of 16 bytes."""
    padding_length = 16 - (len(data) % 16)
    return data + b"E" * padding_length  

def main():
    if len(sys.argv) != 3:
        print("Usage: python aes_ecb_txtFile.py input.txt output.txt")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Read the plaintext message from the input file
    with open(input_path, "rb") as infile:
        message = infile.read()

    # Pad and encrypt the message
    padded = pad(message)
    ciphertext = aesEncryptor.update(padded)

    # Convert ciphertext to hex
    # This is a common way to represent binary data in a human-readable format.
    hex_output = ciphertext.hex()

    # Write hex string to output file
    with open(output_path, "w") as outfile:
        outfile.write(hex_output)

    print(f"[+] Hex-encoded ciphertext saved to: {output_path}")

if __name__ == "__main__":
    main()

# This script encrypts a text file using AES in ECB mode.
# It reads the plaintext from the input file, pads it to a multiple of 16 bytes,
# and then encrypts it using AES in ECB mode.
# The encrypted data is saved to the output file.
# Note: ECB mode is not secure for encrypting files or any data with patterns.
# This is a demonstration of how to use AES encryption in ECB mode.
# Do not use ECB mode for secure applications.
# ECB mode is not recommended for secure applications due to its vulnerabilities.
# This script is for educational purposes only.
# Credit: Practical Cryptography in Python Learning Correct Cryptography by Example
