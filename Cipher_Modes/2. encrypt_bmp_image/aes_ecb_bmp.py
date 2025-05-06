# NEVER USE: ECB is not secure!
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Use a fixed 128-bit key (16 bytes)
test_key = bytes.fromhex('00112233445566778899AABBCCDDEEFF')

# Set up AES cipher in ECB mode
aesCipher = Cipher(
    algorithms.AES(test_key),
    modes.ECB(),
    backend=default_backend()
)
aesEncryptor = aesCipher.encryptor()

# Unoptimal padding funtion to pad the data to a multiple of 16 bytes. 
# This is necessary for AES encryption because AES operates on blocks of 16 bytes.
def pad(data):
    """Pad the data to a multiple of 16 bytes."""
    padding_len = 16 - (len(data) % 16)
    return data + b"\x00" * padding_len

def main():
    if len(sys.argv) != 3:
        print("Usage: python aes_ecb_bmp.py input.bmp output.bmp")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    with open(input_file, "rb") as f:
        image_data = f.read()

    header, body = image_data[:54], image_data[54:]
    padded_body = pad(body)
    encrypted_body = aesEncryptor.update(padded_body)

    with open(output_file, "wb") as f:
        f.write(header + encrypted_body)

    print(f"[+] ECB-encrypted BMP saved to: {output_file}")

if __name__ == "__main__":
    main()
    
# This script encrypts the body of a BMP file using AES in ECB mode.
# It reads the BMP file, pads the body to a multiple of 16 bytes, and then encrypts it.
# The encrypted BMP file is saved with the same header and the encrypted body.
# Note: ECB mode is not secure for encrypting images or any data with patterns.
# This is a demonstration of how to use AES encryption in ECB mode.
# Do not use ECB mode for secure applications.
# ECB mode is not recommended for secure applications due to its vulnerabilities.
# This script is for educational purposes only.
# Credit: Practical Cryptography in Python Learning Correct Cryptography by Example

