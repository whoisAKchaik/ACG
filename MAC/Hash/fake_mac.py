from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, hashlib

class Encryptor:
    def __init__(self, key, nonce):
        aesContext = Cipher(algorithms.AES(key),
                            modes.CTR(nonce),
                            backend=default_backend())
        self.encryptor = aesContext.encryptor()
        self.hasher = hashlib.sha256()

    def update_encryptor(self, plaintext):
        ciphertext = self.encryptor.update(plaintext)
        self.hasher.update(ciphertext)
        return ciphertext

    # Finalize the encryptor and return the MAC
    # This is a fake MAC, just a hash of the ciphertext
    # In a real scenario, you would use a secure MAC algorithm like HMAC or CMAC to ensure integrity and authenticity of the message
    def finalize_encryptor(self):
        return self.encryptor.finalize() + self.hasher.digest()

class Decryptor:
    def __init__(self, key, nonce):
        aesContext = Cipher(algorithms.AES(key),
                            modes.CTR(nonce),
                            backend=default_backend())
        self.decryptor = aesContext.decryptor()
        self.hasher = hashlib.sha256()

    def decrypt_and_verify(self, ciphertext_with_mac):

        # Check if the ciphertext is long enough to contain a MAC (optional)
        # if len(ciphertext_with_mac) < 32:
        #     raise ValueError("Ciphertext too short to contain valid MAC!")

        # Split into ciphertext and MAC (last 32 bytes is MAC: SHA256 hash is 32 bytes)
        mac = ciphertext_with_mac[-32:]         # Transmitted MAC 
        ciphertext = ciphertext_with_mac[:-32]  # Transmitted ciphertext

        # Hash the ciphertext and compare
        self.hasher.update(ciphertext)
        computed_mac = self.hasher.digest()     # Computed MAC

        # To illustrate message tampering
        #computed_mac = bytes.fromhex("c8e6dec3d86e56c8645d5b196b9f55c07a4626b59e7b540d03aafd708edd03d9")

        # Show both MACs
        print("Transmitted MAC:", mac.hex())
        print("Computed MAC:   ", computed_mac.hex())

        if computed_mac != mac:
            raise ValueError("Integrity check failed! Message has been tampered with.")
        else:
            print("Integrity check passed!")

        # MAC is verified, now decrypt
        plaintext = self.decryptor.update(ciphertext) + self.decryptor.finalize()
        return plaintext

# Key and nonce
key = os.urandom(32)
nonce = os.urandom(16)

# Encrypt
manager = Encryptor(key, nonce)
ciphertext = manager.update_encryptor(b"Welcome to HASH!")
ciphertext_with_mac = ciphertext + manager.finalize_encryptor()

# Decrypt
verifier = Decryptor(key, nonce)
try:
    plaintext = verifier.decrypt_and_verify(ciphertext_with_mac)
    print("Decrypted message:", plaintext.decode())
except ValueError as e:
    print("Error:", e)
