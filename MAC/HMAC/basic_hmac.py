#import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# print("Digest size:", hashes.SHA256().digest_size)    # Print the digest size of SHA256
# key = os.urandom(32)  # 32 bytes = 256 bits, suitable for HMAC-SHA256

key = b"CorrectHorseBatteryStaple"
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())  # Initialize HMAC with key and hash function

h.update(b"hello world")  # Add data to be authenticated
hmac_value = h.finalize().hex()  # Finalize the HMAC and get the value
print(f"HMAC: {hmac_value}")  # Print the HMAC value
