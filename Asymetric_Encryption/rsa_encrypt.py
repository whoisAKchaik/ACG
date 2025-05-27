from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

message = input("Input your message => ").encode()

# Load the public key from a file
with open("public_key.pem", "rb") as f:
    public_key_bytes = f.read()

# Deserialize the public key
public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend()
)

# Encrypt the message using the public key
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(               # OAEP (Optimal Asymmetric Encryption Padding) is the recommended padding algorithm for RSA encryption. It cannot be used with RSA signing.
        mgf=padding.MGF1(algorithm=hashes.SHA256()),    # MGF1 (Mask Generation Function) is used to generate a mask for the plaintext before encryption.
        algorithm=hashes.SHA256(),      # Hash algorithm
        label=None
    )
)
# Save the ciphertext to a file
with open("ciphertext.txt", "wb") as f:
    f.write(ciphertext)
print("Message has been encrypted and saved to 'ciphertext.txt'.")
