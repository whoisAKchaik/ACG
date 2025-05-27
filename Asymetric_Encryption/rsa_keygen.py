from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate a private key.
private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
)

# Extract the public key from the private key.
public_key = private_key.public_key()

key_passphrase = input("Choose your key passphrase please => ").encode()

# Key serialization
# Convert the private key into bytes.
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,    # PEM is a Base64 encoded format with header and footer lines.
    format=serialization.PrivateFormat.TraditionalOpenSSL,   # TraditionalOpenSSL is frequently known as PKCS#1 format. Still a widely used format, but generally considered legacy. 
    encryption_algorithm=serialization.BestAvailableEncryption(key_passphrase)  # Encrypt the private key with a passphrase.
)

# Save the private key to a file.
with open("private_key.pem", "wb") as f:
    f.write(private_key_bytes)  

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo  # SubjectPublicKeyInfo is typical format for public keys.
)

# Save the public key to a file.
with open("public_key.pem", "wb") as f:
    f.write(public_key_bytes)

print("Private and public keys have been generated and saved to 'private_key.pem' and 'public_key.pem'.")


