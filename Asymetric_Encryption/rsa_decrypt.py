from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# Load the private key from a file
with open("private_key.pem", "rb") as f:
    private_key_bytes = f.read()

# Deserialize the private key
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=input("Enter your key passphrase => ").encode(),
    backend=default_backend()
)

# Load the ciphertext from a file
with open("ciphertext.txt", "rb") as f:
    ciphertext = f.read()

# Decrypt the ciphertext using the private key
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(               # Same padding scheme as used during encryption
        mgf=padding.MGF1(algorithm=hashes.SHA256()),    
        algorithm=hashes.SHA256(),      
        label=None
    )
)

# Print the decrypted message
print("Decrypted message:", plaintext.decode())

# Save the decrypted message to a file
with open("decrypted_message.txt", "w") as f:
    f.write(plaintext.decode())
print("Decrypted message has been saved to 'decrypted_message.txt'.")
