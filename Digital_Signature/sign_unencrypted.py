from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Step 1: Generate a new RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Step 2: Get the corresponding public key
public_key = private_key.public_key()

# Step 3: Define the message to sign
# message = b"Alice, this is Bob. Meet me at Dawn"
message = input("Type in a phrase please => ").encode()

# Step 4: Sign the message with the private key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),  # Mask Generation Function
        salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length
    ),
    hashes.SHA256()  # Hash algorithm
)
print("Signature:", signature.hex())

#fake_signature = b"3d2359a7369323c167ae0c6279eccb14cce12783e35f19eb603c7c6fa7cc4749653dc70fdbf0b8f2e31f3f31101869fbf6bc110d84069d08e44308ee5a648d8b2cb912708ca8e8f55c8f802e20979ce6a0cc58c75f1d091df74325fd7366e6e0c20b5325dca17b630a9a178ebd013fa940df74a02eb77f4df16fde91e23347ad78ac15bb1e964e307be73828f302a7fef58cdf5b4abe3bca6335a178c34bc3cbb1e9e665f8d2570ee29a9ba1b134bb8bf53e11033648b2dc61a14e454f932b60d2125933977198ecb573e1aa5b3ee2a64f6e1643351d551e871612083d75df10db9864c146f1a79f0d95f0f1fc701ee7195612758c5dd5506645d82dadd202d7"

# Step 5: Verify the signature using the public key
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verify passed!")
except Exception as e:
    print("Verify failed!")
    print(e)

