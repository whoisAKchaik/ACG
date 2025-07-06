from blake3 import blake3

hash1 = blake3(b"hello world").hexdigest()
print("Hash of 'hello world':", hash1)
