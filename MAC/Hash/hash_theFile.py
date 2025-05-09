import hashlib
import sys

def hash_file(filepath):
    
    try:
        with open(filepath, "rb") as f:
            #Reading the file as a whole.But it is recommended to read 
            #the file in chunks to avoid memory issues with large files.
            data = f.read()
            return hashlib.sha256(data).hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python hash_theFile.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    file_hash = hash_file(file_path)
    if file_hash:
        print(f"\nSHA-256 hash of '{file_path}':\n{file_hash}")

if __name__ == "__main__":
    main()
