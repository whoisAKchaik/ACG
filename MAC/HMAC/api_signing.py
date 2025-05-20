# Import necessary modules
import time                          # For generating timestamps
import base64                        # For encoding/decoding base64 strings
import requests                      # For making HTTP requests
import json                          # For working with JSON data
from cryptography.hazmat.primitives import hashes, hmac  # From cryptography for secure HMAC
from cryptography.hazmat.backends import default_backend

# Replace these with your sandbox API credentials
# API_KEY = 'your_api_key'
# API_SECRET = 'your_base64_encoded_secret'
# PASSPHRASE = 'your_passphrase'
API_URL = 'https://api-public.sandbox.exchange.coinbase.com'

# Function to create HMAC SHA256 signature using cryptography library
def create_signature(secret, timestamp, method, request_path, body=''):
    message = f'{timestamp}{method}{request_path}{body}'.encode()  # Encode message to bytes. Coinbase expects the message to be: timestamp + HTTP_METHOD + request_path + body.
    hmac_key = base64.b64decode(secret)                            # Decode the base64-encoded secret (base64 to raw binary)

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())  # Initialize HMAC with SHA256
    h.update(message)                                              # Feed message into HMAC
    signature = h.finalize()                                       # Finalize and get byte object of raw binary signature 
    signature_b64 = base64.b64encode(signature).decode()           # Convert raw binary signature to base64 string -> Covert byte object to string (UTF-8) 
    return signature_b64

# Function to build headers required for Coinbase API authentication
def get_headers(api_key, signature, timestamp, passphrase):
    return {
        'CB-ACCESS-KEY': api_key,
        'CB-ACCESS-SIGN': signature,
        'CB-ACCESS-TIMESTAMP': timestamp,
        'CB-ACCESS-PASSPHRASE': passphrase,
        'Content-Type': 'application/json',
    }

# Function to fetch account data from Coinbase API
def fetch_accounts():
    method = 'GET'
    request_path = '/accounts/'
    body = ''
    timestamp = str(time.time())         # Returns the current time in seconds -> Convert to string   

    signature = create_signature(API_SECRET, timestamp, method, request_path, body)     # Create HMAC SHA256 signature by calling create_signature function
    headers = get_headers(API_KEY, signature, timestamp, PASSPHRASE)                    # Build headers by calling get_headers function

    try:
        response = requests.get(API_URL + request_path, headers=headers)        # Make GET request to API
        response.raise_for_status()                                             # Raise error for bad responses (4xx and 5xx)
        print(json.dumps(response.json(), indent=2))                            # Pretty print the JSON response
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")

# Entry point
if __name__ == "__main__":
    fetch_accounts()
