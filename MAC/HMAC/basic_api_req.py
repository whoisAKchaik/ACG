import requests, json

# API_KEY = 'YOUR_API_KEY'                # Private API key
# API_SECRET = 'YOUR_API_SECRET'          # Private API secret
# PASSPHRASE = 'YOUR_API_PASSPHRASE'      # Private API passphrase
API_URL = 'https://jsonplaceholder.typicode.com'    # Sample API URL

def fetch_data():

    request_path = '/posts/'    # Endpoint to fetch posts. API_URL and request_path can be combined.

    try:
        response = requests.get(API_URL + request_path)  # Make GET request to https://jsonplaceholder.typicode.com/posts/
        response.raise_for_status()  # Raise error for bad responses (4xx and 5xx)
        data = response.json()  # Parse response as JSON

        print("Data fetched successfully:")
        print(json.dumps(data, indent=2))   # Pretty print the JSON data

    except requests.exceptions.RequestException as e:
        print("An error occurred while requesting data:", e)

if __name__ == "__main__":
    fetch_data()
