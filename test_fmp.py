import requests

# ----------------------------------------------------
# PASTE YOUR FMP API KEY HERE
# ----------------------------------------------------
API_KEY = "LsmfKGaW7fxlLWkWGCzpaYJwnnlZFcSi"
# ----------------------------------------------------

SYMBOL = "AAPL"

# This is the URL the app tries to fetch for the /analyze page
profile_url = f"https://financialmodelingprep.com/api/v3/profile/{SYMBOL}?apikey={API_KEY}"

print(f"Testing URL: {profile_url}\n")

try:
    response = requests.get(profile_url)

    print(f"Status Code: {response.status_code}")
    print("--------------------")

    if response.status_code == 200:
        print("SUCCESS! Response JSON:")
        print(response.json())
    else:
        print("ERROR! Response Text:")
        print(response.text)

except Exception as e:
    print(f"An exception occurred: {e}")