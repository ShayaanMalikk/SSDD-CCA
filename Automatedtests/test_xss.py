import requests

BASE = "http://127.0.0.1:5000"

def test_reflected_xss():
    payload = "<script>alert('XSS')</script>"

    r = requests.get(f"{BASE}/reflect?q={payload}")
    response = r.text.lower()

    print("\n--- XSS RESPONSE ---")
    print(response)

    # VULNERABLE should contain raw script
    # FIXED should NOT contain raw script
    assert "<script>" not in response