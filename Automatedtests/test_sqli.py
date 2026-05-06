import requests

BASE = "http://127.0.0.1:5000"

def test_sql_injection():
    payload = "' OR 1=1 --"
    r = requests.get(f"{BASE}/search?keyword={payload}")

    print("\n--- RESPONSE START ---")
    print(r.text)
    print("--- RESPONSE END ---\n")

    data = r.json()

    # FIXED VERSION EXPECTATION:
    # injection should NOT return multiple/all records
    assert isinstance(data, list)
    assert len(data) == 0 or len(data) == 1
