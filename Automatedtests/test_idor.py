import requests

BASE = "http://127.0.0.1:5000"

def test_idor_access():
    session_a = requests.Session()
    session_b = requests.Session()

    # ---- USER A ----
    session_a.post(f"{BASE}/register", data={
        "username": "userA",
        "password": "123"
    })

    session_a.post(f"{BASE}/login", data={
        "username": "userA",
        "password": "123"
    })

    r = session_a.post(f"{BASE}/create-task", data={
        "title": "Private Task",
        "description": "secret data"
    })

    # get task from search (or dashboard)
    res = session_a.get(f"{BASE}/search?keyword=Private")
    task_id = res.json()[0]["id"]

    # logout user A
    session_a.get(f"{BASE}/logout")

    # ---- USER B ----
    session_b.post(f"{BASE}/register", data={
        "username": "userB",
        "password": "123"
    })

    session_b.post(f"{BASE}/login", data={
        "username": "userB",
        "password": "123"
    })

    # TRY ACCESSING USER A TASK (THIS IS THE KEY)
    r2 = session_b.get(f"{BASE}/view-task/{task_id}")

    print("\n--- IDOR RESPONSE ---")
    print(r2.text)

    # ✅ FIXED EXPECTATION
    assert "Unauthorized" in r2.text or r2.status_code == 403