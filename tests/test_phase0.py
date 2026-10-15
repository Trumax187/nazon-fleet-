import os
import requests
import pytest

BASE = os.environ.get("NAZON_BASE", "http://127.0.0.1:8000")


def _login(username, password):
    return requests.post(f"{BASE}/login", json={"username": username, "password": password})


@pytest.fixture(scope="session")
def admin_token():
    user = os.environ.get("NAZON_ADMIN_USER", "nazon")
    pw = os.environ.get("NAZON_ADMIN_PASS")
    if not pw:
        pytest.skip("Set NAZON_ADMIN_PASS to run these tests.")
    r = _login(user, pw)
    assert r.ok, f"Admin login failed: {r.status_code} {r.text}"
    return r.json()["token"]


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def test_server_is_up():
    r = requests.get(f"{BASE}/")
    assert r.ok
    assert r.json().get("system") == "NAZON"


def test_old_password_rejected():
    r = _login("nazon", "nazon123")
    assert r.status_code == 401, "Old demo password should be rejected"


def test_admin_login_works(admin_token):
    assert isinstance(admin_token, str) and len(admin_token) > 20


def test_whoami_with_token(admin_headers):
    r = requests.get(f"{BASE}/whoami", headers=admin_headers)
    assert r.ok
    assert r.json()["is_admin"] is True


def test_zones_list_requires_auth():
    r = requests.get(f"{BASE}/zones")
    assert r.status_code == 401


def test_zones_list_with_token(admin_headers):
    r = requests.get(f"{BASE}/zones", headers=admin_headers)
    assert r.ok
    assert isinstance(r.json(), list)


def test_post_zone_no_token_401():
    r = requests.post(f"{BASE}/zones",
                      json={"name": "pytest-noauth", "kind": "danger",
                            "lat": -15.4, "lon": 28.3, "radius_m": 100})
    assert r.status_code == 401


def test_post_zone_admin_ok(admin_headers):
    r = requests.post(f"{BASE}/zones", headers=admin_headers,
                      json={"name": "pytest-zone", "kind": "danger",
                            "lat": -15.4, "lon": 28.3, "radius_m": 100})
    assert r.ok, r.text


def test_delete_zone_no_token_401():
    r = requests.delete(f"{BASE}/zones/99999")
    assert r.status_code == 401


def test_delete_zone_admin_ok(admin_headers):
    zones = requests.get(f"{BASE}/zones", headers=admin_headers).json()
    mine = [z for z in zones if z["name"] == "pytest-zone"]
    assert mine, "pytest-zone missing; did the add test fail?"
    zid = mine[0]["id"]
    r = requests.delete(f"{BASE}/zones/{zid}", headers=admin_headers)
    assert r.ok, r.text


def test_fleet_requires_auth():
    r = requests.get(f"{BASE}/fleet")
    assert r.status_code == 401


def test_fleet_with_token(admin_headers):
    r = requests.get(f"{BASE}/fleet", headers=admin_headers)
    assert r.ok
    body = r.json()
    assert "speed_limit" in body
    assert "vehicles" in body
    assert isinstance(body["vehicles"], list)


def test_my_vehicles_requires_auth():
    r = requests.get(f"{BASE}/my-vehicles")
    assert r.status_code == 401


def test_my_vehicles_with_token(admin_headers):
    r = requests.get(f"{BASE}/my-vehicles", headers=admin_headers)
    assert r.ok
    assert isinstance(r.json(), list)
    

# --- Batch 2: hashed device keys + rotate ----------------------------------

def test_rotate_key_requires_auth():
    r = requests.post(f"{BASE}/vehicles/ANY/rotate-key")
    assert r.status_code == 401


def test_rotate_key_admin_returns_plaintext_once(admin_headers):
    import uuid
    plate = "PYTEST-ROT-" + uuid.uuid4().hex[:6]

    reg = requests.post(f"{BASE}/vehicles", headers=admin_headers,
                        json={"plate": plate, "owner": "nazon"})
    assert reg.ok, reg.text
    first_key = reg.json()["device_key"]
    assert first_key and len(first_key) == 32

    rot = requests.post(f"{BASE}/vehicles/{plate}/rotate-key",
                        headers=admin_headers)
    assert rot.ok, rot.text
    new_key = rot.json()["device_key"]
    assert new_key and new_key != first_key

    # Old key is now rejected
    old = requests.post(f"{BASE}/track", json={
        "plate": plate, "lat": -15.4, "lon": 28.3, "speed": 0,
        "fuel": 50, "device_key": first_key})
    assert old.status_code == 401, old.text

    # New key works
    new = requests.post(f"{BASE}/track", json={
        "plate": plate, "lat": -15.4, "lon": 28.3, "speed": 0,
        "fuel": 50, "device_key": new_key})
    assert new.ok, new.text


def test_my_vehicles_does_not_leak_key(admin_headers):
    r = requests.get(f"{BASE}/my-vehicles", headers=admin_headers)
    assert r.ok
    for v in r.json():
        assert "device_key" not in v, f"plaintext key leaked for {v['plate']}"
        assert "key_present" in v
        assert isinstance(v["key_present"], bool)


def test_non_owner_cannot_rotate(admin_headers):
    import uuid
    uname = f"pytest-user-{uuid.uuid4().hex[:8]}"

    # create the account
    requests.post(f"{BASE}/accounts", headers=admin_headers,
                  json={"username": uname, "password": "pw-pytest-123",
                        "kind": "personal", "display_name": "Test User"})

    lr = requests.post(f"{BASE}/login",
                       json={"username": uname, "password": "pw-pytest-123"})
    assert lr.ok, lr.text
    user_tok = lr.json()["token"]

    # create a vehicle owned by admin to try to rotate
    import uuid as _u
    plate = "PYTEST-OWN-" + _u.uuid4().hex[:6]
    requests.post(f"{BASE}/vehicles", headers=admin_headers,
                  json={"plate": plate, "owner": "nazon"})

    # non-owner tries to rotate
    r = requests.post(f"{BASE}/vehicles/{plate}/rotate-key",
                      headers={"Authorization": f"Bearer {user_tok}"})
    assert r.status_code == 403, f"expected 403, got {r.status_code}: {r.text}"


def test_audit_log_records_rotate(admin_headers):
    """The rotate endpoint should leave a row in the audit table."""
    import uuid, sqlite3, os
    plate = "PYTEST-AUD-" + uuid.uuid4().hex[:6]

    requests.post(f"{BASE}/vehicles", headers=admin_headers,
                  json={"plate": plate, "owner": "nazon"})
    requests.post(f"{BASE}/vehicles/{plate}/rotate-key", headers=admin_headers)

    # Only meaningful on SQLite; skip if we're on Postgres.
    if not os.path.exists("nazon.db"):
        import pytest
        pytest.skip("audit test only checks the local SQLite DB")

    c = sqlite3.connect("nazon.db")
    rows = c.execute(
        "SELECT action, target FROM audit WHERE target=? ORDER BY id DESC",
        (plate,)).fetchall()
    c.close()

    actions = [r[0] for r in rows]
    assert "device_key.rotate" in actions, f"no rotate audit row: {rows}"
    assert "vehicle.register" in actions, f"no register audit row: {rows}"