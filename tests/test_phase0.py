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