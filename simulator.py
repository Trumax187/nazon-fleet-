import requests, time, random

BASE = "http://127.0.0.1:8000"

# Admin login so the simulator can register its demo vehicles and get device keys.
# (Change the password here if you changed the admin password.)
ADMIN_USER = "nazon"
ADMIN_PASS = "nazon123"

fleet = {
    "NAZON-001": {"pos": [-15.3875, 28.3228], "fuel": 100.0, "sos": False, "key": None},
    "NAZON-002": {"pos": [-15.3982, 28.3225], "fuel": 85.0, "sos": False, "key": None},
    "NAZON-003": {"pos": [-15.4067, 28.2871], "fuel": 60.0, "sos": False, "key": None},
}


def setup():
    r = requests.post(BASE + "/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    if not r.ok:
        print("Login failed. If you changed the admin password, update ADMIN_PASS in this file.")
        raise SystemExit(1)
    token = r.json()["token"]
    headers = {"Authorization": "Bearer " + token}
    for plate in fleet:
        rr = requests.post(BASE + "/vehicles", headers=headers,
                           json={"plate": plate, "owner": ADMIN_USER})
        fleet[plate]["key"] = rr.json()["device_key"]
    print("Vehicles registered with device keys.")
    return headers


headers = setup()
print("Fleet is driving... (Ctrl+C to stop)")
while True:
    for plate, v in fleet.items():
        v["pos"][0] += random.uniform(-0.0015, 0.0015)
        v["pos"][1] += random.uniform(-0.0015, 0.0015)

        speed = random.randint(30, 70)
        if random.random() < 0.25:
            speed = random.randint(85, 120)

        v["fuel"] -= random.uniform(0.3, 0.8)
        if random.random() < 0.05:
            v["fuel"] -= random.uniform(8, 15)
        if v["fuel"] < 15:
            v["fuel"] = 100.0
        v["fuel"] = max(0.0, round(v["fuel"], 1))

        try:
            requests.post(BASE + "/track", json={
                "plate": plate, "lat": v["pos"][0], "lon": v["pos"][1],
                "speed": speed, "fuel": v["fuel"], "device_key": v["key"]})
        except Exception as e:
            print("error:", e)

        if not v["sos"] and random.random() < 0.02:
            try:
                requests.post(BASE + "/sos", headers=headers, json={"plate": plate})
                v["sos"] = True
                print(f"*** {plate} triggered SOS ***")
            except Exception as e:
                print("sos error:", e)
        elif v["sos"] and random.random() < 0.15:
            try:
                requests.post(BASE + "/sos/clear", headers=headers, json={"plate": plate})
                v["sos"] = False
                print(f"--- {plate} SOS cleared ---")
            except Exception as e:
                print("sos clear error:", e)

        tag = "  [SOS]" if v["sos"] else ""
        print(f"{plate}: {speed} km/h  fuel {v['fuel']}%{tag}")
    print("---")
    time.sleep(2)
