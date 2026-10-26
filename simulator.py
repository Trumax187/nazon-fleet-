import requests, time, random, os

BASE = os.environ.get("NAZON_BASE", "http://127.0.0.1:8000")

# Admin login so the simulator can register its demo vehicles and get device keys.
# Credentials come from environment variables (never hardcode them in this file).
ADMIN_USER = os.environ.get("NAZON_ADMIN_USER", "nazon")
ADMIN_PASS = os.environ.get("NAZON_ADMIN_PASS")
if not ADMIN_PASS:
    raise SystemExit("Set NAZON_ADMIN_PASS (and optionally NAZON_ADMIN_USER) before running the simulator.")

fleet = {
    "NAZON-001": {"pos": [-15.3875, 28.3228], "fuel": 100.0, "sos": False, "key": None},
    "NAZON-002": {"pos": [-15.3982, 28.3225], "fuel": 85.0, "sos": False, "key": None},
    "NAZON-003": {"pos": [-15.4067, 28.2871], "fuel": 60.0, "sos": False, "key": None},
}


def setup():
    r = requests.post(BASE + "/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    if not r.ok:
        print("Login failed. Check NAZON_ADMIN_USER / NAZON_ADMIN_PASS match the server's admin account.")
        raise SystemExit(1)
    token = r.json()["token"]
    headers = {"Authorization": "Bearer " + token}
    for plate in fleet:
        rr = requests.post(BASE + "/vehicles", headers=headers,
                           json={"plate": plate, "owner": ADMIN_USER})
        if not rr.ok:
            raise SystemExit(
                f"Vehicle registration failed for {plate}: "
                f"{rr.status_code} {rr.text}")
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
        
        # 2% chance the driver stops for a break (triggers trip end after 10s)
        if random.random() < 0.02:
            speed = 0

        # Normal consumption
        v["fuel"] -= random.uniform(0.1, 0.4)
        
        # 2% chance of a massive fuel theft (siphoning while parked)
        if random.random() < 0.02:
            print(f"!!! {plate} is being siphoned !!!")
            speed = 0 # Force speed to 0 so the server detects the theft
            v["fuel"] -= random.uniform(10.0, 20.0)
            
        # If fuel drops below 15, the driver goes to the station to refuel
        if v["fuel"] < 15:
            print(f"+++ {plate} refueling +++")
            v["fuel"] = 100.0
            
        v["fuel"] = max(0.0, round(v["fuel"], 1))

        try:
            r = requests.post(BASE + "/track", json={
                "plate": plate, "lat": v["pos"][0], "lon": v["pos"][1],
                "speed": speed, "fuel": v["fuel"], "device_key": v["key"]})
            if not r.ok:
                print(f"track rejected for {plate}: {r.status_code} {r.text}")
        except Exception as e:
            print("error:", e)

        if not v["sos"] and random.random() < 0.02:
            try:
                r = requests.post(BASE + "/sos", headers=headers, json={"plate": plate})
                if r.ok:
                    v["sos"] = True
                    print(f"*** {plate} triggered SOS ***")
                else:
                    print(f"sos rejected: {r.status_code} {r.text}")
            except Exception as e:
                print("sos error:", e)
        elif v["sos"] and random.random() < 0.15:
            try:
                r = requests.post(BASE + "/sos/clear", headers=headers, json={"plate": plate})
                if r.ok:
                    v["sos"] = False
                    print(f"--- {plate} SOS cleared ---")
                else:
                    print(f"sos clear rejected: {r.status_code} {r.text}")
            except Exception as e:
                print("sos clear error:", e)

        tag = "  [SOS]" if v["sos"] else ""
        print(f"{plate}: {speed} km/h  fuel {v['fuel']}%{tag}")
    print("---")
    time.sleep(2)
