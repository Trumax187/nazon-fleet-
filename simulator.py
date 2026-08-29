import requests, time, random

BASE = "http://127.0.0.1:8000"
URL = BASE + "/track"

fleet = {
    "NAZON-001": {"pos": [-15.3875, 28.3228], "fuel": 100.0, "sos": False},
    "NAZON-002": {"pos": [-15.3982, 28.3225], "fuel": 85.0, "sos": False},
    "NAZON-003": {"pos": [-15.4067, 28.2871], "fuel": 60.0, "sos": False},
}

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
            requests.post(URL, json={"plate": plate, "lat": v["pos"][0],
                                     "lon": v["pos"][1], "speed": speed,
                                     "fuel": v["fuel"]})
        except Exception as e:
            print("error:", e)

        # occasionally fire an SOS for a vehicle that is not already in SOS
        if not v["sos"] and random.random() < 0.02:
            try:
                requests.post(BASE + "/sos", json={"plate": plate})
                v["sos"] = True
                print(f"*** {plate} triggered SOS ***")
            except Exception as e:
                print("sos error:", e)
        # small chance it resolves on its own so the demo keeps cycling
        elif v["sos"] and random.random() < 0.15:
            try:
                requests.post(BASE + "/sos/clear", json={"plate": plate})
                v["sos"] = False
                print(f"--- {plate} SOS cleared ---")
            except Exception as e:
                print("sos clear error:", e)

        tag = "  [SOS]" if v["sos"] else ""
        print(f"{plate}: {speed} km/h  fuel {v['fuel']}%{tag}")
    print("---")
    time.sleep(2)
