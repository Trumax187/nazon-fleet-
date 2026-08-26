import requests, time, random

URL = "http://127.0.0.1:8000/track"

fleet = {
    "NAZON-001": {"pos": [-15.3875, 28.3228], "fuel": 100.0},
    "NAZON-002": {"pos": [-15.3982, 28.3225], "fuel": 85.0},
    "NAZON-003": {"pos": [-15.4067, 28.2871], "fuel": 60.0},
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
            print(f"{plate}: {speed} km/h  fuel {v['fuel']}%")
        except Exception as e:
            print("error:", e)
    print("---")
    time.sleep(2)
