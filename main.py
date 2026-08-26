from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
from datetime import datetime

app = FastAPI(title="NAZON")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "nazon.db"
SPEED_LIMIT = 80
FUEL_DROP_ALERT = 6

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init():
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS vehicles (
        id INTEGER PRIMARY KEY, plate TEXT UNIQUE, owner TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY, plate TEXT, lat REAL, lon REAL,
        speed REAL DEFAULT 0, fuel REAL DEFAULT 0, ts TEXT)""")
    conn.commit()
    conn.close()

init()

class Ping(BaseModel):
    plate: str
    lat: float
    lon: float
    speed: float = 0
    fuel: float = 0

@app.get("/")
def home():
    return {"system": "NAZON", "status": "online"}

@app.post("/track")
def track(p: Ping):
    conn = db()
    conn.execute("INSERT OR IGNORE INTO vehicles (plate, owner) VALUES (?, ?)",
                 (p.plate, "unknown"))
    conn.execute("""INSERT INTO locations (plate, lat, lon, speed, fuel, ts)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (p.plate, p.lat, p.lon, p.speed, p.fuel,
                  datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"saved": True, "plate": p.plate}

@app.get("/fleet")
def fleet():
    conn = db()
    rows = conn.execute("""
        SELECT l.plate, l.lat, l.lon, l.speed, l.fuel, l.ts
        FROM locations l
        JOIN (SELECT plate, MAX(id) AS mid FROM locations GROUP BY plate) last
        ON l.id = last.mid
    """).fetchall()

    out = []
    for r in rows:
        prev = conn.execute("""SELECT fuel FROM locations WHERE plate=?
                               ORDER BY id DESC LIMIT 1 OFFSET 1""",
                            (r["plate"],)).fetchone()
        fuel_drop = False
        if prev is not None and (prev["fuel"] - r["fuel"]) >= FUEL_DROP_ALERT:
            fuel_drop = True
        out.append({
            "plate": r["plate"], "lat": r["lat"], "lon": r["lon"],
            "speed": r["speed"], "fuel": r["fuel"], "ts": r["ts"],
            "speeding": r["speed"] > SPEED_LIMIT,
            "fuel_drop": fuel_drop
        })
    conn.close()
    return {"speed_limit": SPEED_LIMIT, "vehicles": out}

@app.get("/trail/{plate}")
def trail(plate: str):
    conn = db()
    rows = conn.execute("""SELECT lat, lon FROM locations WHERE plate=?
                           ORDER BY id DESC LIMIT 40""", (plate,)).fetchall()
    conn.close()
    # reverse so it goes oldest -> newest
    pts = [[r["lat"], r["lon"]] for r in rows][::-1]
    return {"plate": plate, "points": pts}
