from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3, math, hashlib, hmac, secrets, time, base64, json, os
from datetime import datetime

app = FastAPI(title="NAZON")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SPEED_LIMIT = 80
FUEL_DROP_ALERT = 6

# Secret comes from the environment in production; falls back to a demo value locally.
SECRET_KEY = os.environ.get("NAZON_SECRET", "nazon-demo-secret-change-me")
TOKEN_HOURS = 12

# If DATABASE_URL is set (on Render), use PostgreSQL; otherwise use a local SQLite file.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = DATABASE_URL.startswith("postgres")

if USE_PG:
    import psycopg2
    import psycopg2.extras
    # Render sometimes provides a "postgres://" URL; psycopg2 wants "postgresql://"
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


class DBWrapper:
    """Thin wrapper so the rest of the code can use one style:
       conn.execute("... ? ...", (args,)).fetchone()/.fetchall()
       works on both SQLite and PostgreSQL."""
    def __init__(self):
        if USE_PG:
            self.conn = psycopg2.connect(DATABASE_URL)
        else:
            self.conn = sqlite3.connect("nazon.db")
            self.conn.row_factory = sqlite3.Row

    def execute(self, sql, params=()):
        if USE_PG:
            sql = sql.replace("?", "%s")
            cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cur = self.conn.cursor()
        cur.execute(sql, params)
        return _Result(cur)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


class _Result:
    def __init__(self, cur):
        self.cur = cur

    def fetchone(self):
        row = self.cur.fetchone()
        return row

    def fetchall(self):
        return self.cur.fetchall()


def db():
    return DBWrapper()


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt + "$" + h.hex()


def verify_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def make_token(username):
    payload = {"u": username, "exp": int(time.time()) + TOKEN_HOURS * 3600}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig


def verify_token(token):
    try:
        body, sig = token.split(".", 1)
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    pad = "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + pad))
    except Exception:
        return None
    if payload.get("exp", 0) < int(time.time()):
        return None
    return payload.get("u")


def current_owner(authorization):
    """Extract and verify the owner from an Authorization: Bearer <token> header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return verify_token(authorization[7:])


def require_owner(authorization):
    username = current_owner(authorization)
    if username is None:
        raise HTTPException(status_code=401, detail="Not logged in")
    return username


def init():
    conn = db()
    pk = "SERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY"
    conn.execute("""CREATE TABLE IF NOT EXISTS owners (
        username TEXT PRIMARY KEY, password TEXT, kind TEXT,
        display_name TEXT, is_admin INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0)""")
    conn.execute("CREATE TABLE IF NOT EXISTS vehicles ("
                 "id " + pk + ", plate TEXT UNIQUE, owner TEXT, device_key TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS locations ("
                 "id " + pk + ", plate TEXT, lat REAL, lon REAL, "
                 "speed REAL DEFAULT 0, fuel REAL DEFAULT 0, ts TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS zones ("
                 "id " + pk + ", name TEXT, kind TEXT, lat REAL, lon REAL, radius_m REAL)")
    conn.execute("""CREATE TABLE IF NOT EXISTS sos (
        plate TEXT PRIMARY KEY, active INTEGER DEFAULT 0, ts TEXT)""")
    count = conn.execute("SELECT COUNT(*) AS c FROM zones").fetchone()["c"]
    if count == 0:
        seed = [
            ("Chibolya", "danger", -15.4400, 28.2720, 700),
            ("Kanyama", "danger", -15.4270, 28.2600, 900),
        ]
        for s in seed:
            conn.execute(
                "INSERT INTO zones (name, kind, lat, lon, radius_m) VALUES (?, ?, ?, ?, ?)", s)
    admin = conn.execute("SELECT username FROM owners WHERE username='nazon'").fetchone()
    if admin is None:
        conn.execute(
            "INSERT INTO owners (username, password, kind, display_name, is_admin, must_change) VALUES (?, ?, ?, ?, 1, 1)",
            ("nazon", hash_password("nazon123"), "admin", "NAZON Admin"))
    conn.commit()
    conn.close()


init()


def meters_between(lat1, lon1, lat2, lon2):
    R = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class Ping(BaseModel):
    plate: str
    lat: float
    lon: float
    speed: float = 0
    fuel: float = 0
    device_key: str = ""


class Zone(BaseModel):
    name: str
    kind: str
    lat: float
    lon: float
    radius_m: float


@app.get("/")
def home():
    return {"system": "NAZON", "status": "online"}


class LoginReq(BaseModel):
    username: str
    password: str


class NewAccount(BaseModel):
    username: str
    password: str
    kind: str = "individual"     # "company" or "individual"
    display_name: str = ""


class ChangePw(BaseModel):
    new_password: str


@app.post("/login")
def login(req: LoginReq):
    conn = db()
    row = conn.execute("SELECT * FROM owners WHERE username=?", (req.username,)).fetchone()
    conn.close()
    if row is None or not verify_password(req.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {
        "token": make_token(row["username"]),
        "username": row["username"],
        "display_name": row["display_name"],
        "is_admin": bool(row["is_admin"]),
        "must_change": bool(row["must_change"]),
    }


@app.get("/whoami")
def whoami(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    row = conn.execute("SELECT username, display_name, is_admin, kind FROM owners WHERE username=?",
                       (username,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Unknown account")
    return {"username": row["username"], "display_name": row["display_name"],
            "is_admin": bool(row["is_admin"]), "kind": row["kind"]}


@app.post("/change-password")
def change_password(req: ChangePw, authorization: str = Header(None)):
    username = require_owner(authorization)
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    conn = db()
    conn.execute("UPDATE owners SET password=?, must_change=0 WHERE username=?",
                 (hash_password(req.new_password), username))
    conn.commit()
    conn.close()
    return {"changed": True}


@app.post("/accounts")
def create_account(req: NewAccount, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    me = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    if me is None or not me["is_admin"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Only admin can create accounts")
    exists = conn.execute("SELECT username FROM owners WHERE username=?", (req.username,)).fetchone()
    if exists:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already taken")
    conn.execute(
        "INSERT INTO owners (username, password, kind, display_name, is_admin, must_change) VALUES (?, ?, ?, ?, 0, 1)",
        (req.username, hash_password(req.password), req.kind, req.display_name or req.username))
    conn.commit()
    conn.close()
    return {"created": req.username}


@app.post("/track")
def track(p: Ping):
    conn = db()
    v = conn.execute("SELECT device_key FROM vehicles WHERE plate=?", (p.plate,)).fetchone()
    if v is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Unknown vehicle. Register it first.")
    if not p.device_key or not hmac.compare_digest(p.device_key, v["device_key"] or ""):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid device key")
    conn.execute("""INSERT INTO locations (plate, lat, lon, speed, fuel, ts)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (p.plate, p.lat, p.lon, p.speed, p.fuel,
                  datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"saved": True, "plate": p.plate}


class RegisterVehicle(BaseModel):
    plate: str
    owner: str = ""     # admin may set; owners get their own


@app.post("/vehicles")
def register_vehicle(req: RegisterVehicle, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    me = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    is_admin = me is not None and me["is_admin"]
    owner = req.owner if (is_admin and req.owner) else username
    # confirm target owner exists
    if conn.execute("SELECT username FROM owners WHERE username=?", (owner,)).fetchone() is None:
        conn.close()
        raise HTTPException(status_code=400, detail="Owner account does not exist")
    existing = conn.execute("SELECT plate FROM vehicles WHERE plate=?", (req.plate,)).fetchone()
    key = secrets.token_hex(16)
    if existing:
        conn.execute("UPDATE vehicles SET owner=?, device_key=? WHERE plate=?",
                     (owner, key, req.plate))
    else:
        conn.execute("INSERT INTO vehicles (plate, owner, device_key) VALUES (?, ?, ?)",
                     (req.plate, owner, key))
    conn.commit()
    conn.close()
    return {"plate": req.plate, "owner": owner, "device_key": key}


@app.get("/my-vehicles")
def my_vehicles(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    me = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    is_admin = me is not None and me["is_admin"]
    if is_admin:
        rows = conn.execute("SELECT plate, owner, device_key FROM vehicles").fetchall()
    else:
        rows = conn.execute("SELECT plate, owner, device_key FROM vehicles WHERE owner=?",
                            (username,)).fetchall()
    conn.close()
    return [{"plate": r["plate"], "owner": r["owner"], "device_key": r["device_key"]} for r in rows]


class SosReq(BaseModel):
    plate: str


def owns_vehicle(conn, username, plate):
    me = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    if me is not None and me["is_admin"]:
        return True
    v = conn.execute("SELECT owner FROM vehicles WHERE plate=?", (plate,)).fetchone()
    return v is not None and v["owner"] == username


@app.post("/sos")
def sos_trigger(s: SosReq, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    if not owns_vehicle(conn, username, s.plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")
    conn.execute("""INSERT INTO sos (plate, active, ts) VALUES (?, 1, ?)
                    ON CONFLICT(plate) DO UPDATE SET active=1, ts=excluded.ts""",
                 (s.plate, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"sos": "active", "plate": s.plate}


@app.post("/sos/clear")
def sos_clear(s: SosReq, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    if not owns_vehicle(conn, username, s.plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")
    conn.execute("UPDATE sos SET active=0 WHERE plate=?", (s.plate,))
    conn.commit()
    conn.close()
    return {"sos": "cleared", "plate": s.plate}


@app.get("/zones")
def get_zones(authorization: str = Header(None)):
    require_owner(authorization)
    conn = db()
    rows = conn.execute("SELECT id, name, kind, lat, lon, radius_m FROM zones").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/zones")
def add_zone(z: Zone):
    conn = db()
    conn.execute("INSERT INTO zones (name, kind, lat, lon, radius_m) VALUES (?, ?, ?, ?, ?)",
                 (z.name, z.kind, z.lat, z.lon, z.radius_m))
    conn.commit()
    conn.close()
    return {"added": z.name}


@app.delete("/zones/{zone_id}")
def delete_zone(zone_id: int):
    conn = db()
    conn.execute("DELETE FROM zones WHERE id=?", (zone_id,))
    conn.commit()
    conn.close()
    return {"deleted": zone_id}


@app.get("/fleet")
def fleet(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    me = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    is_admin = me is not None and me["is_admin"]

    # which plates may this account see?
    if is_admin:
        allowed = None   # all
    else:
        owned = conn.execute("SELECT plate FROM vehicles WHERE owner=?", (username,)).fetchall()
        allowed = {r["plate"] for r in owned}

    rows = conn.execute("""
        SELECT l.plate, l.lat, l.lon, l.speed, l.fuel, l.ts
        FROM locations l
        JOIN (SELECT plate, MAX(id) AS mid FROM locations GROUP BY plate) last
        ON l.id = last.mid
    """).fetchall()
    danger_zones = conn.execute(
        "SELECT name, lat, lon, radius_m FROM zones WHERE kind='danger'").fetchall()
    sos_rows = conn.execute("SELECT plate FROM sos WHERE active=1").fetchall()
    sos_set = {r["plate"] for r in sos_rows}

    out = []
    for r in rows:
        if allowed is not None and r["plate"] not in allowed:
            continue
        prev = conn.execute("""SELECT fuel FROM locations WHERE plate=?
                               ORDER BY id DESC LIMIT 1 OFFSET 1""",
                            (r["plate"],)).fetchone()
        fuel_drop = prev is not None and (prev["fuel"] - r["fuel"]) >= FUEL_DROP_ALERT

        in_zone = None
        for z in danger_zones:
            if meters_between(r["lat"], r["lon"], z["lat"], z["lon"]) <= z["radius_m"]:
                in_zone = z["name"]
                break

        out.append({
            "plate": r["plate"], "lat": r["lat"], "lon": r["lon"],
            "speed": r["speed"], "fuel": r["fuel"], "ts": r["ts"],
            "speeding": r["speed"] > SPEED_LIMIT,
            "fuel_drop": fuel_drop,
            "danger_zone": in_zone,
            "sos": r["plate"] in sos_set
        })
    conn.close()
    return {"speed_limit": SPEED_LIMIT, "vehicles": out}


@app.get("/trail/{plate}")
def trail(plate: str, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    if not owns_vehicle(conn, username, plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")
    rows = conn.execute("""SELECT lat, lon FROM locations WHERE plate=?
                           ORDER BY id DESC LIMIT 2000""", (plate,)).fetchall()
    conn.close()
    pts = [[r["lat"], r["lon"]] for r in rows][::-1]
    return {"plate": plate, "points": pts}


DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>NAZON Fleet Tracking</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <style>
    * { box-sizing: border-box; }
    body { margin:0; font-family:Arial, sans-serif; }
    #bar { background:#0b3d91; color:#fff; padding:14px 18px; font-size:20px; font-weight:bold;
           display:flex; justify-content:space-between; align-items:center; }
    #bar span { font-weight:normal; font-size:14px; opacity:.85; }
    #alertCount { background:#e74c3c; font-size:13px; padding:3px 10px; border-radius:12px; display:none; }
    #wrap { display:flex; height: calc(100vh - 52px); }
    #panel { width:300px; background:#f4f6fb; border-right:1px solid #dbe0ea; overflow-y:auto; padding:12px; }
    #panel h2 { font-size:13px; text-transform:uppercase; letter-spacing:1px; color:#0b3d91; margin:4px 4px 10px; }
    .legend { font-size:11px; color:#555; margin:0 4px 12px; }
    .legend .sw { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:4px; vertical-align:middle; }
    .card { background:#fff; border:1px solid #e2e6ef; border-radius:8px; padding:10px 12px; margin-bottom:10px; cursor:pointer; }
    .card.alert { border-color:#e74c3c; background:#fff5f4; }
    .card .plate { font-weight:bold; color:#0b3d91; font-size:15px; }
    .card .meta { font-size:12px; color:#555; margin-top:4px; }
    .speed.over { color:#e74c3c; font-weight:bold; }
    .tag { font-size:11px; font-weight:bold; color:#fff; padding:1px 6px; border-radius:4px; margin-left:6px; }
    .tag.speed { background:#e74c3c; }
    .tag.fuel { background:#c0392b; }
    .tag.zone { background:#8e0000; }
    .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; background:#2ecc71; }
    .fuelwrap { height:8px; background:#e6e9f0; border-radius:5px; margin-top:6px; overflow:hidden; }
    .fuelbar { height:100%; background:#2ecc71; }
    .fuelbar.low { background:#e67e22; }
    .fuelbar.crit { background:#e74c3c; }
    #map { flex:1; }
    .plateLbl { background:#0b3d91; color:#fff; padding:2px 6px; border-radius:4px; font-size:12px; font-weight:bold; white-space:nowrap; }
    .plateLbl.over { background:#e74c3c; }
    .plateLbl.sos { background:#b30000; animation:flash 0.8s infinite; }
    .zoneLbl { background:rgba(0,0,0,.6); color:#fff; padding:1px 5px; border-radius:3px; font-size:11px; white-space:nowrap; }
    @keyframes flash { 0%,100%{opacity:1;} 50%{opacity:0.35;} }
    .card.sos { border-color:#b30000; background:#ffecec; animation:flash 1.2s infinite; }
    .sosbanner { background:#b30000; color:#fff; font-weight:bold; text-align:center; padding:8px; font-size:14px; display:none; animation:flash 1s infinite; }
    .btnrow { margin-top:8px; }
    .btn { font-size:11px; font-weight:bold; border:none; border-radius:5px; padding:5px 9px; cursor:pointer; color:#fff; }
    .btn.sos { background:#b30000; }
    .btn.clear { background:#555; }
  </style>
</head>
<body>
  <div id="loginOverlay" style="position:fixed;inset:0;background:#0b3d91;display:flex;align-items:center;justify-content:center;z-index:9999;">
    <div style="background:#fff;border-radius:12px;padding:26px;width:300px;font-family:Arial,sans-serif;">
      <div style="font-size:22px;font-weight:bold;color:#0b3d91;text-align:center;">NAZON</div>
      <div style="font-size:13px;color:#777;text-align:center;margin-bottom:16px;">Sign in to your dashboard</div>
      <input id="lgUser" placeholder="Username" style="width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:6px;" />
      <input id="lgPass" type="password" placeholder="Password" style="width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:6px;" />
      <button id="lgBtn" style="width:100%;padding:11px;margin-top:8px;background:#0b3d91;color:#fff;border:none;border-radius:6px;font-weight:bold;font-size:15px;cursor:pointer;">Sign in</button>
      <div id="lgErr" style="color:#e74c3c;font-size:13px;margin-top:8px;text-align:center;"></div>
    </div>
  </div>
  <div id="pwOverlay" style="position:fixed;inset:0;background:rgba(11,61,145,.95);display:none;align-items:center;justify-content:center;z-index:9998;">
    <div style="background:#fff;border-radius:12px;padding:26px;width:300px;font-family:Arial,sans-serif;">
      <div style="font-size:18px;font-weight:bold;color:#0b3d91;text-align:center;">Set a new password</div>
      <div style="font-size:13px;color:#777;text-align:center;margin-bottom:16px;">You're using a temporary password.</div>
      <input id="pwNew" type="password" placeholder="New password (min 6)" style="width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:6px;" />
      <button id="pwBtn" style="width:100%;padding:11px;margin-top:8px;background:#0b3d91;color:#fff;border:none;border-radius:6px;font-weight:bold;font-size:15px;cursor:pointer;">Save password</button>
      <div id="pwErr" style="color:#e74c3c;font-size:13px;margin-top:8px;text-align:center;"></div>
    </div>
  </div>
  <div id="bar">
    <div>NAZON &nbsp;<span id="barSub">Live Fleet Tracking</span></div>
    <div style="display:flex;align-items:center;gap:12px;">
      <div id="alertCount"></div>
      <button id="logoutBtn" style="display:none;background:rgba(255,255,255,.2);color:#fff;border:none;border-radius:6px;padding:5px 10px;font-size:12px;cursor:pointer;">Log out</button>
    </div>
  </div>
  <div id="sosbanner" class="sosbanner"></div>
  <div id="wrap">
    <div id="panel">
      <h2>Vehicles</h2>
      <div class="legend">
        <span class="sw" style="background:#e74c3c"></span>Danger zone &nbsp;
        <span class="sw" style="background:#e67e22"></span>Simulated congestion
      </div>
      <div id="list"></div>
    </div>
    <div id="map"></div>
  </div>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    let TOKEN = localStorage.getItem("nazon_token") || null;
    let refreshTimer = null;

    function authFetch(url, opts){
      opts = opts || {};
      opts.headers = opts.headers || {};
      if(TOKEN) opts.headers["Authorization"] = "Bearer " + TOKEN;
      return fetch(url, opts);
    }

    async function doLogin(){
      const u = document.getElementById("lgUser").value.trim();
      const p = document.getElementById("lgPass").value;
      const err = document.getElementById("lgErr");
      err.textContent = "";
      try{
        const res = await fetch("/login", {method:"POST", headers:{"Content-Type":"application/json"},
          body: JSON.stringify({username:u, password:p})});
        if(!res.ok){ err.textContent = "Invalid username or password"; return; }
        const d = await res.json();
        TOKEN = d.token;
        localStorage.setItem("nazon_token", TOKEN);
        document.getElementById("barSub").textContent = d.display_name || "Live Fleet Tracking";
        document.getElementById("loginOverlay").style.display = "none";
        document.getElementById("logoutBtn").style.display = "inline-block";
        if(d.must_change){ document.getElementById("pwOverlay").style.display = "flex"; }
        startApp();
      }catch(e){ err.textContent = "Could not reach server"; }
    }

    async function doChangePw(){
      const np = document.getElementById("pwNew").value;
      const err = document.getElementById("pwErr");
      if(np.length < 6){ err.textContent = "At least 6 characters"; return; }
      const res = await authFetch("/change-password", {method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({new_password:np})});
      if(res.ok){ document.getElementById("pwOverlay").style.display = "none"; }
      else { err.textContent = "Could not change password"; }
    }

    function logout(){
      TOKEN = null;
      localStorage.removeItem("nazon_token");
      if(refreshTimer) clearInterval(refreshTimer);
      location.reload();
    }

    document.getElementById("lgBtn").addEventListener("click", doLogin);
    document.getElementById("lgPass").addEventListener("keydown", e=>{ if(e.key==="Enter") doLogin(); });
    document.getElementById("pwBtn").addEventListener("click", doChangePw);
    document.getElementById("logoutBtn").addEventListener("click", logout);

    const map = L.map("map").setView([-15.4100, 28.2900], 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { attribution: "(c) OpenStreetMap" }).addTo(map);

    const markers = {}, trails = {};
    const colors = ["#0b3d91","#8e44ad","#16a085","#d35400","#2c3e50"];
    let colorIdx = 0; const plateColor = {};
    function colorFor(p){ if(!plateColor[p]) plateColor[p]=colors[colorIdx++%colors.length]; return plateColor[p]; }
    function ago(iso){ const s=Math.floor((Date.now()-new Date(iso+"Z").getTime())/1000); return s<60? s+"s ago": Math.floor(s/60)+"m ago"; }
    function icon(state){ const c = state==="sos"?"#b30000":(state==="over"?"#e74c3c":"#0b3d91"); const sz = state==="sos"?"width:20px;height:20px;":"width:16px;height:16px;"; return L.divIcon({className:"", html:'<div style="'+sz+'border-radius:50%;border:2px solid #fff;background:'+c+';box-shadow:0 0 6px rgba(0,0,0,.5)"></div>', iconSize:[20,20], iconAnchor:[10,10]}); }
    async function triggerSos(plate){ try{ await authFetch("/sos",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plate:plate})}); refresh(); }catch(e){ console.log(e); } }
    async function clearSos(plate){ try{ await authFetch("/sos/clear",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plate:plate})}); refresh(); }catch(e){ console.log(e); } }

    async function loadZones(){
      try{
        const res = await authFetch("/zones");
        const zones = await res.json();
        zones.forEach(z => {
          const danger = z.kind === "danger";
          const color = danger ? "#e74c3c" : "#e67e22";
          L.circle([z.lat, z.lon], { radius:z.radius_m, color:color, weight:2, fillColor:color, fillOpacity:0.15 })
            .addTo(map)
            .bindTooltip((danger?"[!] ":"[~] ")+z.name, {permanent:true, direction:"center", className:"zoneLbl"});
        });
      }catch(e){ console.log("zones error", e); }
    }

    async function drawTrail(plate){
      try{
        const res=await authFetch("/trail/"+plate); const d=await res.json();
        if(d.points && d.points.length>1){
          if(trails[plate]) trails[plate].setLatLngs(d.points);
          else trails[plate]=L.polyline(d.points,{color:colorFor(plate),weight:3,opacity:0.7}).addTo(map);
        }
      }catch(e){ console.log(e); }
    }

    async function refresh(){
      try{
        const res=await authFetch("/fleet");
        if(res.status===401){ logout(); return; }
        const data=await res.json();
        const limit=data.speed_limit, fleet=data.vehicles;
        const list=document.getElementById("list"); list.innerHTML=""; let alerts=0; let sosPlates=[];
        fleet.forEach(v=>{
          const pos=[v.lat,v.lon], over=v.speeding, theft=v.fuel_drop, inZone=v.danger_zone, sos=v.sos;
          if(over) alerts++; if(theft) alerts++; if(inZone) alerts++; if(sos){ alerts++; sosPlates.push(v.plate); }
          const state = sos?"sos":(over?"over":"normal");
          const lblClass = "plateLbl"+(sos?" sos":(over?" over":""));
          if(!markers[v.plate]){
            markers[v.plate]=L.marker(pos,{icon:icon(state)}).addTo(map).bindTooltip(v.plate,{permanent:true,direction:"top",className:lblClass});
          } else {
            markers[v.plate].setLatLng(pos).setIcon(icon(state));
            markers[v.plate].bindTooltip(v.plate,{permanent:true,direction:"top",className:lblClass});
          }
          drawTrail(v.plate);
          let fclass="fuelbar"; if(v.fuel<20) fclass+=" crit"; else if(v.fuel<40) fclass+=" low";
          const card=document.createElement("div");
          card.className="card"+(sos?" sos":((over||theft||inZone)?" alert":""));
          const btn = sos
            ? '<button class="btn clear" data-plate="'+v.plate+'" data-act="clear">Clear SOS</button>'
            : '<button class="btn sos" data-plate="'+v.plate+'" data-act="sos">SOS</button>';
          card.innerHTML=
            '<div class="plate">'+v.plate+
              (sos?'<span class="tag" style="background:#b30000">SOS</span>':'')+
              (over?'<span class="tag speed">SPEEDING</span>':'')+
              (theft?'<span class="tag fuel">FUEL DROP</span>':'')+
              (inZone?'<span class="tag zone">DANGER ZONE</span>':'')+'</div>'+
            '<div class="meta"><span class="dot"></span>Active  -  '+ago(v.ts)+'</div>'+
            (inZone?'<div class="meta" style="color:#8e0000;font-weight:bold">In: '+inZone+'</div>':'')+
            '<div class="meta">Speed: <span class="speed '+(over?"over":"")+'">'+Math.round(v.speed)+' km/h</span> (limit '+limit+')</div>'+
            '<div class="meta">Fuel: '+v.fuel.toFixed(0)+'%</div>'+
            '<div class="fuelwrap"><div class="'+fclass+'" style="width:'+v.fuel+'%"></div></div>'+
            '<div class="btnrow">'+btn+'</div>';
          card.onclick=()=>map.setView(pos,15);
          list.appendChild(card);
        });
        const badge=document.getElementById("alertCount");
        if(alerts>0){ badge.style.display="inline-block"; badge.textContent=alerts+" alert"+(alerts>1?"s":""); }
        else badge.style.display="none";
        const sb=document.getElementById("sosbanner");
        if(sosPlates.length>0){ sb.style.display="block"; sb.textContent="SOS EMERGENCY - "+sosPlates.join(", "); }
        else sb.style.display="none";
      }catch(e){ console.log(e); }
    }

    document.getElementById("list").addEventListener("click", function(e){
      const b = e.target.closest("button[data-act]");
      if(!b) return;
      e.stopPropagation();
      const plate = b.getAttribute("data-plate");
      if(b.getAttribute("data-act")==="sos") triggerSos(plate);
      else clearSos(plate);
    });

    let started = false;
    function startApp(){
      if(started) return;
      started = true;
      loadZones();
      refresh();
      refreshTimer = setInterval(refresh, 2000);
    }

    // if a token is already stored, try to use it; otherwise show login
    if(TOKEN){
      authFetch("/whoami").then(r=>{
        if(r.ok){
          return r.json().then(d=>{
            document.getElementById("barSub").textContent = d.display_name || "Live Fleet Tracking";
            document.getElementById("loginOverlay").style.display = "none";
            document.getElementById("logoutBtn").style.display = "inline-block";
            startApp();
          });
        } else {
          TOKEN = null; localStorage.removeItem("nazon_token");
        }
      }).catch(()=>{});
    }
  </script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


MOBILE_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>NAZON Phone Tracker</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { margin:0; font-family:Arial, sans-serif; background:#0b3d91; color:#fff; text-align:center; }
    .head { padding:18px; font-size:22px; font-weight:bold; }
    .head span { display:block; font-size:13px; opacity:.85; font-weight:normal; }
    .card { background:#fff; color:#222; margin:16px; border-radius:12px; padding:20px; }
    input, select { width:100%; padding:11px; margin:6px 0; border:1px solid #ccc; border-radius:8px; font-size:15px; box-sizing:border-box; }
    #btn, .gobtn { font-size:18px; font-weight:bold; color:#fff; background:#2ecc71; border:none;
           border-radius:12px; padding:16px 20px; width:100%; margin-top:10px; }
    #btn.stop { background:#e74c3c; }
    .gobtn { background:#0b3d91; }
    .row { font-size:15px; margin:8px 0; }
    .big { font-size:34px; font-weight:bold; color:#0b3d91; }
    .muted { color:#777; font-size:13px; }
    #status { margin-top:10px; font-size:14px; }
    .err { color:#e74c3c; font-size:13px; margin-top:6px; }
  </style>
</head>
<body>
  <div class="head">NAZON<span>Phone Live Tracker</span></div>

  <div id="loginCard" class="card">
    <div class="row muted">Sign in to track your vehicle</div>
    <input id="u" placeholder="Username" />
    <input id="p" type="password" placeholder="Password" />
    <button class="gobtn" id="loginBtn">Sign in</button>
    <div class="err" id="loginErr"></div>
  </div>

  <div id="pickCard" class="card" style="display:none;">
    <div class="row muted">Choose the vehicle this phone is in</div>
    <select id="vehSel"></select>
    <button class="gobtn" id="pickBtn">Use this vehicle</button>
    <div class="err" id="pickErr"></div>
  </div>

  <div id="trackCard" class="card" style="display:none;">
    <div class="row muted">Tracking as <b id="plateLbl"></b></div>
    <div class="row muted">Your current speed</div>
    <div class="big"><span id="speed">0</span> km/h</div>
    <div class="row">Lat: <span id="lat">-</span></div>
    <div class="row">Lon: <span id="lon">-</span></div>
    <div id="status" class="muted">Tap Start and allow location.</div>
    <button id="btn">Start tracking</button>
  </div>

  <script>
    let TOKEN = null, PLATE = null, DEVICE_KEY = null, watchId = null;

    function show(id){ ["loginCard","pickCard","trackCard"].forEach(x=>{ document.getElementById(x).style.display = (x===id?"block":"none"); }); }
    function setStatus(t){ document.getElementById("status").textContent = t; }

    async function login(){
      const u=document.getElementById("u").value.trim(), p=document.getElementById("p").value;
      const err=document.getElementById("loginErr"); err.textContent="";
      try{
        const r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
        if(!r.ok){ err.textContent="Invalid username or password"; return; }
        TOKEN=(await r.json()).token;
        loadVehicles();
      }catch(e){ err.textContent="Could not reach server"; }
    }

    async function loadVehicles(){
      const r=await fetch("/my-vehicles",{headers:{"Authorization":"Bearer "+TOKEN}});
      const list=await r.json();
      const sel=document.getElementById("vehSel");
      if(!list.length){ document.getElementById("pickErr").textContent="No vehicles registered to this account yet."; }
      sel.innerHTML="";
      list.forEach(v=>{ const o=document.createElement("option"); o.value=JSON.stringify({plate:v.plate,key:v.device_key}); o.textContent=v.plate+"  ("+v.owner+")"; sel.appendChild(o); });
      show("pickCard");
    }

    function pick(){
      const sel=document.getElementById("vehSel");
      if(!sel.value){ document.getElementById("pickErr").textContent="No vehicle to select."; return; }
      const v=JSON.parse(sel.value);
      PLATE=v.plate; DEVICE_KEY=v.key;
      document.getElementById("plateLbl").textContent=PLATE;
      show("trackCard");
    }

    async function send(lat, lon, kmh){
      try{
        const r=await fetch("/track",{method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({plate:PLATE, lat:lat, lon:lon, speed:kmh, fuel:100, device_key:DEVICE_KEY})});
        if(!r.ok){ setStatus("Server rejected the update (key/vehicle problem)."); }
      }catch(e){ setStatus("Send failed - is the server reachable?"); }
    }

    function start(){
      if(!navigator.geolocation){ setStatus("This phone has no geolocation."); return; }
      setStatus("Getting GPS fix...");
      watchId=navigator.geolocation.watchPosition(function(pos){
        const lat=pos.coords.latitude, lon=pos.coords.longitude;
        let spd=pos.coords.speed; let kmh=(spd&&spd>0)?Math.round(spd*3.6):0;
        document.getElementById("lat").textContent=lat.toFixed(5);
        document.getElementById("lon").textContent=lon.toFixed(5);
        document.getElementById("speed").textContent=kmh;
        setStatus("Live - sending your location");
        send(lat,lon,kmh);
      }, function(err){ setStatus("Location error: "+err.message); },
      { enableHighAccuracy:true, maximumAge:1000, timeout:10000 });
      const b=document.getElementById("btn"); b.textContent="Stop tracking"; b.classList.add("stop");
    }
    function stop(){
      if(watchId!==null){ navigator.geolocation.clearWatch(watchId); watchId=null; }
      const b=document.getElementById("btn"); b.textContent="Start tracking"; b.classList.remove("stop");
      setStatus("Stopped.");
    }

    document.getElementById("loginBtn").addEventListener("click", login);
    document.getElementById("p").addEventListener("keydown", e=>{ if(e.key==="Enter") login(); });
    document.getElementById("pickBtn").addEventListener("click", pick);
    document.getElementById("btn").addEventListener("click", function(){ if(watchId===null) start(); else stop(); });
  </script>
</body>
</html>"""


@app.get("/mobile", response_class=HTMLResponse)
def mobile():
    return MOBILE_HTML
