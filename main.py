from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import sqlite3, math, hashlib, hmac, secrets, time, base64, json, os
from datetime import datetime, timedelta

app = FastAPI(title="NAZON")
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the client, just keep it open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SPEED_LIMIT = 80
FUEL_DROP_ALERT = 6

# Production = explicit NAZON_ENV=production, or a Postgres DATABASE_URL (Render sets one).
_db_url = os.environ.get("DATABASE_URL", "")
IS_PROD = os.environ.get("NAZON_ENV") == "production" or _db_url.startswith("postgres")

# The signing secret must come from the environment. In production the app refuses to
# start without a strong one; locally it generates a random one (logins reset on restart).
SECRET_KEY = os.environ.get("NAZON_SECRET", "")
if IS_PROD and (len(SECRET_KEY) < 32 or SECRET_KEY == "nazon-demo-secret-change-me"):
    raise SystemExit("NAZON_SECRET missing or weak (need 32+ chars). Refusing to start in production.")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("DEV MODE: random SECRET_KEY generated; logins reset on every restart.")
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


# --- simple in-process rate limiter ---
# Tracks recent request timestamps per key. Resets on restart. Good enough
# for a single-worker deployment; if you scale to multiple workers, replace
# with a shared store (Redis) so limits are enforced across processes.
_RATE_BUCKETS = {}

def rate_limit(key, max_hits, window_seconds):
    """Raise 429 if `key` has exceeded `max_hits` in the last `window_seconds`."""
    now = time.time()
    cutoff = now - window_seconds
    hits = _RATE_BUCKETS.get(key, [])
    # drop expired
    hits = [t for t in hits if t > cutoff]
    if len(hits) >= max_hits:
        _RATE_BUCKETS[key] = hits
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Limit is {max_hits} per {window_seconds}s.",
        )
    hits.append(now)
    _RATE_BUCKETS[key] = hits


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


def hash_device_key(key, salt=None):
    """Same scheme as passwords — good enough for device keys, which are
    already high-entropy random tokens (not user-chosen)."""
    return hash_password(key, salt)


def verify_device_key(submitted, stored_hash):
    if not submitted or not stored_hash:
        return False
    return verify_password(submitted, stored_hash)


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


def require_admin(authorization):
    username = require_owner(authorization)
    conn = db()
    row = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    conn.close()
    if row is None or not row["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin only")
    return username


def audit(conn, actor, action, target="", meta=None):
    """Write an audit row. Uses the caller's open connection so the audit
    row commits in the same transaction as the action it describes."""
    conn.execute(
        "INSERT INTO audit (ts, actor, action, target, meta) VALUES (?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), actor, action, target,
         json.dumps(meta or {})),
    )


def init():
    conn = db()
    pk = "SERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY"
        # Determine if device_key_hash exists — works on both SQLite and Postgres.
    if USE_PG:
        col_rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='vehicles' AND column_name='device_key_hash'"
        ).fetchall()
        has_hash_col = len(col_rows) > 0
    else:
        col_rows = conn.execute("SELECT name FROM pragma_table_info('vehicles')").fetchall()
        has_hash_col = any(c["name"] == "device_key_hash" for c in col_rows)
    conn.execute("""CREATE TABLE IF NOT EXISTS orgs (
        id INTEGER PRIMARY KEY, kind TEXT, display_name TEXT,
        report_cadence TEXT, alert_profile TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS owners (
        username TEXT PRIMARY KEY, password TEXT, kind TEXT,
        display_name TEXT, is_admin INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0,
        org_id INTEGER)""")
    conn.execute("CREATE TABLE IF NOT EXISTS vehicles ("
                 "id " + pk + ", plate TEXT UNIQUE, owner TEXT, "
                 "device_key TEXT, device_key_hash TEXT, org_id INTEGER)")
    conn.execute("CREATE TABLE IF NOT EXISTS locations ("
                 "id " + pk + ", plate TEXT, lat REAL, lon REAL, "
                 "speed REAL DEFAULT 0, fuel REAL DEFAULT 0, ts TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS zones ("
                 "id " + pk + ", name TEXT, kind TEXT, lat REAL, lon REAL, radius_m REAL)")
    conn.execute("""CREATE TABLE IF NOT EXISTS sos (
        plate TEXT PRIMARY KEY, active INTEGER DEFAULT 0, ts TEXT)""")
        # Audit log — who did what, to what, when.
    conn.execute("CREATE TABLE IF NOT EXISTS audit ("
                 "id " + pk + ", ts TEXT, actor TEXT, action TEXT, "
                 "target TEXT, meta TEXT)")
    # Incidents — fuel theft, SOS, speeding, etc.
    conn.execute("CREATE TABLE IF NOT EXISTS incidents ("
                 "id " + pk + ", plate TEXT, org_id INTEGER, type TEXT, "
                 "severity TEXT, detected_at TEXT, acknowledged_at TEXT, "
                 "acknowledged_by TEXT, payload TEXT)")
    # Trips — grouped movements for reporting
    conn.execute("CREATE TABLE IF NOT EXISTS trips ("
                 "id " + pk + ", plate TEXT, org_id INTEGER, start_ts TEXT, "
                 "end_ts TEXT, distance_km REAL, fuel_used_l REAL, "
                 "avg_speed REAL, max_speed REAL)")
        # --- batch 2 migration ---
    # Existing databases were created before device_key_hash existed.
    # SQLite's CREATE TABLE IF NOT EXISTS won't add it, so do it explicitly.
    if not has_hash_col:
        conn.execute("ALTER TABLE vehicles ADD COLUMN device_key_hash TEXT")
        print("Added device_key_hash column to vehicles.")

       # Hash any remaining plaintext keys, then clear plaintext.
    # Idempotent — safe to run every startup; after the first pass device_key is NULL.
    legacy = conn.execute(
        "SELECT plate, device_key FROM vehicles "
        "WHERE device_key IS NOT NULL AND device_key <> ''"
    ).fetchall()
    for row in legacy:
        conn.execute(
            "UPDATE vehicles SET device_key_hash=?, device_key=NULL WHERE plate=?",
            (hash_device_key(row["device_key"]), row["plate"]),
        )
    if legacy:
        print(f"Migrated {len(legacy)} plaintext device key(s) to hashed form.")

    # --- batch 3 migration (phase 1) ---
    # Add org_id to owners and vehicles if they don't have it yet.
    if USE_PG:
        has_org_owners = len(conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='owners' AND column_name='org_id'").fetchall()) > 0
        has_org_vehicles = len(conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='vehicles' AND column_name='org_id'").fetchall()) > 0
    else:
        has_org_owners = any(c["name"] == "org_id" for c in conn.execute("SELECT name FROM pragma_table_info('owners')").fetchall())
        has_org_vehicles = any(c["name"] == "org_id" for c in conn.execute("SELECT name FROM pragma_table_info('vehicles')").fetchall())

    if not has_org_owners:
        conn.execute("ALTER TABLE owners ADD COLUMN org_id INTEGER")
    if not has_org_vehicles:
        conn.execute("ALTER TABLE vehicles ADD COLUMN org_id INTEGER")

    # Seed default org if none exists
    if conn.execute("SELECT id FROM orgs").fetchone() is None:
        conn.execute("""INSERT INTO orgs (id, kind, display_name, report_cadence, alert_profile)
                        VALUES (1, 'company', 'NAZON Default', 'weekly', 'both')""")

    # Backfill: link existing owners and vehicles to org 1
    conn.execute("UPDATE owners SET org_id=1 WHERE org_id IS NULL")
    conn.execute("UPDATE vehicles SET org_id=1 WHERE org_id IS NULL")
    # --- end batch 3 migration ---

    count = conn.execute("SELECT COUNT(*) AS c FROM zones").fetchone()["c"]
    if count == 0:
        seed = [
            ("Chibolya", "danger", -15.4400, 28.2720, 700),
            ("Kanyama", "danger", -15.4270, 28.2600, 900),
        ]
        for s in seed:
            conn.execute(
                "INSERT INTO zones (name, kind, lat, lon, radius_m) VALUES (?, ?, ?, ?, ?)", s)
    # Admin credentials come from the environment; nothing is hardcoded in the repo.
    admin_user = os.environ.get("NAZON_ADMIN_USER", "nazon")
    admin_pass = os.environ.get("NAZON_ADMIN_PASS", "")
    if admin_pass and conn.execute("SELECT username FROM owners WHERE username=?",
                                   (admin_user,)).fetchone() is None:
        conn.execute(
         "INSERT INTO owners (username, password, kind, display_name, is_admin, must_change, org_id) VALUES (?, ?, ?, ?, 1, 0, 1)",
            (admin_user, hash_password(admin_pass), "admin", "NAZON Admin"))
    n_admin = conn.execute("SELECT COUNT(*) AS c FROM owners WHERE is_admin=1").fetchone()["c"]
    if n_admin == 0:
        if IS_PROD:
            raise SystemExit("No admin account exists and NAZON_ADMIN_PASS is not set.")
        print("DEV MODE: no admin account. Set NAZON_ADMIN_PASS and restart.")
        conn.execute("UPDATE owners SET org_id=1 WHERE org_id IS NULL")
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
    kind: str = "personal"       # company | ngo | personal | driver
    display_name: str = ""
    role: str = "driver"         # admin | manager | driver


class ChangePw(BaseModel):
    new_password: str



@app.post("/login")
def login(req: LoginReq):
    conn = db()
    row = conn.execute("SELECT * FROM owners WHERE username=?", (req.username,)).fetchone()
    if row is None or not verify_password(req.password, row["password"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    org = conn.execute("SELECT display_name, kind FROM orgs WHERE id=?", (row["org_id"],)).fetchone()
    conn.close()
    
    org_name = org["display_name"] if org else "NAZON Fleet"
    org_kind = org["kind"] if org else "company"
    
    return {
        "token": make_token(row["username"]),
        "username": row["username"],
        "display_name": row["display_name"],
        "org_name": org_name,
        "org_kind": org_kind,
        "is_admin": bool(row["is_admin"]),
        "must_change": bool(row["must_change"]),
    }


@app.get("/whoami")
def whoami(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    row = conn.execute("SELECT username, display_name, is_admin, kind, org_id FROM owners WHERE username=?",
                       (username,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=401, detail="Unknown account")
    
    org = conn.execute("SELECT display_name, kind FROM orgs WHERE id=?", (row["org_id"],)).fetchone()
    conn.close()
    
    org_name = org["display_name"] if org else "NAZON Fleet"
    org_kind = org["kind"] if org else "company"
    
    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "org_name": org_name,
        "org_kind": org_kind,
        "is_admin": bool(row["is_admin"]),
        "kind": row["kind"]
    }


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
    # Create a new org for this account (unless it's an admin being added to the default org)
    conn.execute(
        "INSERT INTO orgs (kind, display_name, report_cadence, alert_profile) VALUES (?, ?, ?, ?)",
        (req.kind, req.display_name or req.username, "weekly", "both")
    )
    # Get the newly created org's ID (works on both SQLite and Postgres)
    if USE_PG:
        org_id = conn.execute("SELECT currval(pg_get_serial_sequence('orgs', 'id')) AS id").fetchone()["id"]
    else:
        org_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    conn.execute(
        "INSERT INTO owners (username, password, kind, display_name, is_admin, must_change, org_id) VALUES (?, ?, ?, ?, 0, 1, ?)",
        (req.username, hash_password(req.password), req.kind, req.display_name or req.username, org_id))
    
    conn.commit()
    conn.close()
    return {"created": req.username, "org_id": org_id, "kind": req.kind}

# In-memory tracker for active trips
# Format: { "plate": {"start_ts": datetime, "distance": float, "fuel_start": float, "max_speed": float, "last_lat": float, "last_lon": float, "stop_count": int} }
ACTIVE_TRIPS = {}
STOPPED_PINGS_TO_END = 5  # 5 pings * 2 seconds = 10 seconds of being stopped
SPEED_THRESHOLD_MOVING = 15.0
@app.post("/track")
def track(p: Ping):
    # Per-plate rate limit: 60 pings per minute is 2/sec sustained.
    # Anything faster than that is either a misconfigured device or abuse.
    rate_limit("track:" + p.plate, max_hits=60, window_seconds=60)
    conn = db()
    v = conn.execute(
        "SELECT device_key_hash FROM vehicles WHERE plate=?", (p.plate,)
    ).fetchone()
    if v is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Unknown vehicle. Register it first.")
    if not verify_device_key(p.device_key, v["device_key_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid device key")

    # --- Fuel Theft Detection ---
    # Get the last known fuel level and speed
    prev = conn.execute("""
        SELECT fuel, speed FROM locations WHERE plate=?
        ORDER BY id DESC LIMIT 1
    """, (p.plate,)).fetchone()

    if prev is not None:
        fuel_drop = prev["fuel"] - p.fuel
        # If fuel dropped by more than 8% and the vehicle is basically stopped
        if fuel_drop >= 8.0 and p.speed < 5:
            # Log the incident
            payload = json.dumps({
                "previous_fuel": prev["fuel"],
                "current_fuel": p.fuel,
                "drop": round(fuel_drop, 1),
                "speed": p.speed
            })
            org_row = conn.execute("SELECT org_id FROM vehicles WHERE plate=?", (p.plate,)).fetchone()
            org_id = org_row["org_id"] if org_row else 1
            conn.execute(
                "INSERT INTO incidents (plate, org_id, type, severity, detected_at, payload) "
                "VALUES (?, ?, 'fuel_theft', 'high', ?, ?)",
                (p.plate, org_id, datetime.utcnow().isoformat(), payload)
            )
            print(f"*** THEFT DETECTED on {p.plate}: dropped {fuel_drop}% ***")
            # Broadcast to WebSockets
            import asyncio
            asyncio.create_task(manager.broadcast(json.dumps({
                "type": "theft",
                "plate": p.plate,
                "drop": round(fuel_drop, 1)
            })))

    # --- Trip Tracking Logic ---
    now_ts = datetime.utcnow()
    now_str = now_ts.isoformat()
    trip = ACTIVE_TRIPS.get(p.plate)

    if trip is None:
        # If we aren't tracking a trip and the vehicle starts moving, start one!
        if p.speed >= SPEED_THRESHOLD_MOVING:
            ACTIVE_TRIPS[p.plate] = {
                "start_ts": now_ts,
                "distance": 0.0,
                "fuel_start": p.fuel,
                "max_speed": p.speed,
                "last_lat": p.lat,
                "last_lon": p.lon,
                "stop_count": 0
            }
            print(f">>> Trip started for {p.plate}")
    else:
        # We are already tracking a trip. Update distance and max speed.
        dist_m = meters_between(trip["last_lat"], trip["last_lon"], p.lat, p.lon)
        trip["distance"] += (dist_m / 1000.0) # convert to km
        trip["last_lat"] = p.lat
        trip["last_lon"] = p.lon
        if p.speed > trip["max_speed"]:
            trip["max_speed"] = p.speed
            
        # Check if vehicle is stopped
        if p.speed < 5.0:
            trip["stop_count"] += 1
        else:
            trip["stop_count"] = 0 # Reset if they start moving again

        # If stopped for 5 consecutive pings (10 seconds), end the trip!
        if trip["stop_count"] >= STOPPED_PINGS_TO_END:
            # Calculate total fuel used (accounting for the possibility of a refuel mid-trip)
            fuel_used_pct = 0.0
            if trip["fuel_start"] > p.fuel:
                fuel_used_pct = trip["fuel_start"] - p.fuel
            
            fuel_used_l = (fuel_used_pct / 100.0) * 60.0 # Assume 60L tank
            
            duration_mins = (now_ts - trip["start_ts"]).total_seconds() / 60.0
            avg_speed = (trip["distance"] / duration_mins) * 60.0 if duration_mins > 0 else 0

            org_row = conn.execute("SELECT org_id FROM vehicles WHERE plate=?", (p.plate,)).fetchone()
            org_id = org_row["org_id"] if org_row else 1

            conn.execute("""
                INSERT INTO trips (plate, org_id, start_ts, end_ts, distance_km, fuel_used_l, avg_speed, max_speed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                p.plate, org_id, trip["start_ts"].isoformat(), now_str,
                round(trip["distance"], 2), round(fuel_used_l, 2),
                round(avg_speed, 1), round(trip["max_speed"], 1)
            ))
            print(f"<<< Trip ended for {p.plate}. Distance: {round(trip['distance'],2)} km")
            del ACTIVE_TRIPS[p.plate]
    # --- End Trip Tracking Logic ---

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

    existing = conn.execute(
        "SELECT plate, owner FROM vehicles WHERE plate=?", (req.plate,)
    ).fetchone()

    if existing and not is_admin:
        conn.close()
        raise HTTPException(status_code=409, detail="Plate already registered")

    # Get the owner's org_id so the vehicle is isolated to that org
    owner_row = conn.execute(
        "SELECT org_id FROM owners WHERE username=?", (owner,)
    ).fetchone()
    owner_org_id = owner_row["org_id"] if owner_row else 1

    key = secrets.token_hex(16)
    key_hash = hash_device_key(key)

    if existing:
        conn.execute(
            "UPDATE vehicles SET owner=?, org_id=?, device_key=NULL, device_key_hash=? WHERE plate=?",
            (owner, owner_org_id, key_hash, req.plate),
        )
        audit(conn, username, "vehicle.reassign", req.plate,
              {"owner": owner, "previous_owner": existing["owner"]})
    else:
        conn.execute(
            "INSERT INTO vehicles (plate, owner, org_id, device_key, device_key_hash) "
            "VALUES (?, ?, ?, NULL, ?)",
            (req.plate, owner, owner_org_id, key_hash),
        )
        audit(conn, username, "vehicle.register", req.plate, {"owner": owner})

    conn.commit()
    conn.close()
    # Plaintext key is returned exactly once, here, and never again.
    return {"plate": req.plate, "owner": owner, "device_key": key}


@app.post("/vehicles/{plate}/rotate-key")
def rotate_device_key(plate: str, authorization: str = Header(None)):
    """Invalidate the current device key and issue a new one.

    The plaintext key is returned ONCE in this response and never again.
    The caller must save it or the device will lose access until the next
    rotation.
    """
    username = require_owner(authorization)
    conn = db()
    if not owns_vehicle(conn, username, plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")

    key = secrets.token_hex(16)
    conn.execute(
        "UPDATE vehicles SET device_key=NULL, device_key_hash=? WHERE plate=?",
        (hash_device_key(key), plate),
    )
    audit(conn, username, "device_key.rotate", plate)
    conn.commit()
    conn.close()
    return {"plate": plate, "device_key": key}


@app.get("/my-vehicles")
def my_vehicles(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    me = conn.execute("SELECT is_admin FROM owners WHERE username=?", (username,)).fetchone()
    is_admin = me is not None and me["is_admin"]
    if is_admin:
        # Global admin sees everything
        rows = conn.execute(
            "SELECT plate, owner, device_key_hash FROM vehicles"
        ).fetchall()
    else:
        # Normal users see only vehicles in their own org
        me_org = conn.execute(
            "SELECT org_id FROM owners WHERE username=?", (username,)
        ).fetchone()
        my_org_id = me_org["org_id"] if me_org else -1
        rows = conn.execute(
            "SELECT plate, owner, device_key_hash FROM vehicles WHERE org_id=?",
            (my_org_id,),
        ).fetchall()
    conn.close()
    return [
        {
            "plate": r["plate"],
            "owner": r["owner"],
            "key_present": bool(r["device_key_hash"]),
        }
        for r in rows
    ]


class SosReq(BaseModel):
    plate: str


def owns_vehicle(conn, username, plate):
    me = conn.execute(
        "SELECT is_admin, org_id FROM owners WHERE username=?", (username,)
    ).fetchone()
    if me is None:
        return False
    if me["is_admin"]:
        return True
    v = conn.execute(
        "SELECT org_id FROM vehicles WHERE plate=?", (plate,)
    ).fetchone()
    return v is not None and v["org_id"] == me["org_id"]


@app.post("/sos")
def sos_trigger(s: SosReq, authorization: str = Header(None)):
    username = require_owner(authorization)
    # Per-user rate limit: 10 SOS triggers per minute is generous but
    # prevents a runaway client from flooding the alert pipeline.
    rate_limit("sos:" + username, max_hits=10, window_seconds=60)
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

class ImmobilizeReq(BaseModel):
    plate: str
    confirm: bool = False

@app.post("/vehicles/{plate}/immobilize")
def immobilize_vehicle(plate: str, req: ImmobilizeReq, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    if not owns_vehicle(conn, username, plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")
        
    if not req.confirm:
        conn.close()
        raise HTTPException(status_code=400, detail="Must set confirm=true to immobilize.")
        
    # Log the audit event (CRITICAL for legal reasons)
    audit(conn, username, "vehicle.immobilize", plate)
    
    # When hardware is integrated, this is where you send the MQTT/HTTP command to the device.
    # For now, we just log it and return success.
    
    conn.commit()
    conn.close()
    print(f"!!! IMMOBILIZER TRIGGERED FOR {plate} BY {username} !!!")
    return {"status": "immobilized", "plate": plate, "note": "Hardware integration pending"}
@app.post("/sos/clear")
def sos_clear(s: SosReq, authorization: str = Header(None)):
    username = require_owner(authorization)
    rate_limit("sos-clear:" + username, max_hits=10, window_seconds=60)
    conn = db()
    if not owns_vehicle(conn, username, s.plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")
    conn.execute("UPDATE sos SET active=0 WHERE plate=?", (s.plate,))
    conn.commit()
    conn.close()
    return {"sos": "cleared", "plate": s.plate}
@app.post("/incidents/acknowledge")
def acknowledge_incident(req: SosReq, authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    if not owns_vehicle(conn, username, req.plate):
        conn.close()
        raise HTTPException(status_code=403, detail="Not your vehicle")
    
    # Mark the most recent unacknowledged theft for this plate as acknowledged
    conn.execute("""
        UPDATE incidents SET acknowledged_at=?, acknowledged_by=? 
        WHERE plate=? AND type='fuel_theft' AND acknowledged_at IS NULL
    """, (datetime.utcnow().isoformat(), username, req.plate))
    
    audit(conn, username, "incident.ack", req.plate)
    conn.commit()
    conn.close()
    return {"acknowledged": True, "plate": req.plate}


@app.get("/zones")
def get_zones(authorization: str = Header(None)):
    require_owner(authorization)
    conn = db()
    rows = conn.execute("SELECT id, name, kind, lat, lon, radius_m FROM zones").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/zones")
def add_zone(z: Zone, authorization: str = Header(None)):
    require_admin(authorization)
    conn = db()
    conn.execute("INSERT INTO zones (name, kind, lat, lon, radius_m) VALUES (?, ?, ?, ?, ?)",
                 (z.name, z.kind, z.lat, z.lon, z.radius_m))
    conn.commit()
    conn.close()
    return {"added": z.name}


@app.delete("/zones/{zone_id}")
def delete_zone(zone_id: int, authorization: str = Header(None)):
    require_admin(authorization)
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
        me_org = conn.execute(
            "SELECT org_id FROM owners WHERE username=?", (username,)
        ).fetchone()
        my_org_id = me_org["org_id"] if me_org else -1
        owned = conn.execute("SELECT plate FROM vehicles WHERE org_id=?", (my_org_id,)).fetchall()
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

    # Get any unacknowledged theft incidents from the last 24 hours
    theft_rows = conn.execute("""
        SELECT plate FROM incidents 
        WHERE type='fuel_theft' AND acknowledged_at IS NULL 
        AND detected_at > datetime('now', '-1 day')
    """).fetchall()
    theft_set = {r["plate"] for r in theft_rows}

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
            "theft_alert": r["plate"] in theft_set,
            "danger_zone": in_zone,
            "sos": r["plate"] in sos_set
        })
    conn.close()
    return {"speed_limit": SPEED_LIMIT, "vehicles": out}
@app.get("/reports/digest")
def weekly_digest(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    
    # Get user's org
    me = conn.execute("SELECT is_admin, org_id FROM owners WHERE username=?", (username,)).fetchone()
    is_admin = me is not None and me["is_admin"]
    org_id = me["org_id"] if me else -1
    
    # We'll report on the last 7 days
    # (In a real app, this would take start_date and end_date query params)
    seven_days_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    
    # Query trips
    if is_admin:
        trips = conn.execute(
            "SELECT * FROM trips WHERE start_ts > ?", (seven_days_ago,)
        ).fetchall()
    else:
        trips = conn.execute(
            "SELECT * FROM trips WHERE org_id=? AND start_ts > ?", (org_id, seven_days_ago)
        ).fetchall()
        
    # Query theft incidents
    if is_admin:
        thefts = conn.execute(
            "SELECT * FROM incidents WHERE type='fuel_theft' AND detected_at > ?", (seven_days_ago,)
        ).fetchall()
    else:
        thefts = conn.execute(
            "SELECT * FROM incidents WHERE org_id=? AND type='fuel_theft' AND detected_at > ?", (org_id, seven_days_ago)
        ).fetchall()

    total_distance = sum(t["distance_km"] for t in trips)
    total_fuel = sum(t["fuel_used_l"] for t in trips)
    
    # Estimate cost (e.g., 30 ZMW per liter)
    FUEL_PRICE_PER_LITER = 30.0
    total_cost = total_fuel * FUEL_PRICE_PER_LITER
    
    conn.close()
    
    return {
        "period": "Last 7 days",
        "total_trips": len(trips),
        "total_distance_km": round(total_distance, 1),
        "total_fuel_used_l": round(total_fuel, 1),
        "estimated_cost_zmw": round(total_cost, 2),
        "fuel_theft_incidents": len(thefts),
        "fuel_price_assumed": FUEL_PRICE_PER_LITER
    }
@app.get("/reports/fuel-efficiency")
def fuel_efficiency(authorization: str = Header(None)):
    username = require_owner(authorization)
    conn = db()
    
    # Get all vehicles this user/org is allowed to see
    me = conn.execute("SELECT is_admin, org_id FROM owners WHERE username=?", (username,)).fetchone()
    is_admin = me is not None and me["is_admin"]
    org_id = me["org_id"] if me else -1
    
    if is_admin:
        vehicles = conn.execute("SELECT plate FROM vehicles").fetchall()
    else:
        vehicles = conn.execute("SELECT plate FROM vehicles WHERE org_id=?", (org_id,)).fetchall()

    report = []
    TANK_SIZE_L = 60.0 # Assuming a standard 60L tank

    for v in vehicles:
        plate = v["plate"]
        rows = conn.execute("""
            SELECT lat, lon, fuel, ts FROM locations 
            WHERE plate=? ORDER BY id ASC
        """, (plate,)).fetchall()

        if len(rows) < 2:
            continue # Not enough data to calculate

        total_distance_km = 0.0
        fuel_used_pct = 0.0

        for i in range(1, len(rows)):
            prev = rows[i-1]
            curr = rows[i]
            
            # Calculate distance
            dist_m = meters_between(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            total_distance_km += dist_m / 1000.0

            # Calculate fuel used (only if it went down, ignore refuels)
            drop = prev["fuel"] - curr["fuel"]
            if drop > 0:
                fuel_used_pct += drop

        # Convert fuel percentage to liters
        fuel_used_l = (fuel_used_pct / 100.0) * TANK_SIZE_L

        if total_distance_km > 0.1:
            # L/100km = (Liters Used / Distance) * 100
            efficiency = round((fuel_used_l / total_distance_km) * 100, 2)
            report.append({
                "plate": plate,
                "distance_km": round(total_distance_km, 2),
                "fuel_used_l": round(fuel_used_l, 2),
                "efficiency_l_100km": efficiency
            })

    conn.close()
    return {"tank_size_l": TANK_SIZE_L, "report": report}
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
    .btn.rot { background:#555; margin-left:6px; }
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
        <h2 data-i18n="vehicles">Vehicles</h2>
    <div id="digestBox" style="background:#fff; border:1px solid #dbe0ea; border-radius:8px; padding:12px; margin-bottom:15px; display:none;">
        <h3 style="margin:0 0 10px 0; font-size:14px; color:#0b3d91;">Weekly Digest</h3>
        <div style="font-size:12px; line-height:1.6;">
          Trips: <b id="dgTrips">0</b><br>
          Distance: <b id="dgDist">0</b> km<br>
          Fuel: <b id="dgFuel">0</b> L<br>
          Cost: <b id="dgCost" style="color:#e74c3c;">0</b> ZMW<br>
          Theft Alerts: <b id="dgTheft" style="color:#e74c3c;">0</b>
        </div>
      </div>
      <div class="legend">
        <span class="sw" style="background:#e74c3c"></span>Danger zone &nbsp;
        <span class="sw" style="background:#e67e22"></span>Simulated congestion
      </div>
      <div id="list"></div>
      
      <!-- Fuel Efficiency Panel -->
      <h2 style="margin-top:20px; border-top:1px solid #dbe0ea; padding-top:15px;" data-i18n="fuel_efficiency">Fuel Efficiency</h2>
      <div id="fuelReport" style="font-size:12px; color:#555; padding: 0 4px;">
        Calculating...
      </div>
    </div>
    <div id="map"></div>
  </div>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    let TOKEN = localStorage.getItem("nazon_token") || null;
    let IS_ADMIN = false;
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
        IS_ADMIN = !!d.is_admin;
        localStorage.setItem("nazon_token", TOKEN);
        document.getElementById("barSub").textContent = d.org_name || d.display_name || "Live Fleet Tracking";
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
    async function acknowledgeTheft(plate){ try{ await authFetch("/incidents/acknowledge",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plate:plate})}); refresh(); }catch(e){ console.log(e); } }
    async function rotateKey(plate){
      if(!confirm("Rotate the device key for "+plate+"?\\n\\nThe current phone will stop working until the new key is entered.")) return;
      try{
        const r = await authFetch("/vehicles/"+encodeURIComponent(plate)+"/rotate-key", {method:"POST"});
        if(!r.ok){ alert("Rotate failed: "+r.status); return; }
        const d = await r.json();
        await navigator.clipboard.writeText(d.device_key).catch(()=>{});
        alert("New device key for "+plate+":\\n\\n"+d.device_key+"\\n\\n(Copied to clipboard. Shown only once.)");
      }catch(e){ alert("Rotate failed: "+e); }
    }
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
          const pos=[v.lat,v.lon], over=v.speeding, theft=v.theft_alert, inZone=v.danger_zone, sos=v.sos;
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
          const sosBtn = sos
            ? '<button class="btn clear" data-plate="'+v.plate+'" data-act="clear">Clear SOS</button>'
            : '<button class="btn sos" data-plate="'+v.plate+'" data-act="sos">SOS</button>';
          
          const theftBtn = theft
            ? '<button class="btn" style="background:#e67e22" data-plate="'+v.plate+'" data-act="ack">Ack Theft</button>'
            : '';

          const rotateBtn = IS_ADMIN
            ? '<button class="btn rot" data-plate="'+v.plate+'" data-act="rotate">Rotate key</button>'
            : '';
          const btn = sosBtn + theftBtn + rotateBtn;
          card.innerHTML=
            '<div class="plate">'+v.plate+
              (sos?'<span class="tag" style="background:#b30000">SOS</span>':'')+
              (over?'<span class="tag speed">SPEEDING</span>':'')+
              (theft?'<span class="tag fuel" style="animation:flash 0.8s infinite">THEFT ALERT</span>':'')+
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
      const act = b.getAttribute("data-act");
      if(act==="sos") triggerSos(plate);
      else if(act==="rotate") rotateKey(plate);
      else if(act==="ack") acknowledgeTheft(plate);
      else clearSos(plate);
    });

    async function loadDigest(){
      try{
        const res = await authFetch("/reports/digest");
        if(!res.ok) return;
        const d = await res.json();
        document.getElementById("dgTrips").textContent = d.total_trips;
        document.getElementById("dgDist").textContent = d.total_distance_km;
        document.getElementById("dgFuel").textContent = d.total_fuel_used_l;
        document.getElementById("dgCost").textContent = d.estimated_cost_zmw.toLocaleString();
        document.getElementById("dgTheft").textContent = d.fuel_theft_incidents;
        document.getElementById("digestBox").style.display = "block";
      }catch(e){ console.log("digest error", e); }
    }
    async function loadFuelReport(){
      try{
        const res = await authFetch("/reports/fuel-efficiency");
        if(!res.ok) return;
        const data = await res.json();
        const el = document.getElementById("fuelReport");
        if(!data.report || data.report.length === 0){
          el.innerHTML = "<em>Not enough data yet. Keep driving.</em>";
          return;
        }
        let html = '<table style="width:100%; text-align:left; border-collapse:collapse;">';
        html += '<tr style="border-bottom:1px solid #eee;"><th>Plate</th><th>Dist</th><th>L/100km</th></tr>';
        data.report.forEach(r => {
          html += `<tr>
            <td style="padding:4px 0;">${r.plate}</td>
            <td>${r.distance_km} km</td>
            <td style="font-weight:bold; color:${r.efficiency_l_100km > 15 ? '#e74c3c' : '#27ae60'}">${r.efficiency_l_100km}</td>
          </tr>`;
        });
        html += '</table>';
        el.innerHTML = html;
      }catch(e){ console.log("fuel report error", e); }
    }

    // --- WebSocket Alerts ---
    let ws;
    function connectWebSocket(){
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(proto + "//" + location.host + "/ws/alerts");
      
      ws.onmessage = function(event){
        const data = JSON.parse(event.data);
        if(data.type === "theft"){
          // Play a quick beep (requires user to have interacted with page first)
          try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            osc.type = "sine";
            osc.frequency.setValueAtTime(880, ctx.currentTime);
            osc.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.3);
          } catch(e){}
          
          // Flash the title
          let isFlashing = false;
          const flashInterval = setInterval(() => {
            document.title = isFlashing ? "THEFT ALERT - NAZON" : "Live Fleet Tracking";
            isFlashing = !isFlashing;
          }, 500);
          
          // Stop flashing after 10 seconds
          setTimeout(() => {
            clearInterval(flashInterval);
            document.title = "NAZON Fleet Tracking";
          }, 10000);

          // Update the UI immediately
          refresh();
        }
      };
      
      ws.onclose = function(){
        console.log("WebSocket closed. Reconnecting in 5s...");
        setTimeout(connectWebSocket, 5000);
      };
    }

    let started = false;
    function startApp(){
      if(started) return;
      started = true;
      loadZones();
      refresh();
      loadDigest();
      loadFuelReport();
      connectWebSocket(); // <--- Start the WebSocket
      refreshTimer = setInterval(refresh, 2000);
      setInterval(loadFuelReport, 10000); 
    }

    // if a token is already stored, try to use it; otherwise show login
    if(TOKEN){
      authFetch("/whoami").then(r=>{
        if(r.ok){
        return r.json().then(d=>{
            IS_ADMIN = !!d.is_admin;
            document.getElementById("barSub").textContent = d.org_name || d.display_name || "Live Fleet Tracking";
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
    <div class="row muted" style="margin-top:12px;">Paste the device key</div>
    <input id="devKey" placeholder="e.g. 3f9a2c..." autocomplete="off" spellcheck="false" />
    <div class="row muted" style="font-size:12px;">
      Get this from the dashboard: Vehicles &rarr; Rotate key. The key is shown only once.
    </div>
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
      list.forEach(v=>{
        const o=document.createElement("option");
        o.value=v.plate;
        o.textContent=v.plate+"  ("+v.owner+")";
        sel.appendChild(o);
      });
      // Restore any previously-saved key for this browser.
      const saved = localStorage.getItem("nazon_devkey_"+sel.value);
      if (saved) document.getElementById("devKey").value = saved;
      show("pickCard");
    }

    function pick(){
      const sel=document.getElementById("vehSel");
      const keyInput=document.getElementById("devKey");
      const err=document.getElementById("pickErr");
      err.textContent="";
      if(!sel.value){ err.textContent="No vehicle to select."; return; }
      const key = keyInput.value.trim();
      if(!key){ err.textContent="Paste the device key from the dashboard."; return; }
      PLATE = sel.value;
      DEVICE_KEY = key;
      localStorage.setItem("nazon_devkey_"+PLATE, key);
      document.getElementById("plateLbl").textContent = PLATE;
      show("trackCard");
    }

    async function send(lat, lon, kmh){
      try{
        const r=await fetch("/track",{method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({plate:PLATE, lat:lat, lon:lon, speed:kmh, fuel:100, device_key:DEVICE_KEY})});
        if(r.status===401){
          setStatus("Device key rejected - it was rotated. Get a new key from the dashboard.");
          localStorage.removeItem("nazon_devkey_"+PLATE);
          stop();
        } else if(!r.ok){
          setStatus("Server rejected the update ("+r.status+").");
        }
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
