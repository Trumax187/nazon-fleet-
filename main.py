from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3, math
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
    conn.execute("""CREATE TABLE IF NOT EXISTS zones (
        id INTEGER PRIMARY KEY, name TEXT, kind TEXT,
        lat REAL, lon REAL, radius_m REAL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sos (
        plate TEXT PRIMARY KEY, active INTEGER DEFAULT 0, ts TEXT)""")
    count = conn.execute("SELECT COUNT(*) AS c FROM zones").fetchone()["c"]
    if count == 0:
        seed = [
            ("Chibolya", "danger", -15.4400, 28.2720, 700),
            ("Kanyama", "danger", -15.4270, 28.2600, 900),
        ]
        conn.executemany(
            "INSERT INTO zones (name, kind, lat, lon, radius_m) VALUES (?, ?, ?, ?, ?)", seed)
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


class Zone(BaseModel):
    name: str
    kind: str
    lat: float
    lon: float
    radius_m: float


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


class SosReq(BaseModel):
    plate: str


@app.post("/sos")
def sos_trigger(s: SosReq):
    conn = db()
    conn.execute("""INSERT INTO sos (plate, active, ts) VALUES (?, 1, ?)
                    ON CONFLICT(plate) DO UPDATE SET active=1, ts=excluded.ts""",
                 (s.plate, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"sos": "active", "plate": s.plate}


@app.post("/sos/clear")
def sos_clear(s: SosReq):
    conn = db()
    conn.execute("UPDATE sos SET active=0 WHERE plate=?", (s.plate,))
    conn.commit()
    conn.close()
    return {"sos": "cleared", "plate": s.plate}


@app.get("/zones")
def get_zones():
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
def fleet():
    conn = db()
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
def trail(plate: str):
    conn = db()
    rows = conn.execute("""SELECT lat, lon FROM locations WHERE plate=?
                           ORDER BY id DESC LIMIT 40""", (plate,)).fetchall()
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
  <div id="bar">
    <div>NAZON &nbsp;<span>Live Fleet Tracking</span></div>
    <div id="alertCount"></div>
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
    const map = L.map("map").setView([-15.4100, 28.2900], 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { attribution: "(c) OpenStreetMap" }).addTo(map);

    const markers = {}, trails = {};
    const colors = ["#0b3d91","#8e44ad","#16a085","#d35400","#2c3e50"];
    let colorIdx = 0; const plateColor = {};
    function colorFor(p){ if(!plateColor[p]) plateColor[p]=colors[colorIdx++%colors.length]; return plateColor[p]; }
    function ago(iso){ const s=Math.floor((Date.now()-new Date(iso+"Z").getTime())/1000); return s<60? s+"s ago": Math.floor(s/60)+"m ago"; }
    function icon(state){ const c = state==="sos"?"#b30000":(state==="over"?"#e74c3c":"#0b3d91"); const sz = state==="sos"?"width:20px;height:20px;":"width:16px;height:16px;"; return L.divIcon({className:"", html:'<div style="'+sz+'border-radius:50%;border:2px solid #fff;background:'+c+';box-shadow:0 0 6px rgba(0,0,0,.5)"></div>', iconSize:[20,20], iconAnchor:[10,10]}); }
    async function triggerSos(plate){ try{ await fetch("/sos",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plate:plate})}); refresh(); }catch(e){ console.log(e); } }
    async function clearSos(plate){ try{ await fetch("/sos/clear",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({plate:plate})}); refresh(); }catch(e){ console.log(e); } }

    async function loadZones(){
      try{
        const res = await fetch("/zones");
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
        const res=await fetch("/trail/"+plate); const d=await res.json();
        if(d.points && d.points.length>1){
          if(trails[plate]) trails[plate].setLatLngs(d.points);
          else trails[plate]=L.polyline(d.points,{color:colorFor(plate),weight:3,opacity:0.7}).addTo(map);
        }
      }catch(e){ console.log(e); }
    }

    async function refresh(){
      try{
        const res=await fetch("/fleet"); const data=await res.json();
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

    loadZones();
    setInterval(refresh,2000);
    refresh();
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
    #btn { font-size:20px; font-weight:bold; color:#fff; background:#2ecc71; border:none;
           border-radius:12px; padding:18px 20px; width:100%; margin-top:10px; }
    #btn.stop { background:#e74c3c; }
    .row { font-size:15px; margin:8px 0; }
    .big { font-size:34px; font-weight:bold; color:#0b3d91; }
    .muted { color:#777; font-size:13px; }
    #status { margin-top:10px; font-size:14px; }
  </style>
</head>
<body>
  <div class="head">NAZON<span>Phone Live Tracker - AMEN</span></div>
  <div class="card">
    <div class="row muted">Your current speed</div>
    <div class="big"><span id="speed">0</span> km/h</div>
    <div class="row">Lat: <span id="lat">-</span></div>
    <div class="row">Lon: <span id="lon">-</span></div>
    <div id="status" class="muted">Tap Start and allow location.</div>
    <button id="btn">Start tracking</button>
  </div>
  <script>
    const PLATE = "AMEN";
    let watchId = null;
    const btn = document.getElementById("btn");

    function setStatus(t){ document.getElementById("status").textContent = t; }

    async function send(lat, lon, speedKmh){
      try{
        await fetch("/track", {
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({plate:PLATE, lat:lat, lon:lon, speed:speedKmh, fuel:100})
        });
      }catch(e){ setStatus("Send failed - is the server reachable?"); }
    }

    function start(){
      if(!navigator.geolocation){ setStatus("This phone has no geolocation."); return; }
      setStatus("Getting GPS fix...");
      watchId = navigator.geolocation.watchPosition(function(p){
        const lat = p.coords.latitude, lon = p.coords.longitude;
        let spd = p.coords.speed;               // metres/second, may be null
        let kmh = (spd && spd > 0) ? Math.round(spd * 3.6) : 0;
        document.getElementById("lat").textContent = lat.toFixed(5);
        document.getElementById("lon").textContent = lon.toFixed(5);
        document.getElementById("speed").textContent = kmh;
        setStatus("Live - sending your location");
        send(lat, lon, kmh);
      }, function(err){
        setStatus("Location error: " + err.message);
      }, { enableHighAccuracy:true, maximumAge:1000, timeout:10000 });
      btn.textContent = "Stop tracking";
      btn.classList.add("stop");
    }

    function stop(){
      if(watchId !== null){ navigator.geolocation.clearWatch(watchId); watchId = null; }
      btn.textContent = "Start tracking";
      btn.classList.remove("stop");
      setStatus("Stopped.");
    }

    btn.addEventListener("click", function(){
      if(watchId === null) start(); else stop();
    });
  </script>
</body>
</html>"""


@app.get("/mobile", response_class=HTMLResponse)
def mobile():
    return MOBILE_HTML
