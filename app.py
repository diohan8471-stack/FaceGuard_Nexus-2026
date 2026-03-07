import os, json, base64, io, time, hashlib, re, sqlite3, secrets
from datetime import datetime, date, timedelta
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   session, redirect, url_for, Response, g)
import numpy as np
from PIL import Image

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Security: HTTPS-only cookies when running on production
if os.environ.get("RENDER") or os.environ.get("PRODUCTION"):
    app.config.update(
        SESSION_COOKIE_SECURE   = True,
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = "Lax",
    )

DATABASE  = os.environ.get("DB_PATH", "nexus.db")
FACE_SIZE = (80, 80)

# ── Rate limiting (in-memory, resets on restart — good enough for free tier) ──
_rate = {}   # ip -> [timestamps]
def rate_limit(ip, max_calls=30, window=60):
    now = time.time()
    calls = [t for t in _rate.get(ip, []) if now - t < window]
    calls.append(now); _rate[ip] = calls
    return len(calls) > max_calls

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        uid         TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT '',
        role_type   TEXT NOT NULL DEFAULT 'member',
        description TEXT DEFAULT '',
        email       TEXT DEFAULT '',
        phone       TEXT DEFAULT '',
        address     TEXT DEFAULT '',
        birthday    TEXT DEFAULT '',
        tags        TEXT DEFAULT '[]',
        custom_fields TEXT DEFAULT '[]',
        social_links  TEXT DEFAULT '[]',
        cover_photo TEXT DEFAULT '',
        status      TEXT DEFAULT 'active',
        registered  TEXT DEFAULT '',
        pending_id  TEXT DEFAULT '',
        face_photo  TEXT DEFAULT '',
        face_photos TEXT DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS pending (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        role        TEXT DEFAULT '',
        description TEXT DEFAULT '',
        email       TEXT DEFAULT '',
        phone       TEXT DEFAULT '',
        address     TEXT DEFAULT '',
        birthday    TEXT DEFAULT '',
        tags        TEXT DEFAULT '[]',
        photos      TEXT DEFAULT '[]',
        submitted   TEXT DEFAULT '',
        status      TEXT DEFAULT 'pending',
        invite_token TEXT DEFAULT '',
        approved_by TEXT DEFAULT '',
        approved_at TEXT DEFAULT '',
        reject_reason TEXT DEFAULT '',
        rejected_by TEXT DEFAULT '',
        rejected_at TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS projects (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_uid    TEXT NOT NULL,
        title       TEXT NOT NULL,
        description TEXT DEFAULT '',
        status      TEXT DEFAULT 'ongoing',
        priority    TEXT DEFAULT 'medium',
        progress    INTEGER DEFAULT 0,
        due         TEXT DEFAULT '',
        assigned_by TEXT DEFAULT '',
        created     TEXT DEFAULT '',
        FOREIGN KEY(user_uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notes (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        user_uid TEXT NOT NULL,
        text     TEXT NOT NULL,
        by       TEXT DEFAULT '',
        created  TEXT DEFAULT '',
        FOREIGN KEY(user_uid) REFERENCES users(uid) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS history (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        name   TEXT DEFAULT '',
        status TEXT DEFAULT '',
        score  REAL,
        detail TEXT DEFAULT '',
        time   TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS announcements (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        title    TEXT NOT NULL,
        body     TEXT DEFAULT '',
        date     TEXT DEFAULT '',
        author   TEXT DEFAULT '',
        pin      INTEGER DEFAULT 0,
        category TEXT DEFAULT 'General',
        expires  TEXT DEFAULT '',
        reads    TEXT DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS audit (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT DEFAULT '',
        by     TEXT DEFAULT '',
        target TEXT DEFAULT '',
        detail TEXT DEFAULT '',
        time   TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS teams (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        description TEXT DEFAULT '',
        color       TEXT DEFAULT '#38bdf8',
        members     TEXT DEFAULT '[]',
        created     TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    CREATE TABLE IF NOT EXISTS invite_links (
        token      TEXT PRIMARY KEY,
        label      TEXT DEFAULT '',
        created    TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        active     INTEGER DEFAULT 1,
        uses       INTEGER DEFAULT 0
    );
    """)
    # seed default settings
    defaults = {
        "app_name": "Nexus", "app_desc": "Confidential Personal Management System",
        "threshold": "0.78", "session_timeout": "30", "max_attempts": "5",
        "lockout_mins": "10", "accent_color": "#38bdf8", "text_size": "normal",
        "theme": "dark", "pin": "", "backup_reminder_days": "7",
        "last_backup": "", "public_board": "0",
    }
    for k, v in defaults.items():
        db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, v))
    # seed welcome announcement
    cur = db.execute("SELECT COUNT(*) FROM announcements")
    if cur.fetchone()[0] == 0:
        db.execute("""INSERT INTO announcements (title,body,date,author,pin,category,reads)
                      VALUES (?,?,?,?,?,?,?)""",
                   ("Welcome to Nexus",
                    "System is live. New users must submit an application for approval.",
                    "Today", "System", 1, "General", "[]"))
    db.commit()
    db.close()

# ── Settings helpers ──────────────────────────────────────────────────────────
def get_settings():
    db = get_db()
    rows = db.execute("SELECT key,value FROM settings").fetchall()
    s = {r["key"]: r["value"] for r in rows}
    return {
        "app_name":        s.get("app_name",  "Nexus"),
        "app_desc":        s.get("app_desc",  "Confidential Personal Management System"),
        "threshold":       float(s.get("threshold",  "0.78")),
        "session_timeout": int(  s.get("session_timeout", "30")),
        "max_attempts":    int(  s.get("max_attempts",    "5")),
        "lockout_mins":    int(  s.get("lockout_mins",    "10")),
        "accent_color":    s.get("accent_color", "#38bdf8"),
        "text_size":       s.get("text_size",    "normal"),
        "theme":           s.get("theme",        "dark"),
        "pin":             s.get("pin",          ""),
        "backup_reminder_days": int(s.get("backup_reminder_days","7")),
        "last_backup":     s.get("last_backup",  ""),
        "public_board":    s.get("public_board", "0") == "1",
    }

def save_setting(key, value):
    get_db().execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, str(value)))
    get_db().commit()

# ── JSON column helpers ───────────────────────────────────────────────────────
def jload(s, default=None):
    if default is None: default = []
    try: return json.loads(s) if s else default
    except: return default

def jdump(v): return json.dumps(v)

# ── Lockout (in-memory, fine for production) ──────────────────────────────────
_lockouts = {}
def get_lockout(ip):   return _lockouts.get(ip, {"attempts":0,"until":0})
def set_lockout(ip,d): _lockouts[ip] = d
def reset_lockout(ip): _lockouts.pop(ip, None)

# ── Face helpers ──────────────────────────────────────────────────────────────
def b64_to_pil(b64):
    if "," in b64: b64 = b64.split(",")[1]
    return Image.open(io.BytesIO(base64.b64decode(b64))).convert("RGB")

def pil_to_vec(img):
    img = img.resize(FACE_SIZE, Image.LANCZOS).convert("L")
    arr = np.array(img, dtype=np.float32)
    lo, hi = arr.min(), arr.max()
    if hi > lo: arr = (arr-lo)/(hi-lo)
    else: arr /= 255.0
    return arr.flatten()

def pil_to_b64(img):
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88)
    return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

def crop_face(img):
    w,h = img.size
    return img.crop((w//7, h//9, w-w//7, h-h//9))

def cos_sim(a,b):
    n = np.linalg.norm(a)*np.linalg.norm(b)
    return float(np.dot(a,b)/n) if n else 0.0

def process_face_photo(b64):
    """Crop and return compressed b64 JPEG for storage."""
    img = b64_to_pil(b64)
    face = crop_face(img).resize((120,120), Image.LANCZOS)
    return pil_to_b64(face)

def recognize(b64_probe):
    threshold = get_settings()["threshold"]
    probe_img = b64_to_pil(b64_probe)
    probe_vec = pil_to_vec(crop_face(probe_img))
    db = get_db()
    rows = db.execute("SELECT uid,face_photos FROM users WHERE status='active'").fetchall()
    best, best_uid = 0.0, None
    for row in rows:
        for fp in jload(row["face_photos"]):
            try:
                v = pil_to_vec(crop_face(b64_to_pil(fp)))
                s = cos_sim(probe_vec, v)
                if s > best: best, best_uid = s, row["uid"]
            except: pass
    return best_uid, best, threshold

# ── Logging ───────────────────────────────────────────────────────────────────
def log_event(name, status, score=None, detail=""):
    db = get_db()
    db.execute("INSERT INTO history (name,status,score,detail,time) VALUES (?,?,?,?,?)",
               (name, status, score, detail, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()

def audit_log(action, by, target="", detail=""):
    db = get_db()
    db.execute("INSERT INTO audit (action,by,target,detail,time) VALUES (?,?,?,?,?)",
               (action, by, target, detail, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()

# ── Auth helpers ──────────────────────────────────────────────────────────────
def check_session():
    if "user" not in session: return False
    if time.time()-session.get("last_active",0) > get_settings()["session_timeout"]*60:
        session.clear(); return False
    session["last_active"] = time.time()
    return True

def require_login():
    if not check_session():
        return redirect(url_for("login_page")+("?timeout=1" if "user" in session else ""))
    return None

def require_admin():
    r = require_login()
    if r: return r
    u = get_db().execute("SELECT role_type FROM users WHERE uid=?",(session["user"],)).fetchone()
    if not u or u["role_type"] != "admin": return redirect(url_for("dashboard"))
    return None

def build_me():
    uid = session.get("user","")
    if not uid: return {"uid":"","name":"","role":"","role_type":"member","photo":None,"is_admin":False,"completion":0}
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
    if not row: return {"uid":"","name":"","role":"","role_type":"member","photo":None,"is_admin":False,"completion":0}
    me = dict(row)
    me["photo"]    = me.get("face_photo") or None
    me["is_admin"] = me.get("role_type") == "admin"
    me["completion"] = profile_completion(me)
    me["tags"]        = jload(me.get("tags","[]"))
    me["social_links"]= jload(me.get("social_links","[]"))
    return me

def profile_completion(u):
    fields = ["description","email","phone","address"]
    if isinstance(u, sqlite3.Row): u = dict(u)
    filled = sum(1 for f in fields if u.get(f,"").strip())
    has_photo = bool(u.get("face_photo"))
    has_tags  = bool(jload(u.get("tags","[]")))
    has_links = bool(jload(u.get("social_links","[]")))
    return round(((filled+has_photo+has_tags+has_links)/(len(fields)+3))*100)

def days_until(due_str):
    if not due_str: return None
    try: return (date.fromisoformat(due_str) - date.today()).days
    except: return None

def pending_count():
    return get_db().execute("SELECT COUNT(*) FROM pending WHERE status='pending'").fetchone()[0]

def make_uid(name):
    base = re.sub(r"[^a-z0-9]","_", name.strip().lower())[:20]
    uid  = base; c = 1
    db   = get_db()
    while db.execute("SELECT 1 FROM users WHERE uid=?",(uid,)).fetchone():
        uid = f"{base}_{c}"; c += 1
    return uid

def sanitize(s, max_len=500):
    if not isinstance(s, str): return ""
    return s.strip()[:max_len]

def backup_due():
    s = get_settings()
    last = s.get("last_backup","")
    if not last: return True
    try: return (datetime.now()-datetime.strptime(last,"%Y-%m-%d")).days >= s.get("backup_reminder_days",7)
    except: return False

# ── Row → dict helpers ────────────────────────────────────────────────────────
def user_to_dict(row, with_photo=True):
    if row is None: return None
    d = dict(row)
    d["tags"]         = jload(d.get("tags","[]"))
    d["custom_fields"]= jload(d.get("custom_fields","[]"))
    d["social_links"] = jload(d.get("social_links","[]"))
    if not with_photo: d.pop("face_photo",None); d.pop("face_photos",None)
    d["photo"]        = d.get("face_photo") or None
    d["is_admin"]     = d.get("role_type") == "admin"
    d["completion"]   = profile_completion(d)
    return d

def enrich_projects(uid):
    rows = get_db().execute("SELECT * FROM projects WHERE user_uid=? ORDER BY id DESC",(uid,)).fetchall()
    out = []
    for r in rows:
        p = dict(r); p["days_left"] = days_until(p.get("due",""))
        out.append(p)
    return out

def enrich_notes(uid):
    rows = get_db().execute("SELECT * FROM notes WHERE user_uid=? ORDER BY id DESC",(uid,)).fetchall()
    return [dict(r) for r in rows]

# ═══════════════════════════════════════════════════════════════
#  PAGES
# ═══════════════════════════════════════════════════════════════
@app.route("/")
def home():
    n = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if not n: return redirect(url_for("apply_page"))
    if not check_session(): return redirect(url_for("login_page"))
    return redirect(url_for("dashboard"))

@app.route("/login")
def login_page():
    s = get_settings()
    n = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return render_template("login.html", first_run=not n,
        has_pin=bool(s["pin"]), timeout=request.args.get("timeout"),
        app_name=s["app_name"], app_desc=s["app_desc"])

@app.route("/apply")
def apply_page():
    token = request.args.get("t","")
    link  = None
    if token:
        row = get_db().execute("SELECT * FROM invite_links WHERE token=? AND active=1",(token,)).fetchone()
        if row: link = dict(row)
    s = get_settings()
    return render_template("apply.html", app_name=s["app_name"],
        app_desc=s["app_desc"], invite_link=link, token=token)

@app.route("/apply/status")
def apply_status():
    pid  = sanitize(request.args.get("id",""), 20)
    item = None
    if pid:
        row = get_db().execute("SELECT * FROM pending WHERE id=?",(pid,)).fetchone()
        if row: item = dict(row)
    s = get_settings()
    return render_template("apply_status.html", item=item, pid=pid, app_name=s["app_name"])

@app.route("/board")
def public_board():
    s = get_settings()
    if not s["public_board"]: return redirect(url_for("login_page"))
    today = date.today().isoformat()
    rows  = get_db().execute("SELECT * FROM announcements ORDER BY pin DESC, id DESC").fetchall()
    ann   = [dict(r) for r in rows if not r["expires"] or r["expires"] >= today]
    return render_template("public_board.html", announcements=ann, app_name=s["app_name"], app_desc=s["app_desc"])

@app.route("/dashboard")
def dashboard():
    r = require_login();
    if r: return r
    me  = build_me()
    db  = get_db()
    s   = get_settings()
    today = datetime.now().strftime("%Y-%m-%d")
    hist  = db.execute("SELECT * FROM history ORDER BY id DESC LIMIT 6").fetchall()
    ann   = db.execute("SELECT * FROM announcements ORDER BY pin DESC, id DESC LIMIT 3").fetchall()
    activity = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 8").fetchall()
    total_users    = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users   = db.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    total_projects = db.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    granted_today  = db.execute("SELECT COUNT(*) FROM history WHERE status='Access Granted' AND time LIKE ?",(today+"%",)).fetchone()[0]
    total_events   = db.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    p_count        = pending_count() if me["is_admin"] else 0
    chart_data = {}
    for i in range(6,-1,-1):
        d = (datetime.now()-timedelta(days=i)).strftime("%Y-%m-%d")
        cnt = db.execute("SELECT COUNT(*) FROM history WHERE time LIKE ?",(d+"%",)).fetchone()[0]
        chart_data[d[-5:]] = cnt
    return render_template("dashboard.html", me=me, user=me,
        announcements=[dict(a) for a in ann],
        history=[dict(h) for h in hist],
        activity=[dict(a) for a in activity],
        chart_data=chart_data,
        total_users=total_users, active_users=active_users,
        total_projects=total_projects, granted_today=granted_today,
        total_events=total_events, pend_count=p_count,
        backup_due=backup_due() and me["is_admin"], s=s)

@app.route("/people")
def people():
    r = require_login();
    if r: return r
    me   = build_me()
    db   = get_db()
    q        = sanitize(request.args.get("q",""),100).lower()
    role_f   = sanitize(request.args.get("role",""),50)
    status_f = sanitize(request.args.get("status",""),20)
    team_f   = sanitize(request.args.get("team",""),20)
    sort_f   = request.args.get("sort","name")
    all_roles = [r[0] for r in db.execute("SELECT DISTINCT role FROM users ORDER BY role").fetchall()]
    teams     = [dict(t) for t in db.execute("SELECT * FROM teams ORDER BY name").fetchall()]
    rows      = db.execute("SELECT * FROM users ORDER BY name").fetchall()
    results   = []
    for row in rows:
        u = user_to_dict(row)
        if q:
            text_blob = " ".join([u.get("name",""),u.get("role",""),
                " ".join(u.get("tags",[])),
                " ".join(p["title"] for p in enrich_projects(u["uid"])),
                " ".join(n["text"] for n in enrich_notes(u["uid"]))]).lower()
            if q not in text_blob: continue
        if role_f   and u.get("role","").lower() != role_f.lower(): continue
        if status_f and u.get("status","active") != status_f:        continue
        if team_f:
            t = next((t for t in teams if t["id"]==team_f), None)
            if not t or u["uid"] not in jload(t.get("members","[]")): continue
        u["teams"] = [t["name"] for t in teams if u["uid"] in jload(t.get("members","[]"))]
        results.append(u)
    def skey(u):
        if sort_f=="registered": return u.get("registered","")
        if sort_f=="completion": return -u.get("completion",0)
        return u.get("name","").lower()
    results.sort(key=skey)
    return render_template("people.html", users=results, me=me,
        q=q, role_f=role_f, status_f=status_f, team_f=team_f, sort_f=sort_f,
        all_roles=all_roles, teams=teams)

@app.route("/profile/<uid>")
def profile(uid):
    r = require_login();
    if r: return r
    uid  = sanitize(uid, 50)
    db   = get_db()
    row  = db.execute("SELECT * FROM users WHERE uid=?",(uid,)).fetchone()
    if not row: return redirect(url_for("people"))
    me   = build_me()
    u    = user_to_dict(row)
    u["projects"] = enrich_projects(uid)
    u["notes"]    = enrich_notes(uid)
    teams = [dict(t) for t in db.execute("SELECT * FROM teams").fetchall()
             if uid in jload(t["members"])]
    s = get_settings()
    return render_template("profile.html", user=u, me=me, teams=teams, s=s)

@app.route("/teams")
def teams_page():
    r = require_login();
    if r: return r
    me  = build_me()
    db  = get_db()
    raw = [dict(t) for t in db.execute("SELECT * FROM teams ORDER BY name").fetchall()]
    all_users = {row["uid"]: dict(row) for row in db.execute("SELECT * FROM users ORDER BY name").fetchall()}
    enriched  = []
    for t in raw:
        t2 = dict(t)
        t2["member_data"] = [
            {"uid":uid,"name":all_users[uid]["name"],"photo":all_users[uid]["face_photo"],
             "role":all_users[uid]["role"]}
            for uid in jload(t.get("members","[]")) if uid in all_users
        ]
        enriched.append(t2)
    return render_template("teams.html", me=me, teams=enriched,
        all_users=all_users)

@app.route("/pending")
def pending_page():
    r = require_admin();
    if r: return r
    items = [dict(p) for p in get_db().execute("SELECT * FROM pending ORDER BY submitted DESC").fetchall()]
    for item in items: item["tags"] = jload(item.get("tags","[]")); item["photos"] = jload(item.get("photos","[]"))
    return render_template("pending.html", me=build_me(), pending=items, pend_count=pending_count())

@app.route("/register")
def register_page():
    n = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if n:
        rv = require_admin()
        if rv: return rv
    s  = get_settings()
    me = build_me() if session.get("user") else \
         {"name":"Setup","role":"First Run","photo":None,"uid":"","is_admin":True}
    return render_template("register.html", me=me, app_name=s["app_name"])

@app.route("/projects")
def projects_page():
    r = require_login();
    if r: return r
    me   = build_me()
    db   = get_db()
    sf   = request.args.get("status","")
    pf   = request.args.get("priority","")
    q    = "SELECT p.*,u.name as person_name,u.face_photo as person_photo FROM projects p JOIN users u ON p.user_uid=u.uid"
    args = []
    if sf: q += " WHERE p.status=?"; args.append(sf)
    if pf: q += (" AND" if sf else " WHERE")+" p.priority=?"; args.append(pf)
    q += " ORDER BY p.due ASC, p.id DESC"
    rows = db.execute(q, args).fetchall()
    projects = []
    for r2 in rows:
        p = dict(r2); p["person_uid"] = p.pop("user_uid"); p["days_left"] = days_until(p.get("due",""))
        projects.append(p)
    return render_template("projects.html", me=me, projects=projects, status_f=sf, priority_f=pf)

@app.route("/announcements")
def announcements():
    r = require_login();
    if r: return r
    me   = build_me()
    rows = get_db().execute("SELECT * FROM announcements ORDER BY pin DESC, id DESC").fetchall()
    ann  = [dict(a) for a in rows]
    cats = sorted(set(a["category"] or "General" for a in ann))
    return render_template("announcements.html", me=me, announcements=ann, cats=cats)

@app.route("/history")
def history():
    r = require_login();
    if r: return r
    rows = get_db().execute("SELECT * FROM history ORDER BY id DESC LIMIT 500").fetchall()
    return render_template("history.html", me=build_me(), history=[dict(h) for h in rows])

@app.route("/audit")
def audit_page():
    r = require_admin();
    if r: return r
    rows = get_db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 1000").fetchall()
    return render_template("audit.html", me=build_me(), audit=[dict(a) for a in rows])

@app.route("/settings")
def settings_page():
    r = require_admin();
    if r: return r
    db   = get_db()
    info = {
        "version":     "v10",
        "users":       db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "pending":     db.execute("SELECT COUNT(*) FROM pending WHERE status='pending'").fetchone()[0],
        "teams":       db.execute("SELECT COUNT(*) FROM teams").fetchone()[0],
        "history":     db.execute("SELECT COUNT(*) FROM history").fetchone()[0],
        "audit":       db.execute("SELECT COUNT(*) FROM audit").fetchone()[0],
        "started":     app.config.get("START_TIME","—"),
        "storage_kb":  round(os.path.getsize(DATABASE)/1024,1) if os.path.exists(DATABASE) else 0,
    }
    links = [dict(l) for l in db.execute("SELECT * FROM invite_links ORDER BY rowid DESC").fetchall()]
    return render_template("settings.html", me=build_me(), s=get_settings(), info=info, links=links)

@app.route("/logout")
def logout():
    if session.get("user"): audit_log("Logout", build_me().get("name","?"))
    session.clear()
    return redirect(url_for("login_page"))

# ═══════════════════════════════════════════════════════════════
#  API
# ═══════════════════════════════════════════════════════════════
@app.route("/api/recognize", methods=["POST"])
def api_recognize():
    ip = request.remote_addr
    if rate_limit(ip, 60, 60): return jsonify(success=False, message="Too many requests.")
    lk = get_lockout(ip); s = get_settings()
    if time.time() < lk["until"]:
        return jsonify(success=False, locked=True,
            message=f"Locked. Try in {round((lk['until']-time.time())/60,1)} min.")
    data = request.get_json(silent=True)
    if not data or "image" not in data: return jsonify(success=False, message="No image.")
    try: uid, score, threshold = recognize(data["image"])
    except Exception as e: return jsonify(success=False, message="Recognition error.")
    pct = round(score*100,1)
    if uid and score >= threshold:
        name = get_db().execute("SELECT name FROM users WHERE uid=?",(uid,)).fetchone()["name"]
        session["user"] = uid; session["last_active"] = time.time()
        reset_lockout(ip); log_event(name,"Access Granted",pct); audit_log("Login",name,detail=f"{pct}%")
        return jsonify(success=True, message=f"Welcome, {name}!", score=pct)
    lk["attempts"] = lk.get("attempts",0)+1
    if lk["attempts"] >= s["max_attempts"]:
        lk["until"] = time.time()+s["lockout_mins"]*60; lk["attempts"]=0; set_lockout(ip,lk)
        log_event("Unknown","Locked Out",pct)
        return jsonify(success=False, locked=True, message=f"Locked for {s['lockout_mins']} min.", score=pct)
    set_lockout(ip,lk); log_event("Unknown","Access Denied",pct)
    return jsonify(success=False, score=pct, message=f"Not recognised. {s['max_attempts']-lk['attempts']} left.")

@app.route("/api/pin_login", methods=["POST"])
def api_pin_login():
    if rate_limit(request.remote_addr, 10, 60):
        return jsonify(success=False, message="Too many attempts.")
    data = request.get_json(silent=True) or {}; s = get_settings()
    if not s["pin"]: return jsonify(success=False, message="PIN not set.")
    if data.get("pin","") == s["pin"]:
        row = get_db().execute("SELECT uid,name FROM users WHERE role_type='admin' LIMIT 1").fetchone() \
           or get_db().execute("SELECT uid,name FROM users LIMIT 1").fetchone()
        if row:
            session["user"]=row["uid"]; session["last_active"]=time.time()
            log_event(row["name"],"PIN Login"); audit_log("PIN Login",row["name"])
            return jsonify(success=True, message=f"Welcome, {row['name']}!")
    log_event("Unknown","PIN Failed")
    return jsonify(success=False, message="Wrong PIN.")

@app.route("/api/apply", methods=["POST"])
def api_apply():
    if rate_limit(request.remote_addr, 5, 3600):
        return jsonify(success=False, message="Too many applications from this IP.")
    data = request.get_json(silent=True) or {}
    if not sanitize(data.get("name",""),1): return jsonify(success=False, message="Name required.")
    if not sanitize(data.get("role",""),1): return jsonify(success=False, message="Role required.")
    if not data.get("photos"):              return jsonify(success=False, message="Face photos required.")
    pid = hashlib.md5(f"{data['name']}{time.time()}".encode()).hexdigest()[:12]
    # compress photos before storing
    photos = []
    for b64 in data["photos"][:5]:
        try: photos.append(process_face_photo(b64))
        except: pass
    db = get_db()
    db.execute("""INSERT INTO pending (id,name,role,description,email,phone,address,
                  birthday,tags,photos,submitted,status,invite_token) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (pid, sanitize(data["name"],100), sanitize(data.get("role",""),100),
                sanitize(data.get("description",""),1000), sanitize(data.get("email",""),200),
                sanitize(data.get("phone",""),50), sanitize(data.get("address",""),300),
                sanitize(data.get("birthday",""),20), jdump(data.get("tags",[])),
                jdump(photos), datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "pending", sanitize(data.get("invite_token",""),32)))
    db.commit()
    log_event(data["name"],"Applied"); audit_log("Application Submitted",data["name"],detail=f"ID:{pid}")
    return jsonify(success=True, message="Application submitted!", id=pid)

@app.route("/api/pending/approve/<pid>", methods=["POST"])
def approve_pending(pid):
    if require_admin(): return jsonify(success=False, message="Admin only.")
    db   = get_db()
    row  = db.execute("SELECT * FROM pending WHERE id=?",(pid,)).fetchone()
    if not row: return jsonify(success=False, message="Not found.")
    item = dict(row); photos = jload(item.get("photos","[]"))
    uid  = make_uid(item["name"])
    face_photo  = photos[0] if photos else ""
    face_photos = jdump(photos)
    db.execute("""INSERT INTO users (uid,name,role,role_type,description,email,phone,address,
                  birthday,tags,custom_fields,social_links,face_photo,face_photos,
                  status,registered,pending_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (uid, item["name"], item["role"], "member",
                item["description"], item["email"], item["phone"],
                item["address"], item["birthday"], item.get("tags","[]"),
                "[]", "[]", face_photo, face_photos,
                "active", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid))
    me = build_me()
    db.execute("""UPDATE pending SET status='approved',approved_by=?,approved_at=?,photos='[]'
                  WHERE id=?""",
               (me["name"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid))
    db.commit()
    log_event(item["name"],"Approved & Registered"); audit_log("Approved",me["name"],item["name"],f"UID:{uid}")
    return jsonify(success=True, uid=uid, message=f"{item['name']} approved!")

@app.route("/api/pending/reject/<pid>", methods=["POST"])
def reject_pending(pid):
    if require_admin(): return jsonify(success=False)
    data = request.get_json(silent=True) or {}
    row  = get_db().execute("SELECT name FROM pending WHERE id=?",(pid,)).fetchone()
    me   = build_me()
    get_db().execute("""UPDATE pending SET status='rejected',reject_reason=?,rejected_by=?,
                        rejected_at=?,photos='[]' WHERE id=?""",
                     (sanitize(data.get("reason",""),500), me["name"],
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid))
    get_db().commit()
    if row: log_event(row["name"],"Application Rejected"); audit_log("Rejected",me["name"],row["name"],data.get("reason",""))
    return jsonify(success=True)

@app.route("/api/pending/delete/<pid>", methods=["DELETE"])
def delete_pending(pid):
    if require_admin(): return jsonify(success=False)
    get_db().execute("DELETE FROM pending WHERE id=?",(pid,)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    if not data.get("name") or not data.get("role") or not data.get("photos"):
        return jsonify(success=False, message="Name, role and photos required.")
    db  = get_db()
    uid = make_uid(data["name"])
    photos = []
    for b64 in data["photos"][:5]:
        try: photos.append(process_face_photo(b64))
        except: pass
    face_photo  = photos[0] if photos else ""
    db.execute("""INSERT INTO users (uid,name,role,role_type,description,email,phone,address,
                  birthday,tags,custom_fields,social_links,face_photo,face_photos,status,registered)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (uid, sanitize(data["name"],100), sanitize(data["role"],100),
                data.get("role_type","member"),
                sanitize(data.get("description",""),1000),
                sanitize(data.get("email",""),200), sanitize(data.get("phone",""),50),
                sanitize(data.get("address",""),300), sanitize(data.get("birthday",""),20),
                jdump(data.get("tags",[])), "[]", "[]",
                face_photo, jdump(photos),
                "active", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    by = build_me().get("name","System") if session.get("user") else "System"
    log_event(data["name"],"Registered (Direct)"); audit_log("Direct Register",by,data["name"])
    return jsonify(success=True, message=f"{data['name']} registered!", uid=uid)

@app.route("/api/profile/<uid>/update", methods=["POST"])
def update_profile(uid):
    if not check_session(): return jsonify(success=False)
    me = build_me()
    if not me["is_admin"] and me["uid"] != uid: return jsonify(success=False, message="No permission.")
    data = request.get_json(silent=True) or {}
    db   = get_db()
    fields = ["description","email","phone","address","role","status","birthday","cover_photo"]
    sets   = []; args = []
    for f in fields:
        if f in data: sets.append(f"[{f}]=?"); args.append(sanitize(str(data[f]),1000))
    if "tags"          in data: sets.append("tags=?");          args.append(jdump(data["tags"]))
    if "custom_fields" in data: sets.append("custom_fields=?"); args.append(jdump(data["custom_fields"]))
    if "social_links"  in data: sets.append("social_links=?");  args.append(jdump(data["social_links"]))
    if not sets: return jsonify(success=True)
    args.append(uid)
    db.execute(f"UPDATE users SET {','.join(sets)} WHERE uid=?", args); db.commit()
    audit_log("Profile Updated",me["name"],data.get("name",""))
    return jsonify(success=True)

@app.route("/api/profile/<uid>/update_photo", methods=["POST"])
def update_photo(uid):
    if not check_session(): return jsonify(success=False)
    me = build_me()
    if not me["is_admin"] and me["uid"] != uid: return jsonify(success=False)
    photos_raw = (request.get_json(silent=True) or {}).get("photos",[])
    if not photos_raw: return jsonify(success=False, message="No photos.")
    photos = []
    for b64 in photos_raw[:5]:
        try: photos.append(process_face_photo(b64))
        except: pass
    db = get_db()
    db.execute("UPDATE users SET face_photo=?,face_photos=? WHERE uid=?",
               (photos[0] if photos else "", jdump(photos), uid))
    db.commit()
    audit_log("Photos Updated", me["name"], uid)
    return jsonify(success=True)

@app.route("/api/delete_user/<uid>", methods=["DELETE"])
def delete_user(uid):
    if require_admin(): return jsonify(success=False)
    db  = get_db()
    row = db.execute("SELECT name FROM users WHERE uid=?",(uid,)).fetchone()
    if not row: return jsonify(success=False)
    name = row["name"]
    db.execute("DELETE FROM users WHERE uid=?",(uid,))
    db.execute("DELETE FROM projects WHERE user_uid=?",(uid,))
    db.execute("DELETE FROM notes WHERE user_uid=?",(uid,))
    # remove from teams
    for t in db.execute("SELECT id,members FROM teams").fetchall():
        m = jload(t["members"])
        if uid in m: db.execute("UPDATE teams SET members=? WHERE id=?",(jdump([x for x in m if x!=uid]),t["id"]))
    db.commit()
    log_event(name,"Deleted"); audit_log("Deleted User",build_me()["name"],name)
    return jsonify(success=True)

@app.route("/api/profile/<uid>/project/add", methods=["POST"])
def add_project(uid):
    if not check_session(): return jsonify(success=False)
    data = request.get_json(silent=True) or {}
    title = sanitize(data.get("title",""),200)
    if not title: return jsonify(success=False, message="Title required.")
    db = get_db()
    cur = db.execute("""INSERT INTO projects (user_uid,title,description,status,priority,
                        progress,due,assigned_by,created) VALUES (?,?,?,?,?,?,?,?,?)""",
                     (uid, title, sanitize(data.get("description",""),1000),
                      data.get("status","ongoing"), data.get("priority","medium"),
                      int(data.get("progress",0)), sanitize(data.get("due",""),20),
                      build_me().get("name","Admin"), datetime.now().strftime("%Y-%m-%d")))
    db.commit()
    proj = dict(db.execute("SELECT * FROM projects WHERE id=?",(cur.lastrowid,)).fetchone())
    proj["days_left"] = days_until(proj.get("due",""))
    audit_log("Project Assigned",build_me()["name"],uid,title)
    return jsonify(success=True, project=proj)

@app.route("/api/profile/<uid>/project/edit/<int:pid>", methods=["POST"])
def edit_project(uid, pid):
    if not check_session(): return jsonify(success=False)
    data = request.get_json(silent=True) or {}
    sets=[]; args=[]
    for f in ["title","description","status","priority","due"]:
        if f in data: sets.append(f"{f}=?"); args.append(sanitize(str(data[f]),500))
    if "progress" in data: sets.append("progress=?"); args.append(int(data["progress"]))
    if not sets: return jsonify(success=True)
    args += [pid, uid]
    get_db().execute(f"UPDATE projects SET {','.join(sets)} WHERE id=? AND user_uid=?", args)
    get_db().commit(); return jsonify(success=True)

@app.route("/api/profile/<uid>/project/delete/<int:pid>", methods=["DELETE"])
def del_project(uid, pid):
    if not check_session(): return jsonify(success=False)
    get_db().execute("DELETE FROM projects WHERE id=? AND user_uid=?",(pid,uid)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/profile/<uid>/note/add", methods=["POST"])
def add_note(uid):
    if not check_session(): return jsonify(success=False)
    text = sanitize((request.get_json(silent=True) or {}).get("text",""),2000)
    if not text: return jsonify(success=False)
    db = get_db()
    cur = db.execute("INSERT INTO notes (user_uid,text,by,created) VALUES (?,?,?,?)",
                     (uid, text, build_me().get("name",""), datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
    note = dict(db.execute("SELECT * FROM notes WHERE id=?",(cur.lastrowid,)).fetchone())
    return jsonify(success=True, note=note)

@app.route("/api/profile/<uid>/note/delete/<int:nid>", methods=["DELETE"])
def del_note(uid, nid):
    if not check_session(): return jsonify(success=False)
    get_db().execute("DELETE FROM notes WHERE id=? AND user_uid=?",(nid,uid)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/teams/create", methods=["POST"])
def create_team():
    if require_admin(): return jsonify(success=False)
    data = request.get_json(silent=True) or {}
    name = sanitize(data.get("name",""),100)
    if not name: return jsonify(success=False, message="Name required.")
    tid = hashlib.md5(f"team{time.time()}".encode()).hexdigest()[:8]
    get_db().execute("INSERT INTO teams (id,name,description,color,members,created) VALUES (?,?,?,?,?,?)",
                     (tid, name, sanitize(data.get("description",""),500),
                      data.get("color","#38bdf8"), "[]", datetime.now().strftime("%Y-%m-%d %H:%M")))
    get_db().commit()
    audit_log("Team Created",build_me()["name"],name)
    return jsonify(success=True, team={"id":tid,"name":name})

@app.route("/api/teams/<tid>/add_member", methods=["POST"])
def add_team_member(tid):
    if require_admin(): return jsonify(success=False)
    uid = (request.get_json(silent=True) or {}).get("uid","")
    row = get_db().execute("SELECT members FROM teams WHERE id=?",(tid,)).fetchone()
    if not row: return jsonify(success=False)
    m = jload(row["members"])
    if uid not in m: m.append(uid)
    get_db().execute("UPDATE teams SET members=? WHERE id=?",(jdump(m),tid)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/teams/<tid>/remove_member/<uid>", methods=["DELETE"])
def remove_team_member(tid, uid):
    if require_admin(): return jsonify(success=False)
    row = get_db().execute("SELECT members FROM teams WHERE id=?",(tid,)).fetchone()
    if not row: return jsonify(success=False)
    m = [x for x in jload(row["members"]) if x!=uid]
    get_db().execute("UPDATE teams SET members=? WHERE id=?",(jdump(m),tid)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/teams/<tid>/delete", methods=["DELETE"])
def delete_team(tid):
    if require_admin(): return jsonify(success=False)
    get_db().execute("DELETE FROM teams WHERE id=?",(tid,)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/announce/add", methods=["POST"])
def add_announce():
    if not check_session(): return jsonify(success=False)
    data  = request.get_json(silent=True) or {}
    title = sanitize(data.get("title",""),300)
    if not title: return jsonify(success=False)
    me    = build_me()
    db    = get_db()
    cur   = db.execute("""INSERT INTO announcements (title,body,date,author,pin,category,expires,reads)
                          VALUES (?,?,?,?,?,?,?,?)""",
                       (title, sanitize(data.get("body",""),5000),
                        datetime.now().strftime("%b %d, %Y"), me.get("name","?"),
                        1 if data.get("pin") else 0,
                        sanitize(data.get("category","General"),50),
                        sanitize(data.get("expires",""),20), "[]"))
    db.commit()
    item = dict(db.execute("SELECT * FROM announcements WHERE id=?",(cur.lastrowid,)).fetchone())
    audit_log("Announcement Posted",me["name"],detail=title)
    return jsonify(success=True, item=item)

@app.route("/api/announce/read/<int:aid>", methods=["POST"])
def mark_read(aid):
    if not check_session(): return jsonify(success=False)
    row = get_db().execute("SELECT reads FROM announcements WHERE id=?",(aid,)).fetchone()
    if not row: return jsonify(success=False)
    reads = jload(row["reads"])
    if session["user"] not in reads: reads.append(session["user"])
    get_db().execute("UPDATE announcements SET reads=? WHERE id=?",(jdump(reads),aid)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/announce/edit/<int:aid>", methods=["POST"])
def edit_announce(aid):
    if not check_session(): return jsonify(success=False)
    data = request.get_json(silent=True) or {}
    sets=[]; args=[]
    for f,ml in [("title",300),("body",5000),("category",50),("expires",20)]:
        if f in data: sets.append(f"{f}=?"); args.append(sanitize(str(data[f]),ml))
    if "pin" in data: sets.append("pin=?"); args.append(1 if data["pin"] else 0)
    if not sets: return jsonify(success=True)
    args.append(aid)
    get_db().execute(f"UPDATE announcements SET {','.join(sets)} WHERE id=?", args); get_db().commit()
    return jsonify(success=True)

@app.route("/api/announce/delete/<int:aid>", methods=["DELETE"])
def del_announce(aid):
    if not check_session(): return jsonify(success=False)
    get_db().execute("DELETE FROM announcements WHERE id=?",(aid,)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/settings/save", methods=["POST"])
def save_settings():
    if require_admin(): return jsonify(success=False)
    data = request.get_json(silent=True) or {}
    db   = get_db()
    allowed = ["app_name","app_desc","threshold","session_timeout","max_attempts",
               "lockout_mins","accent_color","text_size","theme","pin",
               "backup_reminder_days","public_board"]
    for k in allowed:
        if k in data:
            v = data[k]
            if k == "public_board": v = "1" if v else "0"
            db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)",(k,str(v)))
    db.commit()
    audit_log("Settings Updated",build_me()["name"])
    return jsonify(success=True)

@app.route("/api/settings/clear_history", methods=["POST"])
def clear_history():
    if require_admin(): return jsonify(success=False)
    get_db().execute("DELETE FROM history"); get_db().commit()
    audit_log("History Cleared",build_me()["name"])
    return jsonify(success=True)

@app.route("/api/settings/export")
def export_data():
    if not check_session(): return redirect(url_for("login_page"))
    db   = get_db()
    data = {
        "exported": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "users":    [dict(r) for r in db.execute("SELECT * FROM users").fetchall()],
        "projects": [dict(r) for r in db.execute("SELECT * FROM projects").fetchall()],
        "notes":    [dict(r) for r in db.execute("SELECT * FROM notes").fetchall()],
        "history":  [dict(r) for r in db.execute("SELECT * FROM history ORDER BY id DESC LIMIT 500").fetchall()],
        "announcements": [dict(r) for r in db.execute("SELECT * FROM announcements").fetchall()],
        "teams":    [dict(r) for r in db.execute("SELECT * FROM teams").fetchall()],
        "settings": [dict(r) for r in db.execute("SELECT * FROM settings").fetchall()],
    }
    db.execute("INSERT OR REPLACE INTO settings VALUES ('last_backup',?)",(date.today().isoformat(),))
    db.commit()
    return Response(json.dumps(data,indent=2), mimetype="application/json",
        headers={"Content-Disposition":"attachment;filename=nexus_backup.json"})

@app.route("/api/invite/create", methods=["POST"])
def create_invite():
    if require_admin(): return jsonify(success=False)
    data  = request.get_json(silent=True) or {}
    token = secrets.token_hex(10)
    get_db().execute("INSERT INTO invite_links (token,label,created,created_by,active,uses) VALUES (?,?,?,?,?,?)",
                     (token, sanitize(data.get("label","Invite"),100),
                      datetime.now().strftime("%Y-%m-%d %H:%M"), build_me()["name"], 1, 0))
    get_db().commit()
    return jsonify(success=True, token=token)

@app.route("/api/invite/toggle/<token>", methods=["POST"])
def toggle_invite(token):
    if require_admin(): return jsonify(success=False)
    row = get_db().execute("SELECT active FROM invite_links WHERE token=?",(token,)).fetchone()
    if not row: return jsonify(success=False)
    get_db().execute("UPDATE invite_links SET active=? WHERE token=?",(0 if row["active"] else 1, token))
    get_db().commit(); return jsonify(success=True)

@app.route("/api/invite/delete/<token>", methods=["DELETE"])
def delete_invite(token):
    if require_admin(): return jsonify(success=False)
    get_db().execute("DELETE FROM invite_links WHERE token=?",(token,)); get_db().commit()
    return jsonify(success=True)

@app.route("/api/search")
def api_search():
    if not check_session(): return jsonify([])
    q   = sanitize(request.args.get("q",""),100).lower()
    out = []
    for row in get_db().execute("SELECT uid,name,role,status FROM users ORDER BY name").fetchall():
        if q and q not in row["name"].lower() and q not in row["role"].lower(): continue
        out.append({"uid":row["uid"],"name":row["name"],"role":row["role"],"status":row["status"]})
    return jsonify(out)

@app.route("/api/pending/count")
def api_pending_count():
    return jsonify(count=pending_count())

# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.config["START_TIME"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = not (os.environ.get("RENDER") or os.environ.get("PRODUCTION"))
    print(f"\n✅  FaceGuard Nexus v10 (Production)")
    print(f"📱  http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
