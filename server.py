import hashlib, hmac, json, os, secrets, sqlite3, threading, time, uuid
from typing import Literal
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from processes import PROCESSES

db = sqlite3.connect("server.db", check_same_thread=False)
lock = threading.Lock()
devices = {}
db.execute("""CREATE TABLE IF NOT EXISTS events(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,   -- server order = the sync token
    event_id TEXT UNIQUE,                    -- UNIQUE => idempotency
    device TEXT, step_id TEXT, user TEXT,
    happened_at REAL, prev_hash TEXT, hash TEXT,
    action TEXT DEFAULT 'done')""")
try:  # databases created before unticking existed: old rows count as 'done'
    db.execute("ALTER TABLE events ADD COLUMN action TEXT DEFAULT 'done'")
except sqlite3.OperationalError:
    pass
db.execute("""CREATE TABLE IF NOT EXISTS custom_processes(
    pid TEXT PRIMARY KEY, name TEXT, steps TEXT, created_at REAL)""")
db.execute("""CREATE TABLE IF NOT EXISTS admin(
    id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB, hash BLOB, iters INTEGER)""")
db.commit()

app = FastAPI()


class Event(BaseModel):
    event_id: str
    step_id: str
    user: str
    happened_at: float
    action: Literal["done", "undo"] = "done"


class SyncRequest(BaseModel):
    device: str
    since: int = 0
    events: list[Event] = []


class NewProcess(BaseModel):
    name: str
    steps: list[str]


class AdminPassword(BaseModel):
    password: str


class Review(BaseModel):
    step_id: str
    decision: Literal["verify", "reopen"]


def _hash(eid, sid, user, ts, prev, action="done"):
    # 'done' events hash exactly as before, so chains written by older versions still verify.
    data = [eid, sid, user, ts, prev] + ([] if action == "done" else [action])
    return hashlib.sha256(json.dumps(data).encode()).hexdigest()


def last_hash():
    row = db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    return row[0] if row else "GENESIS"


def verify_chain():
    prev = "GENESIS"
    for seq, eid, sid, user, ts, p, h, act in db.execute(
            "SELECT seq,event_id,step_id,user,happened_at,prev_hash,hash,action "
            "FROM events ORDER BY seq"):
        if p != prev or h != _hash(eid, sid, user, ts, prev, act or "done"):
            return False, seq
        prev = h
    return True, None


# Admin reviews are written by the server only (never accepted from /sync), into the same
# hash chain as everything else:
#   'verify' - an admin confirmed a ticked step is really complete; the step is now locked
#   'reopen' - an admin cleared a step (rejecting a tick, or reopening a verified step)
REVIEW_ACTIONS = ("verify", "reopen")
ADMIN_USER, ADMIN_MIN_LEN, ADMIN_ITERS = "admin", 8, 600_000
ADMIN_MAX_FAILS, ADMIN_LOCK_SECS, SESSION_SECS = 5, 30, 8 * 3600
sessions = {}                      # admin token -> expiry time (memory only)
admin_fails = {"n": 0, "until": 0.0}


def insert_event(event_id, device, step_id, user, ts, action):
    prev = last_hash()
    db.execute("INSERT INTO events(event_id,device,step_id,user,happened_at,prev_hash,hash,action)"
               " VALUES(?,?,?,?,?,?,?,?)",
               (event_id, device, step_id, user, ts, prev,
                _hash(event_id, step_id, user, ts, prev, action), action))


def replay(events):
    """events: (step_id, user, time, action) in server order.
    Returns (ticked, verified), each a dict step_id -> (user, time).
    While a step stays ticked, the first person to tick it keeps the credit. A verified step
    is locked: only an admin 'reopen' clears it, an 'undo' is ignored."""
    ticked, verified = {}, {}
    for sid, user, at, action in events:
        action = action or "done"
        if action == "done":
            ticked.setdefault(sid, (user, at))
        elif action == "verify":
            if sid in ticked:
                verified.setdefault(sid, (user, at))
        elif action == "reopen" or sid not in verified:   # 'undo' or 'reopen'
            ticked.pop(sid, None)
            verified.pop(sid, None)
    return ticked, verified


def replay_db():
    return replay(db.execute("SELECT step_id,user,happened_at,action FROM events ORDER BY seq"))


def all_processes():
    procs = {pid: dict(p, custom=False) for pid, p in PROCESSES.items()}
    for pid, name, steps in db.execute(
            "SELECT pid,name,steps FROM custom_processes ORDER BY rowid"):
        procs[pid] = {"name": name, "steps": [tuple(s) for s in json.loads(steps)], "custom": True}
    return procs


@app.post("/sync")
def sync(req: SyncRequest):
    accepted = []
    with lock:
        devices[req.device] = time.time()
        for e in req.events:
            if not db.execute("SELECT 1 FROM events WHERE event_id=?", (e.event_id,)).fetchone():
                # A verified step is locked: an untick is dropped (still 'accepted', so the
                # client stops resending it, and the 'locked' list below puts it right).
                if not (e.action == "undo" and e.step_id in replay_db()[1]):
                    insert_event(e.event_id, req.device, e.step_id, e.user, e.happened_at, e.action)
            accepted.append(e.event_id)
        db.commit()
        ticked, verified = replay_db()
        rows = db.execute("SELECT seq,event_id,step_id,user,happened_at,action FROM events "
                          "WHERE seq>? ORDER BY seq", (req.since,)).fetchall()
    return {"accepted": accepted,
            "locked": [{"step_id": sid, "by": ticked[sid][0], "at": ticked[sid][1]} for sid in verified],
            "new_events": [dict(seq=r[0], event_id=r[1], step_id=r[2], user=r[3], happened_at=r[4],
                                action=r[5] or "done")
                           for r in rows],
            "latest_seq": rows[-1][0] if rows else req.since}


@app.get("/verify")
def verify():
    with lock:
        ok, seq = verify_chain()
    return {"ok": ok, "broken_at_seq": seq}


@app.post("/api/processes")
def add_process(p: NewProcess):
    name = " ".join(p.name.split())
    steps = [s for s in (" ".join(x.split()) for x in p.steps) if s]
    if not 1 <= len(name) <= 80:
        raise HTTPException(400, "Give the process a name (up to 80 characters).")
    if not 1 <= len(steps) <= 20:
        raise HTTPException(400, "Add between 1 and 20 steps.")
    if any(len(s) > 120 for s in steps):
        raise HTTPException(400, "Each step must be 120 characters or fewer.")
    with lock:
        if name.lower() in {x["name"].lower() for x in all_processes().values()}:
            raise HTTPException(409, "A process with that name already exists.")
        pid = "c" + uuid.uuid4().hex[:8]
        data = [[f"{pid}_{i + 1}", s] for i, s in enumerate(steps)]
        db.execute("INSERT INTO custom_processes(pid,name,steps,created_at) VALUES(?,?,?,?)",
                   (pid, name, json.dumps(data), time.time()))
        db.commit()
    return {"id": pid}


def admin_hash(pw, salt, iters):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)


def new_session():
    token = secrets.token_urlsafe(32)
    with lock:
        sessions[token] = time.time() + SESSION_SECS
    return token


def require_admin(token):
    now = time.time()
    with lock:
        for t in [t for t, exp in sessions.items() if exp < now]:
            del sessions[t]
        ok = token in sessions
    if not ok:
        raise HTTPException(401, "Admin sign-in required.")


@app.post("/api/admin/setup")
def admin_setup(b: AdminPassword):
    """First run only: choose the admin password."""
    if len(b.password) < ADMIN_MIN_LEN:
        raise HTTPException(400, f"The password needs at least {ADMIN_MIN_LEN} characters.")
    salt = os.urandom(16)
    h = admin_hash(b.password, salt, ADMIN_ITERS)
    with lock:
        try:
            db.execute("INSERT INTO admin(id,salt,hash,iters) VALUES(1,?,?,?)", (salt, h, ADMIN_ITERS))
            db.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "An admin password is already set. Sign in instead.")
    return {"token": new_session()}


@app.post("/api/admin/login")
def admin_login(b: AdminPassword):
    with lock:
        wait = admin_fails["until"] - time.time()
        row = db.execute("SELECT salt,hash,iters FROM admin WHERE id=1").fetchone()
    if wait > 0:
        raise HTTPException(429, f"Too many wrong attempts. Try again in {int(wait) + 1} seconds.")
    if not row:
        raise HTTPException(409, "No admin password has been set yet.")
    good = hmac.compare_digest(row[1], admin_hash(b.password, row[0], row[2]))
    with lock:
        if good:
            admin_fails.update(n=0, until=0.0)
        else:
            admin_fails["n"] += 1
            if admin_fails["n"] >= ADMIN_MAX_FAILS:
                admin_fails.update(n=0, until=time.time() + ADMIN_LOCK_SECS)
    if not good:
        raise HTTPException(401, "Wrong password.")
    return {"token": new_session()}


@app.post("/api/admin/logout")
def admin_logout(x_admin_token: str = Header(default="")):
    with lock:
        sessions.pop(x_admin_token, None)
    return {"ok": True}


@app.post("/api/admin/review")
def admin_review(r: Review, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    with lock:
        if r.step_id not in {sid for p in all_processes().values() for sid, _ in p["steps"]}:
            raise HTTPException(404, "No such step.")
        ticked, verified = replay_db()
        if r.decision == "verify":
            if r.step_id not in ticked:
                raise HTTPException(409, "This step is not ticked, so there is nothing to verify.")
            if r.step_id in verified:
                raise HTTPException(409, "This step is already verified.")
        elif r.step_id not in ticked:
            raise HTTPException(409, "This step is already open.")
        insert_event(uuid.uuid4().hex, "admin-dashboard", r.step_id, ADMIN_USER, time.time(), r.decision)
        db.commit()
    return {"ok": True}


@app.get("/api/state")
def state():
    with lock:
        rows = db.execute("SELECT seq,step_id,user,device,happened_at,hash,action FROM events "
                          "ORDER BY seq").fetchall()
        ok, broken = verify_chain()
        seen = dict(devices)
        procs_def = all_processes()
        admin_set = db.execute("SELECT 1 FROM admin").fetchone() is not None
    now = time.time()
    # A step is done if its latest event is a tick; an 'undo' clears it. While a step stays
    # ticked, the first person to tick it keeps the credit. An admin 'verify' locks it.
    first, verified = replay((r[1], r[2], r[4], r[6]) for r in rows)

    step_names = {sid: n for p in procs_def.values() for sid, n in p["steps"]}
    step_proc = {sid: pid for pid, p in procs_def.items() for sid, _ in p["steps"]}

    procs = []
    for pid, p in procs_def.items():
        steps = []
        for sid, name in p["steps"]:
            t, v = first.get(sid), verified.get(sid)
            steps.append({"id": sid, "name": name, "done": bool(t),
                          "by": t[0] if t else None, "at": t[1] if t else None,
                          "verified": bool(v), "verified_at": v[1] if v else None})
        procs.append({"id": pid, "name": p["name"], "custom": p["custom"], "steps": steps,
                      "done": sum(s["done"] for s in steps),
                      "verified": sum(s["verified"] for s in steps), "total": len(steps)})

    users = {}
    for r in rows:
        if r[6] in REVIEW_ACTIONS:
            continue   # an admin's review is not anyone's own work
        u = users.setdefault(r[2], {"user": r[2], "events": 0, "steps": 0, "verified": 0,
                                    "devices": set(), "last": 0, "by_proc": {}})
        u["events"] += 1
        u["devices"].add(r[3])
        u["last"] = max(u["last"], r[4])
    for sid, (who, _at) in first.items():
        u = users[who]
        u["steps"] += 1
        if sid in verified:
            u["verified"] += 1       # credited to whoever ticked it, once an admin has confirmed it
        pid = step_proc.get(sid)
        if pid:
            u["by_proc"][pid] = u["by_proc"].get(pid, 0) + 1
    by_id = {p["id"]: p for p in procs}
    user_list = sorted(
        ({"user": u["user"], "events": u["events"], "steps": u["steps"], "verified": u["verified"],
          "last_ago": int(now - u["last"]), "devices": sorted(u["devices"]),
          "processes_touched": len(u["by_proc"]),
          "by_proc": [{"name": by_id[pid]["name"], "done": n, "total": by_id[pid]["total"]}
                      for pid, n in u["by_proc"].items()]}
         for u in users.values()),
        key=lambda u: (-u["verified"], -u["steps"], u["user"].lower()))

    steps_total = sum(p["total"] for p in procs)
    steps_done = sum(p["done"] for p in procs)
    verb = {"undo": "Unticked: ", "verify": "Verified: ", "reopen": "Reopened by admin: "}
    log = [{"seq": r[0], "step": verb.get(r[6], "") + step_names.get(r[1], r[1]),
            "user": r[2], "device": r[3],
            "at": r[4], "hash": r[5][:10]} for r in rows[-15:]][::-1]
    return {"processes": procs, "chain_ok": ok, "broken_at": broken, "log": log,
            "admin_set": admin_set,
            "devices": [{"device": d, "ago": int(now - t)} for d, t in seen.items()],
            "total_events": len(rows), "users": user_list,
            "summary": {"processes": len(procs),
                        "processes_done": sum(p["done"] == p["total"] for p in procs),
                        "steps_done": steps_done, "steps_verified": sum(p["verified"] for p in procs),
                        "steps_total": steps_total, "users": len(user_list)}}


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lighthouse</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23222'/%3E%3Ccircle cx='32' cy='32' r='9' fill='%23f5f2eb'/%3E%3Ccircle cx='32' cy='32' r='19' fill='none' stroke='%23f5f2eb' stroke-width='3'/%3E%3C/svg%3E"><style>
:root{--bg:#f5f2eb;--panel:#fffdf7;--side:#ece7da;--ink:#222;--muted:#6b6657;--faint:#8a8472;
--line:#d9d3c4;--ok:#3a7d44;--bad:#a4161a;--warn:#b7791f;--ease:cubic-bezier(.22,1,.36,1)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Georgia,"Times New Roman",serif}
[hidden]{display:none!important}
button,input{font:inherit;color:inherit}
.wrap{max-width:980px;margin:0 auto;padding:0 28px}

.top{position:sticky;top:0;z-index:10;background:rgba(245,242,235,.92);backdrop-filter:blur(8px);
border-bottom:1px solid var(--line)}
.bar-row{display:flex;align-items:center;gap:28px;height:58px}
.brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:bold;color:var(--ink);text-decoration:none}
.mark{display:block;flex:none;overflow:visible;color:var(--ink)}
.mark .halo{opacity:.35;transform-origin:center;transform-box:fill-box;animation:pulse 2.6s ease-out infinite}
@keyframes pulse{0%{transform:scale(.6);opacity:.7}100%{transform:scale(1.5);opacity:0}}
nav{position:relative;display:flex;gap:4px;height:100%;align-items:stretch}
nav a{display:flex;align-items:center;padding:0 14px;color:var(--muted);text-decoration:none;font-size:14px;
transition:color .25s}
nav a:hover,nav a.active{color:var(--ink)}
#ink{position:absolute;left:0;bottom:-1px;height:2px;background:var(--ink);width:0}
nav.ready #ink{transition:transform .45s var(--ease),width .45s var(--ease)}
.live{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted);
text-transform:uppercase;letter-spacing:.06em}
.live i{width:8px;height:8px;border-radius:50%;background:var(--faint);transition:background .4s}
.live.ok i{background:var(--ok);animation:blink 2s ease-in-out infinite}
.live.bad i{background:var(--bad)}
@keyframes blink{50%{opacity:.35}}

main{padding-bottom:70px}
.page{display:none}
.page.active{display:block}
.page.active>*{animation:rise .6s var(--ease) both}
.page.active>*:nth-child(2){animation-delay:.06s}.page.active>*:nth-child(3){animation-delay:.12s}
.page.active>*:nth-child(4){animation-delay:.18s}.page.active>*:nth-child(5){animation-delay:.24s}
.page.active>*:nth-child(6){animation-delay:.3s}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.enter{animation:rise .5s var(--ease) both}
.flash{animation:flash 1.6s ease-out}
@keyframes flash{0%{background:rgba(58,125,68,.22)}100%{background:transparent}}

h1{font-size:30px;margin:30px 0 2px}
.sub{color:var(--muted);margin:0 0 22px}
h2{font-size:12px;margin:34px 0 10px;padding-bottom:4px;border-bottom:1px solid var(--ink);
text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.banner{margin:16px 0 0;padding:9px 14px;border:1px solid var(--bad);color:var(--bad);background:#fbeeee;
border-radius:4px;animation:rise .4s var(--ease)}

.card{background:var(--panel);border:1px solid var(--line);border-radius:6px}
.hero{display:grid;grid-template-columns:220px 1fr;gap:18px}
.ringbox{position:relative;display:grid;place-items:center;padding:20px}
.ringbox svg{width:150px;height:150px}
.ringbox .c{position:absolute;text-align:center}
.ringbox .c b{font-size:30px;display:block;line-height:1}
.ringbox .c span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
#ring-fg{transition:stroke-dashoffset 1.1s var(--ease)}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.tile{padding:16px 18px;display:flex;flex-direction:column;justify-content:center}
.tile b{font-size:32px;line-height:1.1}
.tile span{color:var(--muted);font-size:13px}
.links{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.link{display:block;padding:16px 18px;color:inherit;text-decoration:none;
transition:transform .3s var(--ease),box-shadow .3s,border-color .3s}
.link:hover{transform:translateY(-3px);box-shadow:0 8px 20px rgba(34,34,34,.08);border-color:var(--ink)}
.link b{display:flex;justify-content:space-between}
.link b em{font-style:normal;transition:transform .3s var(--ease)}
.link:hover b em{transform:translateX(5px)}
.link span{color:var(--muted);font-size:13px}
.row2{display:flex;flex-wrap:wrap;gap:10px 28px;align-items:center}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:bold;
background:#e4f0e6;color:var(--ok);transition:background .4s,color .4s}
.badge.bad{background:#f7dcdc;color:var(--bad)}
.chip{display:inline-block;padding:2px 10px;border:1px solid var(--line);border-radius:99px;font-size:12px;
background:var(--panel);margin:0 6px 6px 0}

table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 12px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.mono{font:13px Consolas,Menlo,monospace}
.empty{padding:26px;text-align:center;color:var(--faint)}

.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;min-width:90px}
.bar i{display:block;height:100%;width:0;background:var(--ink);border-radius:3px;
transition:width .9s var(--ease),background .4s}
.complete .bar i{background:var(--ok)}

.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.fbtn{background:var(--panel);border:1px solid var(--line);border-radius:99px;padding:4px 14px;cursor:pointer;
font-size:13px;transition:background .25s,color .25s,border-color .25s,transform .2s}
.fbtn:hover{border-color:var(--ink)}.fbtn:active{transform:scale(.96)}
.fbtn.on{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.pcard{margin-bottom:12px;overflow:hidden;transition:box-shadow .3s,border-color .3s}
.pcard:hover{border-color:var(--faint)}
.pcard.open{box-shadow:0 8px 24px rgba(34,34,34,.07)}
.phead{all:unset;box-sizing:border-box;display:grid;grid-template-columns:1fr 130px 54px 18px;gap:16px;
align-items:center;width:100%;padding:14px 18px;cursor:pointer}
.phead:focus-visible{outline:2px solid var(--ink);outline-offset:-2px}
.ptitle{font-size:16px;font-weight:bold}
.ptitle small{font-weight:normal;font-size:12px;color:var(--muted);display:block}
.tag{font-size:10px;text-transform:uppercase;letter-spacing:.06em;border:1px solid var(--line);
border-radius:99px;padding:0 7px;margin-left:8px;color:var(--muted);vertical-align:2px;font-weight:normal}
.ppct{text-align:right;font-weight:bold;color:var(--faint);transition:color .4s}
.complete .ppct{color:var(--ok)}
.chev{width:10px;height:10px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);
transform:rotate(45deg) translate(-2px,-2px);transition:transform .4s var(--ease)}
.pcard.open .chev{transform:rotate(225deg) translate(-2px,-2px)}
.pbody{display:grid;grid-template-rows:0fr;transition:grid-template-rows .45s var(--ease)}
.pcard.open .pbody{grid-template-rows:1fr}
.pin{overflow:hidden;min-height:0}
.pin table{margin:0 0 8px;padding:0 18px;width:calc(100% - 36px);margin-left:18px}
.pin tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:1px 10px;border-radius:99px;font-size:12px;background:var(--side);color:var(--faint);
transition:background .4s,color .4s}
.done .pill{background:#e4f0e6;color:var(--ok);font-weight:bold}
.done:not(.verified) .pill{background:#fbf0d9;color:var(--warn)}
.verified .pill{background:var(--ok);color:#fff}
.col-admin{white-space:nowrap}
.achk{display:inline-flex;align-items:center;cursor:pointer}
.achk input{appearance:none;-webkit-appearance:none;width:24px;height:24px;margin:0;cursor:pointer;
border:2px solid var(--ink);border-radius:5px;background:var(--panel);display:grid;place-items:center;
transition:background .2s,border-color .2s,transform .15s}
.achk input:hover{border-color:var(--ok)}
.achk input:active{transform:scale(.92)}
.achk input::after{content:"\2713";font-size:16px;font-weight:bold;line-height:1;color:#fff;opacity:0;transform:scale(.5);
transition:opacity .2s,transform .2s var(--ease)}
.achk input:checked{background:var(--ok);border-color:var(--ok)}
.achk input:checked::after{opacity:1;transform:none}
.abtn{font-size:12px;border:1px solid var(--ink);background:var(--panel);border-radius:4px;padding:2px 10px;
cursor:pointer;margin-right:6px;transition:background .2s,color .2s}
.abtn:hover{background:var(--ink);color:var(--bg)}
.abtn.ok{background:var(--ok);border-color:var(--ok);color:#fff}
.abtn.ok:hover{background:#2d6336;color:#fff}
.adminbtn{margin-left:16px;font-size:12px;border:1px solid var(--line);background:var(--panel);border-radius:99px;
padding:3px 12px;cursor:pointer;transition:border-color .2s,background .2s,color .2s}
.adminbtn:hover{border-color:var(--ink)}
body.admin .adminbtn{background:var(--ink);color:var(--bg);border-color:var(--ink)}
dialog{border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);padding:22px;width:340px}
dialog::backdrop{background:rgba(34,34,34,.35)}
dialog h3{margin:0 0 6px;font-size:18px}
dialog p{margin:0 0 14px;color:var(--muted);font-size:14px}
dialog input{margin-bottom:8px}
dialog .btns{display:flex;gap:10px;justify-content:flex-end;margin-top:6px}
tr.open-step td:first-child{color:var(--muted)}
.who{display:inline-flex;align-items:center;gap:8px}
.av{width:22px;height:22px;border-radius:50%;background:var(--ink);color:var(--bg);display:inline-grid;
place-items:center;font-size:11px;font-weight:bold;flex:none}

.formgrid{display:grid;grid-template-columns:1fr 340px;gap:22px;align-items:start}
.panel{padding:20px}
label.l{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
input[type=text],input[type=password]{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:8px 10px;
transition:border-color .25s,box-shadow .25s,background .25s}
input[type=text]:focus,input[type=password]:focus{outline:none;border-color:var(--ink);background:#fff;box-shadow:0 0 0 3px rgba(34,34,34,.08)}
.srow{display:grid;grid-template-columns:24px 1fr 30px;gap:10px;align-items:center;margin-bottom:8px;
overflow:hidden;max-height:60px;transition:max-height .25s ease,opacity .25s,margin .25s,transform .25s}
.srow.leaving{max-height:0;opacity:0;margin-bottom:0;transform:translateX(24px)}
.sn{color:var(--faint);text-align:right;font-size:13px}
.x{background:none;border:none;color:var(--faint);font-size:20px;cursor:pointer;border-radius:4px;line-height:1;
transition:color .2s,background .2s,transform .2s}
.x:hover{color:var(--bad);background:#f7dcdc;transform:rotate(90deg)}
.btn{background:var(--ink);color:var(--bg);border:1px solid var(--ink);border-radius:4px;padding:8px 20px;cursor:pointer;
transition:transform .2s var(--ease),opacity .25s,background .25s,color .25s}
.btn:hover{transform:translateY(-1px)}.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.5;cursor:default;transform:none}
.btn.ghost{background:transparent;color:var(--ink)}
.btn.ghost:hover{background:var(--ink);color:var(--bg)}
.err{color:var(--bad);font-size:14px;min-height:22px;margin:10px 0 0}
.preview h3{margin:0 0 8px;font-size:16px}
.preview ol{margin:0;padding-left:22px;color:var(--muted);font-size:14px}
.preview li{margin-bottom:4px;animation:rise .35s var(--ease) both}
.preview .none{color:var(--faint);font-style:italic}

.urow{display:grid;grid-template-columns:minmax(150px,1.2fr) 1.4fr 80px 80px 110px;gap:16px;align-items:center;
padding:14px 18px;border-bottom:1px solid var(--line);transition:background .25s}
.urow:last-child{border-bottom:none}
.urow:hover{background:var(--bg)}
.uname{display:flex;align-items:center;gap:12px}
.uname .av{width:36px;height:36px;font-size:15px}
.uname small{display:block;color:var(--muted);font-size:12px;line-height:1.3}
.unum b{font-size:20px}.unum span{color:var(--muted);font-size:12px;display:block}
.uchips{grid-column:1/-1;margin-top:-4px;padding-left:48px}
.note{color:var(--muted);font-size:13px;margin-top:14px}
.hero3{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}

#toasts{position:fixed;right:22px;bottom:22px;display:flex;flex-direction:column;gap:8px;z-index:50}
.toast{background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:5px;box-shadow:0 8px 24px rgba(0,0,0,.2);
animation:toastIn .45s var(--ease) both;transition:opacity .4s,transform .4s}
.toast.out{opacity:0;transform:translateX(30px)}
@keyframes toastIn{from{opacity:0;transform:translateY(16px) scale(.96)}to{opacity:1;transform:none}}

@media(max-width:760px){
 .wrap{padding:0 16px}.bar-row{gap:10px}.live span{display:none}
 nav a{padding:0 9px;font-size:13px}
 .hero,.formgrid,.links,.hero3{grid-template-columns:1fr}
 .phead{grid-template-columns:1fr 70px 46px 14px;gap:10px}
 .urow{grid-template-columns:1fr 64px 64px}.urow .ubar,.urow .ulast{display:none}.uchips{padding-left:0}
 .pin table{font-size:13px}.col-when{display:none}
}
@media(prefers-reduced-motion:reduce){
 *,*::before,*::after{animation-duration:.01ms!important;animation-delay:0s!important;transition-duration:.01ms!important}
}
</style></head><body>

<header class="top"><div class="wrap bar-row">
 <a class="brand" href="#home"><svg class="mark" viewBox="0 0 64 64" width="26" height="26" aria-hidden="true"><circle cx="32" cy="32" r="9" fill="currentColor"/><circle cx="32" cy="32" r="18" fill="none" stroke="currentColor" stroke-width="2"/><circle class="halo" cx="32" cy="32" r="27" fill="none" stroke="currentColor" stroke-width="2"/></svg>Lighthouse</a>
 <nav id="nav" aria-label="Pages">
  <a href="#home" data-p="home">Home</a>
  <a href="#processes" data-p="processes">Processes</a>
  <a href="#add" data-p="add">Add process</a>
  <a href="#accounts" data-p="accounts">Accounts</a>
  <span id="ink"></span>
 </nav>
 <div class="live" id="live"><i></i><span>Connecting</span></div>
 <button class="adminbtn" id="adminbtn" type="button">Admin sign in</button>
</div></header>

<main class="wrap">
<div class="banner" id="offline" hidden>Cannot reach the server. Showing the last data received.</div>

<section class="page" id="page-home">
 <div><h1>Overview</h1><p class="sub">Everything the team has done, in one place. Updates itself every few seconds.</p></div>
 <div class="hero">
  <div class="card ringbox">
   <svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="60" cy="60" r="52" fill="none" stroke="#d9d3c4" stroke-width="8"/>
    <circle id="ring-fg" cx="60" cy="60" r="52" fill="none" stroke="#222" stroke-width="8" stroke-linecap="round"
     stroke-dasharray="326.73" stroke-dashoffset="326.73" transform="rotate(-90 60 60)"/>
   </svg>
   <div class="c"><b id="ring-pct">0%</b><span>of all steps</span></div>
  </div>
  <div class="tiles">
   <div class="card tile"><b id="st-procs">0</b><span id="st-procs-of">processes complete</span></div>
   <div class="card tile"><b id="st-steps">0</b><span id="st-steps-of">steps done</span></div>
   <div class="card tile"><b id="st-users">0</b><span>people have taken part</span></div>
   <div class="card tile"><b id="st-events">0</b><span>events in the audit log</span></div>
  </div>
 </div>
 <div>
  <h2>Go to</h2>
  <div class="links">
   <a class="card link" href="#processes"><b>Processes <em>&rarr;</em></b><span>See which steps are finished and by whom</span></a>
   <a class="card link" href="#add"><b>Add process <em>&rarr;</em></b><span>Create a new checklist</span></a>
   <a class="card link" href="#accounts"><b>Accounts <em>&rarr;</em></b><span>Users and how much each has done</span></a>
  </div>
 </div>
 <div>
  <h2>System</h2>
  <div class="row2"><span>Audit chain: <span class="badge" id="chain">checking</span></span>
   <span id="devs"></span></div>
 </div>
 <div>
  <h2>Audit log (latest 15 entries)</h2>
  <table><thead><tr><th>#</th><th>Step</th><th>User</th><th>Device</th><th>When</th><th>Hash</th></tr></thead>
  <tbody id="log"></tbody></table>
  <div class="empty" id="log-empty" hidden>Nothing has been logged yet.</div>
 </div>
</section>

<section class="page" id="page-processes">
 <div><h1>Processes</h1><p class="sub">Open a process to see each step, who finished it and when. Admins can sign in (top right) to verify completed steps; a verified step is locked and cannot be unticked.</p></div>
 <div class="filters" id="filters">
  <button class="fbtn on" data-f="all">All</button>
  <button class="fbtn" data-f="progress">In progress</button>
  <button class="fbtn" data-f="complete">Complete</button>
  <button class="fbtn" data-f="none">Not started</button>
 </div>
 <div id="plist"></div>
 <div class="empty" id="pempty" hidden>No processes match this filter.</div>
</section>

<section class="page" id="page-add">
 <div><h1>Add a process</h1><p class="sub">Name it, list its steps in order, and it appears on the Processes page straight away.</p></div>
 <div class="formgrid">
  <div class="card panel">
   <label class="l" for="pname">Process name</label>
   <input type="text" id="pname" maxlength="80" placeholder="e.g. Lost Laptop Response" autocomplete="off">
   <label class="l" style="margin-top:20px">Steps</label>
   <div id="srows"></div>
   <div style="display:flex;gap:10px;margin-top:6px">
    <button class="btn ghost" type="button" id="addstep">+ Add step</button>
    <button class="btn" type="button" id="save">Create process</button>
   </div>
   <p class="err" id="err" role="alert"></p>
  </div>
  <div class="card panel preview"><label class="l">Preview</label><div id="pv"></div></div>
 </div>
 <p class="note">Tip: press Enter in a step to add the next one. Processes created here show on this dashboard; they are not in processes.py.</p>
</section>

<section class="page" id="page-accounts">
 <div><h1>Accounts</h1><p class="sub">Everyone who has completed a step, and how much each person has done.</p></div>
 <div class="hero3">
  <div class="card tile"><b id="ac-users">0</b><span>users</span></div>
  <div class="card tile"><b id="ac-devs">0</b><span>devices synced since the server started</span></div>
  <div class="card tile"><b id="ac-steps">0</b><span>steps ticked in total</span></div>
  <div class="card tile"><b id="ac-ver">0</b><span>steps verified by an admin</span></div>
 </div>
 <div>
  <h2>Users</h2>
  <div class="card" id="ulist"></div>
  <div class="empty card" id="uempty" hidden>No one has completed a step yet.</div>
  <p class="note">Steps are credited to whoever ticked them; unticked steps are not counted. A step is verified once an admin has confirmed it, and from then on it is locked and counts towards that person's verified total. Users come from the audit log, because
  logins are stored on each client, not on the server.</p>
 </div>
</section>
</main>
<div id="toasts" aria-live="polite"></div>
<dialog id="adlg">
 <h3 id="adtitle">Admin sign in</h3>
 <p id="adsub"></p>
 <input type="password" id="adpw" placeholder="Password" autocomplete="off">
 <input type="password" id="adpw2" placeholder="Repeat password" autocomplete="off" hidden>
 <p class="err" id="aderr" role="alert"></p>
 <div class="btns"><button class="btn ghost" type="button" id="adcancel">Cancel</button>
  <button class="btn" type="button" id="adgo">Continue</button></div>
</dialog>

<script>
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const clock=x=>new Date(x*1000).toLocaleString([],{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
const ago=s=>s<5?'just now':s<60?s+'s ago':s<3600?Math.floor(s/60)+'m ago':s<86400?Math.floor(s/3600)+'h ago':Math.floor(s/86400)+'d ago';
const initial=n=>esc((n||'?').trim().charAt(0).toUpperCase()||'?');
const plural=(n,w)=>n+' '+w+(n===1?'':'s');
const REDUCE=matchMedia('(prefers-reduced-motion: reduce)').matches;
const RING=326.73;

function num(el,v,fmt=x=>x){
  el._fmt=fmt;
  if(el._v===v)return;
  el._v=v;
  const from=el._cur||0;
  cancelAnimationFrame(el._raf);
  if(REDUCE||from===v){el._cur=v;el.textContent=fmt(v);return}
  const t0=performance.now(),dur=750;
  const step=t=>{const k=Math.min(1,(t-t0)/dur),e=1-Math.pow(1-k,3);
    el._cur=from+(v-from)*e;el.textContent=fmt(Math.round(el._cur));
    if(k<1)el._raf=requestAnimationFrame(step)};
  el._raf=requestAnimationFrame(step);
}
function setBar(i,pct){i.dataset.w=pct;i.style.width=pct+'%'}
function replay(page){
  $$('.bar i[data-w]',page).forEach(i=>{i.style.transition='none';i.style.width='0';void i.offsetWidth;
    i.style.transition='';i.style.width=i.dataset.w+'%'});
  const ring=$('#ring-fg',page);
  if(ring&&ring.dataset.off){ring.style.transition='none';ring.style.strokeDashoffset=RING;void ring.getBoundingClientRect();
    ring.style.transition='';ring.style.strokeDashoffset=ring.dataset.off}
  $$('*',page).forEach(e=>{if(e._v!==undefined&&e._fmt){const v=e._v,f=e._fmt;e._v=undefined;e._cur=0;num(e,v,f)}});
}
function keyed(parent,items,key,make,update){
  const have=new Map($$(':scope > [data-k]',parent).map(n=>[n.dataset.k,n]));
  items.forEach((it,i)=>{
    const k=String(key(it));let n=have.get(k);const isNew=!n;
    if(isNew){n=make(it);n.dataset.k=k;n.classList.add('enter');n.style.animationDelay=Math.min(i,12)*45+'ms';
      n.addEventListener('animationend',()=>{n.classList.remove('enter');n.style.animationDelay=''},{once:true})}
    else have.delete(k);
    if(parent.children[i]!==n)parent.insertBefore(n,parent.children[i]||null);
    if(isNew)void n.offsetWidth;
    update(n,it,i);
  });
  have.forEach(n=>n.remove());
}
function toast(msg){
  const t=document.createElement('div');t.className='toast';t.textContent=msg;$('#toasts').append(t);
  setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),450)},3200);
}

const PAGES=['home','processes','add','accounts'];
function moveInk(){
  const a=$('#nav a.active'),ink=$('#ink');if(!a)return;
  ink.style.width=a.offsetWidth+'px';ink.style.transform='translateX('+a.offsetLeft+'px)';
}
function route(){
  const h=(location.hash||'#home').slice(1),page=PAGES.includes(h)?h:'home';
  $$('.page').forEach(p=>{
    const on=p.id==='page-'+page;
    if(on&&!p.classList.contains('active')){p.classList.add('active');replay(p);window.scrollTo(0,0)}
    if(!on)p.classList.remove('active');
  });
  $$('#nav a').forEach(a=>a.classList.toggle('active',a.dataset.p===page));
  moveInk();
}
addEventListener('hashchange',route);addEventListener('resize',moveInk);

let DATA=null,filter='all',openSet=new Set(),focusId=null;

function renderHome(d){
  const s=d.summary,pct=s.steps_total?s.steps_done/s.steps_total:0,ring=$('#ring-fg');
  ring.dataset.off=RING*(1-pct);ring.style.strokeDashoffset=ring.dataset.off;
  num($('#ring-pct'),Math.round(pct*100),v=>v+'%');
  num($('#st-procs'),s.processes_done);$('#st-procs-of').textContent='of '+s.processes+' processes complete';
  num($('#st-steps'),s.steps_done);$('#st-steps-of').textContent='of '+s.steps_total+' steps done';
  $('#st-steps-of').textContent='of '+s.steps_total+' steps done ('+s.steps_verified+' verified)';
  num($('#st-users'),s.users);num($('#st-events'),d.total_events);
  const c=$('#chain');c.textContent=d.chain_ok?'Intact':'BROKEN at entry '+d.broken_at;c.classList.toggle('bad',!d.chain_ok);
  $('#devs').textContent=d.devices.length?'Devices: '+d.devices.map(v=>v.device+' ('+ago(v.ago)+')').join(', '):'No devices have synced yet.';
  $('#log-empty').hidden=d.log.length>0;
  keyed($('#log'),d.log,e=>e.seq,e=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+e.seq+'</td><td>'+esc(e.step)+'</td><td>'+esc(e.user)+'</td><td>'+esc(e.device)+
     '</td><td>'+clock(e.at)+'</td><td class="mono">'+esc(e.hash)+'</td>';return tr},()=>{});
}

function makeStepRow(s){
  const tr=document.createElement('tr');
  tr.innerHTML='<td class="c-name"></td><td><span class="pill"></span></td><td class="c-by"></td><td class="col-when c-at"></td><td class="col-admin c-act"></td>';
  tr.querySelector('.c-name').textContent=s.name;return tr;
}
function updateStepRow(tr,s){
  tr.classList.toggle('done',s.done);tr.classList.toggle('open-step',!s.done);tr.classList.toggle('verified',s.verified);
  tr.querySelector('.pill').textContent=s.verified?'Verified':s.done?'Done, unchecked':'Open';
  const act=tr.querySelector('.c-act'),asig=s.done?(s.verified?'v':'d'):'';
  if(act._sig!==asig){act._sig=asig;
    act.innerHTML=!s.done?'':'<label class="achk" title="'+(s.verified?'Verified by admin. Untick to reopen.':'Tick to verify (admin password required)')+'"><input type="checkbox" aria-label="Admin check" data-check data-sid="'+esc(s.id)+'"'+(s.verified?' checked':'')+'></label>'}
  const by=tr.querySelector('.c-by'),sig=s.done?s.by:'';
  if(by._sig!==sig){by._sig=sig;by.innerHTML=s.done?'<span class="who"><span class="av">'+initial(s.by)+'</span>'+esc(s.by)+'</span>':''}
  tr.querySelector('.c-at').textContent=s.done?clock(s.at):'';
  if(s.done&&tr._init&&!tr._done){tr.classList.remove('flash');void tr.offsetWidth;tr.classList.add('flash')}
  tr._done=s.done;tr._init=true;
}
function makeProc(p){
  const n=document.createElement('article');n.className='card pcard';
  n.innerHTML='<button class="phead" aria-expanded="false"><span class="ptitle"><span class="t"></span><small></small></span>'+
   '<span class="bar"><i></i></span><span class="ppct"></span><span class="chev"></span></button>'+
   '<div class="pbody"><div class="pin"><table><thead><tr><th>Step</th><th>Status</th><th>Done by</th><th class="col-when">When</th><th class="col-admin">Admin check</th></tr></thead><tbody></tbody></table></div></div>';
  $('.phead',n).onclick=()=>toggleProc(n);return n;
}
function toggleProc(n,force){
  const on=force??!n.classList.contains('open');
  n.classList.toggle('open',on);$('.phead',n).setAttribute('aria-expanded',on);
  on?openSet.add(n.dataset.k):openSet.delete(n.dataset.k);
}
function updateProc(n,p){
  const st=p.done===p.total?'complete':p.done?'progress':'none',pct=Math.round(100*p.done/p.total);
  n.classList.toggle('complete',st==='complete');
  $('.t',n).innerHTML=esc(p.name)+(p.custom?'<span class="tag">Added</span>':'');
  $('.ptitle small',n).textContent=p.done+' of '+p.total+' steps done'+(p.verified?' · '+p.verified+' verified':'');
  setBar($('.bar i',n),pct);num($('.ppct',n),pct,v=>v+'%');
  if(openSet.has(n.dataset.k)&&!n.classList.contains('open'))toggleProc(n,true);
  keyed($('tbody',n),p.steps,s=>s.id,makeStepRow,updateStepRow);
  const show=filter==='all'||filter===st;
  if(n.hidden===show){n.hidden=!show;if(show){n.classList.remove('enter');void n.offsetWidth;n.classList.add('enter')}}
}
function renderProcs(d){
  keyed($('#plist'),d.processes,p=>p.id,makeProc,updateProc);
  $('#pempty').hidden=$$('#plist .pcard').some(n=>!n.hidden);
  if(focusId){const n=$('#plist [data-k="'+focusId+'"]');
    if(n){toggleProc(n,true);setTimeout(()=>n.scrollIntoView({behavior:'smooth',block:'center'}),150);
      n.classList.remove('flash');void n.offsetWidth;n.classList.add('flash');focusId=null}}
}
$('#filters').onclick=e=>{
  const b=e.target.closest('.fbtn');if(!b)return;
  filter=b.dataset.f;$$('.fbtn').forEach(x=>x.classList.toggle('on',x===b));if(DATA)renderProcs(DATA);
};

function makeUser(u){
  const r=document.createElement('div');r.className='urow';
  r.innerHTML='<div class="uname"><span class="av"></span><span><b class="nm"></b><small class="dv"></small></span></div>'+
   '<div class="ubar"><div class="bar"><i></i></div></div>'+
   '<div class="unum"><b class="ns">0</b><span>steps</span></div>'+'<div class="unum"><b class="nv">0</b><span>verified</span></div>'+
   '<div class="unum ulast"><b class="np">0</b><span class="lt"></span></div><div class="uchips"></div>';
  return r;
}
function updateUser(r,u,i,max){
  $('.av',r).textContent=initial(u.user);$('.nm',r).textContent=u.user;
  $('.dv',r).textContent=plural(u.devices.length,'device')+': '+u.devices.join(', ');
  setBar($('.bar i',r),max?Math.round(100*u.steps/max):0);
  num($('.ns',r),u.steps);num($('.nv',r),u.verified);
  num($('.np',r),u.processes_touched);
  $('.lt',r).textContent=(u.processes_touched===1?'process':'processes')+' · '+ago(u.last_ago);
  const sig=JSON.stringify(u.by_proc),ch=$('.uchips',r);
  if(ch._sig!==sig){ch._sig=sig;ch.innerHTML=u.by_proc.map(b=>'<span class="chip">'+esc(b.name)+': '+b.done+'/'+b.total+'</span>').join('')}
}
function renderAccounts(d){
  num($('#ac-users'),d.users.length);num($('#ac-devs'),d.devices.length);num($('#ac-steps'),d.summary.steps_done);num($('#ac-ver'),d.summary.steps_verified);
  const max=Math.max(0,...d.users.map(u=>u.steps));
  $('#uempty').hidden=d.users.length>0;$('#ulist').hidden=d.users.length===0;
  keyed($('#ulist'),d.users,u=>u.user,makeUser,(r,u,i)=>updateUser(r,u,i,max));
}

function render(d){DATA=d;renderHome(d);renderProcs(d);renderAccounts(d)}

async function load(){
  let d;
  try{const r=await fetch('/api/state');if(!r.ok)throw 0;d=await r.json()}
  catch(e){$('#offline').hidden=false;$('#live').className='live bad';$('#live span').textContent='Offline';return}
  $('#offline').hidden=true;$('#live').className='live ok';$('#live span').textContent='Live';
  try{render(d)}catch(e){console.error(e)}
}

const srows=$('#srows');
function renumber(){$$('.srow:not(.leaving) .sn',srows).forEach((s,i)=>s.textContent=i+1)}
function preview(){
  const name=$('#pname').value.trim(),steps=$$('.srow:not(.leaving) input',srows).map(i=>i.value.trim()).filter(Boolean);
  const sig=name+'\n'+steps.join('\n');if(preview._sig===sig)return;
  const prev=(preview._steps||[]);preview._sig=sig;preview._steps=steps;
  $('#pv').innerHTML='<h3>'+(name?esc(name):'<span class="none">Untitled process</span>')+'</h3>'+
   (steps.length?'<ol>'+steps.map((s,i)=>'<li'+(prev[i]===s?' style="animation:none"':'')+'>'+esc(s)+'</li>').join('')+'</ol>':'<p class="none">Steps will appear here.</p>');
}
function addStep(val='',after=null,focus=true){
  if($$('.srow:not(.leaving)',srows).length>=20){$('#err').textContent='A process can have at most 20 steps.';return}
  const r=document.createElement('div');r.className='srow enter';
  r.innerHTML='<span class="sn"></span><input type="text" maxlength="120" placeholder="Describe the step" aria-label="Step description"><button type="button" class="x" aria-label="Remove step">&times;</button>';
  const inp=$('input',r);inp.value=val;
  inp.addEventListener('input',preview);
  inp.addEventListener('keydown',e=>{
    if(e.key==='Enter'){e.preventDefault();addStep('',r)}
    if(e.key==='Backspace'&&!inp.value&&$$('.srow:not(.leaving)',srows).length>1){
      e.preventDefault();const p=r.previousElementSibling||r.nextElementSibling;removeStep(r);if(p)$('input',p).focus()}
  });
  $('.x',r).onclick=()=>removeStep(r);
  after?after.after(r):srows.append(r);
  renumber();preview();$('#err').textContent='';
  if(focus)inp.focus();
}
function removeStep(r){
  if($$('.srow:not(.leaving)',srows).length<=1){$('input',r).value='';preview();return}
  r.classList.add('leaving');setTimeout(()=>{r.remove();renumber()},260);renumber();preview();
}
function resetForm(){$('#pname').value='';srows.innerHTML='';addStep('',null,false);addStep('',null,false);preview._sig=null;preview()}
$('#pname').addEventListener('input',preview);
$('#pname').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('input',srows).focus()}});
$('#addstep').onclick=()=>addStep();
$('#save').onclick=async()=>{
  const btn=$('#save'),err=$('#err');err.textContent='';
  const name=$('#pname').value.trim(),steps=$$('.srow:not(.leaving) input',srows).map(i=>i.value.trim()).filter(Boolean);
  if(!name){err.textContent='Give the process a name.';$('#pname').focus();return}
  if(!steps.length){err.textContent='Add at least one step.';return}
  btn.disabled=true;btn.textContent='Creating...';
  try{
    const r=await fetch('/api/processes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,steps})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(typeof j.detail==='string'?j.detail:'Could not create the process.');
    focusId=j.id;resetForm();toast('Created "'+name+'"');await load();location.hash='#processes';
  }catch(e){err.textContent=e.message||'Could not reach the server.'}
  finally{btn.disabled=false;btn.textContent='Create process'}
};


let ADMIN='';try{ADMIN=sessionStorage.getItem('lh_admin')||''}catch(e){}
function setAdmin(t){
  ADMIN=t;try{t?sessionStorage.setItem('lh_admin',t):sessionStorage.removeItem('lh_admin')}catch(e){}
  document.body.classList.toggle('admin',!!t);
  $('#adminbtn').textContent=t?'Admin: sign out':'Admin sign in';
}
const adlg=$('#adlg');
let PENDING=null;
$('#adminbtn').onclick=async()=>{
  if(ADMIN){try{await fetch('/api/admin/logout',{method:'POST',headers:{'X-Admin-Token':ADMIN}})}catch(e){}
    setAdmin('');toast('Signed out of admin');return}
  openAdminDialog();
};
function openAdminDialog(){
  if(!DATA){toast('Cannot reach the server.');return}
  const setup=!DATA.admin_set;
  $('#adtitle').textContent=setup?'Create admin password':'Admin sign in';
  $('#adsub').textContent=setup?'No admin password exists yet. Choose one (at least 8 characters). Admins verify that steps are really complete.'
    :'Enter the admin password to verify completed steps.';
  $('#adpw2').hidden=!setup;$('#adpw').value=$('#adpw2').value='';$('#aderr').textContent='';
  adlg.showModal();$('#adpw').focus();
}
$('#adcancel').onclick=()=>{PENDING=null;adlg.close()};
adlg.addEventListener('cancel',()=>{PENDING=null});
async function adminGo(){
  const setup=!DATA.admin_set,pw=$('#adpw').value,err=$('#aderr'),btn=$('#adgo');err.textContent='';
  if(setup){
    if(pw.length<8){err.textContent='The password needs at least 8 characters.';return}
    if(pw!==$('#adpw2').value){err.textContent='The two passwords do not match.';return}
  }else if(!pw){err.textContent='Enter the password.';return}
  btn.disabled=true;
  try{
    const r=await fetch(setup?'/api/admin/setup':'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(typeof j.detail==='string'?j.detail:'Could not sign in.');
    setAdmin(j.token);adlg.close();toast(setup?'Admin password set. You are signed in.':'Signed in as admin');
    const p=PENDING;PENDING=null;if(p)review(p.sid,p.decision);else load();
  }catch(e){err.textContent=e.message||'Could not reach the server.';$('#adpw').value=$('#adpw2').value=''}
  finally{btn.disabled=false}
}
$('#adgo').onclick=adminGo;
for(const id of ['#adpw','#adpw2'])$(id).addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();adminGo()}});
async function review(sid,decision){
  try{
    const r=await fetch('/api/admin/review',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':ADMIN},body:JSON.stringify({step_id:sid,decision})});
    if(r.status===401){setAdmin('');toast('Admin session expired. Sign in again.');return}
    const j=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(typeof j.detail==='string'?j.detail:'Could not save that.');
    toast(decision==='verify'?'Verified. The step is now locked.':'Step reopened');await load();
  }catch(e){toast(e.message||'Could not reach the server.')}
}
document.addEventListener('click',e=>{
  const c=e.target.closest('[data-check]');
  if(c){
    e.preventDefault();                       // the page re-draws the box once the server confirms
    const decision=c.checked?'reopen':'verify';
    if(decision==='reopen'&&ADMIN&&!confirm('Uncheck this step? It will show as not done for everyone and can be ticked again.'))return;
    if(!ADMIN){PENDING={sid:c.dataset.sid,decision};
      if(decision==='reopen'&&!confirm('Uncheck this step? It will show as not done for everyone and can be ticked again.')){PENDING=null;return}
      openAdminDialog();return}
    review(c.dataset.sid,decision);return;
  }
  const b=e.target.closest('[data-review]');if(!b)return;
  const d=b.dataset.review;
  if(d==='reopen'&&!confirm('Clear this step? It will show as not done for everyone and can be ticked again.'))return;
  if(!ADMIN){PENDING={sid:b.dataset.sid,decision:d};openAdminDialog();return}
  review(b.dataset.sid,d);
});
setAdmin(ADMIN);
resetForm();route();
requestAnimationFrame(()=>requestAnimationFrame(()=>$('#nav').classList.add('ready')));
load();setInterval(()=>{if(!document.hidden)load()},2000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return PAGE


if __name__ == "__main__":
    import uvicorn
    print("Lighthouse is running. Dashboard: http://localhost:8000  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=8000)
