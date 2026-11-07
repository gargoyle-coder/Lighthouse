# Lighthouse

**Offline-first cybersecurity checklists.** Built for NUSH Hack 26 by Zhuoxuan (code), Xiaofan (slides) and Yiming (debugging).

---

## Problem Statement

> Build an app that lets safety personnel keep completing security processes offline and syncs their changes correctly when internet access returns.

**How Lighthouse answers it**

| Need | What Lighthouse does |
|---|---|
| Work offline | Every tick is saved to a local SQLite database and queued in an *outbox*. The app never needs the server to record progress. |
| Sync correctly | Each event has a unique ID, so retries never duplicate work. A `since` token pulls only new events. The outbox is cleared only after the server confirms receipt. |
| Trust the record | The server keeps a hash-chained audit log, so any edit to history is detectable. Admins can verify a step, which locks it. |

---

## Manual

### 1. What you get

| File | Role |
|---|---|
| `processes.py` | The 4 built-in checklists (22 steps), shared by client and server |
| `server.py` | FastAPI + SQLite sync server, and the 4-page web dashboard |
| `app.py` | PyQt6 desktop client with its own local database |
| `run.py` | One command that starts the server and one or more client windows |

### 2. Requirements

- **Python 3.9 or newer**
- A desktop OS that can show a window (Windows, macOS or Linux)
- Port **8000** free on your machine

### 3. Install

Put all four `.py` files in the same folder, then open a terminal in that folder.

```bash
pip install fastapi uvicorn pydantic requests PyQt6
```

Optional but recommended: use a virtual environment first.

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
```

### 4. Run it

**One window (just you):**

```bash
python run.py
```

**Several people on one computer (best way to see syncing live):**

```bash
python run.py Ali Bob
```

This starts the server, waits for it to be ready (up to about 12 seconds), and opens one client window per name. The dashboard is at **http://localhost:8000**.

**Stop everything:** close the client windows. If run.py started the server, it shuts the server down when the last client closes. If a server is left running, use:

```bash
python run.py stop
```

> If port 8000 already has a Lighthouse server, `run.py` reuses it and will **not** stop it when you close the clients.

**Run the pieces yourself (alternative):**

```bash
python server.py        # terminal 1
python app.py Ali       # terminal 2
python app.py Bob       # terminal 3
```

### 5. First-time sign-in (desktop client)

1. A sign-in dialog appears.
2. If the name has no account yet, you are asked to **create** one: pick a password of at least 8 characters and repeat it.
3. Next time, use **Sign in** with the same name.

Notes:
- Accounts are stored in `accounts.db` on **this computer**. The server does not know about passwords.
- Passwords are salted PBKDF2-SHA256. **A forgotten password cannot be recovered.**
- 5 wrong attempts lock that account for 30 seconds.
- Change your password from **File → Change password...**

### 6. Using the desktop client

| Area | What it does |
|---|---|
| Left sidebar, **Procedures** | Pick a checklist. Each shows steps done and a progress bar. |
| Left sidebar, **Server dashboard** | Team-wide progress, audit chain status, devices seen and the latest 15 log entries. |
| Left sidebar, **Overall** | Total steps complete across all checklists. |
| Status bar (bottom) | Connection state, number of changes waiting to send, and time of last sync. |

**Tick a step:** click it, then confirm *Yes*. It shows who did it and when.

**Untick a step:** click a ticked step and confirm. You can only untick until an admin verifies it.

**Locked steps:** once an admin verifies a step it shows a green lock and *Verified by admin · locked*. It cannot be unticked.

**Keyboard shortcuts:** `Ctrl+1` to `Ctrl+9` jump to the checklists (and dashboard) in order.

Credit rule: while a step stays ticked, the **first person** to tick it keeps the credit.

### 7. Try the offline demo

This is the core of the project. Run `python run.py Ali Bob` and follow along.

1. In Ali's window, open **Connection → Work offline (for testing)**. The status bar turns amber: *Working offline*.
2. Tick two or three steps. Each is saved on the device. The status bar shows *N change(s) waiting to send*.
3. In Bob's window, notice nothing has changed. Ali's work is still only on Ali's device.
4. In Ali's window, untick **Work offline**. Within a few seconds the changes sync, the waiting count drops to 0, and Bob gets a toast such as *Ali completed: ...*.
5. Open the web dashboard. The audit log shows Ali's events and the chain badge reads **Intact**.

You can also stop the server entirely (`python run.py stop`, with no clients using it), keep working in the client, then start it again. The client retries with backoff and catches up on its own.

Use **Connection → Sync now** to force a sync.

### 8. Using the web dashboard

Open **http://localhost:8000**. It refreshes every 2 seconds.

| Page | Purpose |
|---|---|
| **Home** | Progress ring, totals, audit chain status, devices, latest 15 log entries |
| **Processes** | Expand a checklist to see each step, who did it, when, and its status (*Open*, *Done, unchecked*, *Verified*). Filter by All / In progress / Complete / Not started. |
| **Add process** | Create a new checklist with a live preview |
| **Accounts** | Each person's steps, verified steps, devices and last activity |

#### Add a checklist

1. Go to **Add process**.
2. Enter a name (up to 80 characters) and steps (1 to 20, up to 120 characters each). Press **Enter** in a step to add the next one.
3. Click **Create process**.

The new checklist is tagged *Added* on the dashboard. Desktop clients pick it up on their next poll and show a toast. Duplicate names are rejected.

#### Admin: verify a step

1. Click **Admin sign in** (top right).
2. **First time only:** choose an admin password (8+ characters). It is stored on the server.
3. On the **Processes** page, tick the checkbox in the **Admin check** column next to a completed step. If you are signed out, you are asked for the password first.
4. The step becomes **Verified** and locked on every device.
5. To reopen a verified step, untick its admin checkbox and confirm. It then shows as not done and can be ticked again.

Admin sessions last 8 hours. 5 wrong admin logins lock admin sign-in for 30 seconds.

### 9. The audit log and tamper check

Every tick, untick, verify and reopen is an event stored in a hash chain: each hash covers the event's data plus the hash of the one before it. Editing or deleting an old row breaks every hash after it.

- The dashboard **Audit chain** badge shows *Intact* or *BROKEN at entry N*.
- You can re-check directly at **http://localhost:8000/verify**, which returns `{"ok": true, "broken_at_seq": null}` when the log is clean.

### 10. Where data lives

All files are created in the project folder.

| File | Contents |
|---|---|
| `server.db` | Server events (the audit chain), custom checklists, admin password hash |
| `accounts.db` | Desktop client accounts on this computer |
| `local_<name>.db` | One client's steps, outbox and sync token |
| `server.pid` | Lets `python run.py stop` find the server |
| `server.log`, `client_<name>.log` | Output and errors, useful for debugging |

**Start completely fresh:** stop everything, then delete `server.db`, `accounts.db` and all `local_*.db` files. Deleting only some of them will make clients and server disagree, so delete them together.

### 11. Troubleshooting

| Symptom | Fix |
|---|---|
| "The server exited" | Open `server.log`. Usually port 8000 is busy, or `fastapi`/`uvicorn` is not installed. |
| "The server did not start in time" | Check `server.log`. Slow machines may need a second try. |
| Client closes right away | Open `client_<name>.log`. Usually `PyQt6` or `requests` is missing. |
| Client says *Cannot reach the server* | Start the server (`python run.py` or `python server.py`). Your work is safe in the outbox and will sync once it returns. |
| Dashboard shows *Offline* | Same as above. It keeps showing the last data it received. |
| Chain badge says *BROKEN* | Someone changed `server.db` by hand. Reset it (see section 10) if this was an accident. |
| "Too many wrong attempts" | Wait 30 seconds. |
| Forgot a client password | Not recoverable. Delete `accounts.db` to start over (you will lose the accounts, not the server data). |
| Forgot the admin password | Not recoverable from the UI. Delete the `admin` row in `server.db`, or reset everything. |
| Left-over server after a crash | `python run.py stop`, or end the Python process manually. |

### 12. Limits to know about

- The server listens on `127.0.0.1:8000` only, and the client has the same address built in. All windows must be on **one computer**. To use several machines, change the host in `server.py` (`uvicorn.run(...)`) and `BASE` in `app.py`, and open the port in your firewall.
- Passwords and the admin check protect the demo workflow. The server does not authenticate `/sync` calls, so do not expose it to an untrusted network.
- The 4 built-in checklists live in `processes.py`. Checklists added on the dashboard live in `server.db`.

---

## Quick reference

```bash
python run.py              # server + one client window
python run.py Ali Bob      # server + two client windows
python run.py stop         # stop a leftover server
```

Dashboard: `http://localhost:8000` · Chain check: `http://localhost:8000/verify`
