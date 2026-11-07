# Lighthouse

## The problem

Build an app that lets safety personnel keep completing security processes while they are offline, and that syncs their changes correctly once internet access comes back.

The hard part is the reconnect. Nothing that was done offline can be lost, and syncing must not create duplicates or conflicts, even if a request is retried or two devices disagree.

## What it is

Lighthouse is a set of security checklists (incident response, phishing triage, patching, offboarding) that people tick off on a desktop app. The app works with no connection at all. When it can reach the server, it sends what it has and picks up what everyone else did. A web dashboard shows the team's progress.

Made for nush hack 26 by Zhuoxuan, Xiaofan and Yiming.

## Features

Working offline

- Every tick is written to a local SQLite database and queued in an outbox in the same transaction, so a step is either saved and queued or neither.
- The app never needs the server to record progress.
- An offline switch in the client lets you demo syncing without pulling a cable.

Syncing

- Each change has a unique event id, and the server stores it with a UNIQUE constraint, so a retried request does nothing the second time.
- The client keeps a "since" token and only pulls events it hasn't seen.
- Outbox rows are deleted only after the server confirms them.
- While offline, the client keeps retrying with a short backoff.
- If devices disagree, a completed step wins. While a step stays ticked, the first person to tick it keeps the credit.
- A step can be unticked until an admin verifies it.

Audit log

- Every event is stored with a SHA-256 hash of itself and the hash of the event before it.
- `GET /verify` walks the chain and reports the exact sequence number where it breaks, if it does.
- The dashboard shows whether the chain is intact, along with the full log.

Admin check

- On the dashboard, each ticked step has a checkbox in the Admin check column. Ticking it verifies the step and locks it.
- The checkbox asks for the admin password if you are not signed in. The first time, it asks you to create one (at least 8 characters).
- Five wrong passwords lock admin login for 30 seconds. A session lasts 8 hours.
- A verified step can't be unticked by users. Only an admin can reopen it.
- Verify and reopen are written into the same hash chain as everything else.

Accounts in the desktop client

- Login with a name and password. Passwords use a random salt and PBKDF2-SHA256 at 600,000 iterations, compared in constant time.
- Five wrong passwords lock the account for 30 seconds, and the count survives restarts.
- Passwords can be changed from the app.

Desktop client (PyQt6)

- Animated checkboxes, toasts when someone else finishes or unticks a step, and a status dot for connected, offline or unreachable.
- Shows how many changes are waiting to send, when it last synced, and team progress per checklist.
- Shows the audit log and the devices that have synced.
- Counts your verified tasks and the ones still awaiting an admin check.

Web dashboard

- Four pages: home, processes, add process and accounts. It refreshes every 2 seconds.
- Home has the progress ring, stats, chain status and the audit log.
- Processes lists each checklist with who did each step and when. Filter by all, in progress, complete or not started.
- Add process lets you build a new checklist with a live preview. Names are up to 80 characters, steps up to 120, and 1 to 20 steps. Duplicate names are rejected.
- Accounts shows each person's steps, verified steps, devices and last activity.

## Running it

You need Python 3 and these packages:

```
pip install fastapi uvicorn requests PyQt6
```

Start the server and one client window:

```
python run.py
```

Start one window per person to watch them sync with each other:

```
python run.py Ali Bob
```

The dashboard is at http://localhost:8000. Closing the client windows stops the server that `run.py` started.

To stop a server that was left running:

```
python run.py stop
```

You can also run the pieces yourself with `python server.py` and `python app.py`. Logs go to `server.log` and `client_<name>.log` in the project folder.

## Files

| File | What it does |
|---|---|
| `processes.py` | The four built-in checklists (22 steps). Both the client and the server import it. |
| `server.py` | FastAPI and SQLite sync server, plus the web dashboard. |
| `app.py` | The PyQt6 desktop client and its local database. |
| `run.py` | Starts the server and the client windows. |

Checklists added from the dashboard are stored in `server.db`, not in `processes.py`.

## Limits

- The server only listens on localhost.
- `/sync` has no authentication of its own. Anyone who can reach the server can send events.
- There is one shared admin password, and admin sessions live in memory, so restarting the server signs admins out.
- Step ids come from `processes.py`, so changing a built-in checklist after people have started using it will orphan their old events.
