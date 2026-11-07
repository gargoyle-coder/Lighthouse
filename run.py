import os, signal, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "http://127.0.0.1:8000/api/state"
PIDFILE = os.path.join(HERE, "server.pid")
NT = os.name == "nt"
PY = sys.executable
if NT and PY.lower().endswith("pythonw.exe"):
    alt = PY[:-len("pythonw.exe")] + "python.exe"
    if os.path.exists(alt):
        PY = alt
FLAGS = subprocess.CREATE_NO_WINDOW if NT else 0 


def server_up():
    try:
        urllib.request.urlopen(URL, timeout=1)
        return True
    except Exception:
        return False


def spawn(script, args, logname):
    log = open(os.path.join(HERE, logname), "w", encoding="utf-8")
    return subprocess.Popen([PY, script, *args], cwd=HERE, stdout=log,
                            stderr=subprocess.STDOUT, creationflags=FLAGS)


def rm_pidfile():
    try:
        os.remove(PIDFILE)
    except OSError:
        pass


def stop_server():
    try:
        pid = int(open(PIDFILE).read())
        os.kill(pid, signal.SIGTERM)
        print("Stopped server (pid %d)." % pid)
    except Exception:
        print("No server of mine to stop.")
    rm_pidfile()


def main():
    names = sys.argv[1:]
    if names == ["stop"]:
        return stop_server()

    server = None
    if server_up():
        print("Server already running on port 8000, reusing it.")
    else:
        print("Starting server...")
        server = spawn("server.py", [], "server.log")
        open(PIDFILE, "w").write(str(server.pid))
        for _ in range(60):                 
            if server_up():
                break
            if server.poll() is not None:
                print("The server exited. Check server.log (port 8000 busy? fastapi/uvicorn missing?)")
                return
            time.sleep(0.2)
        else:
            print("The server did not start in time. Check server.log")
            server.terminate()
            return
    print("Server ready.  Dashboard: http://localhost:8000")

    clients = [(n, spawn("app.py", [n], f"client_{n}.log")) for n in names] or \
              [("you", spawn("app.py", [], "client_you.log"))]
    print("Client window(s) open. Close them to stop the server.")
    try:
        for n, c in clients:
            code = c.wait()
            if code:
                print(f"Client '{n}' exited with an error. See client_{n if names else 'you'}.log")
    except KeyboardInterrupt:
        pass
    finally:
        for _, c in clients:
            if c.poll() is None:
                c.terminate()
        if server:
            server.terminate()
            rm_pidfile()
            print("Server stopped.")


if __name__ == "__main__":
    main()
