import getpass, hashlib, hmac, math, os, re, sqlite3, sys, threading, time
from uuid import uuid4
import requests
from PyQt6.QtCore import (Qt, QObject, QPoint, QPointF, QPropertyAnimation, QEasingCurve,
                          QRectF, QTimer, QVariantAnimation, pyqtProperty, pyqtSignal)
from PyQt6.QtGui import (QAction, QColor, QFont, QIcon, QPainter, QPainterPath, QPalette, QPen,
                         QPixmap, QPolygonF)
from PyQt6.QtWidgets import (
    QApplication, QDialog, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton, QScrollArea,
    QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QHeaderView, QAbstractItemView)

from processes import PROCESSES, STEP_NAMES

BG, PANEL, SIDE = "#f5f2eb", "#fffdf7", "#ece7da"
INK, MUTED, FAINT, LINE = "#222222", "#6b6657", "#8a8472", "#d9d3c4"
BAD, OK, WARN = "#a4161a", "#3a7d44", "#b7791f"
SERIF = "Georgia, 'Times New Roman', serif"
OUT = QEasingCurve.Type.OutCubic

QSS = f"""
* {{ font-family: {SERIF}; color: {INK}; }}
QMainWindow, #root {{ background: {BG}; }}
QLabel {{ background: transparent; }}
QScrollArea, QScrollArea > QWidget > QWidget {{ background: {BG}; border: none; }}
#side {{ background: {SIDE}; border: none; border-right: 1px solid {LINE}; }}
#statusbar {{ background: {SIDE}; border-top: 1px solid {LINE}; }}
QProgressBar {{ background: {LINE}; border: none; border-radius: 2px; }}
QProgressBar::chunk {{ background: {INK}; border-radius: 2px; }}
QMenuBar {{ background: {BG}; }}
QMenuBar::item:selected {{ background: {LINE}; }}
QMenu {{ background: {PANEL}; border: 1px solid {LINE}; }}
QMenu::item {{ padding: 5px 22px; }}
QMenu::item:selected {{ background: {LINE}; }}
QTableWidget {{ background: transparent; border: none; font-size: 10pt; }}
QTableWidget::item {{ padding: 4px 8px; border-bottom: 1px solid {LINE}; }}
QHeaderView::section {{ background: transparent; border: none; border-bottom: 1px solid {INK};
    color: {MUTED}; padding: 4px 8px; font-size: 8pt; font-weight: bold; }}
QDialog, QMessageBox, QInputDialog {{ background: {BG}; }}
QLineEdit {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 3px; padding: 5px 8px;
    selection-background-color: {INK}; selection-color: {BG}; }}
QLineEdit:focus {{ border: 1px solid {INK}; }}
QPushButton {{ background: {PANEL}; border: 1px solid {INK}; border-radius: 3px;
    padding: 6px 18px; min-width: 64px; }}
QPushButton:hover, QPushButton:default {{ background: {INK}; color: {BG}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 5px; min-height: 30px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""


def animate(obj, prop, end, ms=250, start=None, curve=OUT):
    key = "_anim_" + prop.decode()
    old = getattr(obj, key, None)
    if old is not None:
        old.stop()
        old.deleteLater()
    a = QPropertyAnimation(obj, prop, obj)
    a.setDuration(ms)
    if start is not None:
        a.setStartValue(start)
    a.setEndValue(end)
    a.setEasingCurve(curve)
    a.start()
    setattr(obj, key, a)
    return a


def count_to(label, target, fmt="{}", ms=600):
    if getattr(label, "_target", None) == target:
        return
    a = QVariantAnimation(label)
    a.setStartValue(float(getattr(label, "_cur", 0)))
    a.setEndValue(float(target))
    a.setDuration(ms)
    a.setEasingCurve(OUT)

    def tick(v):
        label._cur = v
        label.setText(fmt.format(int(round(v))))
    a.valueChanged.connect(tick)
    a.start()
    label._target, label._count_anim = target, a


def set_bar(bar, value):
    value = int(value)
    if getattr(bar, "_target", None) != value:
        bar._target = value
        animate(bar, b"value", value, 650)


def lab(text="", size=11, bold=False, italic=False, color=INK, wrap=False):
    w = QLabel(text)
    w.setStyleSheet(f"color:{color};font-size:{size}pt;"
                    f"font-weight:{'bold' if bold else 'normal'};"
                    f"font-style:{'italic' if italic else 'normal'};")
    w.setWordWrap(wrap)
    return w


def rule(color=INK):
    f = QFrame()
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{color};")
    return f


def section_label(text):
    box = QWidget()
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(3)
    lay.addWidget(lab(text.upper(), 8, True, color=MUTED))
    lay.addWidget(rule(LINE))
    return box


HERE = os.path.dirname(os.path.abspath(__file__))


def clean_name(s):
    return re.sub(r"[^\w-]", "_", s.strip())


class Accounts:
    ITERS, MIN_LEN = 600_000, 8
    MAX_FAILS, LOCK_SECS = 5, 30

    def __init__(self, path=os.path.join(HERE, "accounts.db")):
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("""CREATE TABLE IF NOT EXISTS accounts(
            user TEXT PRIMARY KEY COLLATE NOCASE, salt BLOB, hash BLOB, iters INTEGER,
            fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0)""")
        self.db.commit()

    @staticmethod
    def _hash(pw, salt, iters):
        return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)

    def any(self):
        return self.db.execute("SELECT 1 FROM accounts LIMIT 1").fetchone() is not None

    def exists(self, user):
        return self.db.execute("SELECT 1 FROM accounts WHERE user=?", (user,)).fetchone() is not None

    def create(self, user, pw):
        salt = os.urandom(16)
        try:
            with self.db:
                self.db.execute("INSERT INTO accounts(user,salt,hash,iters) VALUES(?,?,?,?)",
                                (user, salt, self._hash(pw, salt, self.ITERS), self.ITERS))
        except sqlite3.IntegrityError:
            return False
        return True

    def login(self, user, pw):
        row = self.db.execute("SELECT user,salt,hash,iters,fails,locked_until FROM accounts "
                              "WHERE user=?", (user,)).fetchone()
        if not row:
            self._hash(pw, b"0" * 16, self.ITERS)
            return None, "Wrong name or password."
        name, salt, good, iters, fails, locked = row
        now = time.time()
        if locked > now:
            return None, f"Too many wrong attempts. Try again in {int(locked - now) + 1} seconds."
        if hmac.compare_digest(good, self._hash(pw, salt, iters)):
            with self.db:
                self.db.execute("UPDATE accounts SET fails=0, locked_until=0 WHERE user=?", (name,))
            return name, ""
        fails += 1
        if fails >= self.MAX_FAILS:
            fails, locked = 0, now + self.LOCK_SECS
        with self.db:
            self.db.execute("UPDATE accounts SET fails=?, locked_until=? WHERE user=?",
                            (fails, locked, name))
        if locked > now:
            return None, f"Too many wrong attempts. Locked for {self.LOCK_SECS} seconds."
        return None, "Wrong name or password."

    def change_password(self, user, old, new):
        name, err = self.login(user, old)
        if not name:
            return err
        salt = os.urandom(16)
        with self.db:
            self.db.execute("UPDATE accounts SET salt=?, hash=?, iters=? WHERE user=?",
                            (salt, self._hash(new, salt, self.ITERS), self.ITERS, name))
        return ""


def logo_pixmap(px, color=INK, tile=None, dpr=2, weight=2):
    """Lighthouse mark: a solid dot with a ring and a fainter outer ring."""
    pm = QPixmap(px * dpr, px * dpr)
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    if tile:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(tile))
        p.drawRoundedRect(QRectF(0, 0, px, px), px * 0.22, px * 0.22)
    s, c, col = px / 64, QPointF(px / 2, px / 2), QColor(color)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(col)
    p.drawEllipse(c, 9 * s, 9 * s)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.setPen(QPen(col, max(1.0, weight * s)))
    p.drawEllipse(c, 18 * s, 18 * s)
    faint = QColor(col)
    faint.setAlphaF(0.35)
    p.setPen(QPen(faint, max(1.0, weight * s)))
    p.drawEllipse(c, 27 * s, 27 * s)
    p.end()
    return pm


def logo_icon():
    ic = QIcon()
    for n in (16, 20, 24, 32, 40, 48, 64, 96, 128, 256, 512):  # real pixel sizes, sharp at any DPI
        ic.addPixmap(logo_pixmap(n, BG, tile=INK, dpr=1, weight=3.5))
    return ic


def brand_row(size, px):
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(10)
    mark = QLabel()
    mark.setPixmap(logo_pixmap(px))
    lay.addWidget(mark)
    lay.addWidget(lab("Lighthouse", size, True))
    lay.addStretch(1)
    return w


def eye_icon(shown):
    pm = QPixmap(32, 32)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(MUTED), 2.4)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(3, 16)
    path.quadTo(16, 3, 29, 16)
    path.quadTo(16, 29, 3, 16)
    p.drawPath(path)
    p.setBrush(QColor(MUTED))
    p.drawEllipse(QPointF(16, 16), 4.2, 4.2)
    if shown:
        p.drawLine(6, 27, 26, 5)
    p.end()
    return QIcon(pm)


def password_edit(placeholder=""):
    e = QLineEdit()
    e.setEchoMode(QLineEdit.EchoMode.Password)
    e.setPlaceholderText(placeholder)
    act = e.addAction(eye_icon(False), QLineEdit.ActionPosition.TrailingPosition)
    act.setToolTip("Show password")

    def toggle():
        show = e.echoMode() == QLineEdit.EchoMode.Password
        e.setEchoMode(QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password)
        act.setIcon(eye_icon(show))
        act.setToolTip("Hide password" if show else "Show password")
    act.triggered.connect(toggle)
    return e


class LoginDialog(QDialog):
    def __init__(self, accounts, name="", from_cli=False):
        super().__init__()
        self.accounts, self.user = accounts, None
        self.creating = (not accounts.exists(name)) if from_cli else (not accounts.any())
        self.setWindowTitle("Lighthouse")
        self.setFixedWidth(360)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 22)
        lay.setSpacing(8)
        lay.addWidget(brand_row(20, 28))
        self.sub = lab("", 10, color=MUTED, wrap=True)
        lay.addWidget(self.sub)
        lay.addSpacing(6)
        self.name = QLineEdit(name)
        self.name.setPlaceholderText("Name")
        self.pw = password_edit("Password")
        self.pw2 = password_edit("Repeat password")
        for w in (self.name, self.pw, self.pw2):
            w.returnPressed.connect(self.submit)
            lay.addWidget(w)
        self.err = lab("", 9, color=BAD, wrap=True)
        lay.addWidget(self.err)
        self.go = QPushButton()
        self.go.setDefault(True)
        self.go.clicked.connect(self.submit)
        lay.addWidget(self.go)
        self.switch = QPushButton()
        self.switch.setFlat(True)
        self.switch.setCursor(Qt.CursorShape.PointingHandCursor)
        self.switch.setStyleSheet(f"QPushButton{{border:none;background:transparent;color:{MUTED};"
                                  f"text-decoration:underline;padding:4px;}}"
                                  f"QPushButton:hover{{background:transparent;color:{INK};}}")
        self.switch.clicked.connect(self.toggle)
        lay.addWidget(self.switch)
        self.apply_mode()

    def apply_mode(self):
        c = self.creating
        self.sub.setText("Create an account for this computer. Use at least "
                         f"{Accounts.MIN_LEN} characters. A forgotten password cannot be recovered."
                         if c else "Sign in to continue.")
        self.pw2.setVisible(c)
        self.go.setText("Create account" if c else "Sign in")
        self.switch.setText("I already have an account" if c else "Create a new account")
        self.err.setText("")
        self.pw.clear()
        self.pw2.clear()
        self.adjustSize()
        (self.pw if self.name.text() else self.name).setFocus()

    def toggle(self):
        self.creating = not self.creating
        self.apply_mode()

    def fail(self, msg):
        self.err.setText(msg)
        self.pw.clear()
        self.pw2.clear()
        self.pw.setFocus()

    def submit(self):
        name, pw = clean_name(self.name.text()), self.pw.text()
        if not name:
            return self.fail("Enter a name.")
        if self.creating:
            if len(pw) < Accounts.MIN_LEN:
                return self.fail(f"The password needs at least {Accounts.MIN_LEN} characters.")
            if pw != self.pw2.text():
                return self.fail("The two passwords do not match.")
            if not self.accounts.create(name, pw):
                return self.fail("That name is already taken.")
            self.user = name
        else:
            self.go.setEnabled(False)
            QApplication.processEvents()
            user, msg = self.accounts.login(name, pw)
            self.go.setEnabled(True)
            if not user:
                return self.fail(msg)
            self.user = user
        self.accept()


class ChangePasswordDialog(QDialog):
    def __init__(self, accounts, user, parent=None):
        super().__init__(parent)
        self.accounts, self.user = accounts, user
        self.setWindowTitle("Change password")
        self.setFixedWidth(340)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 18)
        lay.setSpacing(8)
        lay.addWidget(lab(f"Change password for {user}", 11, True, wrap=True))
        self.old, self.new, self.new2 = (password_edit("Current password"),
                                         password_edit("New password"),
                                         password_edit("Repeat new password"))
        for w in (self.old, self.new, self.new2):
            w.returnPressed.connect(self.submit)
            lay.addWidget(w)
        self.err = lab("", 9, color=BAD, wrap=True)
        lay.addWidget(self.err)
        go = QPushButton("Change password")
        go.setDefault(True)
        go.clicked.connect(self.submit)
        lay.addWidget(go)

    def submit(self):
        if len(self.new.text()) < Accounts.MIN_LEN:
            return self.err.setText(f"The new password needs at least {Accounts.MIN_LEN} characters.")
        if self.new.text() != self.new2.text():
            return self.err.setText("The new passwords do not match.")
        msg = self.accounts.change_password(self.user, self.old.text(), self.new.text())
        if msg:
            self.old.clear()
            return self.err.setText(msg)
        self.accept()


BASE = "http://127.0.0.1:8000"
SERVER = BASE + "/sync"


class Store:
    def __init__(self, user, server=SERVER):
        self.user, self.server = user, server
        self.device = f"{user}-{uuid4().hex[:5]}"
        self.db = sqlite3.connect(f"local_{user}.db", check_same_thread=False)
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.simulate_offline = False
        self.connected = False
        self.last_sync = None
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS steps(
                id TEXT PRIMARY KEY, done INTEGER DEFAULT 0, done_by TEXT, done_at REAL);
            CREATE TABLE IF NOT EXISTS outbox(
                event_id TEXT PRIMARY KEY, step_id TEXT, user TEXT, happened_at REAL);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
        """)
        for p in PROCESSES.values():
            for sid, _ in p["steps"]:
                self.db.execute("INSERT OR IGNORE INTO steps(id) VALUES(?)", (sid,))
        self.db.commit()

    def complete_step(self, step_id):
        now = time.time()
        with self.lock, self.db:
            self.db.execute("UPDATE steps SET done=1, done_by=?, done_at=? WHERE id=? AND done=0",
                            (self.user, now, step_id))
            self.db.execute("INSERT INTO outbox VALUES(?,?,?,?)",
                            (str(uuid4()), step_id, self.user, now))
        self.wake.set()

    def step_states(self):
        with self.lock:
            rows = self.db.execute("SELECT id,done,done_by,done_at FROM steps").fetchall()
        return {sid: (bool(done), by, at) for sid, done, by, at in rows}

    def pending(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

    def _since(self):
        row = self.db.execute("SELECT value FROM meta WHERE key='since'").fetchone()
        return int(row[0]) if row else 0

    def sync_once(self):
        if self.simulate_offline:
            self.connected = False
            return False
        with self.lock:
            pending = self.db.execute(
                "SELECT event_id,step_id,user,happened_at FROM outbox").fetchall()
            since = self._since()
        payload = {"device": self.device, "since": since,
                   "events": [dict(event_id=e, step_id=s, user=u, happened_at=t)
                              for e, s, u, t in pending]}
        try:
            r = requests.post(self.server, json=payload, timeout=5)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError):
            self.connected = False
            return False
        with self.lock, self.db:
            for eid in data["accepted"]:
                self.db.execute("DELETE FROM outbox WHERE event_id=?", (eid,))
            for ev in data["new_events"]:
                self.db.execute(
                    "UPDATE steps SET done=1, done_by=?, done_at=? WHERE id=? AND done=0",
                    (ev["user"], ev["happened_at"], ev["step_id"]))
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('since',?)",
                            (str(data["latest_seq"]),))
        self.connected, self.last_sync = True, time.time()
        return True

    def sync_loop(self):
        delay = 1
        while True:
            delay = 3 if self.sync_once() else min(delay * 2, 5)
            self.wake.wait(delay)
            self.wake.clear()


class ServerFeed(QObject):
    got = pyqtSignal(object)

    def __init__(self, store):
        super().__init__()
        self.store = store

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            data = None
            if not self.store.simulate_offline:
                try:
                    r = requests.get(BASE + "/api/state", timeout=3)
                    r.raise_for_status()
                    data = r.json()
                except (requests.RequestException, ValueError):
                    data = None
            try:
                self.got.emit(data)
            except RuntimeError:
                return
            time.sleep(2)


class CheckBox(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(24, 24)
        self._p = 0.0

    @pyqtProperty(float)
    def progress(self):
        return self._p

    @progress.setter
    def progress(self, v):
        self._p = v
        self.update()

    def set_done(self, done, animate_it=True):
        target = 1.0 if done else 0.0
        if animate_it:
            animate(self, b"progress", target, 420, curve=QEasingCurve.Type.OutQuad)
        else:
            self.progress = target

    def paintEvent(self, _e):
        t = max(0.0, min(1.0, self._p))
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = 1 + 0.16 * math.sin(math.pi * t)
        p.translate(12, 12)
        p.scale(s, s)
        p.translate(-12, -12)
        r = QRectF(2, 2, 20, 20)
        p.setBrush(QColor(PANEL))
        p.setPen(QPen(QColor(INK), 1.4))
        p.drawRoundedRect(r, 4, 4)
        if t > 0:
            c = QColor(INK)
            c.setAlphaF(min(1.0, t * 2.2))
            p.setBrush(c)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(r, 4, 4)
        if t > 0.25:
            u = (t - 0.25) / 0.75
            a, b, cc = QPointF(7, 12.5), QPointF(10.5, 16), QPointF(17, 8)
            if u <= 0.35:
                k = u / 0.35
                pts = [a, QPointF(a.x() + (b.x() - a.x()) * k, a.y() + (b.y() - a.y()) * k)]
            else:
                k = (u - 0.35) / 0.65
                pts = [a, b, QPointF(b.x() + (cc.x() - b.x()) * k, b.y() + (cc.y() - b.y()) * k)]
            pen = QPen(QColor(BG), 2.4)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPolyline(QPolygonF(pts))


class StepRow(QFrame):
    clicked = pyqtSignal(str, str)

    def __init__(self, idx, sid, name):
        super().__init__()
        self.sid, self.name, self.done = sid, name, False
        self._hover, self._glow = 0.0, 0.0
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(8, 10, 8, 10)
        self._lay.setSpacing(14)
        num = lab(f"{idx}", 10, color=FAINT)
        num.setFixedWidth(22)
        num.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.box = CheckBox()
        col = QVBoxLayout()
        col.setSpacing(1)
        self.title = lab(name, 12)
        self.meta = lab("", 9, italic=True, color=FAINT)
        self.meta.hide()
        col.addWidget(self.title)
        col.addWidget(self.meta)
        self._lay.addWidget(num)
        self._lay.addWidget(self.box)
        self._lay.addLayout(col, 1)

    @pyqtProperty(float)
    def hover(self):
        return self._hover

    @hover.setter
    def hover(self, v):
        self._hover = v
        self._lay.setContentsMargins(8 + int(8 * v), 10, 8, 10)
        self.update()

    @pyqtProperty(float)
    def glow(self):
        return self._glow

    @glow.setter
    def glow(self, v):
        self._glow = v
        self.update()

    def set_state(self, done, by, at, animate_it=True):
        if done != self.done:
            self.done = done
            self.box.set_done(done, animate_it)
            self.title.setStyleSheet(f"color:{MUTED if done else INK};font-size:12pt;")
            self.meta.setVisible(done)
            self.setCursor(Qt.CursorShape.ArrowCursor if done
                           else Qt.CursorShape.PointingHandCursor)
            animate(self, b"hover", 0.0, 150)
            if done and animate_it:
                animate(self, b"glow", 0.0, 1600, start=1.0)
        if done:
            when = time.strftime("%d %b, %H:%M", time.localtime(at)) if at else ""
            self.meta.setText(f"Done by {by}  ·  {when}")

    def paintEvent(self, _e):
        p = QPainter(self)
        if self._hover > 0:
            c = QColor(PANEL)
            c.setAlphaF(self._hover)
            p.fillRect(self.rect(), c)
        if self._glow > 0:
            c = QColor(OK)
            c.setAlphaF(0.20 * self._glow)
            p.fillRect(self.rect(), c)
        p.setPen(QColor(LINE))
        p.drawLine(0, self.height() - 1, self.width(), self.height() - 1)

    def enterEvent(self, e):
        if not self.done:
            animate(self, b"hover", 1.0, 150)

    def leaveEvent(self, e):
        animate(self, b"hover", 0.0, 220)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and not self.done:
            self.clicked.emit(self.sid, self.name)


class NavItem(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, key, title, sub="", maximum=None):
        super().__init__()
        self.key, self.selected = key, False
        self._hover, self._sel = 0.0, 0.0
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 9, 12, 10)
        lay.setSpacing(3)
        self.title = lab(title, 11, wrap=True)
        self.sub = lab(sub, 9, color=MUTED)
        lay.addWidget(self.title)
        lay.addWidget(self.sub)
        self.bar = None
        if maximum:
            self.bar = QProgressBar()
            self.bar.setRange(0, maximum)
            self.bar.setTextVisible(False)
            self.bar.setFixedHeight(4)
            lay.addWidget(self.bar)

    @pyqtProperty(float)
    def hover(self):
        return self._hover

    @hover.setter
    def hover(self, v):
        self._hover = v
        self.update()

    @pyqtProperty(float)
    def sel(self):
        return self._sel

    @sel.setter
    def sel(self, v):
        self._sel = v
        self.update()

    def set_selected(self, selected, animate_it=True):
        self.selected = selected
        self.title.setStyleSheet(
            f"color:{INK};font-size:11pt;font-weight:{'bold' if selected else 'normal'};")
        target = 1.0 if selected else 0.0
        if animate_it:
            animate(self, b"sel", target, 260)
        else:
            self.sel = target

    def set_progress(self, done, total):
        self.sub.setText(f"{done} of {total} steps done")
        if self.bar:
            set_bar(self.bar, done)

    def paintEvent(self, _e):
        p = QPainter(self)
        a = max(self._sel, self._hover * 0.55)
        if a > 0:
            c = QColor(PANEL)
            c.setAlphaF(min(1.0, a))
            p.fillRect(self.rect(), c)
        if self._sel > 0:
            h = int(self.height() * self._sel)
            p.fillRect(0, (self.height() - h) // 2, 3, h, QColor(INK))

    def enterEvent(self, e):
        animate(self, b"hover", 1.0, 150)

    def leaveEvent(self, e):
        animate(self, b"hover", 0.0, 220)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.key)


class StatCard(QFrame):
    def __init__(self, caption):
        super().__init__()
        self.setObjectName("card")
        self.setStyleSheet(f"#card{{background:{PANEL};border:1px solid {LINE};border-radius:4px;}}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.value = lab("-", 20, True)
        lay.addWidget(self.value)
        lay.addWidget(lab(caption.upper(), 8, True, color=MUTED))

    def _color(self, color):
        self.value.setStyleSheet(f"color:{color};font-size:20pt;font-weight:bold;")

    def set(self, text, color=INK):
        self.value._target = None
        self.value.setText(text)
        self._color(color)

    def set_int(self, n, color=INK):
        self._color(color)
        count_to(self.value, n)


class Pulse(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(20, 20)
        self._c, self._t = QColor(FAINT), 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(1700)
        self._anim.setLoopCount(-1)
        self._anim.valueChanged.connect(self._tick)
        self._anim.start()

    def _tick(self, v):
        self._t = v
        self.update()

    def set_color(self, color):
        self._c = QColor(color)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        ring = QColor(self._c)
        ring.setAlphaF(0.45 * (1 - self._t))
        p.setBrush(ring)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(10, 10), 5 + 5 * self._t, 5 + 5 * self._t)
        p.setBrush(self._c)
        p.drawEllipse(QPointF(10, 10), 5, 5)


class Toast(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("toast")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 10, 18, 10)
        self.msg = QLabel()
        self.msg.setStyleSheet(f"color:{BG};font-size:10pt;")
        lay.addWidget(self.msg)
        self.fx = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.fx)
        self._gen = 0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fade_out)
        self.hide()

    def target_pos(self):
        p = self.parentWidget()
        return QPoint(p.width() - self.width() - 28, p.height() - self.height() - 56)

    def reposition(self):
        if self.isVisible():
            self.move(self.target_pos())

    def show_msg(self, text, color=OK):
        self._gen += 1
        self.setStyleSheet(f"#toast{{background:{INK};border-radius:4px;"
                           f"border-left:4px solid {color};}}")
        self.msg.setText(text)
        self.adjustSize()
        end = self.target_pos()
        self.show()
        self.raise_()
        animate(self, b"pos", end, 300, start=QPoint(end.x(), end.y() + 18))
        animate(self.fx, b"opacity", 1.0, 250, start=0.0)
        self._timer.start(3200)

    def _fade_out(self):
        g = self._gen
        a = animate(self.fx, b"opacity", 0.0, 350)
        a.finished.connect(lambda: self.hide() if g == self._gen else None)


class MainWindow(QMainWindow):
    def __init__(self, store):
        super().__init__()
        self.store = store
        self.have_server_data = False
        self._ready = False
        self._prev_done, self._prev_conn = {}, None
        self.setWindowTitle(f"Lighthouse - {store.user}")
        self.resize(1160, 740)
        self.setMinimumSize(920, 600)

        m_file = self.menuBar().addMenu("File")
        pw_act = QAction("Change password...", self)
        pw_act.triggered.connect(self.change_password)
        m_file.addAction(pw_act)
        m_file.addSeparator()
        quit_act = QAction("Quit", self)
        quit_act.triggered.connect(self.close)
        m_file.addAction(quit_act)
        m_conn = self.menuBar().addMenu("Connection")
        self.offline_act = QAction("Work offline (for testing)", self, checkable=True)
        self.offline_act.toggled.connect(self.toggle_offline)
        sync_act = QAction("Sync now", self)
        sync_act.triggered.connect(lambda: store.wake.set())
        m_conn.addAction(self.offline_act)
        m_conn.addAction(sync_act)
        m_view = self.menuBar().addMenu("View")
        for i, key in enumerate(list(PROCESSES) + ["dash"], 1):
            title = PROCESSES[key]["name"] if key in PROCESSES else "Server dashboard"
            act = QAction(title, self)
            act.setShortcut(f"Ctrl+{i}")
            act.triggered.connect(lambda _c=False, k=key: self.select(k))
            m_view.addAction(act)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        main = QHBoxLayout()
        main.setSpacing(0)
        outer.addLayout(main, 1)

        side = QFrame()
        side.setObjectName("side")
        side.setFixedWidth(300)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(18, 24, 18, 16)
        sl.setSpacing(4)
        sl.addWidget(brand_row(22, 32))
        sl.addWidget(lab(f"signed in as {store.user}", 10, italic=True, color=MUTED))
        sl.addSpacing(18)
        sl.addWidget(section_label("Procedures"))
        sl.addSpacing(4)
        self.items = {}
        for pid, p in PROCESSES.items():
            it = NavItem(pid, p["name"], "", len(p["steps"]))
            it.clicked.connect(self.select)
            self.items[pid] = it
            sl.addWidget(it)
        sl.addSpacing(14)
        sl.addWidget(section_label("Overview"))
        sl.addSpacing(4)
        dash_item = NavItem("dash", "Server dashboard", "Live from the sync server")
        dash_item.clicked.connect(self.select)
        self.items["dash"] = dash_item
        sl.addWidget(dash_item)
        sl.addStretch()
        sl.addWidget(section_label("Overall"))
        sl.addSpacing(4)
        self.overall_lbl = lab("", 10, color=MUTED)
        self.overall_bar = QProgressBar()
        self.overall_bar.setTextVisible(False)
        self.overall_bar.setFixedHeight(6)
        self.overall_bar.setRange(0, sum(len(p["steps"]) for p in PROCESSES.values()))
        sl.addWidget(self.overall_lbl)
        sl.addWidget(self.overall_bar)
        main.addWidget(side)

        self.stack = QStackedWidget()
        main.addWidget(self.stack, 1)
        self.pages, self.page_index = {}, {}
        for pid, p in PROCESSES.items():
            self.page_index[pid] = self.stack.count()
            self.stack.addWidget(self.build_checklist(pid, p))
        self.page_index["dash"] = self.stack.count()
        self.stack.addWidget(self.build_dashboard())

        bar = QFrame()
        bar.setObjectName("statusbar")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(14, 5, 18, 5)
        bl.setSpacing(6)
        self.dot = Pulse()
        self.st_conn = lab("", 10, True)
        self.st_rest = lab("", 10, color=MUTED)
        bl.addWidget(self.dot)
        bl.addWidget(self.st_conn)
        bl.addWidget(self.st_rest)
        bl.addStretch()
        outer.addWidget(bar)

        self.toast = Toast(root)
        self.select(next(iter(PROCESSES)), animate_it=False)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.refresh()
        self._ready = True

        self.feed = ServerFeed(store)
        self.feed.got.connect(self.on_server)
        self.feed.start()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.toast.reposition()

    def build_checklist(self, pid, p):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(40, 30, 40, 20)
        lay.setSpacing(0)
        head = QHBoxLayout()
        head.addWidget(lab(p["name"], 20, True), 1)
        pct = lab("0%", 20, True, color=FAINT)
        head.addWidget(pct)
        lay.addLayout(head)
        lay.addSpacing(6)
        lay.addWidget(rule(INK))
        lay.addSpacing(6)
        summary = lab("", 11, color=MUTED)
        lay.addWidget(summary)
        lay.addSpacing(14)
        rows = {}
        for i, (sid, name) in enumerate(p["steps"], 1):
            row = StepRow(i, sid, name)
            row.clicked.connect(self.on_step_clicked)
            rows[sid] = row
            lay.addWidget(row)
        lay.addStretch()
        lay.addWidget(lab("Click a step to mark it done. Completed steps cannot be undone.",
                          9, italic=True, color=FAINT))
        self.pages[pid] = dict(summary=summary, rows=rows, pct=pct)
        return page

    def build_dashboard(self):
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(40, 30, 40, 24)
        lay.setSpacing(0)
        lay.addWidget(lab("Server dashboard", 20, True))
        lay.addSpacing(6)
        lay.addWidget(rule(INK))
        lay.addSpacing(6)
        self.banner = lab("", 10, True, color=BAD)
        lay.addWidget(self.banner)
        self.devices_lbl = lab("", 10, color=MUTED, wrap=True)
        lay.addWidget(self.devices_lbl)
        lay.addSpacing(14)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.c_events, self.c_chain = StatCard("Events logged"), StatCard("Audit chain")
        self.c_devices, self.c_pending = StatCard("Devices seen"), StatCard("Waiting to send")
        for c in (self.c_events, self.c_chain, self.c_devices, self.c_pending):
            cards.addWidget(c, 1)
        lay.addLayout(cards)
        lay.addSpacing(26)

        lay.addWidget(section_label("Team progress (all devices)"))
        lay.addSpacing(8)
        self.team = {}
        for pid, p in PROCESSES.items():
            row = QHBoxLayout()
            row.setSpacing(14)
            row.setContentsMargins(0, 5, 0, 5)
            name = lab(p["name"], 11)
            name.setFixedWidth(280)
            bar = QProgressBar()
            bar.setRange(0, len(p["steps"]))
            bar.setTextVisible(False)
            bar.setFixedHeight(6)
            cnt = lab("-", 10, color=MUTED)
            cnt.setFixedWidth(70)
            cnt.setAlignment(Qt.AlignmentFlag.AlignRight)
            row.addWidget(name)
            row.addWidget(bar, 1)
            row.addWidget(cnt)
            lay.addLayout(row)
            self.team[pid] = (bar, cnt)
        lay.addSpacing(26)

        lay.addWidget(section_label("Audit log (latest 15 entries)"))
        lay.addSpacing(6)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "STEP", "USER", "DEVICE", "WHEN", "HASH"])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.setShowGrid(False)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        hh = self.table.horizontalHeader()
        hh.setHighlightSections(False)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setStretchLastSection(False)
        self.table.setFixedHeight(34)
        lay.addWidget(self.table)
        lay.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        return scroll

    def select(self, key, animate_it=True):
        for k, it in self.items.items():
            it.set_selected(k == key, animate_it)
        idx = self.page_index[key]
        if self.stack.currentIndex() == idx and animate_it:
            return
        self.stack.setCurrentIndex(idx)
        if animate_it:
            w = self.stack.widget(idx)
            fx = QGraphicsOpacityEffect(w)
            w.setGraphicsEffect(fx)
            a = animate(fx, b"opacity", 1.0, 280, start=0.0)
            a.finished.connect(lambda w=w: QTimer.singleShot(0, lambda: w.setGraphicsEffect(None)))

    def change_password(self):
        if ChangePasswordDialog(Accounts(), self.store.user, self).exec():
            self.toast.show_msg("Password changed", OK)

    def toggle_offline(self, on):
        self.store.simulate_offline = on
        self.store.wake.set()
        self.refresh()

    def on_step_clicked(self, sid, name):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Lighthouse")
        box.setText("Mark this step as done?")
        box.setInformativeText(f"{name}\n\nThis cannot be undone.")
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() == QMessageBox.StandardButton.Yes:
            self.store.complete_step(sid)
            self.refresh()
            self.toast.show_msg("Step saved on this device", OK)

    def refresh(self):
        s = self.store
        states = s.step_states()
        total_done = 0
        for pid, p in PROCESSES.items():
            done = sum(states[sid][0] for sid, _ in p["steps"])
            total_done += done
            self.items[pid].set_progress(done, len(p["steps"]))
            pg = self.pages[pid]
            pg["summary"].setText(f"{done} of {len(p['steps'])} steps done")
            count_to(pg["pct"], round(100 * done / len(p["steps"])), "{}%")
            pg["pct"].setStyleSheet(
                f"color:{OK if done == len(p['steps']) else FAINT};font-size:20pt;font-weight:bold;")
            for sid, _ in p["steps"]:
                d, by, at = states[sid]
                pg["rows"][sid].set_state(d, by, at, self._ready)
                if self._ready and d and not self._prev_done.get(sid) and by != s.user:
                    self.toast.show_msg(f"{by} completed: {STEP_NAMES[sid]}", OK)
                self._prev_done[sid] = d
        total = self.overall_bar.maximum()
        self.overall_lbl.setText(f"{total_done} of {total} steps complete")
        set_bar(self.overall_bar, total_done)

        if s.simulate_offline:
            conn, color = "Working offline", WARN
        elif not s.connected:
            conn, color = "Cannot reach the server", BAD
        else:
            conn, color = "Connected", OK
        if self._ready and conn != self._prev_conn:
            if conn == "Connected":
                self.toast.show_msg("Connected. Changes are syncing.", OK)
            elif conn == "Working offline":
                self.toast.show_msg("Working offline. Changes are kept on this device.", WARN)
            else:
                self.toast.show_msg("Lost the server. Changes are kept on this device.", BAD)
        self._prev_conn = conn
        last = time.strftime("%H:%M:%S", time.localtime(s.last_sync)) if s.last_sync else "never"
        pend = s.pending()
        self.dot.set_color(color)
        self.st_conn.setStyleSheet(f"color:{color};font-size:10pt;font-weight:bold;")
        self.st_conn.setText(conn)
        self.st_rest.setText(f"|   {pend} change(s) waiting to send   |   last synced: {last}")
        self.c_pending.set_int(pend, WARN if pend else INK)

    def on_server(self, data):
        if data is None:
            self.banner.setText("Server unreachable. Showing the last data received."
                                if self.have_server_data
                                else "Server unreachable. Start server.py to see live data.")
            self.banner.show()
            return
        self.have_server_data = True
        self.banner.hide()
        self.c_events.set_int(data["total_events"])
        if data["chain_ok"]:
            self.c_chain.set("Intact", OK)
        else:
            self.c_chain.set(f"Broken at {data['broken_at']}", BAD)
        self.c_devices.set_int(len(data["devices"]))
        self.devices_lbl.setText(
            "Devices: " + ", ".join(f"{d['device']} ({d['ago']}s ago)" for d in data["devices"])
            if data["devices"] else "No devices have synced yet.")
        for pid, proc in zip(PROCESSES, data["processes"]):
            bar, cnt = self.team[pid]
            set_bar(bar, proc["done"])
            cnt.setText(f"{proc['done']} of {proc['total']}")
        log = data["log"]
        self.table.setRowCount(len(log))
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(9)
        for r, e in enumerate(log):
            vals = [e["seq"], e["step"], e["user"], e["device"],
                    time.strftime("%d %b, %H:%M:%S", time.localtime(e["at"])), e["hash"]]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                if c == 5:
                    item.setFont(mono)
                self.table.setItem(r, c, item)
        self.table.setFixedHeight(36 + 32 * len(log))


def main():
    if os.name == "nt":
        try:  # own taskbar identity, so Windows shows our icon instead of Python's
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Lighthouse.Client")
        except Exception:
            pass
    app = QApplication(sys.argv)
    try:
        app.styleHints().setColorScheme(Qt.ColorScheme.Light)
    except AttributeError:
        pass
    app.setStyle("Fusion")
    app.setWindowIcon(logo_icon())
    pal = QPalette()
    R = QPalette.ColorRole
    for role, col in [(R.Window, BG), (R.WindowText, INK), (R.Base, PANEL), (R.AlternateBase, BG),
                      (R.Text, INK), (R.Button, SIDE), (R.ButtonText, INK), (R.ToolTipBase, PANEL),
                      (R.ToolTipText, INK), (R.Highlight, INK), (R.HighlightedText, BG),
                      (R.PlaceholderText, FAINT)]:
        pal.setColor(role, QColor(col))
    app.setPalette(pal)
    app.setStyleSheet(QSS)
    cli = len(sys.argv) > 1
    dlg = LoginDialog(Accounts(), clean_name(sys.argv[1]) if cli else getpass.getuser(), cli)
    if not dlg.exec():
        return
    store = Store(dlg.user)
    threading.Thread(target=store.sync_loop, daemon=True).start()
    win = MainWindow(store)
    win.setWindowIcon(logo_icon())
    win.setWindowOpacity(0.0)
    win.show()
    animate(win, b"windowOpacity", 1.0, 450, start=0.0)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
