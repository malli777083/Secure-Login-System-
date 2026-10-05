#!/usr/bin/env python3
"""
Secure Login System (Flask + SQLite + bcrypt)
---------------------------------------------
Security features
  * Passwords hashed with bcrypt (salted, 12 rounds) - never stored in plain text
  * SQL injection protection: every query is parameterised (? placeholders)
  * Input validation (username, email, strong-password policy)
  * Session management: HttpOnly + SameSite cookies, 15-min idle timeout,
    session reset on login (prevents fixation), POST-only logout
  * CSRF tokens on every form
  * Account lockout after 5 failed attempts (brute-force protection)
  * Generic login errors + dummy hash check (no user enumeration / timing leak)
  * Optional 2FA with TOTP (Google Authenticator / Authy), RFC 6238, built on hmac
  * Security headers (CSP, X-Frame-Options, nosniff, no-store caching)

Run:
    pip install -r requirements.txt
    python app.py          ->  http://127.0.0.1:5000
"""
import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import quote

import bcrypt
from flask import (Flask, abort, flash, g, get_flashed_messages, redirect,
                   render_template_string, request, session, url_for)
from markupsafe import Markup

DB_FILE = os.environ.get("DB_FILE", "users.db")
MAX_FAILED = 5
LOCK_SECONDS = 15 * 60
APP_NAME = "SecureLogin"


def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    if os.path.exists(".secret_key"):
        return open(".secret_key").read().strip()
    key = secrets.token_hex(32)
    with open(".secret_key", "w") as fh:
        fh.write(key)
    try:
        os.chmod(".secret_key", 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,          # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",         # basic CSRF protection
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1",  # HTTPS only in production
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),           # idle timeout
    MAX_CONTENT_LENGTH=16 * 1024,
)

DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(12))


# ------------------------------------------------------------ database ----
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    con = sqlite3.connect(DB_FILE)
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        pw_hash BLOB NOT NULL,
        totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        last_totp_step INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL)""")
    con.commit()
    con.close()


def query_one(sql, params=()):
    return db().execute(sql, params).fetchone()   # params are always bound, never concatenated


def execute(sql, params=()):
    cur = db().execute(sql, params)
    db().commit()
    return cur


# ---------------------------------------------------------- validation ----
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,20}")
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}")
COMMON = {"password", "password123", "123456789", "qwerty123", "letmein123", "admin12345"}


def validate_registration(username, email, password):
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-20 characters: letters, numbers, underscore.")
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        errors.append("Enter a valid email address.")
    errors += password_errors(password, username)
    return errors


def password_errors(pw, username=""):
    errs = []
    if len(pw) < 10:
        errs.append("Password must be at least 10 characters.")
    if len(pw.encode()) > 72:
        errs.append("Password must be at most 72 bytes (bcrypt limit).")
    if not re.search(r"[a-z]", pw):
        errs.append("Password needs a lowercase letter.")
    if not re.search(r"[A-Z]", pw):
        errs.append("Password needs an uppercase letter.")
    if not re.search(r"\d", pw):
        errs.append("Password needs a digit.")
    if not re.search(r"[^A-Za-z0-9]", pw):
        errs.append("Password needs a special character.")
    if pw.lower() in COMMON or (username and username.lower() in pw.lower()):
        errs.append("Password is too common or contains your username.")
    return errs


# ------------------------------------------------------------ passwords ---
def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12))


def check_password(pw, stored_hash):
    """Always does one bcrypt check so timing does not reveal if a user exists."""
    data = pw.encode()
    if len(data) > 72:
        return False
    if stored_hash is None:
        bcrypt.checkpw(data, DUMMY_HASH)
        return False
    return bcrypt.checkpw(data, stored_hash)


# ----------------------------------------------------- 2FA (TOTP, RFC 6238)
def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode()


def totp_at(secret, t, step=30, digits=6):
    counter = int(t // step)
    mac = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret, code, last_step=0):
    """Returns the matched time-step, or None. Allows +-30s clock drift and
    rejects a code that was already used (replay protection)."""
    code = (code or "").replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    now_step = int(time.time() // 30)
    for d in (-1, 0, 1):
        step = now_step + d
        if hmac.compare_digest(totp_at(secret, step * 30), code) and step > last_step:
            return step
    return None


def qr_data_uri(text):
    """Optional QR code (needs `pip install qrcode[pil]`); falls back to None."""
    try:
        import qrcode
        buf = io.BytesIO()
        qrcode.make(text).save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None


# ------------------------------------------------------ session / CSRF ----
def start_session(user_id):
    session.clear()                      # new session on login (prevents session fixation)
    session.permanent = True
    session["uid"] = user_id
    session["csrf"] = secrets.token_hex(16)


def current_user():
    uid = session.get("uid")
    return query_one("SELECT * FROM users WHERE id=?", (uid,)) if uid else None


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        user = current_user()
        if not user:
            session.pop("uid", None)      # keep any half-finished 2FA login intact
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        g.user = user
        return view(*a, **kw)
    return wrapper


@app.context_processor
def inject_helpers():
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]
    return {"csrf_token": csrf_token}


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token.")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def register_failure(user):
    n = user["failed_attempts"] + 1
    locked = int(time.time()) + LOCK_SECONDS if n >= MAX_FAILED else 0
    execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
            (0 if locked else n, locked, user["id"]))


# ------------------------------------------------------------ templates ---
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureLogin</title>
<style>
:root{--bg:#f3f5f8;--card:#fff;--ink:#14202e;--mute:#5a6776;--line:#d3dae3;--accent:#0f5fa8;--bad:#b42318;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#0e1620;--card:#162331;--ink:#e8eef4;--mute:#9aaab9;--line:#2a3b4b;--accent:#5eb0f0;--bad:#ff8a80;--ok:#6ee7a8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
nav{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
nav a{color:var(--accent);margin-left:14px;text-decoration:none}nav b{font-size:1.1rem}
main{max-width:460px;margin:28px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:22px}
h1{font-size:1.4rem;margin:0 0 14px}label{display:block;margin:12px 0 4px;font-weight:600}
input[type=text],input[type=email],input[type=password]{width:100%;padding:10px 12px;font:inherit;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
button{margin-top:16px;padding:10px 16px;font:inherit;border:0;border-radius:8px;background:var(--accent);color:var(--bg);font-weight:600;cursor:pointer}
button.link{background:none;color:var(--accent);padding:0;margin:0;font-weight:400;text-decoration:underline}
button.danger{background:var(--bad)}
.msg{padding:10px 12px;border-radius:8px;margin-bottom:12px;border:1px solid var(--line)}
.msg.error{color:var(--bad)}.msg.ok{color:var(--ok)}.mute{color:var(--mute);font-size:.92rem}
code{background:var(--bg);padding:2px 6px;border-radius:5px;word-break:break-all}
img.qr{display:block;margin:10px auto;width:200px;height:200px}form.inline{display:inline}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
</style></head><body>
<nav><b>SecureLogin</b><span>
{% if session.get('uid') %}<a href="{{ url_for('dashboard') }}">Dashboard</a>
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="link" type="submit">Log out</button></form>
{% else %}<a href="{{ url_for('login') }}">Login</a><a href="{{ url_for('register') }}">Register</a>{% endif %}
</span></nav>
<main>{% for cat, m in messages %}<div class="msg {{ cat }}" role="alert">{{ m }}</div>{% endfor %}{{ content }}</main>
</body></html>"""


def page(body, **ctx):
    inner = render_template_string(body, **ctx)       # autoescaped
    msgs = get_flashed_messages(with_categories=True)
    return render_template_string(BASE, content=Markup(inner), messages=msgs)


HOME = """<div class="card"><h1>Secure Login System</h1>
<p>Bcrypt-hashed passwords, parameterised SQL, CSRF protection, account lockout,
session timeout and optional two-factor authentication.</p>
<p><a href="{{ url_for('register') }}">Create an account</a> or <a href="{{ url_for('login') }}">log in</a>.</p></div>"""

REGISTER = """<div class="card"><h1>Create account</h1>
<form method="post" novalidate><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<label for="u">Username</label><input id="u" name="username" type="text" maxlength="20" autocomplete="username" value="{{ username }}" required>
<label for="e">Email</label><input id="e" name="email" type="email" maxlength="254" autocomplete="email" value="{{ email }}" required>
<label for="p">Password</label><input id="p" name="password" type="password" maxlength="72" autocomplete="new-password" required>
<p class="mute">At least 10 characters with upper and lower case letters, a digit and a special character.</p>
<label for="p2">Confirm password</label><input id="p2" name="confirm" type="password" maxlength="72" autocomplete="new-password" required>
<button type="submit">Register</button></form></div>"""

LOGIN = """<div class="card"><h1>Log in</h1>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<label for="u">Username</label><input id="u" name="username" type="text" maxlength="20" autocomplete="username" required>
<label for="p">Password</label><input id="p" name="password" type="password" maxlength="72" autocomplete="current-password" required>
<button type="submit">Log in</button></form>
<p class="mute">No account? <a href="{{ url_for('register') }}">Register</a></p></div>"""

OTP = """<div class="card"><h1>Two-factor authentication</h1>
<p>Enter the 6-digit code from your authenticator app.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<label for="c">Code</label><input id="c" name="code" type="text" inputmode="numeric" maxlength="7" autocomplete="one-time-code" required>
<button type="submit">Verify</button></form></div>"""

DASH = """<div class="card"><h1>Welcome, {{ user['username'] }}</h1>
<p class="mute">Signed in as {{ user['email'] }}</p>
<p>Two-factor authentication: <b>{{ 'enabled' if user['totp_enabled'] else 'not enabled' }}</b></p>
{% if user['totp_enabled'] %}
<form method="post" action="{{ url_for('disable_2fa') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<label for="pw">Password (to turn off 2FA)</label><input id="pw" name="password" type="password" maxlength="72" autocomplete="current-password" required>
<button class="danger" type="submit">Disable 2FA</button></form>
{% else %}<p><a href="{{ url_for('setup_2fa') }}">Enable two-factor authentication</a></p>{% endif %}</div>"""

SETUP = """<div class="card"><h1>Set up 2FA</h1>
<p>1. Open an authenticator app (Google Authenticator, Authy, Microsoft Authenticator).</p>
{% if qr %}<img class="qr" src="{{ qr }}" alt="QR code for authenticator app">{% endif %}
<p>2. Add a key manually if you cannot scan: <code>{{ secret }}</code></p>
<p>3. Enter the 6-digit code shown in the app:</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<label for="c">Code</label><input id="c" name="code" type="text" inputmode="numeric" maxlength="7" autocomplete="one-time-code" required>
<button type="submit">Turn on 2FA</button></form></div>"""


# --------------------------------------------------------------- routes ---
@app.route("/")
def home():
    return page(HOME)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return page(REGISTER, username="", email="")
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    errors = validate_registration(username, email, password)
    if password != request.form.get("confirm", ""):
        errors.append("Passwords do not match.")
    if errors:
        for e in errors:
            flash(e, "error")
        return page(REGISTER, username=username, email=email), 400
    try:
        execute("INSERT INTO users (username, email, pw_hash, created_at) VALUES (?,?,?,?)",
                (username, email, hash_password(password), int(time.time())))
    except sqlite3.IntegrityError:
        flash("That username or email is already registered.", "error")
        return page(REGISTER, username=username, email=email), 409
    flash("Account created. You can log in now.", "ok")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page(LOGIN)
    username = request.form.get("username", "").strip()[:50]
    password = request.form.get("password", "")
    user = query_one("SELECT * FROM users WHERE username=?", (username,))
    if user and user["locked_until"] > time.time():
        flash("Too many failed attempts. Try again in a few minutes.", "error")
        return page(LOGIN), 429
    if not check_password(password, user["pw_hash"] if user else None):
        if user:
            register_failure(user)
        flash("Invalid username or password.", "error")
        return page(LOGIN), 401
    execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (user["id"],))
    if user["totp_enabled"]:
        session.clear()
        session["pre2fa"] = user["id"]
        session["pre2fa_at"] = int(time.time())
        return redirect(url_for("login_2fa"))
    start_session(user["id"])
    return redirect(url_for("dashboard"))


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pre2fa")
    if not uid or time.time() - session.get("pre2fa_at", 0) > 300:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))
    if request.method == "GET":
        return page(OTP)
    user = query_one("SELECT * FROM users WHERE id=?", (uid,))
    if user["locked_until"] > time.time():
        session.clear()
        flash("Too many failed attempts. Try again in a few minutes.", "error")
        return redirect(url_for("login"))
    step = verify_totp(user["totp_secret"], request.form.get("code", ""), user["last_totp_step"])
    if step is None:
        register_failure(user)
        flash("Invalid code.", "error")
        return page(OTP), 401
    execute("UPDATE users SET last_totp_step=? WHERE id=?", (step, user["id"]))
    start_session(user["id"])
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    return page(DASH, user=g.user)


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if g.user["totp_enabled"]:
        return redirect(url_for("dashboard"))
    if "setup_secret" not in session:
        session["setup_secret"] = new_totp_secret()
    secret = session["setup_secret"]
    if request.method == "POST":
        step = verify_totp(secret, request.form.get("code", ""))
        if step is None:
            flash("Invalid code, try again.", "error")
        else:
            execute("UPDATE users SET totp_secret=?, totp_enabled=1, last_totp_step=? WHERE id=?",
                    (secret, step, g.user["id"]))
            session.pop("setup_secret", None)
            flash("Two-factor authentication is now enabled.", "ok")
            return redirect(url_for("dashboard"))
    uri = (f"otpauth://totp/{quote(APP_NAME)}:{quote(g.user['username'])}"
           f"?secret={secret}&issuer={quote(APP_NAME)}")
    return page(SETUP, secret=secret, qr=qr_data_uri(uri))


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    if check_password(request.form.get("password", ""), g.user["pw_hash"]):
        execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?", (g.user["id"],))
        flash("Two-factor authentication disabled.", "ok")
    else:
        flash("Wrong password.", "error")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request(e):
    return page('<div class="card"><h1>Bad request</h1><p>{{ msg }}</p></div>', msg=e.description), 400


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)   # never run debug=True in production
