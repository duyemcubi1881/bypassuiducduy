import os
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "uids.db"

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
API_KEY = os.environ.get("API_KEY", "")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS uids (
                uid TEXT PRIMARY KEY,
                note TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def api_auth_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not API_KEY:
            return view(*args, **kwargs)
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapped


def list_uids():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT uid, note, created_at FROM uids ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def uid_exists(uid: str) -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT 1 FROM uids WHERE uid = ?", (uid,)).fetchone()
    return row is not None


@app.route("/")
@login_required
def index():
    return render_template("index.html", uids=list_uids(), username=ADMIN_USERNAME)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Sai username hoặc password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/uids", methods=["GET"])
def api_get_uids():
    """Public endpoint for bypass client."""
    uids = [item["uid"] for item in list_uids()]
    return jsonify({"uids": uids, "count": len(uids)})


@app.route("/api/uids/firebase", methods=["GET"])
def api_get_uids_firebase_format():
    """Firebase-compatible format for older clients."""
    uids = [item["uid"] for item in list_uids()]
    payload = {
        "default": {
            "uids": {
                str(i): {"uid": uid}
                for i, uid in enumerate(uids, start=1)
            }
        }
    }
    return jsonify(payload)


@app.route("/api/uids", methods=["POST"])
@login_required
@api_auth_required
def api_add_uid():
    data = request.get_json(silent=True) or request.form
    uid = str(data.get("uid", "")).strip()
    note = str(data.get("note", "")).strip()

    if not uid.isdigit():
        return jsonify({"error": "UID phải là số"}), 400
    if uid_exists(uid):
        return jsonify({"error": "UID đã tồn tại"}), 409

    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO uids (uid, note, created_at) VALUES (?, ?, ?)",
            (uid, note, created_at),
        )
        conn.commit()

    return jsonify({"success": True, "uid": uid, "note": note})


@app.route("/api/uids/<uid>", methods=["DELETE"])
@login_required
@api_auth_required
def api_delete_uid(uid):
    uid = str(uid).strip()
    with get_db() as conn:
        cur = conn.execute("DELETE FROM uids WHERE uid = ?", (uid,))
        conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "UID không tồn tại"}), 404
    return jsonify({"success": True, "uid": uid})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "uids": len(list_uids())})


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
