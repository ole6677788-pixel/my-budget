import hashlib
import json
import os
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
DB_PATH = os.environ.get("DATABASE_PATH", "/data/budget.db")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://ole6677788-pixel.github.io").rstrip("/")
CODE_TTL_MINUTES = 10

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


def utcnow():
    return datetime.now(timezone.utc)


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      telegram_id INTEGER NOT NULL UNIQUE,
      username TEXT,
      first_name TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_codes (
      code TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      telegram_id INTEGER,
      status TEXT NOT NULL DEFAULT 'pending',
      session_token TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS user_state (
      user_id INTEGER PRIMARY KEY,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    return conn


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authorized_user(conn=None):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    digest = token_hash(header[7:].strip())
    own_conn = conn is None
    db = conn or connect()
    try:
        row = db.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
            (digest,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        if own_conn:
            db.close()


def telegram_api(method, payload):
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError("Telegram API request failed")
    return result.get("result")


def send_telegram(chat_id, text):
    try:
        telegram_api("sendMessage", {"chat_id": chat_id, "text": text})
    except Exception:
        app.logger.exception("Could not send Telegram message")


def set_webhook_if_configured():
    if not (BOT_TOKEN and PUBLIC_BASE_URL):
        return
    payload = {"url": PUBLIC_BASE_URL + "/telegram/webhook"}
    if WEBHOOK_SECRET:
        payload["secret_token"] = WEBHOOK_SECRET
    try:
        telegram_api("setWebhook", payload)
    except Exception:
        app.logger.exception("Telegram webhook setup failed")


@app.after_request
def cors(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
    return response


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "database": "sqlite",
        "telegram_configured": bool(BOT_TOKEN and BOT_USERNAME),
    })


@app.route("/api/auth/start", methods=["POST", "OPTIONS"])
def auth_start():
    if request.method == "OPTIONS":
        return make_response("", 204)
    if not (BOT_TOKEN and BOT_USERNAME):
        return jsonify({"error": "telegram_not_configured", "message": "Telegram bot is not configured on the server."}), 503
    code = secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]
    created = utcnow().isoformat()
    with connect() as conn:
        conn.execute("DELETE FROM auth_codes WHERE created_at < ?", ((utcnow() - timedelta(hours=1)).isoformat(),))
        conn.execute("INSERT INTO auth_codes(code, created_at, status) VALUES(?, ?, 'pending')", (code, created))
    return jsonify({
        "code": code,
        "bot_url": f"https://t.me/{BOT_USERNAME}?start=login_{code}",
        "expires_in": CODE_TTL_MINUTES * 60,
    })


@app.route("/api/auth/poll", methods=["GET"])
def auth_poll():
    code = request.args.get("code", "").strip()
    if not code or len(code) > 32:
        return jsonify({"error": "invalid_code"}), 400
    with connect() as conn:
        row = conn.execute("SELECT * FROM auth_codes WHERE code=?", (code,)).fetchone()
        if not row:
            return jsonify({"status": "expired"}), 404
        try:
            created = datetime.fromisoformat(row["created_at"])
        except ValueError:
            return jsonify({"status": "expired"}), 404
        if utcnow() - created > timedelta(minutes=CODE_TTL_MINUTES):
            conn.execute("DELETE FROM auth_codes WHERE code=?", (code,))
            return jsonify({"status": "expired"})
        if row["status"] != "approved" or not row["session_token"]:
            return jsonify({"status": "pending"})
        return jsonify({"status": "approved", "token": row["session_token"]})


@app.route("/api/auth/me", methods=["GET", "OPTIONS"])
def auth_me():
    if request.method == "OPTIONS":
        return make_response("", 204)
    user = authorized_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"user": {
        "telegram_id": user["telegram_id"],
        "username": user["username"],
        "first_name": user["first_name"],
        "created_at": user["created_at"],
    }})


@app.route("/api/auth/logout", methods=["POST", "OPTIONS"])
def auth_logout():
    if request.method == "OPTIONS":
        return make_response("", 204)
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        with connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(header[7:].strip()),))
    return jsonify({"ok": True})


@app.route("/api/state", methods=["OPTIONS"])
def state_options():
    return make_response("", 204)


@app.route("/api/state", methods=["GET"])
def get_state():
    user = authorized_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    with connect() as conn:
        row = conn.execute("SELECT payload, updated_at FROM user_state WHERE user_id=?", (user["id"],)).fetchone()
    if not row:
        return jsonify({"state": None, "updatedAt": None})
    return jsonify({"state": json.loads(row["payload"]), "updatedAt": row["updated_at"]})


@app.route("/api/state", methods=["PUT"])
def put_state():
    user = authorized_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("expenses", []), list):
        return jsonify({"error": "invalid_state"}), 400
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with connect() as conn:
        conn.execute(
            "INSERT INTO user_state (user_id, payload, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload, updated_at=CURRENT_TIMESTAMP",
            (user["id"], encoded),
        )
    return jsonify({"ok": True})


@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    if WEBHOOK_SECRET and request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        return jsonify({"error": "forbidden"}), 403
    update = request.get_json(silent=True) or {}
    message = update.get("message") or update.get("edited_message") or {}
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    text = (message.get("text") or "").strip()
    chat_id = chat.get("id")
    telegram_id = sender.get("id")
    if not chat_id or not telegram_id or not text.startswith("/start"):
        return jsonify({"ok": True})
    parts = text.split(maxsplit=1)
    payload = parts[1] if len(parts) > 1 else ""
    if payload.startswith("login_"):
        code = payload[6:]
        with connect() as conn:
            row = conn.execute("SELECT * FROM auth_codes WHERE code=?", (code,)).fetchone()
            if not row:
                send_telegram(chat_id, "Ссылка для входа не найдена или устарела. Вернись на сайт «Мой бюджет» и создай новую.")
                return jsonify({"ok": True})
            try:
                created = datetime.fromisoformat(row["created_at"])
            except ValueError:
                created = utcnow() - timedelta(days=1)
            if utcnow() - created > timedelta(minutes=CODE_TTL_MINUTES):
                conn.execute("DELETE FROM auth_codes WHERE code=?", (code,))
                send_telegram(chat_id, "Ссылка устарела. Вернись на сайт и нажми «Продолжить через Telegram» ещё раз.")
                return jsonify({"ok": True})
            if row["status"] == "approved":
                send_telegram(chat_id, "Этот вход уже подтверждён. Вернись на сайт — профиль должен открыться автоматически.")
                return jsonify({"ok": True})
            now = utcnow().isoformat()
            username = sender.get("username")
            first_name = (sender.get("first_name") or "Пользователь")[:128]
            conn.execute(
                "INSERT INTO users(telegram_id, username, first_name, created_at) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(telegram_id) DO UPDATE SET username=excluded.username, first_name=excluded.first_name",
                (telegram_id, username, first_name, now),
            )
            user = conn.execute("SELECT * FROM users WHERE telegram_id=?", (telegram_id,)).fetchone()
            session = secrets.token_urlsafe(32)
            conn.execute("INSERT INTO sessions(token_hash, user_id, created_at) VALUES(?, ?, ?)",
                         (token_hash(session), user["id"], now))
            conn.execute("UPDATE auth_codes SET telegram_id=?, status='approved', session_token=? WHERE code=?",
                         (telegram_id, session, code))
        send_telegram(chat_id, "Готово! Аккаунт «Мой бюджет» подтверждён. Вернись на сайт — вход завершится автоматически.\n\nЕсли ты не начинал вход, просто проигнорируй это сообщение.")
        return jsonify({"ok": True})
    send_telegram(chat_id, "Привет! Я бот авторизации «Мой бюджет». Чтобы зарегистрироваться или войти, открой сайт и нажми «Продолжить через Telegram».")
    return jsonify({"ok": True})


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "payload_too_large"}), 413


with connect() as _conn:
    pass
set_webhook_if_configured()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
