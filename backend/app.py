import json
import os
import sqlite3
from pathlib import Path
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
DB_PATH = os.environ.get("DATABASE_PATH", "/data/budget.db")
API_TOKEN = os.environ.get("BUDGET_API_TOKEN", "")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://ole6677788-pixel.github.io")

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    return conn

def authorized():
    supplied = request.headers.get("Authorization", "")
    return bool(API_TOKEN) and supplied == "Bearer " + API_TOKEN

@app.after_request
def cors(response):
    origin = request.headers.get("Origin", "")
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, PUT, OPTIONS"
    return response

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "database": "sqlite"})

@app.route("/api/state", methods=["OPTIONS"])
def state_options():
    return make_response("", 204)

@app.route("/api/state", methods=["GET"])
def get_state():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    with connect() as conn:
        row = conn.execute("SELECT payload, updated_at FROM app_state WHERE id=1").fetchone()
    if not row:
        return jsonify({"state": None, "updatedAt": None})
    return jsonify({"state": json.loads(row["payload"]), "updatedAt": row["updated_at"]})

@app.route("/api/state", methods=["PUT"])
def put_state():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("expenses", []), list):
        return jsonify({"error": "invalid_state"}), 400
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with connect() as conn:
        conn.execute(
            "INSERT INTO app_state (id, payload, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=CURRENT_TIMESTAMP",
            (encoded,),
        )
    return jsonify({"ok": True})

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "payload_too_large"}), 413

if __name__ == "__main__":
    connect().close()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
