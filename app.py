"""
PHISH//HUNTER - AI Phishing & Scam Detection System - Web App
Author: Satyam Kanojiya (MIT License)
====================================================
Run:
    pip install -r requirements.txt
    python app.py
Open:  http://127.0.0.1:5000

Environment variables (all optional):
    PORT=5000            server port
    FLASK_DEBUG=1        enable debug mode (never in production)
    PHISH_DB=path        SQLite file for history (default data/history.db)
    RATE_LIMIT=60        max API requests per minute per IP
"""
import csv
import io
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request

from detector import analyze_url, build_model, evaluate

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_TEXT_LEN = 5000
MAX_BATCH = 200

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB uploads
app.config["DB_PATH"] = os.environ.get("PHISH_DB", os.path.join(BASE_DIR, "data", "history.db"))
app.config["RATE_LIMIT"] = int(os.environ.get("RATE_LIMIT", "60"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("phishing")

log.info("Training model, please wait...")
MODEL, TEXTS, LABELS = build_model()
METRICS = evaluate(TEXTS, LABELS)
log.info("Model ready. Hold-out accuracy %s%% | 5-fold CV %s%%", METRICS["accuracy"], METRICS["cv_accuracy"])


# ----------------------------------------------------------------------------
# SQLite history (survives restarts)
# ----------------------------------------------------------------------------
def db():
    path = app.config["DB_PATH"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ts TEXT NOT NULL,
               kind TEXT NOT NULL,
               text TEXT NOT NULL,
               verdict TEXT NOT NULL,
               risk REAL NOT NULL,
               result TEXT NOT NULL,
               feedback INTEGER
           )"""
    )
    return con


def save_result(kind, text, result):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with closing(db()) as con:
        cur = con.execute(
            "INSERT INTO history (ts, kind, text, verdict, risk, result) VALUES (?,?,?,?,?,?)",
            (ts, kind, text, result["verdict"], result["risk"], json.dumps(result)),
        )
        con.commit()
        return cur.lastrowid, ts


def row_to_dict(r):
    return {
        "id": r["id"], "ts": r["ts"], "kind": r["kind"], "text": r["text"],
        "verdict": r["verdict"], "risk": r["risk"], "feedback": r["feedback"],
        "result": json.loads(r["result"]),
    }


# ----------------------------------------------------------------------------
# Simple per-IP rate limiter + security headers
# ----------------------------------------------------------------------------
_hits = defaultdict(deque)


@app.before_request
def rate_limit():
    if not request.path.startswith("/api/") or request.path == "/api/health":
        return None
    limit = app.config["RATE_LIMIT"]
    now, q = time.time(), _hits[request.remote_addr]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        return jsonify({"error": "Too many requests. Please slow down."}), 429
    q.append(now)
    return None


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    )
    return resp


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def get_text(data, key="text"):
    value = (data or {}).get(key, "")
    if not isinstance(value, str):
        return None, ("Invalid input.", 400)
    value = value.strip()
    if not value:
        return None, ("Please enter something to analyze.", 400)
    if len(value) > MAX_TEXT_LEN:
        return None, (f"Input too long (max {MAX_TEXT_LEN} characters).", 413)
    return value, None


def csv_safe(value):
    """Prevent CSV/Excel formula injection."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def summarize(results):
    counts = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING / SCAM": 0}
    for r in results:
        counts[r["verdict"]] += 1
    return counts


# ----------------------------------------------------------------------------
# routes
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        m=METRICS,
        dataset_size=len(TEXTS),
        scam_count=sum(LABELS),
        safe_count=len(LABELS) - sum(LABELS),
    )


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "dataset_size": len(TEXTS), "accuracy": METRICS["accuracy"]})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    text, err = get_text(request.get_json(silent=True))
    if err:
        return jsonify({"error": err[0]}), err[1]
    result = MODEL.analyze(text)
    result["text"] = text
    result["id"], result["ts"] = save_result("message", text, result)
    return jsonify(result)


@app.route("/api/url", methods=["POST"])
def scan_url():
    url, err = get_text(request.get_json(silent=True), "url")
    if err:
        return jsonify({"error": err[0]}), err[1]
    result = analyze_url(url)
    result["id"], result["ts"] = save_result("url", url, result)
    return jsonify(result)


@app.route("/api/batch", methods=["POST"])
def batch():
    """Analyze many messages: JSON {"messages": [...]} or an uploaded .csv/.txt file."""
    messages = []
    if request.files.get("file"):
        raw = request.files["file"].read().decode("utf-8", errors="ignore")
        if raw.lstrip().lower().startswith("text,") or raw.lstrip().lower().startswith('"text"'):
            messages = [(r.get("text") or "").strip() for r in csv.DictReader(io.StringIO(raw))]
        else:
            messages = [ln.strip() for ln in raw.splitlines()]
    else:
        data = request.get_json(silent=True) or {}
        if isinstance(data.get("messages"), list):
            messages = [m.strip() for m in data["messages"] if isinstance(m, str)]
    messages = [m[:MAX_TEXT_LEN] for m in messages if m]
    if not messages:
        return jsonify({"error": "No messages found. Send one message per line."}), 400
    if len(messages) > MAX_BATCH:
        return jsonify({"error": f"Too many messages (max {MAX_BATCH})."}), 413
    results = []
    for m in messages:
        r = MODEL.analyze(m)
        r["text"] = m
        save_result("batch", m, r)
        results.append(r)
    return jsonify({"count": len(results), "summary": summarize(results), "results": results})


@app.route("/api/history")
def history():
    with closing(db()) as con:
        rows = con.execute("SELECT * FROM history ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([row_to_dict(r) for r in rows])


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    with closing(db()) as con:
        con.execute("DELETE FROM history")
        con.commit()
    return jsonify({"cleared": True})


@app.route("/api/export")
def export_csv():
    with closing(db()) as con:
        rows = con.execute("SELECT * FROM history ORDER BY id DESC").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "time_utc", "type", "text", "verdict", "risk_percent", "user_feedback"])
    for r in rows:
        fb = {None: "", 1: "correct", 0: "incorrect"}[r["feedback"]]
        w.writerow([r["id"], r["ts"], r["kind"], csv_safe(r["text"]), r["verdict"], r["risk"], fb])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishing_history.csv"},
    )


@app.route("/api/feedback", methods=["POST"])
def feedback():
    data = request.get_json(silent=True) or {}
    rid, correct = data.get("id"), data.get("correct")
    if not isinstance(rid, int) or not isinstance(correct, bool):
        return jsonify({"error": "Provide integer 'id' and boolean 'correct'."}), 400
    with closing(db()) as con:
        cur = con.execute("UPDATE history SET feedback=? WHERE id=?", (int(correct), rid))
        con.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Result not found."}), 404
    return jsonify({"saved": True})


@app.route("/api/stats")
def stats():
    with closing(db()) as con:
        rows = con.execute("SELECT verdict, COUNT(*) c FROM history GROUP BY verdict").fetchall()
        fb = con.execute(
            "SELECT SUM(feedback) good, COUNT(feedback) total FROM history WHERE feedback IS NOT NULL"
        ).fetchone()
    counts = {r["verdict"]: r["c"] for r in rows}
    return jsonify({
        **METRICS,
        "dataset_size": len(TEXTS),
        "scam_count": sum(LABELS),
        "safe_count": len(LABELS) - sum(LABELS),
        "checked_count": sum(counts.values()),
        "verdict_counts": counts,
        "feedback_total": fb["total"] or 0,
        "feedback_correct": fb["good"] or 0,
    })


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Upload too large (max 1 MB)."}), 413


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
