"""
app_vulnerable.py

A deliberately vulnerable mock hospital patient-portal web app.
Used ONLY against our own local database, for coursework demonstration
of SQL injection and subsequent remediation. Not connected to any real
system or real patient data.

Run:  python3 app_vulnerable.py
Then visit http://127.0.0.1:5000/search?q=Aarav
"""
from flask import Flask, request, jsonify
import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "hospital.db")
app = Flask(__name__)


def get_conn():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def home():
    return (
        "<h2>City Hospital Patient Portal (DEMO - VULNERABLE BUILD)</h2>"
        "<p>Search patients by name: <code>/search?q=Aarav</code></p>"
    )


@app.route("/search")
def search():
    """
    VULNERABLE: builds a raw SQL string directly from user input.
    This allows classic SQL injection, e.g.:
        /search?q=Aarav' OR '1'='1
        /search?q=' UNION SELECT username, password, role, role FROM users--
    """
    q = request.args.get("q", "")
    start = time.time()

    conn = get_conn()
    cur = conn.cursor()
    query = f"SELECT id, name, condition, doctor FROM patients WHERE name LIKE '%{q}%'"
    try:
        cur.execute(query)
        rows = cur.fetchall()
        error = None
    except Exception as e:
        rows = []
        error = str(e)
    conn.close()

    elapsed = time.time() - start
    return jsonify({
        "query_executed": query,
        "results": rows,
        "error": error,
        "response_time_ms": round(elapsed * 1000, 2)
    })


if __name__ == "__main__":
    app.run(port=5000, debug=False)
