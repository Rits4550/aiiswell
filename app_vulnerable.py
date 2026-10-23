"""
import os
import sqlite3
from functools import wraps
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Separate database for the vulnerable demonstration.
DB_PATH = os.path.join(BASE_DIR, "hospital_vulnerable.db")

app = Flask(__name__)
app.secret_key = os.environ.get(
    "HOSPITAL_SECRET_KEY",
    "local-vulnerable-demo-key-change-me"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def audit_event(username, action, target="", outcome="success"):
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO audit_logs
            (timestamp, username, action, target, outcome,
             source_ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(timespec="seconds"),
                username or "anonymous",
                action,
                str(target)[:150],
                outcome,
                request.remote_addr or "unknown",
                request.headers.get("User-Agent", "")[:250]
            )
        )
        conn.commit()
    finally:
        conn.close()


def initialise_database():
    conn = get_db()

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            dob TEXT NOT NULL,
            condition TEXT NOT NULL,
            doctor TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            outcome TEXT NOT NULL,
            source_ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            detection_type TEXT NOT NULL,
            details TEXT NOT NULL,
            prediction TEXT NOT NULL
        );
    """)

    demo_users = [
        ("admin", "AdminDemo!2026", "admin"),
        ("doctor1", "DoctorDemo!2026", "doctor"),
        ("nurse1", "NurseDemo!2026", "nurse"),
    ]

    for username, password, role in demo_users:
        conn.execute(
            """
            INSERT OR IGNORE INTO users
            (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, generate_password_hash(password), role)
        )

    demo_patients = [
        (1, "Aarav Sharma", "1990-01-12",
         "Hypertension", "Dr. Mehta"),
        (2, "Priya Nair", "1985-03-22",
         "Diabetes Type II", "Dr. Rao"),
        (3, "Rohan Gupta", "1978-11-02",
         "Asthma", "Dr. Iyer"),
        (4, "Sana Khan", "1995-07-19",
         "Arm fracture", "Dr. Mehta"),
        (5, "Vikram Singh", "1982-05-30",
         "Post-operative recovery", "Dr. Verma"),
    ]

    for patient in demo_patients:
        conn.execute(
            """
            INSERT OR IGNORE INTO patients
            (id, name, dob, condition, doctor)
            VALUES (?, ?, ?, ?, ?)
            """,
            patient
        )

    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("username"):
                flash("Please sign in to continue.", "error")
                return redirect(url_for("login"))

            if session.get("role") not in roles:
                audit_event(
                    session["username"],
                    "permission_denied",
                    request.path,
                    "denied"
                )
                abort(403)

            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/")
def home():
    if session.get("username"):
        return redirect(url_for("portal"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    user = conn.execute(
        """
        SELECT username, password_hash, role
        FROM users WHERE username = ?
        """,
        (username,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["username"] = user["username"]
        session["role"] = user["role"]

        audit_event(username, "login", "staff portal", "success")
        flash("Welcome back.", "success")
        return redirect(url_for("portal"))

    audit_event(username or "anonymous", "login", "staff portal", "failure")
    flash("Login failed. Check your username and password.", "error")
    return render_template("login.html"), 401


@app.route("/logout")
@login_required
def logout():
    username = session["username"]
    audit_event(username, "logout", "staff portal")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/portal")
@login_required
@roles_required("doctor", "nurse", "admin")
def portal():
    query = request.args.get("q", "").strip()
    conn = get_db()

    if query:
        # INTENTIONALLY VULNERABLE FOR LOCAL COURSEWORK:
        # user input is directly inserted into the SQL statement.
        sql = (
            "SELECT id, name, condition, doctor FROM patients "
            f"WHERE name LIKE '%{query}%' ORDER BY name"
        )
        try:
            patients = conn.execute(sql).fetchall()
        except sqlite3.Error:
            conn.close()
            audit_event(
                session["username"], "patient_search",
                query, "sql_error"
            )
            flash("The search could not be completed.", "error")
            return render_template(
                "portal.html", patients=[], query=query
            ), 400
    else:
        patients = conn.execute(
            """
            SELECT id, name, condition, doctor
            FROM patients ORDER BY name
            """
        ).fetchall()

    conn.close()
    audit_event(
        session["username"],
        "patient_search" if query else "patient_directory_view",
        query or "all records"
    )

    return render_template("portal.html", patients=patients, query=query)


@app.route("/search")
@login_required
@roles_required("doctor", "nurse", "admin")
def search():
    query = request.args.get("q", "").strip()
    conn = get_db()

    # Same intentional SQL injection flaw for the demo.
    sql = (
        "SELECT id, name, condition, doctor FROM patients "
        f"WHERE name LIKE '%{query}%' ORDER BY name"
    )

    try:
        patients = conn.execute(sql).fetchall()
    except sqlite3.Error:
        conn.close()
        audit_event(
            session["username"], "patient_search",
            query, "sql_error"
        )
        flash("The search could not be completed.", "error")
        return render_template(
            "results.html", patients=[], query=query
        ), 400

    conn.close()
    audit_event(session["username"], "patient_search", query or "(empty)")

    return render_template(
        "results.html", patients=patients, query=query
    )


@app.route("/patient/<int:patient_id>")
@login_required
@roles_required("doctor", "nurse", "admin")
def patient_detail(patient_id):
    conn = get_db()

    # Parameterized lookup; this route is not intentionally vulnerable.
    patient = conn.execute(
        """
        SELECT id, name, condition, doctor
        FROM patients WHERE id = ?
        """,
        (patient_id,)
    ).fetchone()

    conn.close()

    if not patient:
        abort(404)

    audit_event(
        session["username"], "patient_record_view", patient_id
    )
    return render_template(
        "results.html", patients=[patient], query=patient["name"]
    )


@app.route("/dashboard")
@login_required
@roles_required("admin")
def dashboard():
    conn = get_db()

    audit_logs = conn.execute(
        """
        SELECT timestamp, username, action, target, outcome,
               source_ip, user_agent
        FROM audit_logs ORDER BY id DESC LIMIT 100
        """
    ).fetchall()

    alerts = conn.execute(
        """
        SELECT timestamp, detection_type, details, prediction
        FROM security_alerts ORDER BY id DESC LIMIT 100
        """
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        audit_logs=audit_logs,
        alerts=alerts
    )


if __name__ == "__main__":
    initialise_database()
    print("Vulnerable hospital portal starting (local demo only).")
    print("Open http://127.0.0.1:5000/")
    app.run(host="0.0.0.0", port=5000, debug=False)
