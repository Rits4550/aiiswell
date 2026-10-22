"""
init_db.py
Creates a small SQLite database simulating a hospital patient records
table. All data here is entirely fake / synthetic, for lab use only.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "hospital.db")

def init():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE patients (
            id INTEGER PRIMARY KEY,
            name TEXT,
            dob TEXT,
            condition TEXT,
            doctor TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE users (
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    fake_patients = [
        (1, "Aarav Sharma", "1990-01-12", "Hypertension", "Dr. Mehta"),
        (2, "Priya Nair", "1985-03-22", "Diabetes Type II", "Dr. Rao"),
        (3, "Rohan Gupta", "1978-11-02", "Asthma", "Dr. Iyer"),
        (4, "Sana Khan", "1995-07-19", "Fracture - left arm", "Dr. Mehta"),
        (5, "Vikram Singh", "1982-05-30", "Post-op recovery", "Dr. Verma"),
    ]
    cur.executemany(
        "INSERT INTO patients (id, name, dob, condition, doctor) VALUES (?, ?, ?, ?, ?)",
        fake_patients
    )

    fake_users = [
        ("nurse_joy", "pass123", "staff"),
        ("admin", "hospitalAdmin!2024", "admin"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        fake_users
    )

    conn.commit()
    conn.close()
    print(f"Database initialised at {DB_PATH}")

if __name__ == "__main__":
    init()
