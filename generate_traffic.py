"""
generate_traffic.py

Fires a mix of benign and malicious (SQL-injection-style) requests at the
patient portal's /search endpoint, and logs each request's extracted
features + its true label into traffic_log.csv.

This is the bridge between the VAPT side (attack traffic) and the AI side
(training data for the ML detector).

Run this AFTER starting app_vulnerable.py in another terminal:
    python3 app_vulnerable.py
    python3 generate_traffic.py
"""
import requests
import random
import string
import csv
import re
import os

BASE_URL = "http://127.0.0.1:5000/search"
OUT_PATH = os.path.join(os.path.dirname(__file__), "traffic_log.csv")

# --- benign query generator -------------------------------------------------
FIRST_NAMES = ["Aarav", "Priya", "Rohan", "Sana", "Vikram", "Anjali", "Karan",
               "Meera", "Dev", "Neha", "Arjun", "Ishita", "Kabir", "Tara"]

def random_benign_query():
    """Looks like a real staff member searching for a patient."""
    choice = random.random()
    if choice < 0.6:
        return random.choice(FIRST_NAMES)
    elif choice < 0.85:
        # partial name search
        name = random.choice(FIRST_NAMES)
        return name[:random.randint(2, len(name))]
    else:
        # empty-ish / short search
        return random.choice(["a", "e", "", "Dr", "ar"])

# --- malicious query generator ----------------------------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "admin'--",
    "' UNION SELECT username, password, role, role FROM users--",
    "' UNION SELECT 1,2,3,4--",
    "'; DROP TABLE patients;--",
    "' AND SLEEP(2)--",
    "' OR '1'='1' LIMIT 1--",
    "\" OR \"1\"=\"1",
    "' OR ''='",
    "1' OR '1'='1",
]

def random_malicious_query():
    return random.choice(SQLI_PAYLOADS)

# --- feature extraction ------------------------------------------------------
SQL_KEYWORDS = re.compile(
    r"(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bSLEEP\b|--|;|'=|=')",
    re.IGNORECASE
)
SPECIAL_CHARS = set("'\";-=#()")

def extract_features(q):
    return {
        "length": len(q),
        "num_quotes": q.count("'") + q.count('"'),
        "num_special_chars": sum(1 for c in q if c in SPECIAL_CHARS),
        "has_sql_keyword": 1 if SQL_KEYWORDS.search(q) else 0,
        "num_spaces": q.count(" "),
        "has_comment_marker": 1 if "--" in q or "#" in q else 0,
        "digit_ratio": (sum(c.isdigit() for c in q) / len(q)) if len(q) > 0 else 0,
    }

def main(n_benign=300, n_malicious=150):
    rows = []

    for _ in range(n_benign):
        q = random_benign_query()
        try:
            r = requests.get(BASE_URL, params={"q": q}, timeout=3)
            resp_time = r.json().get("response_time_ms", None)
            error = r.json().get("error", None)
        except Exception:
            resp_time, error = None, "request_failed"
        feats = extract_features(q)
        feats.update({
            "query_text": q,
            "response_time_ms": resp_time,
            "had_error": 1 if error else 0,
            "label": "benign"
        })
        rows.append(feats)

    for _ in range(n_malicious):
        q = random_malicious_query()
        try:
            r = requests.get(BASE_URL, params={"q": q}, timeout=3)
            resp_time = r.json().get("response_time_ms", None)
            error = r.json().get("error", None)
        except Exception:
            resp_time, error = None, "request_failed"
        feats = extract_features(q)
        feats.update({
            "query_text": q,
            "response_time_ms": resp_time,
            "had_error": 1 if error else 0,
            "label": "malicious"
        })
        rows.append(feats)

    random.shuffle(rows)

    fieldnames = ["query_text", "length", "num_quotes", "num_special_chars",
                  "has_sql_keyword", "num_spaces", "has_comment_marker",
                  "digit_ratio", "response_time_ms", "had_error", "label"]

    with open(OUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Logged {len(rows)} requests ({n_benign} benign, {n_malicious} malicious) to {OUT_PATH}")

if __name__ == "__main__":
    main()
