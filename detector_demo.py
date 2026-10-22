"""
detector_demo.py

LIVE DEMO SCRIPT for presentation.

Loads the trained model, then lets you type in (or script) new search
queries exactly as a user would submit them to the patient portal, and
shows in real time whether the model flags each one as malicious.

This is meant to be run WHILE app_vulnerable.py (or app_patched.py) is
running, so you can show:
  1. A normal staff search  -> classified benign, works normally.
  2. The SQL injection payload -> classified malicious BY THE MODEL,
     at the same moment it would actually succeed against the vulnerable app.
  3. Switch to app_patched.py -> same payload still correctly flagged by
     the model AND now also fails against the app itself (defence in depth).

Run:
    python3 detector_demo.py
"""
import pickle
import os
import requests
import re

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
BASE_URL = "http://127.0.0.1:5000/search"

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

def load_model():
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    return bundle["model"], bundle["features"]

def classify(model, feature_order, query_text):
    import pandas as pd
    feats = extract_features(query_text)
    X = pd.DataFrame([[feats[f] for f in feature_order]], columns=feature_order)
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0][1]  # probability of "malicious"
    return ("MALICIOUS" if pred == 1 else "benign"), prob

def run_against_app(query_text):
    """Actually sends the query to the running patient-portal app too,
    so you can show the detector's verdict side-by-side with what the
    app itself does with the same input."""
    try:
        r = requests.get(BASE_URL, params={"q": query_text}, timeout=3)
        return r.json()
    except Exception as e:
        return {"error": f"could not reach app ({e})"}

def demo_query(model, feature_order, query_text, label=""):
    verdict, prob = classify(model, feature_order, query_text)
    app_result = run_against_app(query_text)
    print(f"\n{'='*70}")
    if label:
        print(f"[{label}]")
    print(f"Query submitted      : {query_text!r}")
    print(f"ML DETECTOR VERDICT   : {verdict}  (malicious probability: {prob:.3f})")
    print(f"App response (rows)   : {len(app_result.get('results', []))} record(s) returned")
    print(f"App executed SQL      : {app_result.get('query_executed', 'n/a')}")
    print(f"{'='*70}")

if __name__ == "__main__":
    model, feature_order = load_model()

    print("Hospital Patient Portal - Live Request Detector")
    print("Make sure app_vulnerable.py or app_patched.py is running on port 5000.\n")

    # ---- scripted demo sequence (edit / present this live) ----
    demo_query(model, feature_order, "Aarav", label="Normal staff search")
    demo_query(model, feature_order, "' OR '1'='1", label="SQL injection attempt - dump all patients")
    demo_query(model, feature_order, "' UNION SELECT username, password, role, role FROM users--",
               label="SQL injection attempt - steal staff credentials")
    demo_query(model, feature_order, "Priya", label="Another normal staff search")

    # ---- optional: interactive mode ----
    print("\nType your own queries to test the detector (or 'quit' to exit):")
    while True:
        try:
            q = input("\nquery> ")
        except EOFError:
            break
        if q.strip().lower() in ("quit", "exit"):
            break
        demo_query(model, feature_order, q)
