"""
dos_monitor_demo.py

LIVE DEMO: reads the patient portal's own request log (dos_requests.log,
one timestamp per request, written by app_patched.py) in real time,
counts requests per 1-second window, and classifies each window as
normal or attack using the model trained in train_dos_model.py.

In a real deployment this would read firewall/webserver access logs or
NetFlow data directly -- here it reads the app's own request log, which
keeps the demo self-contained.

Run in a THIRD terminal, with these already running:
  Terminal 1: python3 app_patched.py
  Terminal 2: python3 dos_attack.py   (start the flood when ready)
  Terminal 3: python3 dos_monitor_demo.py   (this script)
"""
import pickle
import os
import time
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(__file__), "dos_model.pkl")
LOG_PATH = os.path.join(os.path.dirname(__file__), "dos_requests.log")


def load_model():
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)["model"]


def read_all_timestamps():
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH) as f:
        return [float(line.strip()) for line in f if line.strip()]


def monitor_loop(duration_sec=60):
    model = load_model()

    print("Live DoS monitor running -- watching real request timestamps.\n")
    print(f"{'time':>6} | {'requests/s':>10} | verdict")
    print("-" * 40)

    t_start = time.time()
    while time.time() - t_start < duration_sec:
        window_start = time.time()
        time.sleep(1.0)
        window_end = time.time()

        all_ts = read_all_timestamps()
        window_count = sum(1 for ts in all_ts if window_start <= ts < window_end)

        X = pd.DataFrame([[window_count]], columns=["requests_per_window"])
        pred = model.predict(X)[0]
        verdict = "ATTACK DETECTED" if pred == 1 else "normal"

        elapsed = window_end - t_start
        print(f"{elapsed:6.1f}s | {window_count:>10} | {verdict}")


if __name__ == "__main__":
    # clear old log so the demo starts clean
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    monitor_loop(duration_sec=40)
