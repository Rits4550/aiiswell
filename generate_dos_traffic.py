"""
generate_dos_traffic.py

Builds a labeled dataset of REQUEST-RATE windows (not individual request
content, unlike generate_traffic.py for SQLi) -- because a DoS attack
isn't visible in any single request, only in the volume/timing pattern
across many requests. This is the AI-side bridge for the DoS topic.

Produces dos_traffic_log.csv: one row per 1-second window, with the
request count in that window and a normal/attack label.
"""
import requests
import threading
import time
import csv
import os

BASE_URL = "http://127.0.0.1:5000/search"
OUT_PATH = os.path.join(os.path.dirname(__file__), "dos_traffic_log.csv")

WINDOW_SEC = 1.0
NORMAL_PHASE_SEC = 30     # legitimate, low-rate traffic
ATTACK_PHASE_SEC = 20     # flood traffic
NORMAL_REQUEST_INTERVAL = 0.8   # one legit request roughly every 0.8s
NUM_ATTACK_THREADS = 50

request_log = []          # (timestamp,) for every request actually sent
log_lock = threading.Lock()
stop_flag = threading.Event()


def send_request(q):
    try:
        requests.get(BASE_URL, params={"q": q}, timeout=2)
    except Exception:
        pass
    with log_lock:
        request_log.append(time.time())


def normal_traffic_generator(duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        send_request("Aarav")
        time.sleep(NORMAL_REQUEST_INTERVAL)


def attacker_thread():
    while not stop_flag.is_set():
        send_request("flood")


def bucket_into_windows(timestamps, phase_start, phase_end, label):
    """Splits [phase_start, phase_end) into WINDOW_SEC buckets and counts requests in each."""
    rows = []
    t = phase_start
    while t < phase_end:
        window_end = t + WINDOW_SEC
        count = sum(1 for ts in timestamps if t <= ts < window_end)
        rows.append({"requests_per_window": count, "label": label})
        t = window_end
    return rows


def main():
    print("Phase 1: generating NORMAL traffic...")
    phase1_start = time.time()
    normal_traffic_generator(NORMAL_PHASE_SEC)
    phase1_end = time.time()

    print("Phase 2: launching DOS FLOOD...")
    phase2_start = time.time()
    threads = [threading.Thread(target=attacker_thread) for _ in range(NUM_ATTACK_THREADS)]
    for t in threads:
        t.start()
    time.sleep(ATTACK_PHASE_SEC)
    stop_flag.set()
    for t in threads:
        t.join()
    phase2_end = time.time()

    normal_rows = bucket_into_windows(request_log, phase1_start, phase1_end, "normal")
    attack_rows = bucket_into_windows(request_log, phase2_start, phase2_end, "attack")
    all_rows = normal_rows + attack_rows

    with open(OUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["requests_per_window", "label"])
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nLogged {len(all_rows)} one-second windows to {OUT_PATH}")
    print(f"  Normal windows : {len(normal_rows)}  (avg {sum(r['requests_per_window'] for r in normal_rows)/len(normal_rows):.1f} req/s)")
    print(f"  Attack windows : {len(attack_rows)}  (avg {sum(r['requests_per_window'] for r in attack_rows)/len(attack_rows):.1f} req/s)")


if __name__ == "__main__":
    main()
