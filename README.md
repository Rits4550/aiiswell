# Hospital Patient Portal — DoS Attack & ML-Based Detection

**Sector:** Hospital
**VAPT Topic 3:** Malware/Sniffing/Social Engineering/DoS/Session Hijacking/IDS Evasion
  → Technique chosen: **Denial of Service**
**AI Topic 6:** Machine Learning for Cyber Security
**Supporting:** VAPT Topic 1 (scope doc), VAPT Topic 6 (CVSS), AI Topic 7 (case study tie-in)

## Why DoS, for this topic, in this sector

Topic 3 covers many techniques; the guiding document asks you to pick ONE
and go deep rather than touch all of them shallowly. DoS was chosen because:
- It's directly realistic for a hospital: if a patient-records/monitoring
  system becomes unreachable during a shift, that's an immediate patient-
  safety issue, not just an inconvenience.
- It can be simulated completely safely against your own local app —
  no real infrastructure touched.
- It forces a genuinely different kind of ML detector than your earlier
  SQLi work: DoS isn't visible in any single request's content, only in
  the VOLUME/TIMING pattern across many requests. This is a good
  methodological point for your report — content-based vs rate-based
  detection are different problems.

## What this demonstrates

1. A real DoS flood launched against your own patched patient portal,
   with measured before/during/after impact: baseline response time
   ~2.8ms, climbing to ~100ms under load (measured directly, not assumed).
2. A labeled dataset of request-rate windows (normal vs attack), built
   from your own attack traffic.
3. A classifier trained on that data (94% accuracy on held-out data —
   intentionally not perfect; discuss the one false positive honestly).
4. A live monitor that reads the server's real request log in real time
   and flags "ATTACK DETECTED" the moment the flood starts, then drops
   back to "normal" the moment it stops.

## Files (new, for this topic)

| File | Purpose |
|---|---|
| `dos_attack.py` | Floods the portal, measures before/during/after response times |
| `generate_dos_traffic.py` | Builds labeled normal-vs-attack rate dataset from real traffic |
| `train_dos_model.py` | Trains the rate-based classifier, saves `dos_model.pkl` |
| `dos_monitor_demo.py` | **Live demo** — real-time monitor reading the server's own request log |

(Earlier SQLi files — `app_vulnerable.py`, `generate_traffic.py`,
`train_model.py`, `detector_demo.py` — are still here but are not part of
this topic's deliverable; see note at bottom if you want to keep both.)

## How to run it

### One-time setup
```bash
pip install flask scikit-learn pandas requests
python3 init_db.py          # if hospital.db doesn't already exist
```

### Build the rate dataset and train the detector (do this once, ahead of time)
```bash
# Terminal 1
python3 app_patched.py

# Terminal 2
python3 generate_dos_traffic.py
python3 train_dos_model.py
```

### Live demo (presentation day) — THREE terminals

**Terminal 1** — the target:
```bash
python3 app_patched.py
```

**Terminal 2** — leave ready, don't run yet:
```bash
python3 dos_attack.py
```

**Terminal 3** — start the live monitor first:
```bash
python3 dos_monitor_demo.py
```
It immediately starts printing `normal` once per second.

Now go to **Terminal 2** and run `dos_attack.py`. Watch Terminal 3 —
within a second or two it should flip to `ATTACK DETECTED` and hold
that verdict for the duration of the flood, then drop back to `normal`
once it ends. This is your live, real-time evidence.

### Optional: capture it in Wireshark too

Open Wireshark, select the **Loopback (lo)** interface, start capturing
before you launch `dos_attack.py`. You'll see a massive spike in TCP/HTTP
packets on port 5000 during the flood — use **Statistics → I/O Graph**
to show packet rate over time, which visually matches your monitor's
verdict timeline.

## Talking points for your write-up / defence

- **Before/after impact (your core evidence):** baseline avg response
  time ~2.8ms → ~99.9ms during flood (~35x slower) → recovers to ~2.3ms
  after. Quote these numbers directly; they're from an actual measured run.
- **Why rate-based, not content-based detection:** your earlier SQLi
  detector looked at what was INSIDE one request. This detector only
  looks at HOW MANY requests arrive per second — no single request in
  a DoS flood is individually suspicious. Say this explicitly; it's a
  genuine methodological distinction worth a paragraph in your report.
- **Honest limitation:** 94% accuracy, one false positive out of 16 test
  windows, on a small dataset from one flood pattern against a toy Flask
  dev server. State plainly this wouldn't generalize to a production
  load balancer or a more gradual, distributed (DDoS-style) attack
  without more data and a fuller feature set (e.g. per-source-IP rate,
  not just total rate).
- **IDS/firewall evasion (guiding question 3):** discuss how an attacker
  aware of a rate-based detector might evade it by spreading the flood
  across many source IPs (distributed) or pacing requests just under the
  detection threshold — and how this motivates combining rate-based
  detection with other signals (e.g. your earlier content-based detector)
  for defence in depth.
- **CVSS angle (VAPT Topic 6, light touch):** score availability impact —
  Attack Vector: Network, Attack Complexity: Low, Privileges Required:
  None, Confidentiality: None, Integrity: None, Availability: High.

## If you want to combine this with your earlier SQLi work

You can legitimately keep both as supporting material: lead your
presentation with the DoS story (this is your declared Topic 3
deliverable), and mention the SQLi work from Topic 4 as prior work this
semester if your instructor wants broader context — but don't present
both as equally weighted core deliverables unless agreed with your
instructor, given your team size.
