# Wifi Auto Handshaker PMKID

An **autonomous, adaptive** WiFi security-auditing tool for Kali Linux that:

1. **Scans** nearby WiFi networks,
2. **Captures 4-way handshakes** (EAPOL) and **PMKIDs** using the full Kali toolchain,
3. **Strongly verifies** that *only* genuine 4-way handshakes are stored — anything
   else is rejected and deleted,
4. Performs **strategic deauthentication** using almost every Kali deauth engine,
5. **Learns and adapts** from measured success/failure — deterministically, with
   explicit anti-hallucination guarantees.

> **Capture only — no password hashing or cracking.** This tool captures and
> verifies handshakes/PMKIDs. It never runs a dictionary/brute-force attack and
> never computes password hashes.

---

## ⚠️ Legal & ethical notice — read first

Capturing WiFi handshakes/PMKIDs and performing deauthentication attacks against
networks you do **not** own or lack **explicit written permission** to test is
**illegal** in most jurisdictions (e.g. wiretap and computer-fraud statutes).

* You may use this tool **only** on networks you own, or that you are explicitly
  authorized to audit (penetration-testing engagement, bug-bounty scope, lab).
* You are solely responsible for lawful use. The authors provide this software
  for authorized security research and education only.

The tool enforces an interactive **authorization gate** on every autonomous run
and refuses to operate without it.

---

## Requirements

* **Python 3.12+** (the tool is written for 3.12; it also runs on 3.11).
* **Kali Linux** (or another Linux with the wireless toolchain installed).
* Root privileges (`sudo`).
* A wireless adapter that supports **monitor mode** and **packet injection**.

System tools (detected at runtime, none are "abandoned"):

| Purpose | Tools |
|---|---|
| Adapter / monitor mode | `airmon-ng`, `iw`, `iwconfig`, `rfkill` |
| Scanning | `airodump-ng`, `kismet`, `wash` |
| Handshake capture | `airodump-ng`, `hcxdumptool`, `wifite`/`wifite2` |
| Deauthentication | `aireplay-ng`, `mdk4`, `bettercap`, `hcxdumptool` (mode 3) |
| **Verification** | `tshark` (Wireshark), `aircrack-ng`, `hcxpcapngtool`, `cowpatty`, `pyrit` |
| PMKID | `hcxdumptool`, `hcxpcapngtool`, `hcxlabtool`, `hcxpsktool` |
| Analysis | `wireshark` (GUI), `tshark`, `capinfos` |

Install the core suite on Kali/Debian:

```bash
sudo apt update
sudo apt install -y aircrack-ng hcxtools tshark mdk4 bettercap \
                    python3-pip python3-venv
```

Install Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# optional: .venv/bin/pip install scapy   (independent parser fallback)
```

---

## Quick start

```bash
# 1) See which tools are installed / missing
sudo .venv/bin/python -m handshaker tools

# 2) Fully autonomous run: scan -> prioritize -> deauth -> capture -> verify -> learn
sudo .venv/bin/python -m handshaker -i wlan0 capture

# 3) Just scan for nearby APs
sudo .venv/bin/python -m handshaker -i wlan0 scan --duration 15

# 4) Manually verify an existing capture is a genuine 4-way handshake
.venv/bin/python -m handshaker verify data/captures/some.pcapng

# 5) Adapter management (monitor mode / injection test / reset)
sudo .venv/bin/python -m handshaker -i wlan0 adapter

# 6) PMKID capture / conversion
sudo .venv/bin/python -m handshaker pmkid --bssid AA:BB:CC:DD:EE:FF --channel 6
.venv/bin/python -m handshaker pmkid --convert data/captures/some.pcapng
```

After an install (`pip install .`), the `handshaker` console script is also
available.

---

## How verification works (the integrity core)

The centerpiece is `handshaker/core/verifier.py`. It answers one question with
certainty: *"Is this capture a genuine, complete 4-way EAPOL handshake?"*

Verification is **deterministic and multi-tool**, and its design makes
hallucination structurally impossible:

1. **tshark (Wireshark) is the ground truth.** Every EAPOL-Key frame is read and
   classified M1–M4 from the fields Wireshark itself decoded — the `key_ack` /
   `install` flags and the MIC / nonce contents — **not** from any re-implemented
   bit arithmetic that could drift out of sync.
2. **aircrack-ng** independently reports `WPA handshake: <bssid>`.
3. **hcxpcapngtool** independently counts EAPOL pairs.
4. **cowpatty / pyrit** (when present) add further independent checks.

Classification of the 4-way handshake (IEEE 802.11-2020 §12.7.6.2):

| Msg | Direction | Key ACK | Install | Key MIC | Nonce |
|-----|-----------|:-------:|:-------:|:-------:|:-----:|
| M1  | AP → STA  |   ✓     |         |         | ANonce |
| M2  | STA → AP  |         |         |   ✓     | SNonce |
| M3  | AP → STA  |   ✓     |   ✓     |   ✓     | ANonce |
| M4  | STA → AP  |         |         |   ✓     |  —    |

**Retention policy (default `verify.require_full_handshake: true`):**

* A capture **passes** only if **all four messages** (M1, M2, M3, M4) are present,
  MICs and nonces are present, and **no** configured, available tool contradicts it.
* If `require_full_handshake: false`, a crackable **M2 + M3** pair is the minimum.
* Everything else is **rejected and deleted** (optionally quarantined first), with
  a truthful reason recorded.

The verdict is the **intersection** of the configured detectors. A tool that is
*unavailable* is reported truthfully and degrades gracefully — it is never
silently assumed to pass.

---

## How the learning / adaptation works (no hallucinations)

`handshaker/learning/` implements a **deterministic epsilon-greedy bandit** over
deauth actions (tool × burst size × reason code):

* **Only measured outcomes are recorded.** An "action" is only ever stored after
  the verifier decides whether a handshake was actually captured. There is no
  score stored — success rates are recomputed from raw, **time-decayed**
  observations on every call.
* **Honest uncertainty.** Until `learning.min_observations` weighted trials exist,
  the policy stays near-uniform (exploration) rather than trusting a single lucky
  run.
* **No invented actions.** The policy only ever selects from actions that (a) have
  been tried, or (b) are the bounded exploration pick — and only among actions the
  *installed* toolset can actually perform (`tools` registry, never assumed).

The same discipline applies to the optional **NVIDIA NIM** integration
(`handshaker/nim/`):

* NIM is **optional and off by default** — the tool is fully independent.
* NIM only *suggests* strategy parameters (tool, burst size, dwell). Its output is
  validated against a strict schema and clamped to what the toolset can do.
* NIM is **never** consulted for verification, and it is given only measured scan
  facts. Any suggestion is treated as an untrusted hint.

Anti-hallucination principles baked into the code:

1. **Facts vs. decisions are separated.** BSSIDs, channels, clients, signals come
   from the live scan; decisions are made from those facts.
2. **"I don't know" is a valid answer.** Parsers return `None` on garbage instead
   of guessing (`utils/validation.py`).
3. **Verification is independent of strategy/AI** and always deterministic.
4. **Failures are recorded truthfully**, never masked or retconned.

---

## Project layout

```
handshaker/
├── cli.py                 # subcommands: adapter, scan, capture, pmkid, verify, tools
├── config.py              # strict, validated YAML config loading
├── constants.py           # single source of truth for names/paths/codes
├── core/
│   ├── adapter.py         # monitor mode on/off/reset, injection test
│   ├── scanner.py         # airodump-ng scan + strict CSV parsing
│   ├── capturer.py        # background capture sessions (airodump / hcxdumptool)
│   ├── verifier.py        # ★ strong 4-way handshake verification
│   ├── deauth.py          # strategic deauth executor (aireplay/mdk4/bettercap)
│   ├── pmkid.py           # PMKID capture & 22000 conversion
│   ├── analyzer.py        # tshark-based target behavior analysis
│   ├── strategist.py      # target prioritization + action selection
│   └── engine.py          # autonomous loop + authorization gate
├── tools/                 # thin wrappers for every Kali tool
├── learning/              # deterministic bandit + persistent state
├── nim/                   # optional NVIDIA NIM client (strict validation)
└── utils/                 # process runner, logging, parsers/validators
config/config.yaml         # configuration
data/
├── captures/              # raw captures (gitignored)
├── handshakes/            # ★ verified 4-way handshakes only
├── pmkid/                 # PMKID / 22000 output
├── quarantine/            # rejected captures (transient)
└── learning/              # adaptive state
```

---

## Configuration

Edit `config/config.yaml`. Highlights:

* `verify.require_full_handshake` — strict M1–M4 requirement (default `true`).
* `verify.delete_on_fail` — delete anything that isn't a 4-way handshake.
* `deauth.tools` — which deauth engines to use (`aireplay-ng`, `mdk4`, `bettercap`).
* `pmkid.enabled` — whether to also capture PMKIDs.
* `learning.*` — exploration rate, decay, minimum observations.
* `nim.enabled` — optional NVIDIA NIM strategy hints (default `false`).
* `targets.*` — explicit BSSID/ESSID/channel allow-lists and exclusions.

Unknown config keys and out-of-range values are rejected at load time (fail fast,
no silent clamping).

---

## Tests

```bash
.venv/bin/python -m pytest -q
```

The test suite proves the anti-hallucination properties of the verifier and the
policy layer without requiring Kali tools or root.

---

## Disclaimer

This software is provided for authorized security testing and education only.
The authors disclaim all responsibility for unlawful use.
