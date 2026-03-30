# CRT Fault Leak in RSA

A Python demo and interactive GUI that simulates the **Bellcore fault attack** on RSA-CRT signatures — showing how a single injected fault during signing leaks a private key factor, and how a verification-based countermeasure defeats it.

> Built by Akash Manoj, Sai Aravind and Akhilesh Deshmukh


---

## What is the Bellcore Attack?

RSA implementations often use the **Chinese Remainder Theorem (CRT)** to speed up signing by computing partial signatures modulo `p` and `q` separately. If an attacker can induce a hardware or software fault in one of those branches (e.g. via voltage glitching), the resulting faulty signature leaks a prime factor of `n`:

```
g = gcd(|s - s_faulty|, n)  →  recovers p or q
```

With one prime factor recovered, the private key `d` can be recomputed entirely.

---

## Project Structure

```
crypto-project/
├── app.py          # Tkinter GUI — main entry point
├── attack.py       # Fault injection logic and trial runner
├── rsa.py          # RSA key generation, CRT signing, verification
├── graphs.py       # Matplotlib visualizations
├── utils.py        # Prime generation (Miller-Rabin), modular arithmetic
└── main.py         # Demo
```

---

## Features

- **RSA Key Generation** — 1024-bit and 2048-bit keys using probabilistic primality testing (Miller-Rabin, 40 rounds)
- **Vulnerable Mode** — simulates the Bellcore attack with configurable fault injection rate; recovers `p` or `q` via GCD
- **Secure Mode** — applies the verify-then-recompute mitigation; faulty outputs are rejected before they can leak
- **Live Attack Pipeline** — step-by-step trace of each trial (message, correct signature, faulty signature, GCD result)
- **Trial Table** — per-trial results: branch faulted, GCD bit length, success/fail, integrity status, attempt count
- **Graphs** — 4 plots comparing vulnerable vs secure across success rate, latency overhead, confidentiality/integrity, and key-size benchmarks

---

## Installation

**Requirements:** Python 3.10+

```bash
pip install matplotlib
```

No other third-party packages needed — the project uses only `tkinter`, `secrets`, `math`, and `matplotlib`.

---

## Running

### GUI
```bash
python main.py
```

---

## How to Use the GUI

1. **Select key size** (1024 or 2048 bits) and click **Generate Keys / Parameters**
   - Key details panel shows `p`, `q`, `n`, `d`, `dp`, `dq`, `qinv` with bit lengths
2. Click **Run Attack** to simulate the vulnerable CRT signer over 25 trials
   - The Live Attack Pipeline shows the step-by-step GCD recovery for Trial 1
   - Trial Table records each trial's outcome
3. Click **Apply Prevention** to rerun with the secure signer (verify + fallback to full exponentiation)
   - Attack success rate should drop to ~0%
4. Click **Show Graphs** (after running both modes) to benchmark key sizes and plot comparisons

---

## Attack vs. Mitigation Summary

| | Vulnerable | Secure |
|---|---|---|
| Signing method | Raw CRT, no check | CRT + verify; fallback to `m^d mod n` |
| Fault leaked? | Yes — faulty `s` returned | No — rejected before output |
| Attack success | ~90–100% | ~0% |
| Latency overhead | Baseline | Small (one extra modexp on failure) |

---

## Key Modules

### `rsa.py`
- `generate_keypair(bits)` — generates `(PrivateKey, PublicKey)`
- `rsa_sign_crt(m, priv)` — fast CRT-based signing
- `rsa_sign_full(m, priv)` — full `m^d mod n` fallback
- `secure_sign(m, priv, pub)` — verify-then-recompute wrapper
- `rsa_verify(m, s, pub)` — checks `s^e mod n == m`

### `attack.py`
- `inject_fault(value, modulus)` — randomly perturbs `sp` or `sq`
- `run_trials(num_trials, key_bits, mode, ...)` — runs the full experiment; returns success rate, timing stats, and per-trial records
- `benchmark_key_sizes()` — times keygen and signing at 1024 and 2048 bits

### `utils.py`
- `is_probable_prime(n, rounds=40)` — Miller-Rabin primality test
- `generate_prime(bits)` — cryptographically random prime via `secrets`
- `modinv(a, m)` — modular inverse via extended Euclidean algorithm

---

## References

- Boneh, DeMillo, Lipton — *"On the Importance of Checking Computations"* (1997)
- RSA PKCS#1 v2.2 specification
- NIST SP 800-131A — key size recommendations
