
from __future__ import annotations

from dataclasses import dataclass
import math
import secrets
import time
from typing import Callable, cast

from rsa import (
    PrivateKey,
    PublicKey,
    generate_keypair,
    rsa_sign_crt,
    rsa_verify,
    secure_sign,
)
from utils import time_call


DEFAULT_TRIALS = 25


@dataclass
class TrialRecord:
    trial_index: int
    success: bool
    integrity_ok: bool
    fault_branch: str
    fault_applied: bool
    gcd_bits: int
    attack_time: float
    oracle_time: float
    attempts_used: int


def random_message(n: int) -> int:
    return secrets.randbelow(n - 3) + 2


def inject_fault(value: int, modulus: int, fault_rate: float = 0.9) -> tuple[int, bool]:
    if fault_rate <= 0:
        return value, False

    threshold = int(fault_rate * 1_000_000)
    if secrets.randbelow(1_000_000) >= threshold:
        return value, False

    delta = secrets.randbelow(modulus - 1) + 1
    return (value + delta) % modulus, True


def crt_recombine(sp: int, sq: int, priv: PrivateKey) -> tuple[int, int]:
    h = (priv.qinv * (sp - sq)) % priv.p
    s = sq + h * priv.q
    return h, s


def crt_faulty_from_components(
    sp: int,
    sq: int,
    priv: PrivateKey,
    fault_branch: str | None = None,
    fault_rate: float = 0.9,
) -> dict:
    if fault_branch is None:
        fault_branch = "p" if secrets.randbelow(2) == 0 else "q"

    sp_fault = sp
    sq_fault = sq
    fault_applied = False
    if fault_branch == "p":
        sp_fault, fault_applied = inject_fault(sp, priv.p, fault_rate=fault_rate)
    else:
        sq_fault, fault_applied = inject_fault(sq, priv.q, fault_rate=fault_rate)

    h_fault, s_faulty = crt_recombine(sp_fault, sq_fault, priv)
    return {
        "fault_branch": fault_branch,
        "fault_applied": fault_applied,
        "sp": sp,
        "sq": sq,
        "sp_fault": sp_fault,
        "sq_fault": sq_fault,
        "h_fault": h_fault,
        "s_faulty": s_faulty,
    }


def rsa_sign_crt_faulty(
    m: int,
    priv: PrivateKey,
    fault_branch: str | None = None,
    fault_rate: float = 0.9,
) -> tuple[int, str, bool]:
    sp = pow(m, priv.dp, priv.p)
    sq = pow(m, priv.dq, priv.q)

    if fault_branch is None:
        fault_branch = "p" if secrets.randbelow(2) == 0 else "q"

    fault_applied = False
    if fault_branch == "p":
        sp, fault_applied = inject_fault(sp, priv.p, fault_rate=fault_rate)
    else:
        sq, fault_applied = inject_fault(sq, priv.q, fault_rate=fault_rate)

    h = (priv.qinv * (sp - sq)) % priv.p
    s = sq + h * priv.q
    return s, fault_branch, fault_applied


def run_trials(
    num_trials: int,
    key_bits: int,
    mode: str,
    priv: PrivateKey | None = None,
    pub: PublicKey | None = None,
    reuse_key: bool = True,
    fault_rate: float = 0.95,
    max_fault_tries: int = 5,
    progress_hook: Callable[[str], None] | None = None,
    trial_hook: Callable[[TrialRecord], None] | None = None,
    pipeline_hook: Callable[[dict], None] | None = None,
    detail_first: bool = True,
) -> dict:
    if mode not in ("vulnerable", "secure"):
        raise ValueError("mode must be 'vulnerable' or 'secure'")

    records: list[TrialRecord] = []
    successes = 0
    integrity_ok = 0
    oracle_times: list[float] = []
    attack_times: list[float] = []

    keygen_time = 0.0
    if priv is None or pub is None:
        (priv, pub), keygen_time = time_call(generate_keypair, key_bits)

    for i in range(1, num_trials + 1):
        if not reuse_key and i > 1:
            (priv, pub), keygen_time = time_call(generate_keypair, key_bits)

        m = random_message(pub.n)

        sp = pow(m, priv.dp, priv.p)
        sq = pow(m, priv.dq, priv.q)
        h_correct, s_correct = crt_recombine(sp, sq, priv)

        trial_start = time.perf_counter()
        trial_success = False
        trial_integrity = False
        trial_branch = "p"
        trial_fault_applied = False
        trial_gcd_bits = 0
        attempts_used = 0

        if mode == "vulnerable":
            sf = s_correct
            g = 0
            branch = "p"
            fault_applied = False
            last_detail = None
            for attempt in range(1, max_fault_tries + 1):
                attempts_used = attempt
                oracle_start = time.perf_counter()
                detail = crt_faulty_from_components(
                    sp,
                    sq,
                    priv,
                    fault_branch=None,
                    fault_rate=fault_rate,
                )
                sf = detail["s_faulty"]
                branch = detail["fault_branch"]
                fault_applied = detail["fault_applied"]
                oracle_time = time.perf_counter() - oracle_start
                oracle_times.append(oracle_time)

                g = math.gcd(abs(s_correct - sf), pub.n)
                if 1 < g < pub.n and pub.n % g == 0:
                    trial_success = True
                    trial_branch = branch
                    trial_fault_applied = fault_applied
                    trial_gcd_bits = g.bit_length()
                    trial_integrity = rsa_verify(m, sf, pub)
                    last_detail = detail
                    break
                last_detail = detail

            if not trial_success:
                trial_branch = branch
                trial_fault_applied = fault_applied
                trial_gcd_bits = g.bit_length() if g > 0 else 0
                trial_integrity = rsa_verify(m, sf, pub)

            if detail_first and i == 1 and progress_hook is not None and last_detail is not None:
                progress_hook("---- Step-by-step demo (trial 1, vulnerable) ----")
                progress_hook(f"Message m = {m}")
                progress_hook("Correct CRT computation:")
                progress_hook(f"sp = m^dp mod p = {sp}")
                progress_hook(f"sq = m^dq mod q = {sq}")
                progress_hook(f"h = qinv*(sp - sq) mod p = {h_correct}")
                progress_hook(f"s = sq + h*q = {s_correct}")
                progress_hook("Fault injection on one branch:")
                progress_hook(
                    f"fault_branch = {last_detail['fault_branch']} | "
                    f"fault_applied = {last_detail['fault_applied']}"
                )
                if last_detail["fault_branch"] == "p":
                    progress_hook(f"sp_faulty = {last_detail['sp_fault']}")
                else:
                    progress_hook(f"sq_faulty = {last_detail['sq_fault']}")
                progress_hook(f"h_faulty = {last_detail['h_fault']}")
                progress_hook(f"sf (faulty signature) = {last_detail['s_faulty']}")
                progress_hook("GCD factor recovery:")
                progress_hook(f"g = gcd(|s - sf|, n) = {g}")
                if 1 < g < pub.n and pub.n % g == 0:
                    recovered_p = g
                    recovered_q = pub.n // g
                    progress_hook(f"Recovered factor g = {recovered_p}")
                    progress_hook(f"Other factor n/g = {recovered_q}")
                    progress_hook(
                        f"Check: s mod q = {s_correct % priv.q} | "
                        f"sf mod q = {last_detail['s_faulty'] % priv.q}"
                    )
                    progress_hook(
                        f"Check: s mod p = {s_correct % priv.p} | "
                        f"sf mod p = {last_detail['s_faulty'] % priv.p}"
                    )
                else:
                    progress_hook("No factor recovered in this attempt.")

        else:
            trial_branch = "p"
            trial_fault_applied = False
            candidate_faulty = None
            candidate_detail = None

            def faulty_signer(msg: int, key: PrivateKey) -> int:
                nonlocal trial_branch, trial_fault_applied, candidate_faulty, candidate_detail
                detail = crt_faulty_from_components(
                    sp,
                    sq,
                    key,
                    fault_branch=None,
                    fault_rate=fault_rate,
                )
                candidate_detail = detail
                candidate_faulty = detail["s_faulty"]
                trial_branch = detail["fault_branch"]
                trial_fault_applied = detail["fault_applied"]
                return candidate_faulty

            oracle_start = time.perf_counter()
            result = secure_sign(
                m,
                priv,
                pub,
                signer=faulty_signer,
                return_info=True,
            )
            sf, verified, corrected = cast(tuple[int, bool, bool], result)
            oracle_time = time.perf_counter() - oracle_start
            oracle_times.append(oracle_time)

            g = math.gcd(abs(s_correct - sf), pub.n)
            trial_success = 1 < g < pub.n and pub.n % g == 0
            trial_gcd_bits = g.bit_length() if g > 0 else 0
            trial_integrity = rsa_verify(m, sf, pub)
            attempts_used = 1

            if detail_first and i == 1 and progress_hook is not None and candidate_detail is not None:
                progress_hook("---- Step-by-step demo (trial 1, secure) ----")
                progress_hook(f"Message m = {m}")
                progress_hook("Faulty candidate generated inside secure signer:")
                progress_hook(
                    f"fault_branch = {candidate_detail['fault_branch']} | "
                    f"fault_applied = {candidate_detail['fault_applied']}"
                )
                progress_hook(f"candidate sf = {candidate_detail['s_faulty']}")
                progress_hook(f"Verify candidate: {verified}")
                if not verified:
                    progress_hook("Candidate rejected; recomputed with full exponentiation.")
                progress_hook(f"Returned signature = {sf}")
                progress_hook(f"Returned matches correct CRT signature: {sf == s_correct}")
                progress_hook(f"g = gcd(|s - sf|, n) = {g}")

        trial_time = time.perf_counter() - trial_start
        attack_times.append(trial_time)

        if trial_success:
            successes += 1
        if trial_integrity:
            integrity_ok += 1

        record = TrialRecord(
            trial_index=i,
            success=trial_success,
            integrity_ok=trial_integrity,
            fault_branch=trial_branch,
            fault_applied=trial_fault_applied,
            gcd_bits=trial_gcd_bits,
            attack_time=trial_time,
            oracle_time=oracle_times[-1],
            attempts_used=attempts_used,
        )
        records.append(record)

        recovered_factor = None
        other_factor = None
        if 1 < g < pub.n and pub.n % g == 0:
            recovered_factor = g
            other_factor = pub.n // g

        if pipeline_hook is not None:
            pipeline_hook(
                {
                    "trial_index": i,
                    "mode": mode,
                    "message": m,
                    "s_correct": s_correct,
                    "s_faulty": sf,
                    "g": g,
                    "recovered_factor": recovered_factor,
                    "other_factor": other_factor,
                    "fault_branch": trial_branch,
                    "fault_applied": trial_fault_applied,
                    "integrity_ok": trial_integrity,
                    "attempts_used": attempts_used,
                }
            )

        if trial_hook is not None:
            trial_hook(record)

        if progress_hook is not None:
            status = "SUCCESS" if trial_success else "FAIL"
            progress_hook(
                f"Trial {i:02d}: {status} | branch={trial_branch} "
                f"faulted={trial_fault_applied} gcd_bits={trial_gcd_bits} "
                f"integrity_ok={trial_integrity} attempts={attempts_used}"
            )
            if trial_fault_applied:
                if trial_branch == "p":
                    progress_hook("Fault detail: sp (mod p) faulty, sq (mod q) correct")
                else:
                    progress_hook("Fault detail: sq (mod q) faulty, sp (mod p) correct")
            else:
                progress_hook("Fault detail: no fault applied; sp and sq correct")

    num_oracle_calls = len(oracle_times) if oracle_times else 1
    avg_oracle_time = sum(oracle_times) / num_oracle_calls
    avg_attack_time = sum(attack_times) / len(attack_times)

    results = {
        "mode": mode,
        "key_bits": key_bits,
        "num_trials": num_trials,
        "successes": successes,
        "success_rate": (successes / num_trials) * 100.0,
        "integrity_ok": integrity_ok,
        "integrity_rate": (integrity_ok / num_trials) * 100.0,
        "confidentiality_broken_rate": (successes / num_trials) * 100.0,
        "avg_oracle_time": avg_oracle_time,
        "avg_attack_time": avg_attack_time,
        "keygen_time": keygen_time,
        "records": records,
    }
    return results


def benchmark_key_sizes(samples_per_size: int = 5) -> dict:
    results = {}
    for size in (1024, 2048):
        (priv, pub), keygen_time = time_call(generate_keypair, size)

        sign_times = []
        for _ in range(samples_per_size):
            m = random_message(pub.n)
            start = time.perf_counter()
            _ = rsa_sign_crt(m, priv)
            sign_times.append(time.perf_counter() - start)

        avg_sign_time = sum(sign_times) / len(sign_times)
        results[size] = {
            "keygen_time": keygen_time,
            "sign_time": avg_sign_time,
        }
    return results


if __name__ == "__main__":
    results = run_trials(
        num_trials=DEFAULT_TRIALS,
        key_bits=1024,
        mode="vulnerable",
        reuse_key=True,
    )
    print(
        f"Success rate: {results['success_rate']:.2f}% "
        f"Integrity rate: {results['integrity_rate']:.2f}%"
    )
