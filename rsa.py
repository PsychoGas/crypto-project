
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from utils import generate_prime, generate_prime_with_stats, modinv


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int


def generate_keypair(bits: int = 1024) -> tuple[PrivateKey, PublicKey]:
    if bits not in (1024, 2048):
        raise ValueError("Only 1024 and 2048-bit keys are supported in this demo")

    e = 65537
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = modinv(e, phi)
        break

    n = p * q
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)

    priv = PrivateKey(n=n, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)
    pub = PublicKey(n=n, e=e)
    return priv, pub


def generate_keypair_with_info(bits: int = 1024) -> tuple[PrivateKey, PublicKey, dict]:
    if bits not in (1024, 2048):
        raise ValueError("Only 1024 and 2048-bit keys are supported in this demo")

    e = 65537
    total_p_attempts = 0
    total_q_attempts = 0
    keygen_rounds = 0

    while True:
        keygen_rounds += 1
        p, p_attempts = generate_prime_with_stats(bits // 2)
        q, q_attempts = generate_prime_with_stats(bits // 2)
        total_p_attempts += p_attempts
        total_q_attempts += q_attempts

        if p == q:
            continue

        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue

        d = modinv(e, phi)
        break

    n = p * q
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)

    priv = PrivateKey(n=n, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)
    pub = PublicKey(n=n, e=e)
    info = {
        "e": e,
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "d": d,
        "dp": dp,
        "dq": dq,
        "qinv": qinv,
        "p_attempts": total_p_attempts,
        "q_attempts": total_q_attempts,
        "keygen_rounds": keygen_rounds,
    }
    return priv, pub, info


def rsa_sign_full(m: int, priv: PrivateKey) -> int:
    return pow(m, priv.d, priv.n)


def rsa_sign_crt(m: int, priv: PrivateKey) -> int:
    sp = pow(m, priv.dp, priv.p)
    sq = pow(m, priv.dq, priv.q)
    h = (priv.qinv * (sp - sq)) % priv.p
    return sq + h * priv.q


def rsa_verify(m: int, s: int, pub: PublicKey) -> bool:
    return pow(s, pub.e, pub.n) == m


def secure_sign(
    m: int,
    priv: PrivateKey,
    pub: PublicKey,
    signer: Callable[[int, PrivateKey], int] | None = None,
    return_info: bool = False,
):
    if signer is None:
        signer = rsa_sign_crt

    candidate = signer(m, priv)
    verified = rsa_verify(m, candidate, pub)
    corrected = False
    if not verified:
        # Fault detected; recompute with full exponentiation.
        candidate = rsa_sign_full(m, priv)
        corrected = True

    if return_info:
        return candidate, verified, corrected
    return candidate
