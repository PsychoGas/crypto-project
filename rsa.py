from __future__ import annotations

from dataclasses import dataclass
import math
import secrets
from typing import Callable

from utils import generate_prime, generate_prime_with_stats, modinv


# ===================== DATA CLASSES =====================

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


# ===================== KEY GENERATION =====================

def generate_keypair(bits: int = 1024) -> tuple[PrivateKey, PublicKey]:
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

    return (
        PrivateKey(n, d, p, q, dp, dq, qinv),
        PublicKey(n, e),
    )
def generate_keypair_with_info(bits: int = 1024):
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

    priv = PrivateKey(n, d, p, q, dp, dq, qinv)
    pub = PublicKey(n, e)

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


# ===================== BASIC SIGN =====================

def rsa_sign_full(m: int, priv: PrivateKey) -> int:
    return pow(m, priv.d, priv.n)


def rsa_verify(m: int, s: int, pub: PublicKey) -> bool:
    return pow(s, pub.e, pub.n) == m


# ===================== CRT SIGN =====================

def rsa_sign_crt(m: int, priv: PrivateKey) -> tuple[int, int, int]:
    sp = pow(m, priv.dp, priv.p)
    sq = pow(m, priv.dq, priv.q)

    h = (priv.qinv * (sp - sq)) % priv.p
    s = sq + h * priv.q

    return s, sp, sq


# ===================== PROTECTION LAYERS =====================

def crt_consistency_check(s, sp, sq, priv):
    return (s % priv.p == sp) and (s % priv.q == sq)


def infective_response(n: int) -> int:
    return secrets.randbelow(n - 1) + 1


def blind_message(m: int, pub: PublicKey):
    r = secrets.randbelow(pub.n - 2) + 2
    blinded = (m * pow(r, pub.e, pub.n)) % pub.n
    return blinded, r


def unblind_signature(s: int, r: int, pub: PublicKey):
    rinv = pow(r, -1, pub.n)
    return (s * rinv) % pub.n


# ===================== SECURE SIGN =====================

def secure_sign(
    m: int,
    priv: PrivateKey,
    pub: PublicKey,
    return_info: bool = False,
):
    try:
        # Step 1: Message blinding
        m_blind, r = blind_message(m, pub)

        # Step 2: Double computation
        s1, sp1, sq1 = rsa_sign_crt(m_blind, priv)
        s2, sp2, sq2 = rsa_sign_crt(m_blind, priv)

        if s1 != s2:
            fake = infective_response(pub.n)
            if return_info:
                return fake, False, True
            return fake

        # Step 3: CRT consistency check
        if not crt_consistency_check(s1, sp1, sq1, priv):
            fake = infective_response(pub.n)
            if return_info:
                return fake, False, True
            return fake

        # Step 4: Unblind
        s = unblind_signature(s1, r, pub)

        # Step 5: Verify
        verified = rsa_verify(m, s, pub)

        if not verified:
            s = rsa_sign_full(m, priv)
            corrected = True
        else:
            corrected = False

    except Exception:
        fake = infective_response(pub.n)
        if return_info:
            return fake, False, True
        return fake

    if return_info:
        return s, verified, corrected
    return s
