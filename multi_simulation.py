import math

# Modular exponentiation
def modexp(base, exp, mod):
    return pow(base, exp, mod)

# Modular inverse
def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return 1

# Main program
def main():
    print("=== RSA-CRT Fault Attack Demo ===\n")

    p = int(input("Enter prime p: "))
    q = int(input("Enter prime q: "))
    e = int(input("Enter public exponent e: "))
    m = int(input("Enter message m: "))

    n = p * q
    phi = (p - 1) * (q - 1)

    # Find d
    for d in range(1, phi):
        if (d * e) % phi == 1:
            break

    print("\nComputed values:")
    print(f"n = {n}, phi = {phi}, d = {d}")

    # CRT parameters
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)

    # Correct CRT signature
    sp = modexp(m, dp, p)
    sq = modexp(m, dq, q)

    h = (qinv * (sp - sq)) % p
    s = sq + h * q

    print(f"\nCorrect signature s = {s}")

    # Fault inputs
    fault_p = int(input("\nEnter fault value for sp: "))
    fault_q = int(input("Enter fault value for sq: "))

    # Apply faults
    sp_fault = (sp + fault_p) % p
    sq_fault = (sq + fault_q) % q

    h_fault = (qinv * (sp_fault - sq_fault)) % p
    s_fault = sq_fault + h_fault * q

    print(f"\nFaulty signature s' = {s_fault}")

    # GCD Attack
    diff = abs(s - s_fault)
    g = math.gcd(diff, n)

    print(f"\nGCD(|s - s'|, n) = {g}")

    # Result
    if g == 1:
        print("➡️ Attack FAILED (both branches faulty)")
    else:
        print("➡️ Attack SUCCESS!")
        print(f"Recovered factor: {g}")
        print(f"Other factor: {n // g}")

    # Extra clarity
    print("\n--- Interpretation ---")
    if fault_p != 0 and fault_q != 0:
        print("Both branches were faulty → Bellcore attack fails")
    elif fault_p != 0 or fault_q != 0:
        print("Single branch fault → Bellcore attack succeeds")
    else:
        print("No fault → normal RSA behavior")


if __name__ == "__main__":
    main()