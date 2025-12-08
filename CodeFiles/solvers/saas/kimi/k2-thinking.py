from pwn import *
import random
import math
from Crypto.Util.number import inverse

def collect_pairs(conn, count=15):
    """Collect (a, y) pairs where y is a square root of a² modulo n"""
    pairs = []
    for i in range(count):
        print(f"[*] Collecting pair {i+1}/{count}")
        # Generate random a (larger than p and q to ensure reduction modulo n)
        a = random.randint(2**600, 2**650)
        conn.sendline(str(a*a).encode())
        y = int(conn.recvline().split()[1].strip())
        pairs.append((a, y))
    return pairs

def compute_modulus(pairs):
    """Compute n from pairs where each y² ≡ a² (mod n)"""
    diffs = [y*y - a*a for a, y in pairs]
    n = diffs[0]
    for d in diffs[1:]:
        n = math.gcd(n, d)
    return n

def factor_modulus(n, pairs):
    """Factor n using pairs where y ≠ ±a (mod n)"""
    for a, y in pairs:
        # Try both a-y and a+y for different sign combinations
        p = math.gcd(a - y, n)
        if 1 < p < n:
            return p, n // p
        p = math.gcd(a + y, n)
        if 1 < p < n:
            return p, n // p
    return None

def main():
    conn = remote('127.0.0.1', 5000)
    # Stage 1: Collect pairs from the oracle
    print("[*] Collecting pairs from oracle...")
    pairs = collect_pairs(conn, 15)
    # Stage 2: Break the loop to get the challenge message
    print("[*] Breaking oracle loop...")
    conn.sendline("break")  # Any non-integer string triggers exception
    # Receive the challenge message
    conn.recvuntil(b"m = ")
    m = int(conn.recvline().strip())
    print(f"[+] Challenge message: {m}")
    # Stage 3: Compute modulus n
    print("[*] Computing modulus n...")
    n = compute_modulus(pairs)
    print(f"[+] Recovered n: {n}")
    # Stage 4: Factor n
    print("[*] Factoring n...")
    factors = factor_modulus(n, pairs)
    if not factors:
        print("[-] Failed to factor n")
        return
    p, q = factors
    print(f"[+] Factored: p={p}, q={q}")
    assert p * q == n, "Factorization verification failed"
    # Stage 5: Compute RSA private key
    print("[*] Computing private exponent...")
    e = 0x10001
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    print("[+] Private exponent computed")
    # Stage 6: Sign the message
    print("[*] Signing message...")
    s = pow(m, d, n)
    print(f"[+] Signature: {s}")
    # Stage 7: Submit signature and get flag
    print("[*] Submitting signature...")
    conn.sendline(str(s).encode())
    
    flag = conn.recvline().strip().decode()
    print(f"[+] Flag: {flag}")
    conn.close()

if __name__ == "__main__":
    main()