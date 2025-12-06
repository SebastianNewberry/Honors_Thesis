#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 5000

def solve():
    conn = remote(HOST, PORT)
    
    # We need to factor n using the square root oracle
    # If we get sqrt(x) where x is a quadratic residue, we can factor n
    # by computing gcd(sqrt(x) - x^(1/2), n) for different roots
    
    # First, let's gather information to factor n
    # Send 1 to get sqrt(1) which could be ±1 or other roots
    
    # Better approach: use the oracle to factor n
    # If we query with some value and get back a square root r,
    # then r^2 ≡ x (mod n). If we find two different roots r1, r2
    # of the same value where r1 ≠ ±r2 (mod n), then gcd(r1-r2, n) gives a factor
    
    # Query with a known square to try to factor n
    results = []
    test_val = 4  # 2^2
    
    for _ in range(50):
        conn.sendline(str(test_val).encode())
        r = int(conn.recvline().split()[1].strip())
        results.append(r)
    
    # Try to find n by looking at differences
    # r^2 ≡ 4 (mod n), so r^2 - 4 ≡ 0 (mod n)
    from math import gcd
    
    candidates = []
    for r in results:
        candidates.append(r * r - 4)
    
    # n divides all of these
    n = candidates[0]
    for c in candidates[1:]:
        n = gcd(n, c)
    
    log.info(f"Recovered n: {n}")
    
    # Now factor n using the oracle
    # Query same value multiple times, look for non-trivial roots
    p = None
    for _ in range(100):
        conn.sendline(str(test_val).encode())
        r = int(conn.recvline().split()[1].strip())
        # r^2 ≡ 4 (mod n), so (r-2)(r+2) ≡ 0 (mod n)
        g = gcd(r - 2, n)
        if 1 < g < n:
            p = g
            break
        g = gcd(r + 2, n)
        if 1 < g < n:
            p = g
            break
    
    if p is None:
        log.error("Failed to factor n")
        return
    
    q = n // p
    log.success(f"Factored! p={p}, q={q}")
    
    # Now receive m
    conn.sendline(b"")
    line = conn.recvline().decode().strip()
    m = int(line.split(" = ")[1])
    log.info(f"m = {m}")
    
    # Compute signature: s^65537 ≡ m (mod n)
    # We need s = m^d mod n where d = inverse(65537, phi(n))
    e = 0x10001
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    s = pow(m, d, n)
    
    log.info(f"Signature s = {s}")

    conn.sendlineafter(b">>>", str(s).encode())
    
    # Get flag
    response = conn.recvall().decode()
    print(response)

if __name__ == "__main__":
    solve()