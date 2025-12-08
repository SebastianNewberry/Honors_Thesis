from pwn import *
from math import gcd
from Crypto.Util.number import inverse
import random

# Context setup
context.log_level = 'info'

def solve():
    # Connect to the remote server
    # Assuming local docker instance as per instructions
    io = remote('127.0.0.1', 5000)

    # --- Step 1: Recover Modulus N ---
    log.info("Recovering modulus N...")
    
    # We send '2' and '3'. The server returns sqrt(2) mod N and sqrt(3) mod N.
    # r1^2 = 2 mod N  => r1^2 - 2 = k1 * N
    # r2^2 = 3 mod N  => r2^2 - 3 = k2 * N
    # N = gcd(r1^2 - 2, r2^2 - 3)
    
    io.sendlineafter(b'>>> ', b'2')
    r1 = int(io.recvline().strip())
    
    io.sendlineafter(b'>>> ', b'3')
    r2 = int(io.recvline().strip())
    
    n = gcd(r1**2 - 2, r2**2 - 3)
    log.success(f"Recovered N: {n}")

    # --- Step 2: Factor N using the Square Root Oracle ---
    log.info("Attempting to factor N...")
    
    p = 0
    q = 0
    
    # We try random numbers until we find a collision that reveals a factor
    while True:
        u = random.randint(2, n - 1)
        y = pow(u, 2, n)
        
        # Ask oracle for sqrt(u^2)
        io.sendlineafter(b'>>> ', str(y).encode())
        z = int(io.recvline().strip())
        
        # If the oracle returns a root z such that z != +/- u mod N,
        # then gcd(u - z, N) reveals a factor.
        if z != u and z != (n - u):
            p = gcd(u - z, n)
            q = n // p
            break
        else:
            # 50% chance to fail (get back the trivial roots), just retry
            continue

    log.success(f"Found factors: p={p}, q={q}")

    # --- Step 3: Generate Private Key and Sign Message ---
    e = 0x10001
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    
    # Break the server loop by sending a non-integer
    io.sendlineafter(b'>>> ', b'break')
    
    # Receive the challenge message m
    # Output format is "m = <number>"
    resp = io.recvline().decode().strip()
    m = int(resp.split(' = ')[1])
    log.info(f"Challenge message m: {m}")
    
    # Calculate signature s
    s = pow(m, d, n)
    log.info(f"Calculated signature s: {s}")
    
    # Send signature
    io.sendlineafter(b'>>> ', str(s).encode())
    
    # Receive flag
    flag = io.recvall().decode().strip()
    log.success(f"Flag: {flag}")

if __name__ == "__main__":
    solve()