from pwn import *
from math import gcd
from random import randint
import sys

# Connect to the server
r = remote('127.0.0.1', 5000)

# Recover n by querying f(1) many times; max(y) = n-1
ys = []
N_QUERIES = 100
for _ in range(N_QUERIES):
    r.sendlineafter(b'>>> ', b'1')
    y_line = r.recvline().strip()
    y = int(y_line)
    ys.append(y)

n = max(ys) + 1

# Verify all ys satisfy y^2 == 1 mod n
assert all(pow(y, 2, n) == 1 for y in ys), "Failed to recover n correctly (rerun)"

# Factor n using the sqrt oracle
p = q = None
N_FACTOR_TRIALS = 40
for _ in range(N_FACTOR_TRIALS):
    k = randint(1, n - 1)
    x = (k * k) % n
    r.sendlineafter(b'>>> ', str(x).encode())
    y_line = r.recvline().strip()
    y = int(y_line)
    diff = abs(k - y)
    d = gcd(diff, n)
    if 1 < d < n:
        p = d
        q = n // d
        break

assert p is not None, "Failed to factor (rerun)"

# Break the oracle loop with invalid input
r.sendlineafter(b'>>> ', b'a')

# Receive and parse m
m_line = r.recvline().decode().strip()
print(m_line)
assert m_line.startswith('m = ')
m = int(m_line.split()[-1].strip())  # "m=123..." -> 123...

assert 0 <= m < n

# Compute signature: s = m^d mod n
e = 0x10001
phi = (p - 1) * (q - 1)
d_priv = pow(e, -1, phi)
s = pow(m, d_priv, n)

# Send s
r.sendlineafter(b'>>> ', str(s).encode())

# Receive flag
flag = r.recvline().decode().strip()
print(f"Flag: {flag}")

r.close()