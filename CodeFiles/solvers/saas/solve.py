from pwn import *
from math import gcd

# Connect to the remote (local for testing)
r = remote('127.0.0.1', 5000)

# Collect 4 unique square roots of 4 mod n by spamming l=4
roots = []
print("Collecting roots...")
for i in range(50):  # Upper bound; should get 4 unique quickly
    r.recvuntil(b'>>> ')
    r.sendline(b'4')
    resp = r.recvline().decode().strip()
    if resp:
        try:
            root = int(resp)
            if root not in roots:
                roots.append(root)
                print(f"Got new root: {root} (total: {len(roots)})")
            if len(roots) == 4:
                break
        except ValueError:
            pass  # Ignore junk lines

assert len(roots) == 4, "Failed to collect 4 unique roots"

# Break the loop with invalid input
r.recvuntil(b'>>> ')
r.sendline(b'foo')  # Triggers except: break

# Receive and parse m
line = r.recvline().decode().strip()
print(f"Received: {line}")
if 'm =' in line:
    m = int(line.split('=')[1].strip())
else:
    # Fallback: might need to recv more
    r.recvline()
    line = r.recvline().decode().strip()
    m = int(line.split('=')[1].strip())
print(f"{m = }")

# Recover n: after sorting, smallest + largest = n
roots.sort()
n = roots[0] + roots[-1]
print(f"{n = }")

# Factor: gcd of adjacent diff gives p (or q)
diff = abs(roots[1] + roots[0])
p = gcd(diff, n)
q = n // p
assert p * q == n and p != q, "Factoring failed"
print(f"{p = }, {q = }")

# RSA private key
phi = (p - 1) * (q - 1)
e = 0x10001
d = pow(e, -1, phi)
print(f"{d = }")

# Forge signature
s = pow(m, d, n)
print(f"{s = }")

# Submit s
r.recvuntil(b'>>> ')
r.sendline(str(s).encode())

# Get flag
flag = r.recvall().decode().strip()
print(f"Flag: {flag}")

r.close()