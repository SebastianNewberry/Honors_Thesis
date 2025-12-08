#!/usr/bin/env python3
from pwn import remote
from math import gcd
from Crypto.Util.number import inverse

HOST, PORT = "127.0.0.1", 5000
e = 0x10001

io = remote(HOST, PORT)

# step 1: recover n
io.recvuntil(b">>> ")
io.sendline(b"0")
y0 = int(io.recvline())
n = y0

io.recvuntil(b">>> ")
io.sendline(b"1")
y1 = int(io.recvline())
assert pow(y1, 2, n) == 1          # sanity check

# step 2: get the message to sign
io.recvuntil(b">>> ")
io.sendline(b"q")                   # leave the oracle loop
mline = io.recvline().decode().strip()
m = int(mline.split("=")[1].strip())

# step 3: sign it
d = inverse(e, n - 1)               # good enough; works because e is invertible mod λ(n)
s = pow(m, d, n)

# step 4: send signature and win
io.recvuntil(b">>> ")
io.sendline(str(s).encode())
flag = io.recvline().decode().strip()
print(flag)