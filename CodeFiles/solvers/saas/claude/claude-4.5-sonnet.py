#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import inverse

# Connect to the challenge
io = remote('127.0.0.1', 5000)

def get_sqrt(x):
    """Query the oracle for a square root of x mod n"""
    io.sendlineafter(b'>>> ', str(x).encode())
    result = int(io.recvline().strip())
    return result

# We need to extract n first by using the oracle
# Get two square roots to help us find n
r1 = get_sqrt(2)
r2 = get_sqrt(2)

# FINAL CORRECT APPROACH:
# We compute t where t^(2^16) = m by taking 16 square roots
# Then s = t / m^(1/65537). But since s^65537 = m, we have s = m^(1/65537)
# And t^65536 = m, so m^(1/65536) = t
# Therefore m^(1/65537) = m^(1/65536) * m^(-1/65537) ... 
# Using the fact that 65537 = 65536 + 1:
# s * s^65536 = m, and t^65536 = m, so s = m / t (mod n) when we can find modular inverse

# Actually: s = t * inverse(m, n) should work! Let's verify:
# (t / m)^65537 = t^65537 / m^65537 = t * t^65536 / m^65537 = t * m / m^65537 = m^(1-65536) = m^(-65535)
# No...

# Let me try: s^65537 = m, t^65536 = m
# So s^65537 = t^65536
# Taking 65536-th root: s^(65537/65536) = t
# So s = t^(65536/65537) = t / t^(1/65537) = t / s ... circular again

# Wait! The answer is simply: try all 4 combinations of signs from the last square root!
# s = ±m^(1/65536) * (±m^(1/65536))^(-1) mod n ... no

# Correct solution: s = t where t is obtained by taking 16 square roots, trying different sign combinations

io.recvuntil(b'm = ')
m = int(io.recvline().strip())

# Take 16 square roots to compute m^(1/2^16)
current = m
for i in range(16):
    current = get_sqrt(current)

# current^(2^16) should equal m (up to sign)
# We want s such that s^65537 = m
# Since 65537 = 2^16 + 1, we have s^(2^16) * s = m
# If current^(2^16) = m, then s = current should work... let's try

# Actually we need to try different values since the oracle has random signs
# The signature should be s = current (or related by sign/inverse)

# Try current as the signature
io.sendlineafter(b'>>> ', str(current).encode())
response = io.recvall().decode()
print(response)

io.close()