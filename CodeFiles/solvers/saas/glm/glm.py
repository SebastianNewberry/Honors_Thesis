#!/usr/bin/env python3
from pwn import *
import math
import sys

def solve():
    # Connect to the challenge
    conn = remote('127.0.0.1', 5000)
    
    # Get the message m
    conn.recvuntil(b'm = ')
    m_line = conn.recvline().decode().strip()
    m = int(m_line.strip())
    log.info(f"Got message m = {m}")
    
    # The vulnerability: we have a square root oracle
    # This is a classic setup where having access to square roots
    # can break the cryptosystem
    
    # Get a square root of m
    conn.sendline(str(m))
    sqrt_m = int(conn.recvline().decode().strip())
    log.info(f"Got sqrt(m) = {sqrt_m}")
    
    # The key insight: if we can get square roots, we might be able to
    # exploit this to forge a signature
    
    # Try submitting the square root as the signature
    # This exploits the fact that the signature verification might
    # not be properly implemented
    conn.sendline(str(sqrt_m))
    result = conn.recvline().decode().strip()
    print(result)
    
    # If that didn't work, let's try a few more variations
    if "flag" not in result:
        print("Trying variations...")
        
        # Try getting multiple square roots
        for i in range(3):
            conn.close()
            conn = remote('127.0.0.1', 5000)
            conn.recvuntil(b'm = ')
            m_line = conn.recvline().decode().strip()
            m = int(m_line.split('=')[1].strip())
            
            conn.sendline(str(m))
            sqrt_m = int(conn.recvline().decode().strip())
            
            conn.sendline(str(sqrt_m))
            result = conn.recvline().decode().strip()
            print(f"Attempt {i+1}: {result}")
            if "flag" in result:
                break
    
    conn.close()

if __name__ == "__main__":
    solve()