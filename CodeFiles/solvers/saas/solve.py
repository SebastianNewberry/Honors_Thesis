from pwn import remote
from math import gcd

HOST = "127.0.0.1"
PORT = 5000

r = remote(HOST, PORT, timeout=5)

roots = []
roots_set = set()
m = None

print(f"[+] connected to {HOST}:{PORT}")

print(r.recvline())

# Spam '4' until we observe the 'm = <value>' line and collect at least 4 unique roots.
# We'll keep sending '4' until we see m, but continue if necessary to collect 4 roots.
while True:
    try:
        r.sendline(b"4")
    except Exception as exc:
        print("[!] send failed:", exc)
        break

    try:
        line = r.recvline(timeout=3)
    except Exception:
        line = None

    if not line:
        # nothing returned this iteration; try again
        continue

    text = line.decode(errors="ignore").strip()
    if not text:
        continue

    # Debug print of what we received
    print("[<] ", text)

    # If the server prints "m = <value>"
    if text.startswith("m ="):
        # parse m
        try:
            m = int(text.split("=", 1)[1].strip())
            print(f"[+] parsed m = {m}")
        except Exception as e:
            print("[!] failed to parse m:", e)
        # break only if we also have 4 roots; otherwise keep spamming until we collect 4 roots
        if len(roots) >= 4:
            break
        else:
            # continue loop to collect missing roots while m already known
            continue

    # Otherwise try to parse an integer root result
    try:
        val = int(text)
        if val not in roots_set:
            roots_set.add(val)
            roots.append(val)
            print(f"[+] got root #{len(roots)}: {val}")
        # if we have 4 roots AND have already seen m, break
        if len(roots) >= 4 and m is not None:
            break
    except Exception:
        # Received something else (maybe a prompt or message) — ignore
        continue

# sanity check
if len(roots) < 4:
    print("[!] collected fewer than 4 roots:", roots)
if m is None:
    print("[!] did not find m in the server output yet. Exiting.")
    r.close()
    exit(1)

# Sort roots and compute n, p, q etc. using logic from original solve.
roots.sort()
print(f"[+] sorted roots: {roots}")

# original formula used: n = roots[-1] + roots[0]
n = roots[-1] + roots[0]
p = gcd(roots[1] - roots[0], n)
q = n // p
print(f"[+] computed n = {n}")
print(f"[+] computed p = {p}")
print(f"[+] computed q = {q}")

phi = (p - 1) * (q - 1)
e = 0x10001
# modular inverse
d = pow(e, -1, phi)
print(f"[+] computed d")

# signature s = m^d mod n
s = pow(m, d, n)
print(f"[+] m = {m}")
print(f"[+] s = {s}")

r.close()