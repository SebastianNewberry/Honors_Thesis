# No solution provided
# Reasoning: 
# How many times do we need to send? We need at least two distinct roots for x=1. Since the function f randomly chooses signs, we have four roots. We can collect until we have two distinct roots that are not additive inverses? Actually, if we get two roots that are additive inverses, then r1 + r2 = n and gcd(r1 - r2, n) = gcd(2*r1, n) might not yield a factor. So we need two roots that are distinct and not additive inverses.
# We can do: roots = set() while len(roots) < 4: # we might not get all four, but we can break when we have two that are not additive inverses? Actually, we can break when we have two roots that are distinct and also (r1 + r2) % n != 0.
# Alternatively, we can collect several roots and then try all pairs until we find one that factors n.
# But note: we don't know n? Actually, we do: the server prints m later, but we don't have n at the beginning. However, note that the function f returns a value modulo n. We can get n by computing the modulus? Actually, we can send two different values and see the modulus? But we don't have to: the challenge code uses n and we can get it by factoring.
# Wait: the challenge prints m = ... after we break the loop, but we need n to factor. How can we get n?
