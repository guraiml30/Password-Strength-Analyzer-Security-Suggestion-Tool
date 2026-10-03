"""Entropy-style estimate: bits = length * log2(character_pool), then replace predictable
segments with their (much cheaper) pattern cost using dynamic programming.
This is an ESTIMATE of guessing difficulty, not a proof of security."""
import math
import string

SYMBOLS = set(string.punctuation) | {" "}


def pool_size(pw):
    pool = 0
    if any(c.islower() for c in pw if c.isascii()): pool += 26
    if any(c.isupper() for c in pw if c.isascii()): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(c in SYMBOLS for c in pw): pool += 33
    if any(not c.isascii() for c in pw): pool += 32
    return max(pool, 1)


def naive_bits(pw):
    return len(pw) * math.log2(pool_size(pw))


def adjusted_bits(pw, segments):
    """Cheapest way an attacker could 'spell' the password using known segments."""
    per_char = math.log2(pool_size(pw))
    n = len(pw)
    best = [0.0] + [math.inf] * n
    for i in range(1, n + 1):
        best[i] = best[i - 1] + per_char
        for (s, e, _k, bits, _m) in segments:
            if e == i and best[s] + bits < best[i]:
                best[i] = best[s] + bits
    return best[n]
