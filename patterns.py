"""Pattern detectors. Each returns segments: (start, end, kind, bits, message).
`bits` is the rough cost an attacker pays to guess that segment; the scorer uses it."""
import math
import re
from .data import COMMON_PASSWORDS, COMMON_WORDS, KEYBOARD_ROWS, LEET

WORD_BITS = 11.0       # assume an attacker dictionary of ~2000 common words
SEQ_BITS = 5.0
KEYWALK_BITS = 6.0
YEAR_BITS = 7.0


def normalize(pw: str) -> str:
    """Lowercase and undo common leetspeak so 'P@ssw0rd' is treated like 'password'."""
    return pw.lower().translate(LEET)


def find_repeats(pw):
    out = []
    for m in re.finditer(r"(.)\1{2,}", pw):                    # aaa, 1111
        out.append((m.start(), m.end(), "repeated_chars", 4.0 + math.log2(len(m.group())),
                    f"Repeated character run '{m.group()}'"))
    for m in re.finditer(r"(.{2,}?)\1+", pw):                  # abcabc
        if len(set(m.group())) > 1:
            out.append((m.start(), m.end(), "repeated_block", 8.0 + math.log2(len(m.group()) / len(m.group(1))),
                        f"Repeated block '{m.group(1)}'"))
    return out


def find_sequences(pw):
    out, low, n = [], pw.lower(), len(pw)
    i = 0
    while i < n - 2:
        step = ord(low[i + 1]) - ord(low[i])
        if step in (1, -1) and low[i].isalnum() and low[i + 1].isalnum():
            j = i + 1
            while j + 1 < n and ord(low[j + 1]) - ord(low[j]) == step and low[j + 1].isalnum():
                j += 1
            if j - i + 1 >= 3:
                out.append((i, j + 1, "sequence", SEQ_BITS + math.log2(j - i + 1),
                            f"Sequential run '{pw[i:j + 1]}'"))
                i = j
        i += 1
    return out


def find_keyboard(pw):
    out, low = [], pw.lower()
    for row in KEYBOARD_ROWS:
        for r in (row, row[::-1]):
            for size in range(len(r), 3, -1):
                for s in range(len(r) - size + 1):
                    chunk = r[s:s + size]
                    k = low.find(chunk)
                    while k != -1:
                        out.append((k, k + size, "keyboard_pattern", KEYWALK_BITS + math.log2(size),
                                    f"Keyboard pattern '{pw[k:k + size]}'"))
                        k = low.find(chunk, k + 1)
    return out


def find_words(pw):
    out, norm = [], normalize(pw)
    for w in COMMON_WORDS:
        k = norm.find(w)
        while k != -1:
            out.append((k, k + len(w), "dictionary_word", WORD_BITS, f"Common word '{pw[k:k + len(w)]}'"))
            k = norm.find(w, k + 1)
    return out


def find_years(pw):
    return [(m.start(), m.end(), "year", YEAR_BITS, f"Year-like number '{m.group()}'")
            for m in re.finditer(r"(?<!\d)(19|20)\d{2}(?!\d)", pw)]


def common_password_hit(pw):
    """'exact' = on the list (also after leet-normalizing); 'decorated' = list word + digits/symbols."""
    low, norm = pw.lower(), normalize(pw)
    squashed = re.sub(r"[\s_-]+", "", low)
    if low in COMMON_PASSWORDS or norm in COMMON_PASSWORDS or squashed in COMMON_PASSWORDS:
        return "exact"
    stripped = re.sub(r"[\d\W_]+$", "", low)
    stripped_n = re.sub(r"[\d\W_]+$", "", norm)
    for s in (stripped, stripped_n):
        if len(s) >= 4 and s in COMMON_PASSWORDS and len(pw) - len(s) <= 6:
            return "decorated"
    return None


def context_overlap(pw, context):
    """Optional personal info (name, pet, birth year...). Returns matching tokens. Never stored."""
    norm, hits = normalize(pw), []
    for item in context or []:
        t = str(item).strip()
        if len(t) >= 3 and (normalize(t) in norm or t.lower() in pw.lower()):
            hits.append(t)
    return hits
