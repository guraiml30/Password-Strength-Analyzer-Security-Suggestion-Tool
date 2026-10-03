"""Turns findings into plain-language advice, plus passphrase guidance and hygiene tips."""

ADVICE = {
    "common_password": "Never use passwords found in breach lists. Pick something new and unrelated.",
    "personal_info": "Remove names, pets, birthdays or usernames; attackers try these first.",
    "too_short": "Make it much longer. Length is the single biggest factor.",
    "short": "Extend to at least 14 characters (16+ for important accounts).",
    "low_variety": "Avoid repeating the same few characters.",
    "repeated_chars": "Avoid runs like 'aaa' or '1111'.",
    "repeated_block": "Avoid repeating a chunk (e.g. 'abcabc'); it adds almost no strength.",
    "sequence": "Avoid sequences such as 'abc' or '1234'.",
    "keyboard_pattern": "Avoid keyboard walks such as 'qwerty' or 'asdf'.",
    "dictionary_word": "A common word (even with 'a'->'@' swaps) is easy to guess; combine unrelated words instead.",
    "year": "Years and birth years are very guessable; leave them out.",
}

PASSPHRASE_TIP = ("Passphrase idea: join 4+ random, unrelated words (picked by dice or a password manager) "
                  "that you have never seen written together. Long and random beats short and 'complex'.")
HYGIENE = [
    "Use a unique password for every account.",
    "Store passwords in a reputable password manager.",
    "Turn on multi-factor authentication (MFA) wherever possible.",
    "Change a password immediately if you suspect a leak; avoid pointless forced rotation.",
    "Never share passwords by email/chat, and beware phishing pages asking for them.",
]


def build_suggestions(result):
    out, seen = [], set()
    for f in result["findings"]:
        a = ADVICE.get(f["kind"])
        if a and a not in seen:
            seen.add(a); out.append(a)
    if result["length"] < 14 and ADVICE["short"] not in seen:
        out.append(ADVICE["short"])
    if sum(result["classes"].values()) < 2:
        out.append("Mixing character types helps a little, but length and randomness matter more.")
    if result["label"] in ("VERY WEAK", "WEAK", "MODERATE"):
        out.append(PASSPHRASE_TIP)
    if not out:
        out.append("Looks good. Keep it unique per account and enable MFA.")
    return out
