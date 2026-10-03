"""Core engine: password in -> structured result out. Nothing is stored or sent anywhere."""
import string
from . import patterns as P
from .entropy import naive_bits, adjusted_bits, pool_size
from .suggestions import build_suggestions

LABELS = [(20, "VERY WEAK"), (40, "WEAK"), (60, "MODERATE"), (80, "STRONG"), (101, "VERY STRONG")]
FULL_SCORE_BITS = 90.0   # ~90 adjusted bits maps to a score of 100


def label_for(score):
    return next(name for limit, name in LABELS if score < limit)


def analyze(password: str, context=None) -> dict:
    n = len(password)
    if n == 0:
        return {"score": 0, "label": "VERY WEAK", "length": 0, "findings": [], "suggestions": ["Enter a password."],
                "bits_naive": 0, "bits_adjusted": 0, "classes": {}, "pool": 0}

    classes = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(c in string.punctuation or c == " " for c in password),
    }
    segments = (P.find_repeats(password) + P.find_sequences(password) + P.find_keyboard(password)
                + P.find_words(password) + P.find_years(password))

    findings, seen = [], set()
    for (_s, _e, kind, _b, msg) in segments:
        if msg not in seen:
            seen.add(msg)
            findings.append({"kind": kind, "severity": "medium", "message": msg})

    caps = []  # score ceilings applied for serious problems
    hit = P.common_password_hit(password)
    if hit:
        findings.insert(0, {"kind": "common_password", "severity": "high",
                            "message": "Matches a commonly used password" if hit == "exact"
                            else "A common password with predictable digits/symbols added"})
        caps.append(5 if hit == "exact" else 15)
    ctx = P.context_overlap(password, context)
    if ctx:
        findings.insert(0, {"kind": "personal_info", "severity": "high",
                            "message": f"Contains personal context ({len(ctx)} item(s)) an attacker could guess"})
        caps.append(30)
    if n < 8:
        findings.append({"kind": "too_short", "severity": "high", "message": f"Only {n} characters; aim for 14+"})
        caps.append(20)
    elif n < 12:
        findings.append({"kind": "short", "severity": "low", "message": f"{n} characters; 14+ is much safer"})
        caps.append(55)
    if len(set(password)) <= max(2, n // 4):
        findings.append({"kind": "low_variety", "severity": "medium", "message": "Very few unique characters"})
        caps.append(25)

    bits_adj = adjusted_bits(password, segments)
    score = min(100, int(bits_adj * 100 / FULL_SCORE_BITS))
    if caps:
        score = min(score, min(caps))

    result = {
        "score": score, "label": label_for(score), "length": n, "classes": classes, "pool": pool_size(password),
        "bits_naive": round(naive_bits(password), 1), "bits_adjusted": round(bits_adj, 1),
        "findings": findings,
        "disclaimer": "Estimate only: no single formula can measure real-world password strength.",
    }
    result["suggestions"] = build_suggestions(result)
    return result
