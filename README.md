# PassGuard: Password Strength Analyzer & Security Suggestion Tool

A **defensive**, fully local Python tool that scores a password and explains *why*, instead of only checking
"has uppercase + number + symbol". Zero dependencies.

> `Password123!` passes most composition rules, yet scores **VERY WEAK** here because it is a common word + a sequence.

## Quick start
```bash
git clone <your-repo-url> && cd password-analyzer
python run_all.py            # tests -> demo table -> dashboard at http://127.0.0.1:8765
python run_all.py --no-dashboard
python -m passguard.cli      # hidden-input CLI (add --context yourname petname)
python -m unittest discover -s tests -v
```

## Features
Score 0-100 and 5 classes (VERY WEAK to VERY STRONG); length and character-diversity analysis; common-password
detection (incl. leetspeak and decorated forms); repeated chars/blocks; sequences; keyboard walks; dictionary words;
years; optional personal-context warning; entropy-style estimate (naive vs adjusted); tailored suggestions;
passphrase guidance; hygiene tips; optional aggregate-only history; local dashboard.

## Architecture
```
input -> analyzer.analyze()
           |-- patterns.py    repeats, sequences, keyboard, words, years, common-password, context
           |-- entropy.py     pool size, naive bits, pattern-aware adjusted bits (dynamic programming)
           |-- suggestions.py advice, passphrase guidance, hygiene
           -> result dict -> cli.py | dashboard.py | history.py (metadata only)
```

## How scoring works
1. `naive bits = length x log2(character pool)`: what simple meters believe.
2. Detected patterns are replaced by their cheaper "attacker cost" (a common word is about 11 bits). A small
   dynamic program finds the cheapest way to "spell" the password: the **adjusted bits**.
3. `score = adjusted_bits / 90 x 100` (max 100).
4. Hard caps: exact common password 5, common password + decoration 15, personal info 30, under 8 chars 20, under 12 chars 55.
5. Classes: <20 VERY WEAK, <40 WEAK, <60 MODERATE, <80 STRONG, otherwise VERY STRONG.

## Limitations
No formula can perfectly measure strength. Built-in wordlists are small (extend with `data/common_passwords.txt`,
e.g. a public top-10k list). Costs are heuristic. This does not replace breach checks, MFA or a password manager.
Nothing is sent to online breach APIs.

## Privacy & ethics
See [SECURITY.md](SECURITY.md). Use only synthetic passwords for screenshots (`data/demo_passwords.txt`).


## Roadmap
Larger wordlists, opt-in k-anonymity breach check, zxcvbn comparison, CI badge, packaging.

License: MIT
