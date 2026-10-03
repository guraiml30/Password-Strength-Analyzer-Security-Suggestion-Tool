"""Command-line interface. getpass keeps the password hidden and out of shell history."""
import argparse
import getpass
import json
from .analyzer import analyze
from .suggestions import HYGIENE


def render(r):
    print(f"\n  Strength : {r['label']}  (score {r['score']}/100)")
    print(f"  Length   : {r['length']}   Character pool: {r['pool']}")
    print(f"  Entropy  : naive {r['bits_naive']} bits -> adjusted {r['bits_adjusted']} bits")
    print("  Classes  : " + ", ".join(k for k, v in r["classes"].items() if v))
    if r["findings"]:
        print("\n  Weaknesses:")
        for f in r["findings"]:
            print(f"   - [{f['severity']}] {f['message']}")
    print("\n  Suggestions:")
    for s in r["suggestions"]:
        print(f"   * {s}")
    print(f"\n  Note: {r.get('disclaimer', '')}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local password strength analyzer (defensive).")
    ap.add_argument("--context", nargs="*", default=[], help="optional personal words to check (name, pet, ...)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--hygiene", action="store_true", help="print password hygiene tips")
    a = ap.parse_args(argv)
    if a.hygiene:
        print("\n".join(f" - {h}" for h in HYGIENE)); return
    r = analyze(getpass.getpass("Password (hidden, analyzed locally): "), a.context)
    print(json.dumps(r, indent=2)) if a.json else render(r)


if __name__ == "__main__":
    main()
