#!/usr/bin/env python3
"""One command to run everything:  python run_all.py   (add --no-dashboard to skip the web UI)"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def step(title):
    print(f"\n{'=' * 60}\n {title}\n{'=' * 60}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()

    step("1/3  Running unit tests")
    if subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT) != 0:
        sys.exit("Tests failed. Fix them before continuing.")

    step("2/3  Demo analysis (synthetic passwords only)")
    from passguard import analyze
    print(f"{'Demo password':<34}{'Score':>6}  {'Label':<12}{'Naive':>7}{'Adj.':>7}")
    with open(os.path.join(ROOT, "data", "demo_passwords.txt"), encoding="utf-8") as fh:
        for line in fh:
            pw = line.rstrip("\n")
            if not pw or pw.startswith("#"):
                continue
            r = analyze(pw)
            print(f"{pw:<34}{r['score']:>6}  {r['label']:<12}{r['bits_naive']:>7}{r['bits_adjusted']:>7}")

    if a.no_dashboard:
        return
    step("3/3  Starting dashboard")
    from passguard.dashboard import serve
    serve(a.port)


if __name__ == "__main__":
    main()
