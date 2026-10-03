import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from passguard import analyze, history


def kinds(r): return {f["kind"] for f in r["findings"]}


class TestAnalyzer(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(analyze("")["label"], "VERY WEAK")

    def test_common_password(self):
        r = analyze("password"); self.assertIn("common_password", kinds(r)); self.assertEqual(r["label"], "VERY WEAK")

    def test_composition_trap(self):
        r = analyze("Password123!")           # meets 'rules' but predictable
        self.assertIn(r["label"], ("VERY WEAK", "WEAK"))
        self.assertGreater(r["bits_naive"], r["bits_adjusted"] + 20)

    def test_leetspeak(self):
        self.assertIn("common_password", kinds(analyze("P@ssw0rd")))

    def test_repeats(self):
        self.assertIn("repeated_chars", kinds(analyze("xaaaay9")))

    def test_sequence(self):
        self.assertIn("sequence", kinds(analyze("abcd")))
        self.assertIn("sequence", kinds(analyze("zx9876")))

    def test_keyboard(self):
        self.assertIn("keyboard_pattern", kinds(analyze("qwertyZ9")))

    def test_year(self):
        self.assertIn("year", kinds(analyze("kQ8m1987")))

    def test_context(self):
        r = analyze("Rohan#Zq83v!", context=["rohan"])
        self.assertIn("personal_info", kinds(r)); self.assertLessEqual(r["score"], 30)

    def test_long_random_is_strong(self):
        self.assertIn(analyze("k8#Vq!2mZp@x7LwR")["label"], ("STRONG", "VERY STRONG"))

    def test_passphrase_beats_short_complex(self):
        self.assertGreater(analyze("purple-Tractor-lamp-ocean-91")["score"], analyze("Xk9#mQ2")["score"])

    def test_short_capped(self):
        self.assertLessEqual(analyze("Xk9#mQ2!")["score"], 55)

    def test_history_has_no_password(self):
        pw = "Zq83!uniqueSecret"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "h.jsonl"); history.record(analyze(pw), p)
            with open(p) as fh: raw = fh.read()
            self.assertNotIn(pw, raw); self.assertNotIn("Zq83", raw)
            self.assertEqual(history.summary(p)["count"], 1)


if __name__ == "__main__":
    unittest.main()
