"""Offline tests: the policy and the input handling. No network calls (the feeds are stubbed)."""
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import triage  # noqa: E402


class TierPolicy(unittest.TestCase):
    def test_every_combination(self):
        # (in_kev, epss, exposed) -> expected tier
        cases = [
            ((True, 0.00, True), "T0"),
            ((True, 0.00, False), "T1"),
            ((False, 0.50, True), "T1"),
            ((False, 0.50, False), "T2"),
            ((False, 0.01, True), "T2"),
            ((False, 0.01, False), "T3"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(triage.tier(*args)[0], expected)

    def test_threshold_is_inclusive(self):
        self.assertEqual(triage.tier(False, 0.10, False)[0], "T2")
        self.assertEqual(triage.tier(False, 0.0999, False)[0], "T3")

    def test_custom_threshold(self):
        self.assertEqual(triage.tier(False, 0.05, True, threshold=0.05)[0], "T1")

    def test_deadlines(self):
        self.assertEqual(triage.tier(True, 0, True), ("T0", 3))
        self.assertEqual(triage.tier(False, 0, False), ("T3", None))


class Cli(unittest.TestCase):
    def run_main(self, argv, kev=(), epss=None):
        out = io.StringIO()
        with (mock.patch.object(triage, "load_kev", return_value=set(kev)),
              mock.patch.object(triage, "load_epss", return_value=epss or {}),
              redirect_stdout(out)):
            code = triage.main(argv)
        return code, out.getvalue()

    def test_table_output(self):
        code, out = self.run_main(["--exposed", "CVE-2021-44228"], kev={"CVE-2021-44228"},
                                  epss={"CVE-2021-44228": (0.97, 1.0)})
        self.assertEqual(code, 0)
        self.assertIn("T0  fix within 3 days", out)

    def test_fail_on_gate(self):
        code, _ = self.run_main(["--fail-on", "T1", "CVE-2021-44228"], kev={"CVE-2021-44228"})
        self.assertEqual(code, 1)  # KEV but not exposed is T1, which is at the limit
        code, _ = self.run_main(["--fail-on", "T0", "CVE-2021-44228"], kev={"CVE-2021-44228"})
        self.assertEqual(code, 0)

    def test_dedupes_and_normalises(self):
        args = triage.argparse.Namespace(cves=["cve-2021-44228", "CVE-2021-44228 "], file=None)
        self.assertEqual(triage.read_cves(args), ["CVE-2021-44228"])

    def test_rejects_garbage(self):
        args = triage.argparse.Namespace(cves=["log4shell"], file=None)
        with self.assertRaises(SystemExit):
            triage.read_cves(args)


if __name__ == "__main__":
    unittest.main()
