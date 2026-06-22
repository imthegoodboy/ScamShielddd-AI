import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "executas"
    / "scamshield-analyzer"
    / "scamshield_analyzer.py"
)
spec = importlib.util.spec_from_file_location("scamshield_analyzer", MODULE_PATH)
scamshield = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = scamshield
spec.loader.exec_module(scamshield)


class ScamShieldAnalyzerTests(unittest.TestCase):
    def test_job_fee_is_high_risk(self):
        result = scamshield.tool_investigate(
            mode="job",
            text=(
                "Amazon Work From Home. Salary Rs 60,000/month. "
                "Pay registration fee Rs 500 immediately to receive interview letter."
            ),
        )
        self.assertGreaterEqual(result["score"], 80)
        self.assertIn(result["verdict"], {"dangerous", "high_risk"})
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Job offer asks for money", titles)
        self.assertIn("Upfront payment request", titles)

    def test_lookalike_url_is_flagged(self):
        result = scamshield.tool_investigate(
            mode="website",
            url="amaz0n-sale-offers.xyz",
            text="Verify your account immediately.",
        )
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Possible brand impersonation", titles)
        self.assertIn("Higher-risk domain ending", titles)

    def test_safe_text_stays_low_risk(self):
        result = scamshield.tool_investigate(
            mode="message",
            text="Can we move our meeting agenda to 3 PM tomorrow?",
        )
        self.assertLess(result["score"], 30)
        self.assertEqual(result["verdict"], "low_risk")


if __name__ == "__main__":
    unittest.main()
