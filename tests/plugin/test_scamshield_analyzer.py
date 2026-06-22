import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


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

    def test_network_probe_blocks_literal_private_ip(self):
        result = scamshield.tool_investigate(
            mode="website",
            url="https://127.0.0.1/admin",
            allow_network=True,
        )
        probe = result["url_preview"]["network_probe"]
        self.assertFalse(probe["ok"])
        self.assertTrue(probe["blocked"])
        self.assertIn("non-public IP", probe["error"])

    def test_network_probe_blocks_private_dns_resolution(self):
        with patch.object(
            scamshield.socket,
            "getaddrinfo",
            return_value=[(scamshield.socket.AF_INET, scamshield.socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))],
        ):
            result = scamshield.tool_investigate(
                mode="website",
                url="https://example.test",
                allow_network=True,
            )
        probe = result["url_preview"]["network_probe"]
        self.assertFalse(probe["ok"])
        self.assertTrue(probe["blocked"])
        self.assertIn("non-public IP space", probe["error"])


if __name__ == "__main__":
    unittest.main()
