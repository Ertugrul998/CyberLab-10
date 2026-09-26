import unittest

from core.correlation import correlate_alerts
from core.risk_engine import calculate_risk


class TestCombinedRisk(unittest.TestCase):

    def test_ssh_and_web_risk_score(self):
        ip = "192.168.56.200"

        alerts = [
            {
                "ip": ip,
                "type": "Possible SSH brute force",
                "severity": "HIGH",
                "successful_login": False
            },
            {
                "ip": ip,
                "type": "Suspicious web activity",
                "severity": "HIGH",
                "sensitive_paths": ["/admin"]
            }
        ]

        incidents = correlate_alerts(alerts)

        self.assertEqual(len(incidents), 1)

        result = calculate_risk(incidents[0])

        self.assertEqual(result["ip"], ip)
        self.assertEqual(result["alert_count"], 2)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["risk_score"], 65)
        self.assertEqual(result["risk_level"], "HIGH")


if __name__ == "__main__":
    unittest.main()

