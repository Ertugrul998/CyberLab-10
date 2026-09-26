import unittest

from core.correlation import correlate_alerts
from core.risk_engine import calculate_risk


class TestRiskScoreCap(unittest.TestCase):

    def test_risk_score_cannot_exceed_100(self):
        ip = "192.168.56.240"

        alerts = [
            {
                "ip": ip,
                "type": "Possible SSH brute force",
                "severity": "CRITICAL",
                "successful_login": True
            },
            {
                "ip": ip,
                "type": "Suspicious web activity",
                "severity": "HIGH",
                "sensitive_paths": ["/admin"]
            },
            {
                "ip": ip,
                "type": "Suspicious web activity",
                "severity": "HIGH",
                "sensitive_paths": ["/.env"]
            }
        ]

        incidents = correlate_alerts(alerts)

        self.assertEqual(len(incidents), 1)

        result = calculate_risk(incidents[0])

        self.assertEqual(result["ip"], ip)
        self.assertEqual(result["alert_count"], 3)

        self.assertEqual(
            result["risk_score"],
            100
        )

        self.assertEqual(
            result["risk_level"],
            "CRITICAL"
        )


if __name__ == "__main__":
    unittest.main()
