import unittest

from core.risk_engine import calculate_risk


class TestRiskEngine(unittest.TestCase):

    def test_no_alerts(self):
        result = calculate_risk({"alerts": []})

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_ssh_failed_attempts(self):
        incident = {
            "alerts": [
                {
                    "type": "Possible SSH brute force",
                    "successful_login": False
                }
            ]
        }

        result = calculate_risk(incident)

        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_ssh_successful_login(self):
        incident = {
            "alerts": [
                {
                    "type": "Possible SSH brute force",
                    "successful_login": True
                }
            ]
        }

        result = calculate_risk(incident)

        self.assertEqual(result["risk_score"], 65)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_combined_attack(self):
        incident = {
            "alerts": [
                {
                    "type": "Possible SSH brute force",
                    "successful_login": True
                },
                {
                    "type": "Suspicious web activity",
                    "sensitive_paths": ["/.env", "/admin"]
                }
            ]
        }

        result = calculate_risk(incident)

        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
