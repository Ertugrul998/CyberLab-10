import unittest

from core.correlation import correlate_alerts


class TestCorrelation(unittest.TestCase):

    def test_same_ip_combines_alerts(self):
        alerts = [
            {
                "ip": "192.168.56.20",
                "type": "Possible SSH brute force",
                "severity": "HIGH"
            },
            {
                "ip": "192.168.56.20",
                "type": "Suspicious web activity",
                "severity": "HIGH"
            }
        ]

        incidents = correlate_alerts(alerts)

        self.assertEqual(len(incidents), 1)

        incident = incidents[0]

        self.assertEqual(incident["alert_count"], 2)
        self.assertEqual(incident["ip"], "192.168.56.20")
        self.assertEqual(incident["severity"], "CRITICAL")
        self.assertEqual(len(incident["attack_types"]), 2)

    def test_different_ips_separate_incidents(self):
        alerts = [
            {
                "ip": "192.168.56.20",
                "type": "Possible SSH brute force",
                "severity": "HIGH"
            },
            {
                "ip": "192.168.56.30",
                "type": "Suspicious web activity",
                "severity": "HIGH"
            }
        ]

        incidents = correlate_alerts(alerts)

        self.assertEqual(len(incidents), 2)

        ips = {incident["ip"] for incident in incidents}

        self.assertEqual(
            ips,
            {"192.168.56.20", "192.168.56.30"}
        )

if __name__ == "__main__":
    unittest.main()
