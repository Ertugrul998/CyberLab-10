import unittest

from detectors.web_detector import detect_web_attacks


class TestWebDetector(unittest.TestCase):

    def test_web_attack_detection(self):
        alerts = detect_web_attacks(
            "data/access_sample.log"
        )

        self.assertGreater(len(alerts), 0)

        for alert in alerts:
            self.assertEqual(
                alert["type"],
                "Suspicious web activity"
            )

            self.assertIn("ip", alert)
            self.assertIn("sensitive_paths", alert)
            self.assertIn("max_requests_per_minute", alert)


if __name__ == "__main__":
    unittest.main()
