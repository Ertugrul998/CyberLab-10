import unittest

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHDetector(unittest.TestCase):

    def test_ssh_attack_detection(self):
        alerts = detect_ssh_attacks(
            "data/ssh_sample.log"
        )

        self.assertGreater(len(alerts), 0)

        for alert in alerts:
            self.assertEqual(
                alert["type"],
                "Possible SSH brute force"
            )

            self.assertIn("ip", alert)
            self.assertIn("failed_attempts", alert)
            self.assertIn("successful_login", alert)


if __name__ == "__main__":
    unittest.main()
