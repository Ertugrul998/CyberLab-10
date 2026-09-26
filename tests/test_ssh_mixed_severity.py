import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHMixedSeverity(unittest.TestCase):

    def test_two_ips_different_severity(self):
        ip1 = "192.168.56.20"
        ip2 = "192.168.56.30"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            with log_path.open("w", encoding="utf-8") as file:
                for _ in range(6):
                    file.write(
                        f"Failed password for root from {ip1} "
                        "port 22 ssh2\n"
                    )

                file.write(
                    f"Accepted password for root from {ip1} "
                    "port 22 ssh2\n"
                )

                for _ in range(5):
                    file.write(
                        f"Failed password for admin from {ip2} "
                        "port 22 ssh2\n"
                    )

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(len(alerts), 2)

            results = {
                alert["ip"]: alert
                for alert in alerts
            }

            self.assertEqual(
                results[ip1]["severity"], "CRITICAL"
            )
            self.assertTrue(
                results[ip1]["successful_login"]
            )

            self.assertEqual(
                results[ip2]["severity"], "HIGH"
            )
            self.assertFalse(
                results[ip2]["successful_login"]
            )


if __name__ == "__main__":
    unittest.main()
