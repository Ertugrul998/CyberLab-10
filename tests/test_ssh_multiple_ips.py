import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHMultipleIPs(unittest.TestCase):

    def test_two_attackers(self):
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
                results[ip1]["failed_attempts"], 6
            )
            self.assertEqual(
                results[ip2]["failed_attempts"], 5
            )

            self.assertEqual(
                results[ip1]["severity"], "HIGH"
            )
            self.assertEqual(
                results[ip2]["severity"], "HIGH"
            )


if __name__ == "__main__":
    unittest.main()
