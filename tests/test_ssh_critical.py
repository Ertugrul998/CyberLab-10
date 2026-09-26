import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHCritical(unittest.TestCase):

    def test_failed_then_successful_login(self):
        ip = "192.168.56.50"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            with log_path.open("w", encoding="utf-8") as file:
                for _ in range(5):
                    file.write(
                        f"Failed password for root from {ip} "
                        "port 22 ssh2\n"
                    )

                file.write(
                    f"Accepted password for root from {ip} "
                    "port 22 ssh2\n"
                )

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)
            self.assertEqual(alerts[0]["failed_attempts"], 5)
            self.assertTrue(alerts[0]["successful_login"])
            self.assertEqual(alerts[0]["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
