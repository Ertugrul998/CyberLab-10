import unittest
import tempfile
import os

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHThreshold(unittest.TestCase):

    def test_multiple_failed_attempts(self):
        ip = "192.168.56.20"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "auth.log")

            with open(log_path, "w", encoding="utf-8") as file:
                for _ in range(6):
                    file.write(
                        f"Failed password for root from {ip} "
                        "port 22 ssh2\n"
                    )

            alerts = detect_ssh_attacks(log_path, threshold=5)

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)
            self.assertEqual(alerts[0]["failed_attempts"], 6)
            self.assertEqual(alerts[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
