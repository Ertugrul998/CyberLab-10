import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHExactThreshold(unittest.TestCase):

    def test_exactly_five_failed_attempts(self):
        ip = "192.168.56.30"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            with log_path.open("w", encoding="utf-8") as file:
                for _ in range(5):
                    file.write(
                        f"Failed password for root from {ip} "
                        "port 22 ssh2\n"
                    )

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)
            self.assertEqual(alerts[0]["failed_attempts"], 5)
            self.assertEqual(alerts[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
