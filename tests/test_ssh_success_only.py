import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHSuccessOnly(unittest.TestCase):

    def test_successful_logins_no_alert(self):
        ip = "192.168.56.60"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            with log_path.open("w", encoding="utf-8") as file:
                for _ in range(10):
                    file.write(
                        f"Accepted password for admin from {ip} "
                        "port 22 ssh2\n"
                    )

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
