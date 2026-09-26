import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHBelowThreshold(unittest.TestCase):

    def test_four_failed_attempts_no_alert(self):
        ip = "192.168.56.40"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            with log_path.open("w", encoding="utf-8") as file:
                for _ in range(4):
                    file.write(
                        f"Failed password for root from {ip} "
                        "port 22 ssh2\n"
                    )

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
