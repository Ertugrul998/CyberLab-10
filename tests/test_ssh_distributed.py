import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHDistributed(unittest.TestCase):

    def test_multiple_ips_below_threshold(self):
        ip1 = "192.168.56.20"
        ip2 = "192.168.56.30"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            with log_path.open(
                "w", encoding="utf-8"
            ) as file:

                for _ in range(3):
                    file.write(
                        f"Failed password for root from {ip1} "
                        "port 22 ssh2\n"
                    )

                for _ in range(4):
                    file.write(
                        f"Failed password for admin from {ip2} "
                        "port 22 ssh2\n"
                    )

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
