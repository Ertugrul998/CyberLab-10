import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks
from detectors.web_detector import detect_web_attacks
from core.correlation import correlate_alerts


class TestSSHWebIntegration(unittest.TestCase):

    def test_same_ip_ssh_and_web_attacks(self):
        ip = "192.168.56.200"

        with tempfile.TemporaryDirectory() as temp_dir:
            ssh_log = Path(temp_dir) / "auth.log"
            web_log = Path(temp_dir) / "access.log"

            with ssh_log.open("w", encoding="utf-8") as file:
                for _ in range(6):
                    file.write(
                        f"Failed password for root from {ip} "
                        "port 22 ssh2\n"
                    )

            web_log.write_text(
                f'{ip} - - '
                '[25/Sep/2026:12:00:00 +0300] '
                '"GET /admin HTTP/1.1" 403 512\n',
                encoding="utf-8"
            )

            ssh_alerts = detect_ssh_attacks(
                str(ssh_log),
                threshold=5
            )

            web_alerts = detect_web_attacks(
                str(web_log),
                threshold=10
            )

            self.assertEqual(len(ssh_alerts), 1)
            self.assertEqual(len(web_alerts), 1)

            incidents = correlate_alerts(
                ssh_alerts + web_alerts
            )

            self.assertEqual(len(incidents), 1)

            incident = incidents[0]

            self.assertEqual(incident["ip"], ip)
            self.assertEqual(incident["alert_count"], 2)
            self.assertEqual(
                incident["severity"],
                "CRITICAL"
            )

            self.assertEqual(
                set(incident["attack_types"]),
                {
                    "Possible SSH brute force",
                    "Suspicious web activity"
                }
            )


if __name__ == "__main__":
    unittest.main()
