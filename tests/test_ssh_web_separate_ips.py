import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks
from detectors.web_detector import detect_web_attacks
from core.correlation import correlate_alerts


class TestSSHWebSeparateIPs(unittest.TestCase):

    def test_different_ips_create_separate_incidents(self):
        ssh_ip = "192.168.56.210"
        web_ip = "192.168.56.220"

        with tempfile.TemporaryDirectory() as temp_dir:
            ssh_log = Path(temp_dir) / "auth.log"
            web_log = Path(temp_dir) / "access.log"

            with ssh_log.open("w", encoding="utf-8") as file:
                for _ in range(6):
                    file.write(
                        f"Failed password for root from {ssh_ip} "
                        "port 22 ssh2\n"
                    )

            web_log.write_text(
                f'{web_ip} - - '
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

            self.assertEqual(len(incidents), 2)

            results = {
                incident["ip"]: incident
                for incident in incidents
            }

            self.assertEqual(
                set(results),
                {ssh_ip, web_ip}
            )

            self.assertEqual(
                results[ssh_ip]["alert_count"],
                1
            )
            self.assertEqual(
                results[web_ip]["alert_count"],
                1
            )

            self.assertEqual(
                results[ssh_ip]["severity"],
                "HIGH"
            )
            self.assertEqual(
                results[web_ip]["severity"],
                "HIGH"
            )

            self.assertEqual(
                results[ssh_ip]["attack_types"],
                ["Possible SSH brute force"]
            )
            self.assertEqual(
                results[web_ip]["attack_types"],
                ["Suspicious web activity"]
            )


if __name__ == "__main__":
    unittest.main()
