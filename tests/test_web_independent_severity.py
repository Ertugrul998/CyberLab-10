import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebIndependentSeverity(unittest.TestCase):

    def test_different_ips_different_severity(self):
        traffic_ip = "192.168.56.40"
        admin_ip = "192.168.56.50"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:

                for second in range(12):
                    file.write(
                        f'{traffic_ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /index.html HTTP/1.1" 200 1024\n'
                    )

                file.write(
                    f'{admin_ip} - - '
                    '[25/Sep/2026:12:00:20 +0300] '
                    '"GET /admin HTTP/1.1" 403 512\n'
                )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 2)

            results = {
                alert["ip"]: alert
                for alert in alerts
            }

            self.assertEqual(
                results[traffic_ip]["severity"],
                "MEDIUM"
            )
            self.assertEqual(
                results[traffic_ip]["max_requests_per_minute"],
                12
            )
            self.assertEqual(
                results[traffic_ip]["sensitive_paths"],
                []
            )

            self.assertEqual(
                results[admin_ip]["severity"],
                "HIGH"
            )
            self.assertEqual(
                results[admin_ip]["max_requests_per_minute"],
                1
            )
            self.assertIn(
                "/admin",
                results[admin_ip]["sensitive_paths"]
            )


if __name__ == "__main__":
    unittest.main()
