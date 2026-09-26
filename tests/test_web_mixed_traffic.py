import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebMixedTraffic(unittest.TestCase):

    def test_only_suspicious_ip_generates_alert(self):
        normal_ip1 = "192.168.56.10"
        suspicious_ip = "192.168.56.20"
        normal_ip2 = "192.168.56.30"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:

                for second in range(4):
                    file.write(
                        f'{normal_ip1} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /index.html HTTP/1.1" 200 1024\n'
                    )

                for second in range(12):
                    file.write(
                        f'{suspicious_ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /about HTTP/1.1" 200 1024\n'
                    )

                for second in range(3):
                    file.write(
                        f'{normal_ip2} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /contact HTTP/1.1" 200 1024\n'
                    )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(
                alerts[0]["ip"],
                suspicious_ip
            )
            self.assertEqual(
                alerts[0]["max_requests_per_minute"],
                12
            )
            self.assertEqual(
                alerts[0]["severity"],
                "MEDIUM"
            )
            self.assertEqual(
                alerts[0]["sensitive_paths"],
                []
            )


if __name__ == "__main__":
    unittest.main()
