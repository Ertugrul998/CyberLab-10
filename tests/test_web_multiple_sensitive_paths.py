import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebMultipleSensitivePaths(unittest.TestCase):

    def test_three_sensitive_paths(self):
        ip = "192.168.56.160"

        requests = [
            ("/admin", 403),
            ("/.env", 404),
            ("/phpmyadmin", 403)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:
                for second, (path, status) in enumerate(requests):
                    file.write(
                        f'{ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        f'"GET {path} HTTP/1.1" '
                        f'{status} 512\n'
                    )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)
            self.assertEqual(alerts[0]["severity"], "HIGH")

            sensitive_paths = alerts[0]["sensitive_paths"]

            self.assertIn("/admin", sensitive_paths)
            self.assertIn("/.env", sensitive_paths)
            self.assertIn("/phpmyadmin", sensitive_paths)

            self.assertEqual(
                alerts[0]["max_requests_per_minute"],
                3
            )


if __name__ == "__main__":
    unittest.main()
