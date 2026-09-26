import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebHTTPMethods(unittest.TestCase):

    def test_get_and_post_sensitive_path(self):
        ip = "192.168.56.170"

        requests = [
            ("GET", "/admin", 403),
            ("POST", "/admin", 401)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:
                for second, (method, path, status) in enumerate(requests):
                    file.write(
                        f'{ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        f'"{method} {path} HTTP/1.1" '
                        f'{status} 512\n'
                    )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)

            self.assertEqual(
                alerts[0]["severity"],
                "HIGH"
            )

            self.assertIn(
                "/admin",
                alerts[0]["sensitive_paths"]
            )

            self.assertEqual(
                alerts[0]["max_requests_per_minute"],
                2
            )


if __name__ == "__main__":
    unittest.main()
