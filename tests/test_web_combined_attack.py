import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebCombinedAttack(unittest.TestCase):

    def test_high_traffic_and_sensitive_path(self):
        ip = "192.168.56.130"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:

                for second in range(11):
                    file.write(
                        f'{ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /index.html HTTP/1.1" 200 1024\n'
                    )

                file.write(
                    f'{ip} - - '
                    '[25/Sep/2026:12:00:11 +0300] '
                    '"GET /admin HTTP/1.1" 403 512\n'
                )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)

            self.assertEqual(
                alerts[0]["max_requests_per_minute"], 12
            )

            self.assertIn(
                "/admin",
                alerts[0]["sensitive_paths"]
            )

            self.assertEqual(
                alerts[0]["severity"], "HIGH"
            )


if __name__ == "__main__":
    unittest.main()
