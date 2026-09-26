import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebTimeWindow(unittest.TestCase):

    def test_requests_in_different_minutes(self):
        ip = "192.168.56.120"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:

                for second in range(6):
                    file.write(
                        f'{ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /index.html HTTP/1.1" 200 1024\n'
                    )

                for second in range(6):
                    file.write(
                        f'{ip} - - '
                        f'[25/Sep/2026:12:01:{second:02d} +0300] '
                        '"GET /about HTTP/1.1" 200 1024\n'
                    )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
