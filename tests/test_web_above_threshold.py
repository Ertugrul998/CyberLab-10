import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebAboveThreshold(unittest.TestCase):

    def test_twelve_requests(self):
        ip = "192.168.56.100"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:
                for second in range(12):
                    file.write(
                        f'{ip} - - '
                        f'[25/Sep/2026:12:00:{second:02d} +0300] '
                        '"GET /index.html HTTP/1.1" 200 1024\n'
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
            self.assertEqual(
                alerts[0]["severity"], "MEDIUM"
            )
            self.assertEqual(
                alerts[0]["sensitive_paths"], []
            )


if __name__ == "__main__":
    unittest.main()
