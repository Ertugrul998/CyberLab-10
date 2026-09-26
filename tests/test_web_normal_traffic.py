import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebNormalTraffic(unittest.TestCase):

    def test_normal_requests_no_alert(self):
        ip = "192.168.56.70"

        paths = [
            "/",
            "/index.html",
            "/about",
            "/contact"
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:
                for path in paths:
                    file.write(
                        f'{ip} - - [25/Sep/2026:12:00:00 +0300] '
                        f'"GET {path} HTTP/1.1" 200 1024\n'
                    )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
