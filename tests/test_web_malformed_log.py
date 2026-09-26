import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebMalformedLog(unittest.TestCase):

    def test_malformed_lines_are_ignored(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:
                file.write("\n")
                file.write("THIS IS NOT A VALID LOG\n")
                file.write("192.168.56.10 incomplete\n")
                file.write("GET /admin\n")

                file.write(
                    '192.168.56.10 - - '
                    '[25/Sep/2026:12:00:00 +0300] '
                    '"GET /index.html HTTP/1.1" 200 1024\n'
                )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
