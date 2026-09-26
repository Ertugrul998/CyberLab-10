import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebSensitivePath(unittest.TestCase):

    def test_admin_access_generates_alert(self):
        ip = "192.168.56.80"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            log_path.write_text(
                f'{ip} - - [25/Sep/2026:12:00:00 +0300] '
                '"GET /admin HTTP/1.1" 403 512\n',
                encoding="utf-8"
            )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], ip)
            self.assertEqual(alerts[0]["severity"], "HIGH")
            self.assertIn(
                "/admin",
                alerts[0]["sensitive_paths"]
            )
            self.assertEqual(
                alerts[0]["max_requests_per_minute"], 1
            )


if __name__ == "__main__":
    unittest.main()
