import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebEmptyLog(unittest.TestCase):

    def test_empty_log_returns_no_alerts(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            log_path.write_text(
                "",
                encoding="utf-8"
            )

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()

