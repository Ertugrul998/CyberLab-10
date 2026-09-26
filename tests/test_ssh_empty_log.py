import unittest
import tempfile
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestSSHEmptyLog(unittest.TestCase):

    def test_empty_log_returns_no_alerts(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"

            log_path.write_text("", encoding="utf-8")

            alerts = detect_ssh_attacks(
                str(log_path),
                threshold=5
            )

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
