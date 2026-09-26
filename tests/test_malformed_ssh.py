import tempfile
import unittest
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks


class TestMalformedSSH(unittest.TestCase):

    def test_malformed_log(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "broken.log"

            log_path.write_text(
                "THIS IS NOT AN SSH LOG\n"
                "12345 ??? INVALID DATA\n"
                "\n"
                "random text without an IP\n",
                encoding="utf-8"
            )

            alerts = detect_ssh_attacks(str(log_path))

            self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
