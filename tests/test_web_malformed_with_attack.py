import unittest
import tempfile
from pathlib import Path

from detectors.web_detector import detect_web_attacks


class TestWebMalformedWithAttack(unittest.TestCase):

    def test_valid_attack_among_malformed_lines(self):
        attacker_ip = "192.168.56.140"
        normal_ip = "192.168.56.150"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "access.log"

            with log_path.open("w", encoding="utf-8") as file:
                file.write("\n")
                file.write("INVALID LOG LINE\n")
                file.write("GET /admin\n")

                file.write(
                    f'{normal_ip} - - '
                    '[25/Sep/2026:12:00:00 +0300] '
                    '"GET /index.html HTTP/1.1" 200 1024\n'
                )

                file.write(
                    f'{attacker_ip} - - '
                    '[25/Sep/2026:12:00:01 +0300] '
                    '"GET /admin HTTP/1.1" 403 512\n'
                )

                file.write("BROKEN HTTP REQUEST\n")

            alerts = detect_web_attacks(
                str(log_path),
                threshold=10
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(
                alerts[0]["ip"],
                attacker_ip
            )
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
                1
            )


if __name__ == "__main__":
    unittest.main()
