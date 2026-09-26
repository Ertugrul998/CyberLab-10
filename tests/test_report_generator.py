import unittest
import json
import os
import tempfile

from reports.report_generator import generate_reports


class TestReportGenerator(unittest.TestCase):

    def test_json_and_html_reports(self):
        incidents = [
            {
                "ip": "192.168.56.20",
                "attack_types": [
                    "Possible SSH brute force",
                    "Suspicious web activity"
                ],
                "risk_score": 100,
                "risk_level": "CRITICAL"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            paths = generate_reports(
                incidents,
                output_dir=temp_dir
            )

            self.assertTrue(
                os.path.isfile(paths["json"])
            )

            self.assertTrue(
                os.path.isfile(paths["html"])
            )

            with open(
                paths["json"],
                encoding="utf-8"
            ) as file:
                data = json.load(file)

            self.assertEqual(data["incident_count"], 1)

            self.assertEqual(
                data["incidents"][0]["ip"],
                "192.168.56.20"
            )

            self.assertEqual(
                data["incidents"][0]["risk_level"],
                "CRITICAL"
            )

            with open(
                paths["html"],
                encoding="utf-8"
            ) as file:
                html = file.read()

            self.assertIn("192.168.56.20", html)
            self.assertIn("CRITICAL", html)


if __name__ == "__main__":
    unittest.main()
