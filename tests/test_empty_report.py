import json
import tempfile
import unittest
from pathlib import Path

from reports.report_generator import generate_reports


class TestEmptyReport(unittest.TestCase):

    def test_empty_incidents(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            paths = generate_reports(
                [],
                output_dir=temp_dir
            )

            json_path = Path(paths["json"])
            html_path = Path(paths["html"])

            self.assertTrue(json_path.is_file())
            self.assertTrue(html_path.is_file())

            with json_path.open(
                encoding="utf-8"
            ) as file:
                data = json.load(file)

            self.assertEqual(
                data["incident_count"], 0
            )

            self.assertEqual(
                data["incidents"], []
            )

            html = html_path.read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "Total incidents: 0",
                html
            )


if __name__ == "__main__":
    unittest.main()
