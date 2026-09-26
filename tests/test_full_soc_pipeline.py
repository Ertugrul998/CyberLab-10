import unittest
import tempfile
import json
from pathlib import Path

from detectors.ssh_detector import detect_ssh_attacks
from detectors.web_detector import detect_web_attacks
from core.correlation import correlate_alerts
from core.risk_engine import calculate_risk
from reports.report_generator import generate_reports


class TestFullSOCPipeline(unittest.TestCase):

    def test_complete_soc_pipeline(self):
        ip = "192.168.56.250"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)

            ssh_log = temp / "auth.log"
            web_log = temp / "access.log"
            report_dir = temp / "reports"

            # 1. SSH saldirisi
            with ssh_log.open(
                "w", encoding="utf-8"
            ) as file:
                for _ in range(6):
                    file.write(
                        f"Failed password for root from {ip} "
                        "port 22 ssh2\n"
                    )

                file.write(
                    f"Accepted password for root from {ip} "
                    "port 22 ssh2\n"
                )

            # 2. Hassas web adresine erisim
            web_log.write_text(
                f'{ip} - - '
                '[25/Sep/2026:12:00:00 +0300] '
                '"GET /admin HTTP/1.1" 403 512\n',
                encoding="utf-8"
            )

            # 3. Dedektorleri calistir
            ssh_alerts = detect_ssh_attacks(
                str(ssh_log),
                threshold=5
            )

            web_alerts = detect_web_attacks(
                str(web_log),
                threshold=10
            )

            self.assertEqual(len(ssh_alerts), 1)
            self.assertEqual(len(web_alerts), 1)

            # 4. Olaylari birlestir
            incidents = correlate_alerts(
                ssh_alerts + web_alerts
            )

            self.assertEqual(len(incidents), 1)

            # 5. Risk puanini hesapla
            incident = calculate_risk(incidents[0])

            self.assertEqual(incident["ip"], ip)
            self.assertEqual(
                incident["alert_count"], 2
            )
            self.assertEqual(
                incident["risk_score"], 100
            )
            self.assertEqual(
                incident["risk_level"], "CRITICAL"
            )

            # 6. JSON ve HTML raporlarini uret
            paths = generate_reports(
                [incident],
                output_dir=report_dir
            )

            json_path = Path(paths["json"])
            html_path = Path(paths["html"])

            self.assertTrue(json_path.is_file())
            self.assertTrue(html_path.is_file())

            # 7. JSON raporunu dogrula
            with json_path.open(
                "r", encoding="utf-8"
            ) as file:
                report = json.load(file)

            self.assertEqual(
                report["incident_count"], 1
            )
            self.assertEqual(
                report["incidents"][0]["ip"], ip
            )
            self.assertEqual(
                report["incidents"][0]["risk_score"],
                100
            )

            # 8. HTML raporunu dogrula
            html = html_path.read_text(
                encoding="utf-8"
            )

            self.assertIn(ip, html)
            self.assertIn("CRITICAL", html)


if __name__ == "__main__":
    unittest.main()
