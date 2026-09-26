from reports.report_generator import generate_reports
from pprint import pprint

from detectors.ssh_detector import detect_ssh_attacks
from detectors.web_detector import detect_web_attacks
from core.correlation import correlate_alerts
from core.risk_engine import calculate_risk


def main():
    ssh_alerts = detect_ssh_attacks(
        "data/ssh_sample.log"
    )

    web_alerts = detect_web_attacks(
        "data/access_sample.log"
    )

    all_alerts = ssh_alerts + web_alerts
    incidents = correlate_alerts(all_alerts)

    print("\n=== CYBERLAB-10 RISK REPORT ===")

    results = []

    for incident in incidents:
        # print("\nDEBUG - RISK MOTORUNA GELEN ALARMLAR:")
        # pprint(incident["alerts"])

        result = calculate_risk(incident)
        pprint(result)
        results.append(result)

    paths = generate_reports(results)

    print("\nRAPORLAR OLUSTURULDU")
    print("JSON:", paths["json"])
    print("HTML:", paths["html"])


if __name__ == "__main__":
    main()

