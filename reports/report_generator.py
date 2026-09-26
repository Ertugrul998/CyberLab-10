import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path


def generate_reports(incidents, output_dir="output"):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat()

    report = {
        "project": "CyberLab-10",
        "generated_at": timestamp,
        "incident_count": len(incidents),
        "incidents": incidents
    }

    # JSON raporu
    json_path = output / "soc_report.json"

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    # HTML raporu
    rows = []

    for incident in incidents:
        ip = escape(str(incident.get("ip", "Unknown")))
        score = escape(str(incident.get("risk_score", 0)))
        level = escape(str(incident.get("risk_level", "Unknown")))

        attacks = ", ".join(
            escape(str(attack))
            for attack in incident.get("attack_types", [])
        )

        rows.append(
            f"<tr><td>{ip}</td><td>{attacks}</td>"
            f"<td>{score}</td><td>{level}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CyberLab-10 SOC Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #101827;
            color: #e5e7eb;
            padding: 40px;
        }}
        h1 {{ color: #38bdf8; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
        }}
        th, td {{
            padding: 14px;
            border: 1px solid #475569;
            text-align: left;
        }}
        th {{ background: #334155; }}
    </style>
</head>
<body>
    <h1>CyberLab-10 SOC Report</h1>
    <p>Generated: {escape(timestamp)}</p>
    <p>Total incidents: {len(incidents)}</p>

    <table>
        <tr>
            <th>IP Address</th>
            <th>Attack Types</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
        </tr>
        {''.join(rows)}
    </table>
</body>
</html>"""

    html_path = output / "soc_report.html"
    html_path.write_text(html, encoding="utf-8")

    return {
        "json": str(json_path),
        "html": str(html_path)
    }

