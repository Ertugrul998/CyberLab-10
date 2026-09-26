from collections import defaultdict


def correlate_alerts(alerts):
    grouped = defaultdict(list)

    for alert in alerts:
        grouped[alert["ip"]].append(alert)

    incidents = []

    for ip, ip_alerts in grouped.items():
        types = {alert["type"] for alert in ip_alerts}

        severity = (
            "CRITICAL"
            if len(types) > 1
            else ip_alerts[0]["severity"]
        )

        incidents.append({
            "ip": ip,
            "alert_count": len(ip_alerts),
            "attack_types": sorted(types),
            "severity": severity,
            "alerts": ip_alerts
        })

    return incidents

