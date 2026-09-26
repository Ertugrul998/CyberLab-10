def calculate_risk(incident):
    score = 0

    for alert in incident["alerts"]:
        attack_type = alert.get("type", "")

        if attack_type == "Possible SSH brute force":
            score += 30

            if alert.get("successful_login"):
                score += 35

        elif attack_type == "Suspicious web activity":
            score += 20

            if alert.get("sensitive_paths"):
                score += 15

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        **incident,
        "risk_score": score,
        "risk_level": level
    }

