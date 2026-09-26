import re
from collections import defaultdict

FAILED_PATTERN= re.compile(
    r"Failed password for (?:invalid user )?\S+ "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for \S+ "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def detect_ssh_attacks(log_path, threshold=5):
    failed_attempts = defaultdict(int)
    successful_logins = set()

    with open(log_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            failed = FAILED_PATTERN.search(line)
            success = SUCCESS_PATTERN.search(line)

            if failed:
                ip = failed.group("ip")
                failed_attempts[ip] +=1

            if success:
                successful_logins.add(
                    success.group("ip")
                )

    alerts = []

    for ip, count in failed_attempts.items():
        if count >= threshold:
            alerts.append({
                "ip": ip,
                "type": "Possible SSH brute force",
                "failed_attempts": count,
                "successful_login": ip in successful_logins,
                "severity": (
                    "CRITICAL"
                    if ip in successful_logins
                    else "HIGH"

                ),
                "mitre": "T1110"
            })

    return alerts

