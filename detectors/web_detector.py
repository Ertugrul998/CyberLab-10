import re
from collections import defaultdict
from datetime import datetime, timedelta

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) .*?'
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3})'
)

SENSITIVE_PATHS = (
    "/admin",
    "/.env",
    "/.git",
    "/phpmyadmin",
    "/wp-admin",
    "/etc/passwd"
)


def detect_web_attacks(log_path, threshold=10):
    requests = defaultdict(list)
    sensitive_hits = defaultdict(list)

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            match = LOG_PATTERN.search(line)

            if not match:
                continue

            ip = match.group("ip")
            path = match.group("path")

            timestamp = datetime.strptime(
                match.group("time").split()[0],
                "%d/%b/%Y:%H:%M:%S"
            )

            requests[ip].append(timestamp)

            if any(
                path.lower().startswith(item)
                for item in SENSITIVE_PATHS
            ):
                sensitive_hits[ip].append(path)

    alerts = []

    for ip, timestamps in requests.items():
        timestamps.sort()
        left = 0
        max_requests = 0

        for right, current in enumerate(timestamps):
            while (
                current - timestamps[left]
                > timedelta(minutes=1)
            ):
                left += 1

            max_requests = max(
                max_requests,
                right - left + 1
            )

        hits = sensitive_hits[ip]

        if max_requests >= threshold or hits:
            alerts.append({
                "ip": ip,
                "type": "Suspicious web activity",
                "max_requests_per_minute": max_requests,
                "sensitive_paths": sorted(set(hits)),
                "severity": (
                    "HIGH" if hits else "MEDIUM"
                ),
                "mitre": "T1595.003"
            })

    return alerts
