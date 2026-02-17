"""
Auth Log Parser
---------------
Parses Linux auth.log lines into structured records.
"""

import re
from datetime import datetime
from typing import Optional, Dict

# Regex for auth.log
AUTH_LOG_REGEX = re.compile(
    r"""
    ^(?P<month>\w{3})\s+
    (?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<process>\w+)\[\d+\]:\s+
    (?P<message>.*)$
    """,
    re.VERBOSE,
)

IP_REGEX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def parse_auth_log_line(line: str) -> Optional[Dict]:
    """
    Parse a single auth.log line.

    Returns a dictionary or None if parsing fails.
    """
    match = AUTH_LOG_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Build timestamp (auth.log has no year)
    now = datetime.now()
    timestamp_str = f"{data['month']} {data['day']} {now.year} {data['time']}"
    timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")

    # Extract IP if present
    ip_match = IP_REGEX.search(data["message"])
    ip_address = ip_match.group(0) if ip_match else None

    # Extract username (simple heuristic)
    user = None
    if " for " in data["message"]:
        try:
            user = data["message"].split(" for ")[1].split()[0]
        except IndexError:
            pass

    return {
        "timestamp": timestamp,
        "process": data["process"],
        "message": data["message"],
        "user": user,
        "ip": ip_address,
    }
