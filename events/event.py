"""
Event Model
-----------
Represents a normalized security-relevant event.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    timestamp: datetime
    event_type: str
    user: Optional[str]
    ip: Optional[str]
    raw_message: str

def classify_event(parsed_record: dict) -> Event:
    """
    Convert parsed log record into an Event.
    """
    message = parsed_record["message"]

    if "Failed password" in message:
        event_type = "login_failed"
    elif "Accepted password" in message:
        event_type = "login_success"
    else:
        event_type = "unknown"

    return Event(
        timestamp=parsed_record["timestamp"],
        event_type=event_type,
        user=parsed_record.get("user"),
        ip=parsed_record.get("ip"),
        raw_message=message,
    )
