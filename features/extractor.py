"""
Feature Extraction Module
-------------------------
Converts Event objects into time-windowed metrics.
"""

from typing import List
import pandas as pd
from events.event import Event


def extract_features(events: List[Event], window_minutes: int = 10) -> pd.DataFrame:
    """
    Aggregate events into time windows and compute metrics.

    Metrics:
    - failed_login_count
    - unique_ip_count
    - unique_user_count
    """
    if not events:
        return pd.DataFrame()

    # Convert Event objects to DataFrame
    df = pd.DataFrame({
        "timestamp": [e.timestamp for e in events],
        "event_type": [e.event_type for e in events],
        "user": [e.user for e in events],
        "ip": [e.ip for e in events],
    })

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Create time window
    window = f"{window_minutes}min"
    df["window_start"] = df["timestamp"].dt.floor(window)

    # Aggregate metrics
    features = (
        df.groupby("window_start")
          .agg(
              failed_login_count=("event_type", lambda x: (x == "login_failed").sum()),
              unique_ip_count=("ip", "nunique"),
              unique_user_count=("user", "nunique"),
          )
          .reset_index()
    )

    return features
