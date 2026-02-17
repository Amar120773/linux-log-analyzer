"""
Reporting Module
----------------
Generates structured security reports from anomaly detection results.
"""

import pandas as pd


def assign_severity(row: pd.Series) -> str:
    """
    Assign severity level based on anomaly signals.
    """
    if row["statistical_spike"]:
        return "CRITICAL"
    elif row["failed_login_count"] > 5:
        return "HIGH"
    elif row["high_failed_logins"] or row["high_unique_ips"]:
        return "MEDIUM"
    else:
        return "NORMAL"


def generate_report(anomaly_df: pd.DataFrame) -> dict:
    """
    Generate summary security report.
    """
    if anomaly_df.empty:
        return {
            "total_windows": 0,
            "anomalous_windows": 0,
            "highest_severity": "NORMAL"
        }

    df = anomaly_df.copy()

    df["severity"] = df.apply(assign_severity, axis=1)

    total_windows = len(df)
    anomalous_windows = df["is_anomaly"].sum()

    severity_order = ["NORMAL", "MEDIUM", "HIGH", "CRITICAL"]
    highest_severity = "NORMAL"

    for level in reversed(severity_order):
        if level in df["severity"].values:
            highest_severity = level
            break

    return {
        "total_windows": total_windows,
        "anomalous_windows": int(anomalous_windows),
        "highest_severity": highest_severity,
        "detailed": df
    }

