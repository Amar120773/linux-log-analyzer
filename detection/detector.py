"""
Anomaly Detection Module
------------------------
Applies rule-based anomaly detection on aggregated features.
"""

import pandas as pd


def detect_anomalies(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect suspicious time windows using simple threshold rules.

    Rules:
    - failed_login_count > 3
    - unique_ip_count > 3
    - failed_login_count significantly higher than usual
    """

    if features_df.empty:
        return features_df

    df = features_df.copy()

    # Basic thresholds
    df["high_failed_logins"] = df["failed_login_count"] > 3
    df["high_unique_ips"] = df["unique_ip_count"] > 3

    # Statistical anomaly (z-score style logic)
    mean_failed = df["failed_login_count"].mean()
    std_failed = df["failed_login_count"].std()

    if std_failed > 0:
        df["zscore_failed"] = (df["failed_login_count"] - mean_failed) / std_failed
        df["statistical_spike"] = df["zscore_failed"] > 2
    else:
        df["zscore_failed"] = 0
        df["statistical_spike"] = False

    # Final anomaly flag
    df["is_anomaly"] = (
        df["high_failed_logins"] |
        df["high_unique_ips"] |
        df["statistical_spike"]
    )

    return df
