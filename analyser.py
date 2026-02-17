#!/usr/bin/env python3
"""
Linux Log Analyser
------------------
Entry point for the Linux log analysis and anomaly detection pipeline.
"""

import sys
import argparse
import logging
import yaml

from reporting.reporter import generate_report
from ingestion.reader import read_log_file
from parsing.auth_parser import parse_auth_log_line
from events.event import classify_event
from features.extractor import extract_features
from detection.detector import detect_anomalies


def load_config(config_path: str) -> dict:
    """
    Load YAML configuration file.
    """
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"❌ Config file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"❌ Failed to parse config file: {e}")
        sys.exit(1)


def setup_logging(log_level: str = "INFO"):
    """
    Configure application-wide logging.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Linux Log Analyser - Batch log analysis and anomaly detection"
    )

    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to configuration file",
    )

    parser.add_argument(
        "--export",
        help="Export final anomaly report to CSV file",
    )

    return parser.parse_args()





def main() -> int:
    """
    Main entry point.
    """    
    
    args = parse_arguments()

    # Load configuration
    config = load_config(args.config)

    # etup logging
    setup_logging(config.get("logging", {}).get("level", "INFO"))

    logging.info("Linux Log Analyser started")
    logging.info("Configuration loaded successfully")

    log_path = config["input"]["log_path"]

    try:
        # -------- Day 3: Parsing & Events --------
        events = []

        for line in read_log_file(log_path):
            parsed = parse_auth_log_line(line)
            if not parsed:
                continue

            event = classify_event(parsed)
            events.append(event)

        logging.info(f"Parsed {len(events)} events")

        # -------- Day 4: Feature Extraction --------
        window_minutes = config.get("processing", {}).get("time_window_minutes", 10)
        features_df = extract_features(events, window_minutes=window_minutes)

        if features_df.empty:
            logging.info("No features generated")
        else:
            logging.info(f"Generated {len(features_df)} time windows")
            logging.info("\n" + features_df.to_string(index=False))

        # -------- Day 5: Anomaly Detection --------
        anomaly_df = detect_anomalies(features_df)

        if anomaly_df.empty:
            logging.info("No anomaly analysis performed")
        else:
            anomaly_count = anomaly_df["is_anomaly"].sum()
            logging.info(f"Detected {anomaly_count} anomalous windows")
            logging.info("\n" + anomaly_df.to_string(index=False))


        # -------- Day 6: Reporting --------
        report = generate_report(anomaly_df)

        logging.info("=== SECURITY REPORT ===")
        logging.info(f"Total Time Windows: {report['total_windows']}")
        logging.info(f"Anomalous Windows: {report['anomalous_windows']}")
        logging.info(f"Highest Severity: {report['highest_severity']}")

        # -------- Day 7: CSV Export --------
        if args.export and not anomaly_df.empty:
            anomaly_df.to_csv(args.export, index=False)
            logging.info(f"Report exported to {args.export}")

    except Exception as e:
        logging.error(f"Pipeline failed: {e}")
        return 1

    print("Linux Log Analyser initialized successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
