"""
Log Ingestion Module
-------------------
Reads log files safely using streaming.
"""

from pathlib import Path
import logging


def read_log_file(log_path: str):
    """
    Generator that reads a log file line by line.

    :param log_path: Path to the log file
    :yield: Non-empty log lines
    """
    path = Path(log_path)

    if not path.exists():
        logging.error(f"Log file not found: {log_path}")
        raise FileNotFoundError(f"Log file not found: {log_path}")

    logging.info(f"Reading log file: {log_path}")

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()
            if line:
                yield line
