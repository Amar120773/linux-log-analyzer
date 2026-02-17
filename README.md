# Linux Log Analyser

Linux Log Analyser is a **Python and Bash based log analysis and anomaly detection system**
designed to process unstructured Linux logs in **batch mode**.  
It converts raw log files into structured events, analyzes system behavior over time,
and detects abnormal patterns using **explainable statistical techniques**.

The project is built as a **production-style scripting and automation tool**, focusing on
clarity, scalability, and real-world system relevance.

---

## Why This Project Exists

Linux servers generate large volumes of logs related to authentication, system activity,
and application behavior. Manual log inspection is time-consuming, error-prone, and does
not scale well.

Linux Log Analyser automates this process by:
- Structuring raw log data
- Detecting abnormal behavior early
- Generating actionable, automation-ready reports

This reflects how **real-world monitoring and internal tooling systems** are designed.

---

## High-Level Architecture

```text
Raw Linux Logs
      ↓
Log Ingestion (streaming, memory-safe)
      ↓
Parsing & Normalization
      ↓
Event Modeling
      ↓
Feature Engineering (time windows)
      ↓
Statistical Anomaly Detection
      ↓
Severity Scoring
      ↓
Automated Reports (JSON / CSV / TXT)
