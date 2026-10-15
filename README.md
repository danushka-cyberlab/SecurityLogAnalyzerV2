# Security Log Analyzer V2

A beginner-friendly Python cybersecurity project that analyzes authentication logs, detects suspicious login patterns, classifies IP address risk levels, and generates security reports and visual dashboards.

## Project Overview

Security Log Analyzer V2 is a Python-based security log analysis tool designed to help learners understand authentication monitoring and basic threat detection. It processes login events, identifies repeated failed login attempts, detects potential brute-force patterns, and produces reports and charts to support security investigations.

## Features

- Analyze successful and failed login attempts.
- Count failed login attempts by username and IP address.
- Identify accounts with repeated authentication failures.
- Classify IP addresses as LOW, MEDIUM, or HIGH risk using configurable thresholds.
- Detect potential brute-force patterns using a configurable time window.
- Validate timestamps, usernames, and IP addresses in log entries.
- Track failed login activity by hour.
- Generate text and JSON security reports.
- Generate five visualizations using Matplotlib.
- Handle invalid log entries and display warnings for troubleshooting.
- Provide security recommendations based on the overall severity classification.

## Technologies Used

- Python 3.13
- Matplotlib
- JSON
- `ipaddress` module
- `datetime` module
- `collections` module
- Git and GitHub

## Requirements

- Python 3.13 or another compatible Python 3 version.
- Matplotlib.

Install Matplotlib using PowerShell:

```powershell
py -m pip install matplotlib
```

## How to Run

1. Clone or download this repository.
2. Open PowerShell in the project directory.
3. Ensure that the configured log file exists and contains valid sample data.
4. Run the analyzer:

```powershell
py security_dashboard.py
```

5. Review the generated security reports and chart images.

**Note:** The script currently uses a configured log-file path. If you run it from another computer, update `log_path` in `security_dashboard.py` to point to the correct `security_log.txt` location.

## Generated Reports

The analyzer generates the following reports:

- `security_report.txt` — Human-readable security analysis and recommendations.
- `security_report.json` — Structured security results for further processing.

## Generated Visualizations

The project creates five charts:

1. `security_dashboard.png` — Comparison of successful and failed login attempts.
2. `failed_logins_by_ip.png` — Failed login attempts grouped by IP address.
3. `ip_risk_distribution.png` — Distribution of IP addresses by risk level.
4. `failed_attempts_by_risk.png` — Failed login attempts grouped by IP risk level.
5. `failed_login_timeline.png` — Failed login activity grouped by minute.

These visualizations help summarize authentication activity, compare risk levels, and identify periods of increased failed-login activity.

## Detection Logic

- **IP risk classification:** Based on configurable counts of failed login attempts per IP address.
- **Brute-force detection:** Flags an IP address when five or more failed login events occur within a two-minute window.
- **Overall severity:** Classifies the analyzed activity as LOW, MEDIUM, HIGH, or CRITICAL according to the total number of valid failed login events.
- **Security recommendations:** Provides suggested investigation and monitoring actions based on the severity classification.

These thresholds are educational examples and should be tuned and tested before use in a real environment.

## Project Structure

```text
SecurityLogAnalyzerV2/
+-- security_dashboard.py
+-- security_log.txt
+-- security_report.txt
+-- security_report.json
+-- security_dashboard.png
+-- failed_logins_by_ip.png
+-- ip_risk_distribution.png
+-- failed_attempts_by_risk.png
+-- failed_login_timeline.png
```

## Disclaimer

This project is intended for educational purposes. Risk classifications and brute-force alerts are heuristic indicators and do not, by themselves, prove malicious activity. Analyze only logs you are authorized to access. Use synthetic sample data in public repositories and remove credentials, personal information, and confidential security details before publishing.

## Author

Python Cybersecurity Learning Project