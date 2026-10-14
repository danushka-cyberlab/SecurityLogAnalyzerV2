# Security Log Analyzer V2

## Project Overview

Security Log Analyzer V2 is a beginner-friendly Python cybersecurity project that analyzes login logs, identifies suspicious activity, classifies IP address risk levels, detects potential brute-force login patterns, and generates security reports and visual charts.

## Features

- Analyze successful and failed login attempts.
- Count failed login attempts by username and IP address.
- Identify suspicious IP addresses.
- Classify IP addresses as LOW, MEDIUM, or HIGH risk using configurable thresholds.
- Detect potential brute-force patterns using a time window.
- Validate timestamps and IP addresses in log entries.
- Generate text and JSON security reports.
- Create four charts using Matplotlib.
- Handle invalid log entries without stopping the entire analysis.

## Technologies Used

- Python
- Matplotlib
- JSON
- IP address validation with `ipaddress`
- Date and time processing

## Requirements

- Python 3.13 or another compatible Python 3 version
- Matplotlib

Install Matplotlib using:

powershell
py -m pip install matplotlib


## How to Run

1. Download or clone this repository.
2. Open PowerShell in the project directory.
3. Run:

```powershell
py security_dashboard.py
```

4. Review the generated security reports and chart images.

## Generated Visualizations

- `security_dashboard.png`
- `failed_logins_by_ip.png`
- `ip_risk_distribution.png`
- `failed_attempts_by_risk.png`

## Disclaimer

This project is intended for educational purposes. Risk classifications and brute-force alerts are heuristic indicators and do not, by themselves, prove malicious activity. Use only logs you are authorized to analyze.

## Author

Python Cybersecurity Learning Project