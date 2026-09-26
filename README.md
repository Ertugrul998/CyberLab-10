# CyberLab-10 — Python SOC Log Analyzer

A Python-based security log analysis project developed
for educational and defensive cybersecurity purposes.

## Features

- SSH brute-force detection
- Suspicious HTTP activity detection
- Sensitive web path monitoring
- IP-based security alert correlation
- Risk scoring from 0 to 100
- JSON and HTML security reports
- 40 automated unit and integration tests

## Project Structure

- `main.py` — Main application
- `detectors/` — SSH and web attack detection
- `core/` — Alert correlation and risk scoring
- `reports/` — JSON and HTML report generation
- `data/` — Sample security logs
- `tests/` — Automated tests
- `output/` — Generated reports

## Requirements

- Python 3
- A Python virtual environment (recommended)

## Usage

Run the application from the project directory:

```bash
python3 main.py
```

The application analyzes the sample SSH and web logs.

Generated reports:

- `output/soc_report.json`
- `output/soc_report.html`

## Run Tests

```bash
python3 -m unittest discover -s tests -v
```

The project includes 40 automated tests.

## Security Notice

This project is intended for authorized security
monitoring, education and laboratory environments.
