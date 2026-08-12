# Phishing Email Detection and Analysis Tool

## 1. Project Overview

Phishing emails are a common cybersecurity threat in which attackers attempt to deceive users into revealing sensitive information or interacting with malicious content.

This project implements a Python-based phishing email analysis tool that examines email headers and content for suspicious characteristics. The tool helps identify potential phishing emails by analyzing authentication results, received headers, URLs, and suspicious language.

The project also demonstrates the analysis of both legitimate and phishing email samples.

---

## 2. Objectives

The main objectives of this project are

- To analyze email headers and metadata.
- To check SPF, DKIM, and DMARC authentication results.
- To extract URLs from email content.
- To identify suspicious characteristics in URLs.
- To detect urgency-related phrases commonly used in phishing emails.
- To calculate a risk score based on detected indicators.
- To classify emails as
  - LIKELY LEGITIMATE
  - SUSPICIOUS
  - PHISHING
- To provide a simple command-line based phishing email analysis tool.

---

## 3. Technologies Used

- Python 3
- Python `email` module
- Python `re` (Regular Expressions)
- Command Line  PowerShell
- Git and GitHub

---

## 4. Project Structure

```text
Phishing-Email-Detection
│
├── email_analyzer.py
├── email_analyzer_backup.py
├── README.md
│
├── samples
│   ├── legitimate
│   │   └── PLIX Email.txt
│   │
│   └── phishing
│       ├── phishing_email.txt
│       └── phishing_email_002.txt
│
└── screenshots
    ├── 01_project_structure.png
    ├── 02_legitimate_analysis.png
    ├── 03_phishing_analysis_001.png
    └── 04_phishing_analysis_002.png