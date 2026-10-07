
# Firmware Analyzer

## 📌 Project Overview

Firmware Analyzer is a cybersecurity tool designed to analyze firmware files and identify possible security risks.

The project combines firmware upload, hash verification, firmware extraction, static security scanning, and machine-learning-based risk analysis into one system.

## 🚀 Features

- Firmware file upload
- SHA-256 hash verification
- Firmware extraction using Binwalk
- Static scanning for suspicious strings
- Detection of hardcoded passwords and API keys
- Machine-learning-based analysis
- Risk scoring
- Analysis results and reports

## 🧩 Project Modules

### Module 1 — Frontend
Provides the user interface for uploading firmware files, entering a hash, and viewing analysis results.

Technology:
- Python
- Streamlit

### Module 2 — Core Backend
Handles firmware hash verification and extraction.

Main functions:
- SHA-256 hash checking
- Firmware extraction using Binwalk

### Module 3 — Static Regex Scanner
Scans extracted firmware files for suspicious patterns such as:

- Hardcoded passwords
- API keys
- Suspicious credentials
- Possible backdoor-related strings

### Module 4 — ML Classifier & Risk Scoring
Uses machine learning to identify anomalous code strings and generate a security risk score.

Technology:
- Python
- Scikit-learn
- Pandas

## 🛠️ Requirements

Install the required Python packages using:

```bash
pip install -r requirements.txt

## ▶️ How to Run

1. Install the required packages:

```bash
pip install -r requirements.txt

2. Run the Streamlit application :

   python -m streamlit run Module1.py

3. Open the local URL shown in the terminal

  Project Structure---

   Firmware_Analyzer2/
├── Module1.py
├── module2_extractor.py
├── module3_scanner.py
├── Module4_ml_classifier.py
├── firmware_test.bin
├── requirements.txt
├── results.csv
├── scanner_output.txt
├── README.md
└── Module4_ML/
