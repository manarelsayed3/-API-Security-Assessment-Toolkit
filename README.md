# API Security Assessment Toolkit

A Python-based toolkit for performing basic API security assessment tasks in authorized and controlled environments.

## Project Goal

The goal of this project is to build a practical API security assessment toolkit that follows a simplified professional security testing workflow:


```text
Target
  ↓
Discovery
  ↓
Request / Response Analysis
  ↓
Security Checks
  ↓
Authentication
  ↓
Authorization / BOLA
  ↓
Evidence
  ↓
Severity & Confidence
  ↓
Security Report
Current Features
Endpoint discovery
Authentication checks
Object-Level Authorization testing
BOLA / IDOR detection
HTTP request and response analysis
Security header checks
Misconfiguration checks
Severity classification
Confidence classification
Evidence collection
Security recommendations
JSON report generation
Markdown report generation
Modular scanner architecture
BOLA / IDOR Testing

The toolkit includes a controlled BOLA / IDOR testing module that compares access to a baseline object against other object IDs.

The test can identify:

Potential unauthorized object access
HTTP 401 / 403 authorization enforcement
HTTP 404 responses
Unexpected authorization responses
Generic or identical responses that may require manual verification

Example vulnerable behavior:

Object 1 → HTTP 200
Object 2 → HTTP 200
        ↓
Potential IDOR / BOLA

Example secure behavior:

Object 1 → HTTP 200
Object 2 → HTTP 403
        ↓
Object-Level Authorization Enforced
Test Environment

The project includes controlled Flask API environments for demonstrating both vulnerable and secure object-level authorization behavior.

Vulnerable API
test_api.py
Secure API
test_api_secure.py

These environments are intended for local security testing and educational demonstration.

Project Structure
api-security/
│
├── auth.py
├── discovery.py
├── headers.py
├── idor.py
├── main.py
├── misconfiguration.py
├── response_analysis.py
│
├── scanner/
│   ├── __init__.py
│   ├── engine.py
│   ├── findings.py
│   └── reporting.py
│
├── test_api.py
├── test_api_secure.py
│
├── report.json
├── report.md
├── requirements.txt
├── .gitignore
└── README.md
Reporting

The toolkit generates two report formats:

report.json
report.md

Reports include:

Target
Scan time
Total findings
Severity summary
Finding category
Endpoint
HTTP method
HTTP status
Evidence
Confidence
Recommendation
Technologies
Python
Requests
Flask
HTTP / REST APIs
Disclaimer

This project is intended for authorized security testing, educational purposes, and controlled lab environments.

Do not use the toolkit against systems or APIs without explicit authorization.
