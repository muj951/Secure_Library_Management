# Secure Library Management System

A secure, web-based Library Management application built with Flask and Python. This project demonstrates the implementation of a Secure Software Development Life Cycle (SDLC), featuring comprehensive input validation, robust authentication, and automated security testing.

## Features
* **Role-Based Access Control:** Distinct privileges for Admin and Standard users.
* **Secure Authentication:** Password hashing via Werkzeug Security and secure session management.
* **Vulnerability Defenses:** Built-in protection against SQL Injection, XSS, and CSRF.
* **Audit Logging:** Secure server-side logging for user activities and system exceptions.

## Security Testing (DevSecOps)
This application was actively tested and hardened using modern security tools:
* **SAST (Static Application Security Testing):** SonarLint was utilized to remediate hardcoded credentials, enforce explicit HTTP methods, and secure exception handling.
* **DAST (Dynamic Application Security Testing):** OWASP ZAP was utilized to verify input validation (anchored Regex) and enforce modern HTTP security headers (SameSite, X-Content-Type-Options).

## Local Setup Instructions
1. Clone the repository.
2. Create a virtual environment: `python -m venv venv`
3. Activate the environment and install dependencies: `pip install -r requirements.txt`
4. Run the application: `python app.py`
5. Access via `http://127.0.0.1:5000`