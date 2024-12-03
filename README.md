# Automated Hardening Configuration Review with CIS Benchmarks & Python

## Overview
This project provides an automated Python-based script to evaluate system-level security configurations for **Apache** and **Ubuntu** systems. It uses **CIS Benchmarks** to ensure compliance with industry-standard security practices. The tool identifies running services, validates configurations, and generates a detailed compliance report in CSV format.

---

## Features
- **Apache Configuration Checks**: Validates key Apache security settings.
- **Ubuntu SSH Configuration Checks**: Ensures SSH configurations meet CIS standards.
- **Service Identification**: Detects active services on the system for security evaluation.
- **CSV Report**: Generates a structured report with compliance status and remediation suggestions.

---

## Prerequisites
- **Python 3.x**
- Permissions to read system configuration files (Run as `sudo` or administrator).
- Apache installed for configuration checks (`/etc/apache2/apache2.conf`).
- OpenSSH installed for Ubuntu configuration checks (`/etc/ssh/sshd_config`).

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/automated-hardening-review.git
   cd automated-hardening-review
2. Install required Python modules (if not pre-installed):
      ```bash
   pip install psutil

---

## Usage
1. Run the script:
   ```bash
   sudo python automated_hardening_review.py
2. Review the results in the generated `compliance_results.csv` file.

---

## Output
The CSV file contains three columns:

- Configuration: The specific configuration being checked.
- Status: Compliant or Non-Compliant.
- Details: Additional information, including expected vs. actual values and remediation suggestions.

Example:
csv
Configuration,Status,Details
Apache: ServerTokens,Compliant,Value: Prod
Ubuntu: PermitRootLogin,Non-Compliant,Expected: no, Found: yes

---

## Configurations Checked 
### Apache Configurations
- ServerTokens: Prevents Disclosing server version information.
- ServerSignature: Disables signature in error pages.
- TraceEnable: Disables HTTP TRACE requests.
- Options: Prevents directory listing.
- SSLProtocol: Disables outdated SSL protocols (SSLv2, SSLv3).
- SSLCipherSuite: Enforces strong SSL/TLS cipher suites.

### Ubuntu SSH Configurations
- PermitRootLogin: Prevents root login over SSH.
- PasswordAuthentication: Ensures password-based login is allowed.
- MaxAuthTries: Limits the number of authentication attempts.
- IgnoreRhosts: Disables the use of `.rhosts` files.
- Protocol: Ensures SSH uses protocol version 2.
- LogLevel: Sets logging level for SSHD to `INFO`.

---

## Customization
To customize the configuration being checked:
   1. Edit the `APACHE_RULES` or `UBUNTU_RULES` dictionaries in the script.
   2. Add or modify key value pairs based on your security policies or CIS Benchmarks.

---

## Limitations
- Assumes default file paths for Apache and SSH configurations.
- Does not automatically remediate non-compliant configurations.
- Requires manual updates to rules for different versions of CIS Benchmarks.
