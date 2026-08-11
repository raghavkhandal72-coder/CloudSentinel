# ☁️ CloudSentinel

**Multi-Cloud Security Posture Analyzer**

CloudSentinel is an automated Cloud Security Posture Management (CSPM) tool designed to audit AWS and Azure environments for critical security misconfigurations. 

It replaces manual cloud console checks with a fast, deterministic **Risk Engine** that outputs actionable findings mapped to severity levels.

## 🏗️ Architecture

```mermaid
graph TD
    A[CloudSentinel CLI] --> B{Mock Mode?}
    B -- Yes --> C[Mock Data JSONs]
    B -- No --> D[AWS SDK boto3]
    B -- No --> E[Azure SDK azure-identity]
    
    C --> F[Risk Engine]
    D --> F
    E --> F
    
    F --> G(Calculate Risk Score 0-100)
    G --> H{Report Generator}
    
    H -- --report md --> I[Markdown Output]
    H -- --report json --> J[JSON Output]
    H -- --report html --> K[HTML Dashboard]
```

## 🚀 Features
- **Real SDK Integration**: Uses official `boto3` (AWS) and `azure-identity` (Azure) SDKs for live environment interrogation.
- **Advanced Risk Engine**: Calculates a normalized 0-100 risk score based on Base Severity, Exposure, Privilege, Data Sensitivity, and Exploitability.
- **AWS Audits**:
  - IAM: Root MFA checks, password policies, dangerous inline policies, AdministratorAccess, wildcard privileges, old access keys.
  - S3: Public bucket exposure, missing default encryption, versioning, ACLs, logging.
  - EC2/Security Groups: Open `0.0.0.0/0` access on sensitive ports (22, 3389, 3306, 5432, 1433) and unrestricted egress.
  - CloudTrail: Verifies multi-region trails, log validation, and KMS encryption.
- **Azure Audits**:
  - Storage Accounts: Checks for "Secure Transfer Required" and Public Blob access.
  - Network Security Groups (NSG): Inbound rules allowing Internet to sensitive ports.
  - RBAC: Subscription-level over-privileged Owner and User Access Administrator roles.
  - Monitor: Validates diagnostic settings log retention policies.

## ⚙️ Installation & Usage

### 1. Setup
```bash
git clone https://github.com/raghavkhandal72-coder/CloudSentinel.git
cd CloudSentinel
pip install -r backend/requirements.txt
```

### 2. Run the Scanner
You can scan either AWS, Azure, or both simultaneously. Ensure you have authenticated to your cloud providers locally (`aws configure` or `az login`).

```bash
python backend/main.py --aws --azure
```

**Interview / Recruiter Mode (No Cloud Credentials Needed):**
```bash
python backend/main.py --mock
```
This mode simulates a deliberately vulnerable multi-cloud environment locally, returning realistic findings instantly without incurring cloud costs or requiring authentication.

### 3. Reporting Options
CloudSentinel supports Markdown (default), JSON, and HTML reports:

```bash
# Markdown (Default Terminal Output)
python backend/main.py --mock --report md

# JSON (For CI/CD or SIEM ingestion)
python backend/main.py --mock --report json

# HTML (Interactive Dashboard output)
python backend/main.py --mock --report html
```

## 📊 Sample Output (Markdown)
```text
# CloudSentinel Security Report

## Summary
Critical: 3
High:     3
Medium:   0
Low:      0

## Detailed Findings
- [Critical] (Score: 75) AWS S3: company-prod-backups: Bucket does not block all public access
- [Critical] (Score: 70) Azure Storage: prodassets001: Public blob access is allowed
- [High] (Score: 65) AWS IAM User: backup-svc: User has direct inline policies attached (AdministratorAccess)
```

## 🧪 Testing and CI/CD
CloudSentinel uses `pytest` for comprehensive testing and `bandit` for SAST.
Tests are run automatically via GitHub Actions on every push to `main`.

```bash
python -m pytest tests/
```

## ⚠️ Security Notice
This tool runs read-only queries against your cloud environments. **Never commit `.env` files or credentials to version control.** A strict `.gitignore` is provided in this repository.
