# ☁️ CloudSentinel

**Multi-Cloud Security Posture Analyzer**

CloudSentinel is an automated Cloud Security Posture Management (CSPM) tool designed to audit AWS and Azure environments for critical security misconfigurations. 

It replaces manual cloud console checks with a fast, deterministic risk engine that outputs actionable findings mapped to severity levels.

## 🚀 Features
- **Real SDK Integration**: Uses official `boto3` (AWS) and `azure-identity` (Azure) SDKs for live environment interrogation.
- **AWS Audits**:
  - IAM: Root MFA checks, dangerous inline policies.
  - S3: Public bucket exposure, missing default encryption.
  - EC2/Security Groups: Open `0.0.0.0/0` access on sensitive ports (22, 3389, 3306).
  - CloudTrail: Verifies multi-region trails are enabled.
- **Azure Audits**:
  - Storage Accounts: Checks for "Secure Transfer Required" and Public Blob access.
  - Network Security Groups (NSG): Inbound rules allowing Internet to sensitive ports.

## ⚙️ Installation & Usage

### 1. Prerequisites
Ensure you have authenticated to your cloud providers locally:
- **AWS**: Configure `~/.aws/credentials` (via `aws configure`).
- **Azure**: Login via Azure CLI (`az login`).

### 2. Setup
```bash
git clone https://github.com/raghavkhandal72-coder/CloudSentinel.git
cd CloudSentinel/backend
pip install -r requirements.txt
```

### 3. Run the Scanner
You can scan either AWS, Azure, or both simultaneously:

```bash
python main.py --aws --azure
```

**Interview / Recruiter Mode (No Cloud Credentials Needed):**
```bash
python main.py --mock
```
This mode simulates a vulnerable AWS and Azure environment locally, returning critical findings instantly without incurring cloud costs or requiring authentication.

To output results in JSON format for CI/CD pipelines or SIEM ingestion:
```bash
python main.py --mock --json
```

## 📊 Sample Output
```text
# ☁️ CloudSentinel Security Report

## Summary
🔴 Critical: 2
🟠 High:     1
🟡 Medium:   1
🟢 Low:      0

## Detailed Findings
- [Critical] AWS Global: Authentication Failed: No AWS Credentials Found
- [Critical] Azure Global: Authentication Failed: No Azure Credentials Found (az login)
- [High] S3: company-backup-bucket: Bucket does not block all public access
- [Medium] IAM User: backup-svc: User has direct inline policies attached
```

## ⚠️ Security Notice
This tool runs read-only queries against your cloud environments. **Never commit `.env` files or credentials to version control.** A strict `.gitignore` is provided in this repository.
