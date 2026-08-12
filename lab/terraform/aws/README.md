# AWS Vulnerable Lab

**⚠️ INTENTIONALLY VULNERABLE — FOR LOCAL/DEDICATED TEST ACCOUNTS ONLY**

Do not deploy this in a production account. This Terraform module creates intentionally vulnerable resources for CloudSentinel security testing.

## Resources Created:
1. **S3 Bucket**: Allows public read access and has Block Public Access disabled.
2. **Security Group**: Allows inbound SSH (22) and RDP (3389) from `0.0.0.0/0`.
3. **IAM User**: Has `AdministratorAccess` attached directly.

## Usage
```bash
terraform init
terraform apply
```
