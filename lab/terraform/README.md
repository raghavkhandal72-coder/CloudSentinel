# CloudSentinel Vulnerable Lab

**⚠️ INTENTIONALLY VULNERABLE — FOR LOCAL/DEDICATED TEST ACCOUNTS ONLY**

This directory contains intentionally vulnerable Terraform infrastructure for both AWS and Azure. It is designed specifically to test and demonstrate the detection capabilities of the **CloudSentinel** security scanner.

Do **NOT** deploy these templates in any production or shared environment.

## Architecture

This lab provisions resources that violate cloud security best practices, such as:
- Publicly accessible S3 buckets and Azure Blob Storage containers.
- Overly permissive Network Security Groups / Security Groups exposing SSH (22) and RDP (3389) to the internet (`0.0.0.0/0`).
- Over-privileged IAM identities and Azure Service Principals (e.g., direct `AdministratorAccess` or `Owner` roles).
- Missing security configurations (unencrypted storage, disabled HTTPS/TLS).

## Quick Start

### Deploying AWS Lab
```bash
cd aws
terraform init
terraform apply
```

### Deploying Azure Lab
```bash
cd azure
terraform init
terraform apply
```

## Running the Demo

Once the resources are deployed in your isolated test account, you can run CloudSentinel against them to generate a comprehensive security report:

```bash
# From the root of the project
python main.py --aws --azure --report html
```

*Note: After testing is complete, always remember to run `terraform destroy` to clean up the vulnerable resources.*
