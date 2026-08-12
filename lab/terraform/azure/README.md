# Azure Vulnerable Lab

**⚠️ INTENTIONALLY VULNERABLE — FOR LOCAL/DEDICATED TEST ACCOUNTS ONLY**

Do not deploy this in a production subscription. This Terraform module creates intentionally vulnerable resources for CloudSentinel security testing.

## Resources Created:
1. **Storage Account**: Allows public blob access and disables HTTPS traffic only.
2. **Network Security Group (NSG)**: Allows inbound SSH (22) and RDP (3389) from `*`.
3. **RBAC**: Assigns the `Owner` role to a Service Principal at the resource group scope.

## Usage
```bash
terraform init
terraform apply
```
