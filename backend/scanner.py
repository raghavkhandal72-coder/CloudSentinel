from sqlalchemy.orm import Session
from models import Finding
import json

def run_mock_scan(db: Session):
    # Clear existing
    db.query(Finding).delete()
    db.commit()

    findings = [
        Finding(
            cloud_provider="AWS",
            resource_id="arn:aws:s3:::company-financial-data-backup",
            finding_title="Public S3 Bucket (Over-permissive ACL)",
            why_it_matters="A public S3 bucket exposes sensitive data to the internet. Anyone can read, list, or download the contents without authentication, leading to a massive data breach.",
            evidence=json.dumps({"BlockPublicAcls": False, "BlockPublicPolicy": False, "Grantee": "http://acs.amazonaws.com/groups/global/AllUsers"}, indent=2),
            cis_benchmark="CIS AWS Foundations 1.4.0 - 2.1.1",
            risk_level="CRITICAL",
            remediation="1. Go to S3 Console. 2. Select the bucket. 3. Navigate to Permissions. 4. Enable 'Block all public access'."
        ),
        Finding(
            cloud_provider="AWS",
            resource_id="arn:aws:iam::123456789012:user/dev-intern-01",
            finding_title="Over-permissive IAM Policy Attached to User",
            why_it_matters="The user has the AdministratorAccess managed policy attached directly instead of assuming a role via group membership. If their access keys are leaked, attackers gain full account control.",
            evidence=json.dumps({"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}, indent=2),
            cis_benchmark="CIS AWS Foundations 1.4.0 - 1.16",
            risk_level="HIGH",
            remediation="1. Remove AdministratorAccess from user. 2. Create an IAM Group with least-privilege policies. 3. Add user to the group."
        ),
        Finding(
            cloud_provider="Azure",
            resource_id="/subscriptions/xxx/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
            finding_title="Dangerous Security Group Rule (SSH Open to 0.0.0.0/0)",
            why_it_matters="Port 22 (SSH) is exposed to the entire internet. This allows automated scanners and brute-forcers to attempt to compromise the VMs in this subnet.",
            evidence=json.dumps({"SecurityRule": "AllowSSH_All", "Direction": "Inbound", "SourceAddressPrefix": "*", "DestinationPortRange": "22"}, indent=2),
            cis_benchmark="CIS Microsoft Azure Foundations 1.3.0 - 6.1",
            risk_level="HIGH",
            remediation="1. Edit the NSG Rule. 2. Change Source from 'Any' to specific corporate IP addresses or use Azure Bastion."
        ),
        Finding(
            cloud_provider="AWS",
            resource_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events",
            finding_title="CloudTrail Log File Validation Disabled",
            why_it_matters="Without log file validation, there is no cryptographic guarantee that logs haven't been tampered with or deleted by an attacker attempting to cover their tracks.",
            evidence=json.dumps({"LogFileValidationEnabled": False}, indent=2),
            cis_benchmark="CIS AWS Foundations 1.4.0 - 3.2",
            risk_level="MEDIUM",
            remediation="Enable log file validation in the CloudTrail settings. Use AWS KMS for key management."
        ),
        Finding(
            cloud_provider="Azure",
            resource_id="/subscriptions/xxx/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/prod-db",
            finding_title="Auditing for SQL Database is Disabled",
            why_it_matters="Database auditing tracks database events and writes them to an audit log. Without it, investigating data exfiltration or SQL injection incidents is nearly impossible.",
            evidence=json.dumps({"AuditingState": "Disabled"}, indent=2),
            cis_benchmark="CIS Microsoft Azure Foundations 1.3.0 - 4.1.1",
            risk_level="MEDIUM",
            remediation="Navigate to Azure SQL server > Auditing. Toggle 'Enable SQL auditing' to ON."
        )
    ]
    
    # Add some dummy 'passed' resources to pad the stats
    for i in range(64):
        findings.append(
            Finding(
                cloud_provider="AWS" if i % 2 == 0 else "Azure",
                resource_id=f"resource-passed-{i}",
                finding_title="Resource Compliant",
                why_it_matters="",
                evidence="",
                cis_benchmark="",
                risk_level="PASSED",
                remediation=""
            )
        )

    db.add_all(findings)
    db.commit()
