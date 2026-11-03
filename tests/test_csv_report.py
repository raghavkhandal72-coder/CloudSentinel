import csv
import io

from backend.reports.csv_report import generate_csv_report


def test_csv_generation():
    findings = [
        {
            "id": "CS-0001",
            "provider": "AWS",
            "service": "RDS",
            "resource": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
            "issue": "RDS database instance is publicly accessible",
            "severity": "Critical",
            "risk_level": "Critical",
            "risk_score": 90,
            "evidence": "PubliclyAccessible = True",
            "remediation": {
                "title": "Disable Public Accessibility",
                "steps": ["Modify DB instance to PubliclyAccessible=False"],
                "cli_command": "aws rds modify-db-instance --no-publicly-accessible",
                "terraform": 'resource "aws_db_instance" "example" { publicly_accessible = false }',
            },
            "frameworks": {
                "cis_aws": "2.3.1",
                "soc2": "CC6.6",
                "pci_dss": "1.3",
                "hipaa": "164.312(a)(1)",
            },
        },
        {
            "id": "CS-0002",
            "provider": "Azure",
            "service": "KeyVault",
            "resource": "sub-123/prod-vault",
            "issue": "Key Vault soft delete is disabled",
            "severity": "High",
            "risk_level": "High",
            "risk_score": 75,
            "evidence": "enable_soft_delete = False",
            "remediation": "Enable soft delete with 90-day retention",
            "cli_remediation": "az keyvault update --name prod-vault --enable-soft-delete true",
            "terraform_remediation": 'resource "azurerm_key_vault" "example" { soft_delete_retention_days = 90 }',
            "frameworks": {
                "cis_azure": "8.4",
                "soc2": "CC6.1",
                "pci_dss": "3.5",
            },
        },
    ]

    csv_data = generate_csv_report(findings)
    reader = csv.DictReader(io.StringIO(csv_data))
    rows = list(reader)

    assert len(rows) == 2
    assert rows[0]["Finding ID"] == "CS-0001"
    assert rows[0]["Cloud Provider"] == "AWS"
    assert rows[0]["Service"] == "RDS"
    assert rows[0]["Severity"] == "Critical"
    assert rows[0]["CIS Benchmark"] == "2.3.1"
    assert rows[0]["SOC 2 Controls"] == "CC6.6"
    assert rows[0]["PCI-DSS"] == "1.3"
    assert rows[0]["HIPAA"] == "164.312(a)(1)"
    assert "aws rds modify-db-instance" in rows[0]["CLI Command"]
    assert "publicly_accessible = false" in rows[0]["Terraform Snippet"]

    assert rows[1]["Finding ID"] == "CS-0002"
    assert rows[1]["Cloud Provider"] == "Azure"
    assert rows[1]["Service"] == "KeyVault"
    assert rows[1]["Severity"] == "High"
    assert rows[1]["CIS Benchmark"] == "8.4"
    assert rows[1]["SOC 2 Controls"] == "CC6.1"
    assert rows[1]["PCI-DSS"] == "3.5"
    assert rows[1]["HIPAA"] == "N/A"
    assert "az keyvault update" in rows[1]["CLI Command"]


def test_csv_output_file(tmp_path):
    findings = [{"issue": "Test issue", "resource": "res-1", "severity": "Low"}]
    out_file = tmp_path / "compliance_report.csv"
    csv_data = generate_csv_report(findings, str(out_file))

    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == csv_data
