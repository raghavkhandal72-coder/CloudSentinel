import csv
import io
import os


def generate_csv_report(findings: list, output_path: str | None = None) -> str:
    """
    Generates an auditor-ready CSV report for compliance audits (SOC 2, ISO 27001, PCI-DSS, HIPAA).
    """
    fieldnames = [
        "Finding ID",
        "Cloud Provider",
        "Service",
        "Resource ID",
        "Severity",
        "Risk Level",
        "Risk Score",
        "Issue Description",
        "Evidence",
        "Remediation Guidance",
        "CLI Command",
        "Terraform Snippet",
        "CIS Benchmark",
        "SOC 2 Controls",
        "PCI-DSS",
        "HIPAA",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    for idx, f in enumerate(findings):
        rem = f.get("remediation", "")
        if isinstance(rem, dict):
            rem_title = rem.get("title", "")
            steps = "; ".join(rem.get("steps", []))
            rem_text = f"{rem_title}: {steps}"
            cli = rem.get("cli_command", f.get("cli_remediation", ""))
            tf = rem.get("terraform", f.get("terraform_remediation", ""))
        else:
            rem_text = str(rem)
            cli = f.get("cli_remediation", "")
            tf = f.get("terraform_remediation", "")

        frameworks = f.get("frameworks", {})
        cis = frameworks.get("cis_aws") or frameworks.get("cis_azure") or "N/A"
        soc2 = frameworks.get("soc2", "N/A")
        pci = frameworks.get("pci_dss", "N/A")
        hipaa = frameworks.get("hipaa", "N/A")

        row = {
            "Finding ID": f.get("id", f"CS-{idx + 1:04d}"),
            "Cloud Provider": f.get("provider", "Cloud"),
            "Service": f.get("service", "General"),
            "Resource ID": f.get("resource", "Unknown"),
            "Severity": f.get("severity", "Medium"),
            "Risk Level": f.get("risk_level", f.get("severity", "Medium")),
            "Risk Score": f.get("risk_score", 0),
            "Issue Description": f.get("issue", ""),
            "Evidence": str(f.get("evidence", "")),
            "Remediation Guidance": rem_text,
            "CLI Command": cli,
            "Terraform Snippet": tf,
            "CIS Benchmark": cis,
            "SOC 2 Controls": soc2,
            "PCI-DSS": pci,
            "HIPAA": hipaa,
        }
        writer.writerow(row)

    csv_content = output.getvalue()

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write(csv_content)

    return csv_content
