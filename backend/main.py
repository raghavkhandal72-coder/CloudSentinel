import json
import argparse
import os
from backend.scanners.aws import AWSScanner
from backend.scanners.azure import AzureScanner
from backend.engine.risk import RiskEngine
from backend.engine.remediation import RemediationEngine
from backend.reports.html_report import generate_html_report
from backend.reports.json_report import generate_json_report

def generate_mock_findings():
    try:
        mock_file = os.path.join(os.path.dirname(__file__), "..", "mock", "expected_findings.json")
        with open(mock_file, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading mock findings: {e}")
        return []

def print_markdown(findings):
    critical = sum(1 for f in findings if f.get('risk_level') == 'Critical')
    high = sum(1 for f in findings if f.get('risk_level') == 'High')
    medium = sum(1 for f in findings if f.get('risk_level') == 'Medium')
    low = sum(1 for f in findings if f.get('risk_level') == 'Low')

    print("\n# CloudSentinel Security Report\n")
    print("## Summary")
    print(f"Critical: {critical}")
    print(f"High:     {high}")
    print(f"Medium:   {medium}")
    print(f"Low:      {low}\n")
    
    print("## Detailed Findings")
    for finding in findings:
        score = finding.get('risk_score', 0)
        level = finding.get('risk_level', 'Unknown')
        print(f"### [{level}] (Score: {score}) {finding.get('resource')}")
        print(f"**Issue:** {finding.get('issue')}")
        factors = finding.get('risk_factors', [])
        if factors:
            print("**Why is this Risk Level?**")
            for factor in factors:
                print(f"  - {factor}")
        remediation = finding.get('remediation')
        if remediation:
            print(f"**Remediation:** {remediation}")
        print("\n")

def main():
    parser = argparse.ArgumentParser(description="CloudSentinel: Multi-Cloud Security Posture Analyzer")
    parser.add_argument("--aws", action="store_true", help="Scan AWS environment")
    parser.add_argument("--azure", action="store_true", help="Scan Azure environment")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode (simulates a vulnerable environment without cloud credentials)")
    parser.add_argument("--report", choices=["json", "html", "md"], default="md", help="Output format (default: md)")
    args = parser.parse_args()

    if not args.aws and not args.azure and not args.mock:
        print("Please specify at least one target to scan: --aws, --azure, or --mock")
        return

    all_findings = []

    if args.mock:
        all_findings.extend(generate_mock_findings())
    else:
        if args.aws:
            aws = AWSScanner()
            all_findings.extend(aws.scan_all())
        
        if args.azure:
            azure_scan = AzureScanner()
            all_findings.extend(azure_scan.scan_all())

    # Evaluate risk score
    engine = RiskEngine()
    evaluated_findings = engine.evaluate_findings(all_findings)

    # Apply remediation
    remediation_engine = RemediationEngine()
    evaluated_findings = remediation_engine.apply_remediation(evaluated_findings)

    if args.report == "json":
        report = generate_json_report(evaluated_findings)
        print(json.dumps(report, indent=4))
    elif args.report == "html":
        out_path = generate_html_report(evaluated_findings)
        print(f"HTML Report generated at: {out_path}")
    else:
        print_markdown(evaluated_findings)

if __name__ == "__main__":
    main()
