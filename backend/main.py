import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from backend.engine.remediation import RemediationEngine
from backend.engine.risk import RiskEngine
from backend.reports.csv_report import generate_csv_report
from backend.reports.html_report import generate_html_report
from backend.reports.json_report import generate_json_report
from backend.reports.sarif_report import generate_sarif_report
from backend.scanners.aws import AWSScanner
from backend.scanners.azure import AzureScanner


def generate_mock_findings():
    try:
        mock_file = os.path.join(os.path.dirname(__file__), "..", "mock", "expected_findings.json")
        with open(mock_file, "r") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
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
    parser = argparse.ArgumentParser(description="CloudSentinel: Enterprise Multi-Cloud Security Posture Analyzer")
    parser.add_argument("--aws", action="store_true", help="Scan AWS environment")
    parser.add_argument("--azure", action="store_true", help="Scan Azure environment")
    parser.add_argument("--all", action="store_true", help="Scan all configured cloud environments (AWS & Azure)")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode (simulates a vulnerable environment without cloud credentials)")
    parser.add_argument("--profile", type=str, default=None, help="AWS CLI profile name (e.g. production, security-audit)")
    parser.add_argument("--subscription", type=str, default=None, help="Azure Subscription ID to scan")
    parser.add_argument("--report", choices=["json", "html", "md", "sarif", "csv"], default="md", help="Output format (default: md)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Save report directly to output file path")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None, help="Exit with code 1 if findings meet or exceed this risk level (CI/CD gate)")
    parser.add_argument("--serve", action="store_true", help="Start the interactive REST API server and dashboard on port 8000")
    parser.add_argument("--port", type=int, default=8000, help="Port for the server (default: 8000)")
    args = parser.parse_args()

    if args.serve:
        from backend.server import start_server
        start_server(port=args.port)
        return

    if not args.aws and not args.azure and not args.mock and not args.all:
        print("Please specify at least one target to scan: --aws, --azure, --all, or --mock (or --serve to start dashboard API)")
        return

    all_findings = []

    if args.mock:
        all_findings.extend(generate_mock_findings())
    else:
        if args.aws or args.all:
            aws = AWSScanner(profile_name=args.profile)
            all_findings.extend(aws.scan_all())
        
        if args.azure or args.all:
            azure_scan = AzureScanner(subscription_id=args.subscription)
            all_findings.extend(azure_scan.scan_all())

    # Evaluate risk score
    engine = RiskEngine()
    evaluated_findings = engine.evaluate_findings(all_findings)

    # Apply remediation
    remediation_engine = RemediationEngine()
    evaluated_findings = remediation_engine.apply_remediation(evaluated_findings)

    report_content = ""
    if args.report == "json":
        report = generate_json_report(evaluated_findings)
        report_content = json.dumps(report, indent=4)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report_content)
            print(f"JSON Report saved to: {args.output}")
        else:
            print(report_content)
    elif args.report == "html":
        out_path = generate_html_report(evaluated_findings, output_path=args.output)
        print(f"HTML Report generated at: {out_path}")
    elif args.report == "sarif":
        report = generate_sarif_report(evaluated_findings, output_path=args.output)
        report_content = json.dumps(report, indent=2)
        if args.output:
            print(f"SARIF Report saved to: {args.output}")
        else:
            print(report_content)
    elif args.report == "csv":
        report_content = generate_csv_report(evaluated_findings, output_path=args.output)
        if args.output:
            print(f"CSV Report saved to: {args.output}")
        else:
            print(report_content)
    else:
        if args.output:
            import io
            from contextlib import redirect_stdout
            f_io = io.StringIO()
            with redirect_stdout(f_io):
                print_markdown(evaluated_findings)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(f_io.getvalue())
            print(f"Markdown Report saved to: {args.output}")
        else:
            print_markdown(evaluated_findings)

    if args.fail_on:
        thresholds = {
            "critical": ["Critical"],
            "high": ["Critical", "High"],
            "medium": ["Critical", "High", "Medium"],
            "low": ["Critical", "High", "Medium", "Low"],
        }
        failing_levels = thresholds.get(args.fail_on.lower(), ["Critical"])
        breaches = [f for f in evaluated_findings if f.get("risk_level") in failing_levels]
        if breaches:
            print(f"\n[CI GATE FAILED] {len(breaches)} findings breached risk threshold '{args.fail_on}'.", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
