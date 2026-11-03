import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from backend.engine.drift import DriftEngine
from backend.engine.remediation import RemediationEngine
from backend.engine.risk import RiskEngine
from backend.notifications.webhook import WebhookNotifier
from backend.reports.console import ConsoleReporter
from backend.reports.csv_report import generate_csv_report
from backend.reports.html_report import generate_html_report
from backend.reports.json_report import generate_json_report
from backend.reports.sarif_report import generate_sarif_report
from backend.scanners.aws import AWSScanner
from backend.scanners.azure import AzureScanner
from backend.scanners.gcp import GCPScanner
from backend.scanners.kubernetes import KubernetesScanner


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
    parser.add_argument("--gcp", action="store_true", help="Scan Google Cloud Platform (GCP) environment")
    parser.add_argument("--k8s", type=str, default=None, help="Scan Kubernetes manifests (file or directory path)")
    parser.add_argument("--all", action="store_true", help="Scan all configured cloud environments (AWS, Azure & GCP)")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode (simulates a vulnerable environment without cloud credentials)")
    parser.add_argument("--profile", type=str, default=None, help="AWS CLI profile name (e.g. production, security-audit)")
    parser.add_argument("--subscription", type=str, default=None, help="Azure Subscription ID to scan")
    parser.add_argument("--project", type=str, default=None, help="GCP Project ID to scan")
    parser.add_argument("--baseline", type=str, default=None, help="Path to baseline JSON report for security drift & regression detection")
    parser.add_argument("--report", choices=["json", "html", "md", "sarif", "csv"], default="md", help="Output format (default: md)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Save report directly to output file path")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None, help="Exit with code 1 if findings meet or exceed this risk level (CI/CD gate)")
    parser.add_argument("--fail-on-new", choices=["critical", "high", "medium", "low"], default=None, help="Exit with code 1 if NEW regression findings meet or exceed this risk level")
    parser.add_argument("--notify-webhook", type=str, default=None, help="Webhook URL (Slack, MS Teams, SIEM) to dispatch scan alerts")
    parser.add_argument("--serve", action="store_true", help="Start the interactive REST API server and dashboard on port 8000")
    parser.add_argument("--port", type=int, default=8000, help="Port for the server (default: 8000)")
    args = parser.parse_args()

    if args.serve:
        from backend.server import start_server
        start_server(port=args.port)
        return

    if not args.aws and not args.azure and not args.gcp and not args.k8s and not args.mock and not args.all:
        print("Please specify at least one target to scan: --aws, --azure, --gcp, --k8s, --all, or --mock (or --serve to start dashboard API)")
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

        if args.gcp or args.all:
            gcp_scan = GCPScanner(project_id=args.project)
            all_findings.extend(gcp_scan.scan_all())

        if args.k8s:
            k8s_scan = KubernetesScanner(target_path=args.k8s)
            all_findings.extend(k8s_scan.scan_all())

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
            reporter = ConsoleReporter()
            reporter.print_report(evaluated_findings)

    # Security Drift & Regression Analysis
    drift_result = None
    if args.baseline:
        if os.path.exists(args.baseline):
            try:
                with open(args.baseline, "r", encoding="utf-8") as bf:
                    base_data = json.load(bf)
                baseline_findings = base_data.get("findings", base_data) if isinstance(base_data, dict) else base_data
                drift_result = DriftEngine.calculate_drift(baseline_findings, evaluated_findings)
                summary = drift_result["summary"]
                print(f"\n[DRIFT REPORT] Status: {summary['status']} | New: {summary['new_count']} | Resolved: {summary['resolved_count']} | Unchanged: {summary['unchanged_count']}")
                for nf in drift_result["new_findings"]:
                    sev = nf.get("risk_level", nf.get("severity", "MEDIUM"))
                    print(f"  + [NEW {sev}] {nf.get('resource', nf.get('resource_id'))} - {nf.get('issue', nf.get('finding_title'))}")
                for rf in drift_result["resolved_findings"]:
                    sev = rf.get("risk_level", rf.get("severity", "MEDIUM"))
                    print(f"  - [RESOLVED {sev}] {rf.get('resource', rf.get('resource_id'))} - {rf.get('issue', rf.get('finding_title'))}")
            except Exception as e:  # noqa: BLE001
                print(f"[WARN] Failed to process baseline file '{args.baseline}': {e}", file=sys.stderr)
        else:
            print(f"[WARN] Baseline file not found: {args.baseline}", file=sys.stderr)

    # Enterprise Webhook Notification (Slack / Teams / SIEM)
    webhook_url = args.notify_webhook or os.getenv("CLOUDSENTINEL_WEBHOOK_URL")
    if webhook_url:
        target_label = "k8s" if args.k8s else ("aws" if args.aws else ("azure" if args.azure else ("gcp" if args.gcp else "all")))
        res = WebhookNotifier.send_notification(webhook_url, evaluated_findings, cloud_target=target_label)
        print(f"[NOTIFICATION] Dispatched alert to webhook: status={res.get('status')}")

    if args.fail_on:
        thresholds = {
            "critical": ["Critical", "CRITICAL"],
            "high": ["Critical", "CRITICAL", "High", "HIGH"],
            "medium": ["Critical", "CRITICAL", "High", "HIGH", "Medium", "MEDIUM"],
            "low": ["Critical", "CRITICAL", "High", "HIGH", "Medium", "MEDIUM", "Low", "LOW"],
        }
        failing_levels = thresholds.get(args.fail_on.lower(), ["Critical"])
        breaches = [f for f in evaluated_findings if f.get("risk_level") in failing_levels]
        if breaches:
            print(f"\n[CI GATE FAILED] {len(breaches)} findings breached risk threshold '{args.fail_on}'.", file=sys.stderr)
            sys.exit(1)

    if args.fail_on_new and drift_result:
        thresholds = {
            "critical": ["Critical", "CRITICAL"],
            "high": ["Critical", "CRITICAL", "High", "HIGH"],
            "medium": ["Critical", "CRITICAL", "High", "HIGH", "Medium", "MEDIUM"],
            "low": ["Critical", "CRITICAL", "High", "HIGH", "Medium", "MEDIUM", "Low", "LOW"],
        }
        failing_levels = thresholds.get(args.fail_on_new.lower(), ["Critical", "CRITICAL"])
        new_breaches = [f for f in drift_result["new_findings"] if f.get("risk_level", f.get("severity")) in failing_levels]
        if new_breaches:
            print(f"\n[CI REGRESSION GATE FAILED] {len(new_breaches)} new regression findings breached risk threshold '{args.fail_on_new}'.", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
