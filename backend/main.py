import json
import argparse
from aws.scanner import AWSScanner
from azure.scanner import AzureScanner

def generate_report(findings):
    report = {
        "summary": {
            "critical": sum(1 for f in findings if f['severity'] == 'Critical'),
            "high": sum(1 for f in findings if f['severity'] == 'High'),
            "medium": sum(1 for f in findings if f['severity'] == 'Medium'),
            "low": sum(1 for f in findings if f['severity'] == 'Low')
        },
        "findings": findings
    }
    return report

def print_markdown(report):
    print("\n# CloudSentinel Security Report\n")
    print("## Summary")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High:     {report['summary']['high']}")
    print(f"Medium:   {report['summary']['medium']}")
    print(f"Low:      {report['summary']['low']}\n")
    
    print("## Detailed Findings")
    for finding in report['findings']:
        print(f"- **[{finding['severity']}]** {finding['resource']}: {finding['issue']}")
    print("\n")

def main():
    parser = argparse.ArgumentParser(description="CloudSentinel: Multi-Cloud Security Posture Analyzer")
    parser.add_argument("--aws", action="store_true", help="Scan AWS environment")
    parser.add_argument("--azure", action="store_true", help="Scan Azure environment")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    if not args.aws and not args.azure:
        print("Please specify at least one cloud provider to scan: --aws and/or --azure")
        return

    all_findings = []

    if args.aws:
        aws = AWSScanner()
        all_findings.extend(aws.scan_all())
    
    if args.azure:
        azure_scan = AzureScanner()
        all_findings.extend(azure_scan.scan_all())

    report = generate_report(all_findings)

    if args.json:
        print(json.dumps(report, indent=4))
    else:
        print_markdown(report)

if __name__ == "__main__":
    main()
