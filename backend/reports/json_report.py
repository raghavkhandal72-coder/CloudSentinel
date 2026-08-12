import datetime
import json
import os


def generate_json_report(findings, output_path=None):
    total_findings = len(findings)
    critical = sum(1 for f in findings if f.get('risk_level') == 'Critical')
    high = sum(1 for f in findings if f.get('risk_level') == 'High')
    medium = sum(1 for f in findings if f.get('risk_level') == 'Medium')
    low = sum(1 for f in findings if f.get('risk_level') == 'Low')
    
    scores = [f.get('risk_score', 0) for f in findings]
    average_risk_score = sum(scores) / len(scores) if scores else 0.0
    maximum_risk_score = max(scores) if scores else 0
    
    providers = list({f.get('provider') for f in findings if f.get('provider')})
    
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    report = {
        "metadata": {
            "tool": "CloudSentinel",
            "version": "1.0.0",
            "scan_started_at": now,  # In a real tool this would be tracked from start
            "scan_finished_at": now,
            "providers": providers
        },
        "summary": {
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "average_risk_score": round(average_risk_score, 1),
            "maximum_risk_score": maximum_risk_score
        },
        "findings": findings
    }
    
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
            
    return report
