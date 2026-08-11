import json
import os

def generate_json_report(findings, output_path=None):
    report = {
        "summary": {
            "critical": sum(1 for f in findings if f.get('risk_level') == 'Critical'),
            "high": sum(1 for f in findings if f.get('risk_level') == 'High'),
            "medium": sum(1 for f in findings if f.get('risk_level') == 'Medium'),
            "low": sum(1 for f in findings if f.get('risk_level') == 'Low')
        },
        "findings": findings
    }
    
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
            
    return report
