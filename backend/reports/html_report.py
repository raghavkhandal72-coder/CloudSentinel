import os

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>CloudSentinel Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background-color: #f8f9fa; color: #333; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; }
        .stat-box { flex: 1; padding: 20px; text-align: center; border-radius: 8px; color: white; font-weight: bold; }
        .stat-critical { background-color: #e74c3c; }
        .stat-high { background-color: #e67e22; }
        .stat-medium { background-color: #f1c40f; color: #333; }
        .stat-low { background-color: #3498db; }
        .finding { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 6px; border-left: 5px solid #ddd; }
        .Critical { border-left-color: #e74c3c; }
        .High { border-left-color: #e67e22; }
        .Medium { border-left-color: #f1c40f; }
        .Low { border-left-color: #3498db; }
        .score { font-weight: bold; padding: 3px 8px; border-radius: 4px; color: white; float: right; }
        .score-Critical { background-color: #e74c3c; }
        .score-High { background-color: #e67e22; }
        .score-Medium { background-color: #f1c40f; color: #333;}
        .score-Low { background-color: #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CloudSentinel Security Assessment</h1>
        <h2>Summary</h2>
        <div class="summary">
            <div class="stat-box stat-critical">
                <div style="font-size: 24px;">{{ critical }}</div>
                <div>Critical</div>
            </div>
            <div class="stat-box stat-high">
                <div style="font-size: 24px;">{{ high }}</div>
                <div>High</div>
            </div>
            <div class="stat-box stat-medium">
                <div style="font-size: 24px;">{{ medium }}</div>
                <div>Medium</div>
            </div>
            <div class="stat-box stat-low">
                <div style="font-size: 24px;">{{ low }}</div>
                <div>Low</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        {{ findings_html }}
    </div>
</body>
</html>
"""

def generate_html_report(findings, output_path="reports/cloudsentinel-report.html"):
    critical = sum(1 for f in findings if f.get('risk_level') == 'Critical')
    high = sum(1 for f in findings if f.get('risk_level') == 'High')
    medium = sum(1 for f in findings if f.get('risk_level') == 'Medium')
    low = sum(1 for f in findings if f.get('risk_level') == 'Low')
    
    findings_html = ""
    for f in findings:
        risk_level = f.get('risk_level', 'Low')
        findings_html += f"""
        <div class="finding {risk_level}">
            <span class="score score-{risk_level}">Risk Score: {f.get('risk_score', 0)}/100</span>
            <h3>{f.get('resource')}</h3>
            <p><strong>Issue:</strong> {f.get('issue')}</p>
        """
        
        factors = f.get('risk_factors', [])
        if factors:
            findings_html += "<p><strong>Why is this Risk Level?</strong><ul>"
            for factor in factors:
                findings_html += f"<li>{factor}</li>"
            findings_html += "</ul></p>"
            
        remediation = f.get('remediation')
        if remediation:
            findings_html += f"<p><strong>Remediation:</strong> {remediation}</p>"
            
        findings_html += "</div>"
    
    html = HTML_TEMPLATE.replace("{{ critical }}", str(critical))
    html = html.replace("{{ high }}", str(high))
    html = html.replace("{{ medium }}", str(medium))
    html = html.replace("{{ low }}", str(low))
    html = html.replace("{{ findings_html }}", findings_html)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html)
    
    return output_path
