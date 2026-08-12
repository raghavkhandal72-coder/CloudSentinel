import html
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
        .finding-card { border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; background: #fff; overflow: hidden; font-size: 14px; }
        .finding-header { padding: 15px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .Critical .finding-header { background-color: #e74c3c; }
        .High .finding-header { background-color: #e67e22; }
        .Medium .finding-header { background-color: #f1c40f; color: #333; }
        .Low .finding-header { background-color: #3498db; }
        .PASSED .finding-header { background-color: #2ecc71; }
        .finding-body { padding: 15px; }
        .finding-row { margin-bottom: 10px; }
        .finding-label { font-weight: bold; color: #555; }
        ul { margin: 5px 0 0 20px; padding: 0; }
        .remediation-box { background: #fdf2e9; border-left: 4px solid #e67e22; padding: 10px; margin-top: 15px; }
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

def esc(value):
    if value is None:
        return ""
    return html.escape(str(value))

def generate_html_report(findings, output_path="reports/cloudsentinel-report.html"):
    critical = sum(1 for f in findings if f.get('risk_level') == 'Critical')
    high = sum(1 for f in findings if f.get('risk_level') == 'High')
    medium = sum(1 for f in findings if f.get('risk_level') == 'Medium')
    low = sum(1 for f in findings if f.get('risk_level') == 'Low')
    
    findings_html = ""
    for f in findings:
        risk_level = f.get('risk_level', 'Low')
        score = f.get('risk_score', 0)
        provider = esc(f.get('provider', 'Unknown'))
        service = esc(f.get('service', 'Unknown'))
        issue = esc(f.get('issue', 'Unknown'))
        resource = esc(f.get('resource', 'Unknown'))
        evidence = esc(f.get('evidence', 'None provided'))
        
        factors = f.get('risk_factors', [])
        factors_html = "<ul>" + "".join([f"<li>{esc(factor)}</li>" for factor in factors]) + "</ul>" if factors else "None"
        
        # Remediation could be string or dict from new remediation engine
        rem = f.get('remediation', '')
        if isinstance(rem, dict):
            rem_title = esc(rem.get('title', ''))
            rem_steps = "<ul>" + "".join([f"<li>{esc(step)}</li>" for step in rem.get('steps', [])]) + "</ul>"
            rem_html = f"<strong>{rem_title}</strong><br>{rem_steps}"
        else:
            rem_html = esc(rem)
            
        fw = f.get('frameworks', {})
        fw_html = ", ".join([f"{esc(k)}: {esc(v)}" for k, v in fw.items()])
        
        card = f"""
        <div class="finding-card {risk_level}">
            <div class="finding-header">
                <div>
                    <div style="font-weight: bold; font-size: 16px;">{risk_level.upper()} &nbsp;&nbsp;&nbsp; {score} / 100</div>
                    <div>{provider} • {service}</div>
                    <div style="font-size: 18px; margin-top: 5px;">{issue}</div>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-row"><span class="finding-label">Resource:</span> {resource}</div>
                <div class="finding-row"><span class="finding-label">Evidence:</span> <pre style="margin: 5px 0; background: #eee; padding: 5px; border-radius: 4px;">{evidence}</pre></div>
                
                <div class="finding-row" style="margin-top: 15px;">
                    <span class="finding-label">Why is this Risk Level?</span>
                    {factors_html}
                </div>
                
                <div class="remediation-box">
                    <span class="finding-label">Remediation:</span><br>
                    {rem_html}
                </div>
                
                <div class="finding-row" style="margin-top: 15px; font-size: 12px; color: #777;">
                    <span class="finding-label">Framework Mapping:</span> {fw_html}
                </div>
            </div>
        </div>
        """
        findings_html += card
    
    html_content = HTML_TEMPLATE.replace("{{ critical }}", str(critical))
    html_content = html_content.replace("{{ high }}", str(high))
    html_content = html_content.replace("{{ medium }}", str(medium))
    html_content = html_content.replace("{{ low }}", str(low))
    html_content = html_content.replace("{{ findings_html }}", findings_html)
    
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(html_content)
    
    return output_path
