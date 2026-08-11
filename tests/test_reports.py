import pytest
import os
from backend.reports.html_report import generate_html_report
from backend.reports.json_report import generate_json_report

def test_json_report():
    findings = [{"resource": "Test", "risk_level": "High", "risk_score": 75}]
    report = generate_json_report(findings)
    assert report['summary']['high'] == 1
    assert report['summary']['critical'] == 0

def test_html_report(tmp_path):
    findings = [{"resource": "Test", "issue": "Missing MFA", "severity": "Critical", "risk_level": "High", "risk_score": 75}]
    out_file = tmp_path / "report.html"
    generate_html_report(findings, str(out_file))
    
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "CloudSentinel Security Assessment" in content
    assert "Missing MFA" in content
