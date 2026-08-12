import pytest
import json
import os
from backend.reports.json_report import generate_json_report
from backend.reports.html_report import generate_html_report, esc

def test_json_summary():
    findings = [
        {"risk_level": "Critical", "risk_score": 90, "provider": "AWS"},
        {"risk_level": "High", "risk_score": 75, "provider": "AWS"},
        {"risk_level": "Medium", "risk_score": 50, "provider": "Azure"}
    ]
    report = generate_json_report(findings)
    assert report["summary"]["total_findings"] == 3
    assert report["summary"]["critical"] == 1
    assert report["summary"]["high"] == 1
    assert report["summary"]["medium"] == 1
    assert report["summary"]["low"] == 0
    assert "metadata" in report
    assert "CloudSentinel" in report["metadata"]["tool"]
    assert "AWS" in report["metadata"]["providers"]
    assert "Azure" in report["metadata"]["providers"]

def test_json_scores():
    findings = [
        {"risk_score": 10},
        {"risk_score": 20},
        {"risk_score": 60}
    ]
    report = generate_json_report(findings)
    assert report["summary"]["average_risk_score"] == 30.0
    assert report["summary"]["maximum_risk_score"] == 60

def test_json_empty_findings():
    report = generate_json_report([])
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["average_risk_score"] == 0.0
    assert report["summary"]["maximum_risk_score"] == 0
    assert report["metadata"]["providers"] == []

def test_html_generation(tmp_path):
    findings = [
        {"resource": "test_resource", "issue": "test_issue", "risk_level": "High", "risk_score": 70}
    ]
    out_path = tmp_path / "report.html"
    res = generate_html_report(findings, str(out_path))
    assert out_path.exists()
    
    with open(out_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "CloudSentinel Security Assessment" in content
        assert "test_resource" in content
        assert "test_issue" in content
        assert "HIGH" in content
        assert "70 / 100" in content

def test_html_escaping(tmp_path):
    malicious = "<script>alert(1)</script>"
    findings = [
        {"resource": malicious, "issue": malicious, "remediation": malicious}
    ]
    out_path = tmp_path / "report.html"
    generate_html_report(findings, str(out_path))
    
    with open(out_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "<script>" not in content
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content

def test_html_escaping_missing_optional_fields(tmp_path):
    findings = [
        {"risk_level": "Low", "risk_score": 10} # Missing resource, issue, evidence
    ]
    out_path = tmp_path / "report.html"
    generate_html_report(findings, str(out_path))
    
    with open(out_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Unknown" in content
        assert "None provided" in content
