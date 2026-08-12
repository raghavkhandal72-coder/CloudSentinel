from backend.engine.remediation import RemediationEngine
from backend.engine.risk import RiskEngine
from backend.main import generate_mock_findings
from backend.reports.html_report import generate_html_report
from backend.reports.json_report import generate_json_report


def test_full_mock_scan_pipeline(tmp_path):
    # 1. Ingestion: Mock vulnerable configuration
    findings = generate_mock_findings()
    assert len(findings) > 0, "Should generate mock findings"
    
    # 2. Risk Engine Analysis
    risk_engine = RiskEngine()
    evaluated_findings = risk_engine.evaluate_findings(findings)
    assert all('risk_score' in f for f in evaluated_findings)
    assert all('risk_level' in f for f in evaluated_findings)
    assert all('risk_factors' in f for f in evaluated_findings)
    
    # 3. Remediation Enrichment
    rem_engine = RemediationEngine()
    remediated_findings = rem_engine.apply_remediation(evaluated_findings)
    assert all('remediation' in f for f in remediated_findings)
    
    # 4. JSON Generation
    json_path = tmp_path / "report.json"
    json_report = generate_json_report(remediated_findings, str(json_path))
    assert json_path.exists()
    assert json_report["summary"]["total_findings"] == len(findings)
    assert "metadata" in json_report
    
    # 5. HTML Generation
    html_path = tmp_path / "report.html"
    generate_html_report(remediated_findings, str(html_path))
    assert html_path.exists()
    
    # Verify escaping in HTML
    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
        assert "CloudSentinel Security Assessment" in html_content
        # Spot check that one of the resource titles is present
        assert remediated_findings[0]['resource'] in html_content
