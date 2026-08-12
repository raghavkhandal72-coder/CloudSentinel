from backend.main import generate_mock_findings


def test_mock_findings_load():
    findings = generate_mock_findings()
    assert len(findings) > 0
    # Ensure there are no padded "PASSED" fake resources as requested
    for f in findings:
        assert f.get("severity") != "PASSED"
        assert f.get("risk_level") != "PASSED"
