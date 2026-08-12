import pytest

from backend.engine.risk import RiskEngine


@pytest.fixture
def engine():
    return RiskEngine()

def test_critical_public_s3(engine):
    finding = {
        "severity": "Critical",
        "exposure": 20,
        "privilege": 0,
        "data_sensitivity": 15,
        "exploitability": 0
    }
    score = engine.calculate_risk(finding)
    # Severity 40 + 20 + 15 = 75
    assert score == 75
    assert finding['risk_level'] == 'High'
    assert 'Internet or broadly exposed' in finding['risk_factors']
    assert 'Sensitive data or storage resource' in finding['risk_factors']

def test_high_iam_owner(engine):
    finding = {
        "severity": "High",
        "exposure": 0,
        "privilege": 15,
        "data_sensitivity": 0,
        "exploitability": 10
    }
    score = engine.calculate_risk(finding)
    # Severity 30 + 15 + 10 = 55
    assert score == 55
    assert finding['risk_level'] == 'Medium'
    assert 'High privileges granted' in finding['risk_factors']
    assert 'Easily exploitable configuration (e.g. unencrypted, no MFA)' in finding['risk_factors']

def test_public_storage(engine):
    finding = {
        "severity": "Critical", # 40
        "exposure": 20,
        "data_sensitivity": 15,
        "privilege": 0,
        "exploitability": 10
    }
    score = engine.calculate_risk(finding)
    # 40 + 20 + 15 + 10 = 85
    assert score == 85
    assert finding['risk_level'] == 'Critical'

def test_open_ssh(engine):
    finding = {
        "severity": "Critical", # 40
        "exposure": 20,
        "exploitability": 10,
        "privilege": 0,
        "data_sensitivity": 0
    }
    score = engine.calculate_risk(finding)
    # 40 + 20 + 10 = 70
    assert score == 70
    assert finding['risk_level'] == 'High'

def test_mfa_missing(engine):
    finding = {
        "severity": "High", # 30
        "exposure": 0,
        "exploitability": 10,
        "privilege": 0,
        "data_sensitivity": 0
    }
    score = engine.calculate_risk(finding)
    # 30 + 10 = 40
    assert score == 40
    assert finding['risk_level'] == 'Medium'

def test_score_cap_at_100(engine):
    finding = {
        "severity": "Critical", # 40
        "exposure": 20,
        "privilege": 20,
        "data_sensitivity": 20,
        "exploitability": 20
    }
    score = engine.calculate_risk(finding)
    # 40 + 80 = 120 -> capped at 100
    assert score == 100
    assert finding['risk_level'] == 'Critical'

def test_risk_level_mapping(engine):
    levels = [
        (85, 'Critical'),
        (65, 'High'),
        (40, 'Medium'),
        (10, 'Low'),
        (0, 'PASSED')
    ]
    for target_score, expected_level in levels:
        finding = {"severity": "PASSED", "exposure": target_score} # Base severity is 0
        engine.calculate_risk(finding)
        # Exposure alone will drive the score
        if target_score == 0:
             assert finding['risk_level'] == expected_level
        else:
             assert finding['risk_level'] == expected_level

def test_sorting(engine):
    findings = [
        {"severity": "Low", "exposure": 0, "privilege": 0, "data_sensitivity": 0, "exploitability": 0}, # 10
        {"severity": "Critical", "exposure": 20, "privilege": 15, "data_sensitivity": 15, "exploitability": 10}, # 100
        {"severity": "High", "exposure": 0, "privilege": 15, "data_sensitivity": 0, "exploitability": 10} # 55
    ]
    sorted_findings = engine.evaluate_findings(findings)
    assert sorted_findings[0]['risk_score'] == 100
    assert sorted_findings[1]['risk_score'] == 55
    assert sorted_findings[2]['risk_score'] == 10

def test_zero_score(engine):
    finding = {
        "severity": "PASSED",
        "exposure": 0,
        "privilege": 0,
        "data_sensitivity": 0,
        "exploitability": 0
    }
    score = engine.calculate_risk(finding)
    assert score == 0
    assert finding['risk_level'] == 'PASSED'
    assert len(finding['risk_factors']) == 0

def test_risk_factors(engine):
    finding = {
        "severity": "Critical",
        "exposure": 20,
        "privilege": 15,
        "data_sensitivity": 15,
        "exploitability": 10
    }
    engine.calculate_risk(finding)
    assert len(finding['risk_factors']) == 5
    assert "Base severity is Critical" in finding['risk_factors']
    assert "Internet or broadly exposed" in finding['risk_factors']
    assert "High privileges granted" in finding['risk_factors']
    assert "Sensitive data or storage resource" in finding['risk_factors']
    assert "Easily exploitable configuration (e.g. unencrypted, no MFA)" in finding['risk_factors']
