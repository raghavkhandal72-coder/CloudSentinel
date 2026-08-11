import pytest
from backend.engine.risk import RiskEngine

def test_risk_calculation():
    engine = RiskEngine()
    
    # High base severity but no exposure/privilege
    finding = {"resource": "Test", "issue": "Generic issue", "severity": "High"}
    score = engine.calculate_risk(finding)
    assert score == 30
    assert finding['risk_level'] == 'Low' # 30 is Low
    
    # Public S3 bucket (Severity 40 + Data 15 + Exposure 20) = 75 (High)
    finding_s3 = {"resource": "S3: prod-db", "issue": "public internet access", "severity": "Critical"}
    score = engine.calculate_risk(finding_s3)
    assert score == 75
    assert finding_s3['risk_level'] == 'High'

    # Admin access with missing MFA (Severity 40 + Privilege 15 + Exploitability 10) = 65
    finding_iam = {"resource": "IAM User", "issue": "Missing MFA on Administrator", "severity": "Critical"}
    score = engine.calculate_risk(finding_iam)
    assert score == 65
    assert finding_iam['risk_level'] == 'High'

def test_evaluate_findings():
    engine = RiskEngine()
    findings = [
        {"resource": "A", "issue": "Low issue", "severity": "Low"},
        {"resource": "B", "issue": "public internet S3 bucket without mfa administrator", "severity": "Critical"}
    ]
    evaluated = engine.evaluate_findings(findings)
    assert evaluated[0]['resource'] == "B" # Highest risk first
    assert evaluated[1]['resource'] == "A"
