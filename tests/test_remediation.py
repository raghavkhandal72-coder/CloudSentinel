import pytest
from backend.engine.remediation import RemediationEngine

@pytest.fixture
def engine():
    return RemediationEngine()

def test_remediation_mapping_public_s3(engine):
    findings = [{"issue": "S3 bucket has public access"}]
    res = engine.apply_remediation(findings)
    rem = res[0]['remediation']
    assert isinstance(rem, dict)
    assert rem['title'] == "Disable public access"
    assert "Enable Block Public Access" in rem['steps'][0]

def test_remediation_mapping_open_ssh(engine):
    findings = [{"issue": "Allows ingress to port 22 from internet"}]
    res = engine.apply_remediation(findings)
    rem = res[0]['remediation']
    assert isinstance(rem, dict)
    assert rem['title'] == "Restrict SSH exposure"
    assert "Remove 0.0.0.0/0" in rem['steps'][0]

def test_remediation_mapping_public_blob(engine):
    findings = [{"issue": "Public blob access is allowed"}]
    res = engine.apply_remediation(findings)
    rem = res[0]['remediation']
    assert isinstance(rem, dict)
    assert rem['title'] == "Disable Public Blob Access"

def test_remediation_mapping_iam_owner(engine):
    findings = [{"issue": "User has administratoraccess directly attached"}]
    res = engine.apply_remediation(findings)
    rem = res[0]['remediation']
    assert isinstance(rem, dict)
    assert rem['title'] == "Apply Least Privilege"

def test_remediation_fallback_with_existing(engine):
    findings = [{"issue": "Something completely random", "remediation": "Do something specific"}]
    res = engine.apply_remediation(findings)
    rem = res[0]['remediation']
    assert isinstance(rem, dict)
    assert rem['title'] == "Do something specific"
    assert "Apply the recommended fix" in rem['steps'][0]

def test_remediation_default_fallback(engine):
    findings = [{"issue": "Something completely random"}]
    res = engine.apply_remediation(findings)
    rem = res[0]['remediation']
    assert isinstance(rem, dict)
    assert rem['title'] == "Manual Review Required"
