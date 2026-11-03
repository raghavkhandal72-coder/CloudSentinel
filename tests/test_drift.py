from backend.engine.drift import DriftEngine


def test_drift_engine_detection():
    baseline = [
        {"provider": "AWS", "service": "S3", "resource": "bucket-a", "issue": "Public Read", "risk_level": "High"},
        {"provider": "AWS", "service": "EC2", "resource": "sg-123", "issue": "SSH Open", "risk_level": "Critical"},
    ]

    current = [
        # bucket-a was fixed (not in current)
        # sg-123 is still present (unchanged)
        {"provider": "AWS", "service": "EC2", "resource": "sg-123", "issue": "SSH Open", "risk_level": "Critical"},
        # rds-db is newly added (regression)
        {"provider": "AWS", "service": "RDS", "resource": "rds-db", "issue": "Unencrypted Storage", "risk_level": "High"},
    ]

    drift = DriftEngine.calculate_drift(baseline, current)
    summary = drift["summary"]

    assert summary["new_count"] == 1
    assert summary["resolved_count"] == 1
    assert summary["unchanged_count"] == 1
    assert summary["new_high"] == 1
    assert summary["status"] == "REGRESSION"

    assert drift["new_findings"][0]["resource"] == "rds-db"
    assert drift["resolved_findings"][0]["resource"] == "bucket-a"
    assert drift["unchanged_findings"][0]["resource"] == "sg-123"


def test_drift_engine_improved():
    baseline = [
        {"provider": "AWS", "service": "S3", "resource": "b1", "issue": "Public Read", "risk_level": "Medium"},
    ]
    current = []  # Fixed all issues

    drift = DriftEngine.calculate_drift(baseline, current)
    assert drift["summary"]["status"] == "IMPROVED"
    assert drift["summary"]["resolved_count"] == 1
    assert drift["summary"]["new_count"] == 0


def test_drift_engine_stable():
    findings = [
        {"provider": "GCP", "service": "Storage", "resource": "gs://data", "issue": "Public Access", "risk_level": "High"},
    ]

    drift = DriftEngine.calculate_drift(findings, findings)
    assert drift["summary"]["status"] == "STABLE"
    assert drift["summary"]["new_count"] == 0
    assert drift["summary"]["resolved_count"] == 0
    assert drift["summary"]["unchanged_count"] == 1
