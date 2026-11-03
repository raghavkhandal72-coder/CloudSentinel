from backend.reports.sarif_report import generate_sarif_report


def test_sarif_generation():
    findings = [
        {
            "provider": "AWS",
            "service": "S3",
            "resource": "arn:aws:s3:::my-bucket",
            "issue": "Bucket does not block all public access",
            "severity": "Critical",
            "risk_level": "Critical",
            "risk_score": 85,
            "remediation": {"title": "Enable Block Public Access", "steps": ["Step 1"]},
            "frameworks": {"cis_aws": "2.1.1", "mitre": "T1530"},
        },
        {
            "provider": "Azure",
            "service": "Storage",
            "resource": "prodaccount",
            "issue": "Public blob access is allowed",
            "severity": "High",
            "risk_level": "High",
            "risk_score": 70,
            "remediation": "Set allow_blob_public_access to False",
            "frameworks": {"cis_azure": "3.7"},
        },
    ]

    sarif = generate_sarif_report(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CloudSentinel"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "error"
    assert len(run["tool"]["driver"]["rules"]) == 2


def test_sarif_output_file(tmp_path):
    findings = [{"issue": "Test issue", "resource": "res-1", "severity": "Low", "risk_level": "Low"}]
    out_file = tmp_path / "results.sarif"
    sarif = generate_sarif_report(findings, str(out_file))

    assert out_file.exists()
    assert sarif["runs"][0]["results"][0]["level"] == "note"
