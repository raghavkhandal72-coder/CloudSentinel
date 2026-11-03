from backend.reports.console import ConsoleReporter


def test_console_reporter_output(capsys):
    findings = [
        {
            "provider": "AWS",
            "service": "S3",
            "resource": "arn:aws:s3:::test-bucket",
            "issue": "Bucket allows public access",
            "severity": "Critical",
            "risk_level": "Critical",
            "risk_score": 85,
            "risk_factors": ["Internet exposed"],
            "frameworks": {"cis_aws": "2.1.1"},
            "remediation": {
                "title": "Enable Block Public Access",
                "steps": ["Step 1"],
                "cli_command": "aws s3api put-public-access-block ...",
                "terraform": 'resource "aws_s3_bucket" "test" {}',
            },
        }
    ]

    reporter = ConsoleReporter(use_color=False)
    reporter.print_report(findings)

    captured = capsys.readouterr().out
    assert "CloudSentinel" in captured
    assert "EXECUTIVE POSTURE GRADE" in captured
    assert "[CRITICAL]" in captured
    assert "aws s3api put-public-access-block" in captured
    assert "resource \"aws_s3_bucket\"" in captured
