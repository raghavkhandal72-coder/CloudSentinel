import tempfile
from pathlib import Path

from backend.engine.autofix import AutoFixEngine


def test_autofix_generate_scripts():
    findings = [
        {
            "provider": "AWS",
            "service": "EC2",
            "resource": "sg-12345",
            "issue": "Security group allows SSH on port 22",
            "risk_level": "CRITICAL",
            "cli_remediation": "aws ec2 revoke-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "terraform_remediation": 'ingress {\n  cidr_blocks = ["10.0.0.0/16"]\n}',
        },
        {
            "provider": "AWS",
            "service": "RDS",
            "resource": "db-test",
            "issue": "RDS database is publicly accessible",
            "risk_level": "HIGH",
            "cli_remediation": "aws rds modify-db-instance --db-instance-identifier db-test --no-publicly-accessible --apply-immediately",
            "terraform_remediation": "publicly_accessible = false",
        },
    ]

    engine = AutoFixEngine()
    sh_content, tf_content = engine.generate_remediation_bundle(findings)

    assert "#!/usr/bin/env bash" in sh_content
    assert "aws ec2 revoke-security-group-ingress" in sh_content
    assert "aws rds modify-db-instance" in sh_content
    assert "terraform" in tf_content.lower() or "ingress" in tf_content

    with tempfile.TemporaryDirectory() as tmpdir:
        files = engine.save_remediation_scripts(findings, output_dir=tmpdir)
        assert len(files) == 2
        for f in files:
            assert Path(f).exists()
            assert Path(f).stat().st_size > 0
