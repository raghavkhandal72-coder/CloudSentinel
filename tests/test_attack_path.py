from backend.engine.attack_path import AttackPathEngine


def test_attack_path_detection_toxic_combination():
    findings = [
        {
            "provider": "AWS",
            "service": "EC2",
            "resource": "sg-0123456789",
            "issue": "Security group allows unrestricted SSH access (0.0.0.0/0 on port 22)",
            "risk_level": "CRITICAL",
        },
        {
            "provider": "AWS",
            "service": "IAM",
            "resource": "arn:aws:iam::123456789012:user/admin",
            "issue": "User has AdministratorAccess policy attached directly",
            "risk_level": "CRITICAL",
        },
        {
            "provider": "AWS",
            "service": "RDS",
            "resource": "db-production",
            "issue": "RDS database is publicly accessible and storage is unencrypted",
            "risk_level": "HIGH",
        },
    ]

    engine = AttackPathEngine()
    paths = engine.correlate_attack_paths(findings)

    assert len(paths) >= 1
    p = paths[0]
    assert "Attack Path" in p["title"] or "Toxic" in p["title"]
    assert p["severity"] == "CRITICAL"
    assert len(p["kill_chain"]) >= 2
    assert "ascii_diagram" in p
    assert "mermaid_diagram" in p
    assert "remediation_priority" in p


def test_attack_path_k8s_container_breakout():
    findings = [
        {
            "provider": "Kubernetes",
            "service": "Workload",
            "resource": "k8s/default/Deployment/backend-api/container/app",
            "issue": "Privileged container execution enabled in container 'app'",
            "risk_level": "CRITICAL",
        },
        {
            "provider": "Kubernetes",
            "service": "Workload",
            "resource": "k8s/default/Deployment/backend-api",
            "issue": "Host namespace sharing enabled (hostNetwork, hostPID)",
            "risk_level": "HIGH",
        },
    ]

    engine = AttackPathEngine()
    paths = engine.correlate_attack_paths(findings)

    assert len(paths) >= 1
    k8s_path = next(p for p in paths if "Kubernetes" in p["title"] or "Container" in p["title"])
    assert "Breakout" in k8s_path["title"] or "Host" in k8s_path["title"]
    assert k8s_path["severity"] == "CRITICAL"


def test_attack_path_clean_findings():
    findings = [
        {
            "provider": "AWS",
            "service": "S3",
            "resource": "clean-bucket",
            "issue": "Bucket logging disabled",
            "risk_level": "LOW",
        }
    ]

    engine = AttackPathEngine()
    paths = engine.correlate_attack_paths(findings)
    assert len(paths) == 0
