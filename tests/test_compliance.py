from backend.engine.compliance import ComplianceEngine


def test_compliance_engine_grades():
    assert ComplianceEngine.calculate_posture_grade(96) == "A+"
    assert ComplianceEngine.calculate_posture_grade(90) == "A"
    assert ComplianceEngine.calculate_posture_grade(80) == "B"
    assert ComplianceEngine.calculate_posture_grade(65) == "C"
    assert ComplianceEngine.calculate_posture_grade(50) == "D"
    assert ComplianceEngine.calculate_posture_grade(30) == "F"


def test_evaluate_compliance_clean():
    engine = ComplianceEngine()
    res = engine.evaluate_compliance([])
    assert res["posture_score"] == 100
    assert res["posture_grade"] == "A+"
    assert res["total_findings"] == 0
    assert res["severity_breakdown"]["critical"] == 0


def test_evaluate_compliance_with_findings():
    findings = [
        {
            "risk_level": "Critical",
            "frameworks": {"cis_aws": "2.1.1", "soc2": "CC6.6"},
        },
        {
            "risk_level": "High",
            "frameworks": {"cis_azure": "3.7"},
        },
    ]
    engine = ComplianceEngine()
    res = engine.evaluate_compliance(findings)
    # penalty: 15 (critical) + 8 (high) = 23 -> score: 77 -> grade: B
    assert res["posture_score"] == 77
    assert res["posture_grade"] == "B"
    assert res["total_findings"] == 2
    assert res["severity_breakdown"]["critical"] == 1
    assert res["severity_breakdown"]["high"] == 1
    assert res["frameworks"]["cis_aws"]["violations_count"] == 1
    assert res["frameworks"]["cis_azure"]["violations_count"] == 1
    assert res["frameworks"]["soc2"]["violations_count"] == 1
