from backend.server import calculate_dashboard_stats, run_scan


def test_calculate_dashboard_stats():
    findings = [
        {"risk_level": "CRITICAL"},
        {"risk_level": "HIGH"},
        {"risk_level": "MEDIUM"},
        {"risk_level": "LOW"},
    ]
    stats = calculate_dashboard_stats(findings)

    assert stats["critical"] == 1
    assert stats["high"] == 1
    assert stats["medium"] == 1
    assert stats["passed"] == 1
    assert stats["total_findings"] == 4
    # deduction: 20 + 10 + 5 = 35 -> score: 65
    assert stats["score"] == 65


def test_calculate_dashboard_stats_clean():
    stats = calculate_dashboard_stats([])
    assert stats["score"] == 100
    assert stats["total_findings"] == 0


def test_run_scan_mock():
    results = run_scan("mock")
    assert len(results) > 0
    first = results[0]
    assert "id" in first
    assert "cloud_provider" in first
    assert "resource_id" in first
    assert "finding_title" in first
    assert "risk_level" in first
    assert "remediation" in first
