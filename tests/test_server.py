from unittest.mock import MagicMock

from backend.server import CloudSentinelAPIHandler, calculate_dashboard_stats, run_scan


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
    assert stats["score"] == 65
    assert stats["grade"] == "C"


def test_calculate_dashboard_stats_clean():
    stats = calculate_dashboard_stats([])
    assert stats["score"] == 100
    assert stats["grade"] == "A+"
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
    assert "cli_remediation" in first
    assert "terraform_remediation" in first


def test_api_handler_routes():
    # Test GET routes logic via mocking the handler
    handler = CloudSentinelAPIHandler.__new__(CloudSentinelAPIHandler)
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = MagicMock()

    # Test /api/stats
    handler.path = "/api/stats"
    handler.do_GET()
    assert handler.send_response.called

    # Test /api/compliance
    handler.send_response.reset_mock()
    handler.path = "/api/compliance"
    handler.do_GET()
    assert handler.send_response.called

    # Test /api/export/csv
    handler.send_response.reset_mock()
    handler.path = "/api/export/csv"
    handler.do_GET()
    assert handler.send_response.called

    # Test /api/export/sarif
    handler.send_response.reset_mock()
    handler.path = "/api/export/sarif"
    handler.do_GET()
    assert handler.send_response.called
