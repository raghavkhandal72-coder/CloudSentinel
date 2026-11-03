from unittest.mock import MagicMock, patch

from backend.notifications.webhook import WebhookNotifier


def test_format_slack_payload():
    findings = [
        {"provider": "AWS", "service": "S3", "resource": "my-bucket", "issue": "Public Access", "risk_level": "CRITICAL"},
        {"provider": "Azure", "service": "KeyVault", "resource": "my-vault", "issue": "Soft-delete disabled", "risk_level": "HIGH"},
    ]
    payload = WebhookNotifier.format_slack_payload(findings, score=65, grade="C", cloud_target="AWS")

    assert "attachments" in payload
    att = payload["attachments"][0]
    assert "Grade C" in att["title"]
    assert any(f["title"] == "Critical Violations" and f["value"] == "1" for f in att["fields"])
    assert any(f["title"] == "High Violations" and f["value"] == "1" for f in att["fields"])


def test_format_teams_payload():
    findings = [
        {"provider": "GCP", "service": "Compute", "resource": "vm-prod", "issue": "Public IP", "risk_level": "MEDIUM"}
    ]
    payload = WebhookNotifier.format_teams_payload(findings, score=90, grade="A", cloud_target="GCP")

    assert payload["@type"] == "MessageCard"
    assert "Grade A" in payload["summary"]


def test_send_notification_mock_success():
    findings = [{"risk_level": "LOW", "resource": "test", "issue": "info"}]

    mock_resp = MagicMock()
    mock_resp.status = 200

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        res = WebhookNotifier.send_notification("https://hooks.slack.com/services/XXX", findings, "aws")
        assert res["status"] == "delivered"
        assert res["status_code"] == 200


def test_send_notification_empty_url():
    res = WebhookNotifier.send_notification("", [])
    assert res["status"] == "skipped"
