from unittest.mock import MagicMock, patch

from backend.scanners.gcp import GCPScanner


def test_gcp_scanner_unauthenticated():
    with patch.dict("sys.modules", {"google.auth": None}):
        scanner = GCPScanner()
        scanner.is_authenticated = False
        findings = scanner.scan_all()
        assert len(findings) == 1
        assert "Authentication Failed" in findings[0]["issue"]
        assert findings[0]["provider"] == "GCP"


def test_gcp_scanner_public_storage():
    scanner = GCPScanner(project_id="test-project")
    scanner.is_authenticated = True
    scanner.credentials = MagicMock()

    mock_bucket = MagicMock()
    mock_bucket.name = "public-assets-bucket"
    mock_bucket.get_iam_policy.return_value = {
        "roles/storage.objectViewer": ["allUsers"]
    }
    mock_bucket.iam_configuration.uniform_bucket_level_access_enabled = False

    mock_storage = MagicMock()
    mock_storage.Client.return_value.list_buckets.return_value = [mock_bucket]
    mock_cloud = MagicMock()
    mock_cloud.storage = mock_storage

    with patch.dict("sys.modules", {
        "google": MagicMock(),
        "google.cloud": mock_cloud,
        "google.cloud.storage": mock_storage,
    }):
        findings = scanner.scan_storage()

        assert any("public internet access" in f["issue"] for f in findings)
        assert any(f["severity"] == "Critical" for f in findings)
        assert any("uniform bucket-level access" in f["issue"] for f in findings)


def test_gcp_scanner_firewall_ssh():
    scanner = GCPScanner(project_id="test-project")
    scanner.is_authenticated = True
    scanner.credentials = MagicMock()

    rule = MagicMock()
    rule.name = "allow-ssh-all"
    rule.direction = "INGRESS"
    rule.disabled = False
    rule.source_ranges = ["0.0.0.0/0"]

    allowed = MagicMock()
    allowed.I_p_protocol = "tcp"
    allowed.ports = ["22"]
    rule.allowed = [allowed]

    mock_compute = MagicMock()
    mock_compute.FirewallsClient.return_value.list.return_value = [rule]
    mock_cloud = MagicMock()
    mock_cloud.compute_v1 = mock_compute

    with patch.dict("sys.modules", {
        "google": MagicMock(),
        "google.cloud": mock_cloud,
        "google.cloud.compute_v1": mock_compute,
    }):
        findings = scanner.scan_compute_firewalls()

        assert any("inbound SSH (Port 22)" in f["issue"] for f in findings)
        assert any(f["severity"] == "Critical" for f in findings)
