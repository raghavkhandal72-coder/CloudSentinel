import pytest
from backend.scanners.azure import AzureScanner
from unittest.mock import MagicMock, patch

@patch("backend.scanners.azure.DefaultAzureCredential")
@patch("backend.scanners.azure.SubscriptionClient")
def test_azure_scanner_unauthenticated(mock_sub, mock_cred):
    mock_sub.side_effect = Exception("No credentials")
    scanner = AzureScanner()
    assert not scanner.is_authenticated
    
    findings = scanner.scan_all()
    assert len(findings) == 1
    assert "Authentication Failed" in findings[0]['issue']

@patch("backend.scanners.azure.DefaultAzureCredential")
@patch("backend.scanners.azure.SubscriptionClient")
def test_azure_scanner_authenticated(mock_sub, mock_cred):
    mock_client = MagicMock()
    mock_sub.return_value = mock_client
    
    # Mock subscriptions
    mock_sub_item = MagicMock()
    mock_sub_item.subscription_id = "test-sub-123"
    mock_client.subscriptions.list.return_value = [mock_sub_item]
    
    scanner = AzureScanner()
    assert scanner.is_authenticated
