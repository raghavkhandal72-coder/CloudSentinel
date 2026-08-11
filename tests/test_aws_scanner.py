import pytest
from backend.scanners.aws import AWSScanner
from unittest.mock import MagicMock, patch
from botocore.exceptions import NoCredentialsError, ClientError

@patch("boto3.client")
def test_aws_scanner_unauthenticated(mock_boto):
    mock_boto.side_effect = NoCredentialsError()
    scanner = AWSScanner()
    assert not scanner.is_authenticated
    
    findings = scanner.scan_all()
    assert len(findings) == 1
    assert "Authentication Failed" in findings[0]['issue']

@patch("boto3.client")
def test_aws_scan_s3(mock_boto):
    scanner = AWSScanner()
    scanner.is_authenticated = True
    scanner.s3 = MagicMock()
    
    scanner.s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    
    # Mock BPA missing
    error_response = {'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration'}}
    scanner.s3.get_public_access_block.side_effect = ClientError(error_response, 'GetPublicAccessBlock')
    
    findings = scanner.scan_s3()
    # At least one finding for missing BPA
    assert any("Bucket does not block all public access" in f['issue'] or "Bucket does not have Block Public Access enabled" in f['issue'] for f in findings)
