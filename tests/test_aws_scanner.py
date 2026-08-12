import pytest
import datetime
import json
from unittest.mock import MagicMock, patch
from botocore.exceptions import NoCredentialsError, ClientError
from backend.scanners.aws import AWSScanner

@pytest.fixture
def scanner():
    with patch("boto3.client") as mock_boto:
        s = AWSScanner()
        s.is_authenticated = True
        s.iam = MagicMock()
        s.s3 = MagicMock()
        s.ec2 = MagicMock()
        s.cloudtrail = MagicMock()
        return s

def test_aws_scanner_unauthenticated():
    with patch("boto3.client") as mock_boto:
        mock_boto.side_effect = NoCredentialsError()
        s = AWSScanner()
        assert not s.is_authenticated
        findings = s.scan_all()
        assert "Authentication Failed" in findings[0]['issue']

def test_root_mfa_disabled(scanner):
    scanner.iam.get_account_summary.return_value = {'SummaryMap': {'AccountMFAEnabled': 0}}
    scanner.iam.list_users.return_value = {'Users': []}
    scanner.iam.list_roles.return_value = {'Roles': []}
    
    findings = scanner.scan_iam()
    assert any("Root account does not have MFA enabled" in f['issue'] for f in findings)

def test_user_without_mfa(scanner):
    scanner.iam.get_account_summary.return_value = {'SummaryMap': {'AccountMFAEnabled': 1}}
    scanner.iam.list_users.return_value = {'Users': [{'UserName': 'test-user'}]}
    scanner.iam.list_mfa_devices.return_value = {'MFADevices': []}
    scanner.iam.list_user_policies.return_value = {'PolicyNames': []}
    scanner.iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
    scanner.iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
    scanner.iam.list_roles.return_value = {'Roles': []}
    
    findings = scanner.scan_iam()
    assert any("IAM user does not have MFA enabled" in f['issue'] for f in findings)

def test_admin_access(scanner):
    scanner.iam.get_account_summary.return_value = {'SummaryMap': {'AccountMFAEnabled': 1}}
    scanner.iam.list_users.return_value = {'Users': [{'UserName': 'test-user'}]}
    scanner.iam.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': '123'}]}
    scanner.iam.list_user_policies.return_value = {'PolicyNames': []}
    scanner.iam.list_attached_user_policies.return_value = {'AttachedPolicies': [{'PolicyName': 'AdministratorAccess'}]}
    scanner.iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
    scanner.iam.list_roles.return_value = {'Roles': []}
    
    findings = scanner.scan_iam()
    assert any("AdministratorAccess" in f['issue'] for f in findings)

def test_wildcard_policy(scanner):
    scanner.iam.get_account_summary.return_value = {'SummaryMap': {'AccountMFAEnabled': 1}}
    scanner.iam.list_users.return_value = {'Users': [{'UserName': 'test-user'}]}
    scanner.iam.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': '123'}]}
    scanner.iam.list_user_policies.return_value = {'PolicyNames': []}
    scanner.iam.list_attached_user_policies.return_value = {'AttachedPolicies': [{'PolicyName': 'CustomPol', 'PolicyArn': 'arn:aws:iam::1:policy/CustomPol'}]}
    scanner.iam.get_policy.return_value = {'Policy': {'DefaultVersionId': 'v1'}}
    scanner.iam.get_policy_version.return_value = {
        'PolicyVersion': {
            'Document': {
                'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
            }
        }
    }
    scanner.iam.list_access_keys.return_value = {'AccessKeyMetadata': []}
    scanner.iam.list_roles.return_value = {'Roles': []}
    
    findings = scanner.scan_iam()
    assert any("wildcard Action and Resource" in f['issue'] for f in findings)

def test_old_access_key(scanner):
    scanner.iam.get_account_summary.return_value = {'SummaryMap': {'AccountMFAEnabled': 1}}
    scanner.iam.list_users.return_value = {'Users': [{'UserName': 'test-user'}]}
    scanner.iam.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': '123'}]}
    scanner.iam.list_user_policies.return_value = {'PolicyNames': []}
    scanner.iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
    old_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=100)
    scanner.iam.list_access_keys.return_value = {'AccessKeyMetadata': [{'AccessKeyId': 'AKIA123', 'CreateDate': old_date, 'Status': 'Active'}]}
    scanner.iam.list_roles.return_value = {'Roles': []}
    
    findings = scanner.scan_iam()
    assert any("older than 90 days" in f['issue'] for f in findings)

def test_public_s3(scanner):
    scanner.s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    error_response = {'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration'}}
    scanner.s3.get_public_access_block.side_effect = ClientError(error_response, 'GetPublicAccessBlock')
    
    findings = scanner.scan_s3()
    assert any("Block Public Access enabled" in f['issue'] or "block all public access" in f['issue'] for f in findings)

def test_unencrypted_s3(scanner):
    scanner.s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    error_response = {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}
    scanner.s3.get_bucket_encryption.side_effect = ClientError(error_response, 'GetBucketEncryption')
    
    findings = scanner.scan_s3()
    assert any("default Server-Side Encryption" in f['issue'] for f in findings)

def test_public_s3_acl(scanner):
    scanner.s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    scanner.s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
    }
    findings = scanner.scan_s3()
    assert any("Bucket ACL allows public" in f['issue'] for f in findings)

def test_public_s3_policy(scanner):
    scanner.s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    policy_doc = {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::test-bucket/*"}]
    }
    scanner.s3.get_bucket_policy.return_value = {'Policy': json.dumps(policy_doc)}
    findings = scanner.scan_s3()
    assert any("public object access" in f['issue'] for f in findings)

def test_open_ssh(scanner):
    scanner.ec2.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-123',
            'IpPermissions': [{'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        }]
    }
    findings = scanner.scan_security_groups()
    assert any("sensitive port 22" in f['issue'] for f in findings)
    assert findings[0]['severity'] == 'Critical'

def test_open_rdp(scanner):
    scanner.ec2.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-123',
            'IpPermissions': [{'FromPort': 3389, 'ToPort': 3389, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        }]
    }
    findings = scanner.scan_security_groups()
    assert any("sensitive port 3389" in f['issue'] for f in findings)
    assert findings[0]['severity'] == 'Critical'

def test_open_database(scanner):
    scanner.ec2.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-123',
            'IpPermissions': [{'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        }]
    }
    findings = scanner.scan_security_groups()
    assert any("sensitive port 3306" in f['issue'] for f in findings)
    assert findings[0]['severity'] == 'High'

def test_cloudtrail_missing(scanner):
    scanner.cloudtrail.describe_trails.return_value = {'trailList': []}
    findings = scanner.scan_cloudtrail()
    assert any("No CloudTrail trails exist" in f['issue'] for f in findings)

def test_cloudtrail_not_logging(scanner):
    scanner.cloudtrail.describe_trails.return_value = {'trailList': [{'Name': 'test-trail', 'IsMultiRegionTrail': True, 'LogFileValidationEnabled': True, 'KmsKeyId': 'key'}]}
    scanner.cloudtrail.get_trail_status.return_value = {'IsLogging': False}
    findings = scanner.scan_cloudtrail()
    assert any("logging is disabled" in f['issue'] for f in findings)

def test_cloudtrail_not_multiregion(scanner):
    scanner.cloudtrail.describe_trails.return_value = {'trailList': [{'Name': 'test-trail', 'IsMultiRegionTrail': False, 'LogFileValidationEnabled': True, 'KmsKeyId': 'key'}]}
    scanner.cloudtrail.get_trail_status.return_value = {'IsLogging': True}
    findings = scanner.scan_cloudtrail()
    assert any("No multi-region CloudTrail is enabled" in f['issue'] for f in findings)
