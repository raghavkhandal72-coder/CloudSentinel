import boto3
from botocore.exceptions import NoCredentialsError, ClientError

class AWSScanner:
    def __init__(self):
        try:
            self.iam = boto3.client('iam', region_name='us-east-1')
            self.s3 = boto3.client('s3', region_name='us-east-1')
            self.ec2 = boto3.client('ec2', region_name='us-east-1')
            self.cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')
            self.is_authenticated = True
        except (NoCredentialsError, ClientError):
            self.is_authenticated = False

    def scan_all(self):
        if not self.is_authenticated:
            return [{"resource": "AWS Global", "issue": "Authentication Failed: No AWS Credentials Found", "severity": "Critical"}]
        
        findings = []
        findings.extend(self.scan_iam())
        findings.extend(self.scan_s3())
        findings.extend(self.scan_security_groups())
        findings.extend(self.scan_cloudtrail())
        return findings

    def scan_iam(self):
        findings = []
        try:
            # Check for MFA on root account
            summary = self.iam.get_account_summary()
            if summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                findings.append({"resource": "IAM Root Account", "issue": "Root account does not have MFA enabled", "severity": "Critical"})
            
            # Check for inline policies on users (best practice: attach to groups/roles instead)
            users = self.iam.list_users()['Users']
            for user in users:
                inline_policies = self.iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
                if inline_policies:
                    findings.append({"resource": f"IAM User: {user['UserName']}", "issue": "User has direct inline policies attached", "severity": "Medium"})
        except Exception as e:
            findings.append({"resource": "IAM", "issue": f"Failed to scan IAM: {str(e)}", "severity": "Low"})
        return findings

    def scan_s3(self):
        findings = []
        try:
            buckets = self.s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                # Check block public access
                try:
                    bpa = self.s3.get_public_access_block(Bucket=name)
                    config = bpa['PublicAccessBlockConfiguration']
                    if not (config.get('BlockPublicAcls') and config.get('IgnorePublicAcls') and config.get('BlockPublicPolicy') and config.get('RestrictPublicBuckets')):
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket does not block all public access", "severity": "High"})
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket does not have Block Public Access enabled", "severity": "High"})
                
                # Check default encryption
                try:
                    self.s3.get_bucket_encryption(Bucket=name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket does not have default Server-Side Encryption enabled", "severity": "Medium"})
        except Exception as e:
            findings.append({"resource": "S3", "issue": f"Failed to scan S3: {str(e)}", "severity": "Low"})
        return findings

    def scan_security_groups(self):
        findings = []
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for perm in sg.get('IpPermissions', []):
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = perm.get('FromPort')
                            if port in [22, 3389, 3306, 5432]:
                                findings.append({
                                    "resource": f"EC2 SG: {sg['GroupId']} ({sg['GroupName']})",
                                    "issue": f"Allows ingress from 0.0.0.0/0 on sensitive port {port}",
                                    "severity": "Critical"
                                })
        except Exception as e:
            findings.append({"resource": "EC2 SGs", "issue": f"Failed to scan Security Groups: {str(e)}", "severity": "Low"})
        return findings

    def scan_cloudtrail(self):
        findings = []
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            multi_region_enabled = any(t.get('IsMultiRegionTrail', False) for t in trails)
            if not multi_region_enabled:
                findings.append({"resource": "CloudTrail", "issue": "No multi-region CloudTrail is enabled", "severity": "High"})
        except Exception as e:
            findings.append({"resource": "CloudTrail", "issue": f"Failed to scan CloudTrail: {str(e)}", "severity": "Low"})
        return findings
