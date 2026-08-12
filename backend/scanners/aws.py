import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from .base import BaseScanner
import datetime
import json

class AWSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
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
            # Check Root MFA
            summary = self.iam.get_account_summary()
            if summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                findings.append({"resource": "IAM Root Account", "issue": "Root account does not have MFA enabled", "severity": "Critical"})
            
            # Check Password Policy
            try:
                pw_policy = self.iam.get_account_password_policy()
                if not pw_policy['PasswordPolicy'].get('RequireUppercaseCharacters') or not pw_policy['PasswordPolicy'].get('RequireSymbols'):
                    findings.append({"resource": "IAM Password Policy", "issue": "Password policy is weak (does not require uppercase or symbols)", "severity": "Medium"})
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    findings.append({"resource": "IAM Password Policy", "issue": "No account password policy set", "severity": "High"})

            # Users
            users = self.iam.list_users()['Users']
            now = datetime.datetime.now(datetime.timezone.utc)
            for user in users:
                user_name = user['UserName']
                try:
                    mfa_devices = self.iam.list_mfa_devices(UserName=user_name)['MFADevices']
                    if not mfa_devices:
                        findings.append({
                            "resource": f"IAM User: {user_name}",
                            "issue": "IAM user does not have MFA enabled",
                            "severity": "High"
                        })
                except Exception:
                    pass

                # Check direct inline policies
                inline_policies = self.iam.list_user_policies(UserName=user_name)['PolicyNames']
                if inline_policies:
                    findings.append({"resource": f"IAM User: {user_name}", "issue": "User has direct inline policies attached", "severity": "Medium"})
                
                # Check attached managed policies for AdministratorAccess and wildcard
                attached = self.iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                for pol in attached:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        findings.append({"resource": f"IAM User: {user_name}", "issue": "User has AdministratorAccess directly attached", "severity": "High"})
                    else:
                        try:
                            arn = pol['PolicyArn']
                            policy = self.iam.get_policy(PolicyArn=arn)['Policy']
                            version = self.iam.get_policy_version(PolicyArn=arn, VersionId=policy['DefaultVersionId'])['PolicyVersion']
                            doc = version.get('Document', {})
                            for stat in doc.get('Statement', []):
                                if isinstance(stat, dict) and stat.get('Effect') == 'Allow':
                                    actions = stat.get('Action', [])
                                    if isinstance(actions, str): actions = [actions]
                                    resources = stat.get('Resource', [])
                                    if isinstance(resources, str): resources = [resources]
                                    if '*' in actions and '*' in resources:
                                        findings.append({
                                            "resource": f"IAM Policy: {pol['PolicyName']}",
                                            "issue": "Policy grants wildcard Action and Resource permissions",
                                            "severity": "Critical"
                                        })
                        except Exception:
                            pass

                # Access Keys age & inactive
                keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                for key in keys:
                    age_days = (now - key['CreateDate']).days
                    if age_days > 90:
                        findings.append({"resource": f"IAM Access Key: {key['AccessKeyId']}", "issue": f"Access key is older than 90 days ({age_days} days)", "severity": "Medium"})
                    
                    if key['Status'] == 'Inactive' and age_days > 90:
                         findings.append({"resource": f"IAM Access Key: {key['AccessKeyId']}", "issue": "Inactive access key has not been deleted after 90 days", "severity": "Low"})
            
            # Cross-account risky trust & wildcard
            roles = self.iam.list_roles()['Roles']
            for role in roles:
                doc = role.get('AssumeRolePolicyDocument', {})
                for stat in doc.get('Statement', []):
                    # Check wildcard principle
                    if stat.get('Effect') == 'Allow' and stat.get('Principal') == '*':
                         findings.append({"resource": f"IAM Role: {role['RoleName']}", "issue": "Role trust policy allows all AWS accounts (*)", "severity": "Critical"})
        except Exception as e:
            findings.append({"resource": "IAM", "issue": f"Failed to scan IAM: {str(e)}", "severity": "Low"})
        return findings

    def scan_s3(self):
        findings = []
        try:
            buckets = self.s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                
                # Block public access
                try:
                    bpa = self.s3.get_public_access_block(Bucket=name)
                    config = bpa['PublicAccessBlockConfiguration']
                    if not (config.get('BlockPublicAcls') and config.get('IgnorePublicAcls') and config.get('BlockPublicPolicy') and config.get('RestrictPublicBuckets')):
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket does not block all public access", "severity": "High"})
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket does not have Block Public Access enabled", "severity": "High"})
                
                # Encryption
                try:
                    self.s3.get_bucket_encryption(Bucket=name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket does not have default Server-Side Encryption enabled", "severity": "Medium"})
                
                # Versioning
                try:
                    vers = self.s3.get_bucket_versioning(Bucket=name)
                    if vers.get('Status') != 'Enabled':
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket versioning is not enabled", "severity": "Low"})
                except Exception:
                    pass
                
                # Logging
                try:
                    log_res = self.s3.get_bucket_logging(Bucket=name)
                    if not log_res.get('LoggingEnabled'):
                        findings.append({"resource": f"S3: {name}", "issue": "Bucket server access logging is not enabled", "severity": "Low"})
                except Exception:
                    pass

                # ACL check
                try:
                    acls = self.s3.get_bucket_acl(Bucket=name)
                    for grant in acls.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') in ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                            findings.append({"resource": f"S3: {name}", "issue": "Bucket ACL allows public or any authenticated AWS user access", "severity": "Critical"})
                except Exception:
                    pass

                # Bucket policy check for public access
                try:
                    policy_str = self.s3.get_bucket_policy(Bucket=name)['Policy']
                    policy_doc = json.loads(policy_str)
                    for stat in policy_doc.get('Statement', []):
                        if stat.get('Effect') == 'Allow':
                            prin = stat.get('Principal', '')
                            if prin == '*' or (isinstance(prin, dict) and prin.get('AWS') == '*'):
                                actions = stat.get('Action', [])
                                if isinstance(actions, str): actions = [actions]
                                if 's3:GetObject' in actions or 's3:*' in actions or '*' in actions:
                                    findings.append({
                                        "resource": f"S3: {name}",
                                        "issue": "S3 bucket policy allows public object access",
                                        "severity": "Critical"
                                    })
                except Exception:
                    pass

        except Exception as e:
            findings.append({"resource": "S3", "issue": f"Failed to scan S3: {str(e)}", "severity": "Low"})
        return findings

    def scan_security_groups(self):
        findings = []
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                # Ingress
                for perm in sg.get('IpPermissions', []):
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = perm.get('FromPort')
                            to_port = perm.get('ToPort')
                            if from_port in [22, 3389]:
                                findings.append({
                                    "resource": f"EC2 SG: {sg['GroupId']}",
                                    "issue": f"Allows ingress from 0.0.0.0/0 on sensitive port {from_port} (SSH/RDP)",
                                    "severity": "Critical"
                                })
                            elif from_port in [3306, 5432, 1433, 6379, 27017, 9200, 23]:
                                findings.append({
                                    "resource": f"EC2 SG: {sg['GroupId']}",
                                    "issue": f"Allows ingress from 0.0.0.0/0 on sensitive port {from_port}",
                                    "severity": "High"
                                })
                            elif from_port == 21:
                                findings.append({
                                    "resource": f"EC2 SG: {sg['GroupId']}",
                                    "issue": f"Allows ingress from 0.0.0.0/0 on port {from_port} (FTP)",
                                    "severity": "Medium"
                                })
                # Egress
                for perm in sg.get('IpPermissionsEgress', []):
                    if perm.get('IpProtocol') == '-1': # All traffic
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                findings.append({
                                    "resource": f"EC2 SG: {sg['GroupId']}",
                                    "issue": "Allows unrestricted egress traffic (0.0.0.0/0 on all ports)",
                                    "severity": "Low"
                                })
        except Exception as e:
            findings.append({"resource": "EC2 SGs", "issue": f"Failed to scan Security Groups: {str(e)}", "severity": "Low"})
        return findings

    def scan_cloudtrail(self):
        findings = []
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            if not trails:
                findings.append({"resource": "CloudTrail", "issue": "No CloudTrail trails exist", "severity": "Critical"})
                return findings

            multi_region_enabled = any(t.get('IsMultiRegionTrail', False) for t in trails)
            if not multi_region_enabled:
                findings.append({"resource": "CloudTrail", "issue": "No multi-region CloudTrail is enabled", "severity": "High"})
            
            for t in trails:
                name = t.get('Name')
                # Log validation
                if not t.get('LogFileValidationEnabled'):
                    findings.append({"resource": f"CloudTrail: {name}", "issue": "Log file validation is disabled", "severity": "Medium"})
                # KMS Encryption
                if not t.get('KmsKeyId'):
                    findings.append({"resource": f"CloudTrail: {name}", "issue": "Logs are not encrypted with a KMS CMK", "severity": "Medium"})
                
                # Management events
                try:
                    selectors = self.cloudtrail.get_event_selectors(TrailName=name).get('EventSelectors', [])
                    has_management = any(s.get('IncludeManagementEvents') for s in selectors)
                    if not has_management:
                         findings.append({"resource": f"CloudTrail: {name}", "issue": "Trail does not record management events", "severity": "High"})
                except Exception:
                    pass

                # Logging status
                try:
                    status = self.cloudtrail.get_trail_status(Name=name)
                    if not status.get('IsLogging'):
                        findings.append({
                            "resource": f"CloudTrail: {name}",
                            "issue": "CloudTrail trail exists but logging is disabled",
                            "severity": "Critical"
                        })
                except Exception:
                    pass

        except Exception as e:
            findings.append({"resource": "CloudTrail", "issue": f"Failed to scan CloudTrail: {str(e)}", "severity": "Low"})
        return findings
