import datetime
import json

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from backend.models.finding import Finding

from .base import BaseScanner


class AWSScanner(BaseScanner):
    def __init__(self, profile_name: str | None = None, region_name: str | None = None):
        super().__init__()
        self.profile_name = profile_name
        self.default_region = region_name or "us-east-1"
        try:
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                self.iam = session.client('iam', region_name='us-east-1')
                self.s3 = session.client('s3', region_name=self.default_region)
                self.ec2 = session.client('ec2', region_name=self.default_region)
                self.cloudtrail = session.client('cloudtrail', region_name=self.default_region)
                self.rds = session.client('rds', region_name=self.default_region)
                self.kms = session.client('kms', region_name=self.default_region)
                self.guardduty = session.client('guardduty', region_name=self.default_region)
            else:
                self.iam = boto3.client('iam', region_name='us-east-1')
                self.s3 = boto3.client('s3', region_name=self.default_region)
                self.ec2 = boto3.client('ec2', region_name=self.default_region)
                self.cloudtrail = boto3.client('cloudtrail', region_name=self.default_region)
                self.rds = boto3.client('rds', region_name=self.default_region)
                self.kms = boto3.client('kms', region_name=self.default_region)
                self.guardduty = boto3.client('guardduty', region_name=self.default_region)
            self.is_authenticated = True
        except (NoCredentialsError, ClientError):
            self.is_authenticated = False

    def get_regions(self) -> list[str]:
        try:
            res = self.ec2.describe_regions(AllRegions=False)
            return [r['RegionName'] for r in res.get('Regions', [])]
        except Exception:  # noqa: BLE001
            return ['us-east-1']

    def scan_all(self):
        if not self.is_authenticated:
            return [Finding(
                provider="AWS",
                service="Global",
                resource="Authentication",
                issue="Authentication Failed: No AWS Credentials Found",
                severity="Critical",
                evidence="boto3.client failed",
                remediation="Configure aws credentials using 'aws configure'",
                frameworks={"cis_aws": "N/A", "mitre": "N/A"},
                exposure=0,
                privilege=0,
                data_sensitivity=0,
                exploitability=10
            ).to_dict()]
        
        findings = []
        findings.extend(self.scan_iam())
        findings.extend(self.scan_s3())
        findings.extend(self.scan_security_groups())
        findings.extend(self.scan_cloudtrail())
        findings.extend(self.scan_rds())
        findings.extend(self.scan_kms())
        findings.extend(self.scan_guardduty())
        return findings

    def _create_finding(
        self,
        service,
        resource,
        issue,
        severity,
        evidence,
        remediation,
        cis="N/A",
        mitre="N/A",
        soc2="N/A",
        pci_dss="N/A",
        hipaa="N/A",
        exposure=0,
        privilege=0,
        data_sensitivity=0,
        exploitability=0,
        cli_remediation="",
        terraform_remediation="",
    ):
        frameworks = {"cis_aws": cis, "mitre": mitre}
        if soc2 != "N/A":
            frameworks["soc2"] = soc2
        if pci_dss != "N/A":
            frameworks["pci_dss"] = pci_dss
        if hipaa != "N/A":
            frameworks["hipaa"] = hipaa

        return Finding(
            provider="AWS",
            service=service,
            resource=resource,
            issue=issue,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            frameworks=frameworks,
            exposure=exposure,
            privilege=privilege,
            data_sensitivity=data_sensitivity,
            exploitability=exploitability,
            cli_remediation=cli_remediation,
            terraform_remediation=terraform_remediation,
        ).to_dict()

    def scan_iam(self):
        findings = []
        try:
            # Check Root MFA
            summary = self.iam.get_account_summary()
            if summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                findings.append(self._create_finding(
                    "IAM", "Root Account", "Root account does not have MFA enabled", "Critical",
                    "AccountMFAEnabled == 0", "Enable MFA for root user", "1.1",
                    soc2="CC6.1", pci_dss="8.3", hipaa="164.312(d)", exploitability=10
                ))
            
            # Check Password Policy
            try:
                pw_policy = self.iam.get_account_password_policy()
                if not pw_policy['PasswordPolicy'].get('RequireUppercaseCharacters') or not pw_policy['PasswordPolicy'].get('RequireSymbols'):
                    findings.append(self._create_finding(
                        "IAM", "Password Policy", "Password policy is weak (does not require uppercase or symbols)", "Medium",
                        "Policy lacks complexity", "Enforce strong password policy", "1.8", soc2="CC6.1", pci_dss="8.2"
                    ))
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    findings.append(self._create_finding(
                        "IAM", "Password Policy", "No account password policy set", "High",
                        "NoSuchEntity", "Create an account password policy", "1.8", soc2="CC6.1"
                    ))

            # Users
            users = self.iam.list_users()['Users']
            now = datetime.datetime.now(datetime.UTC)
            for user in users:
                user_name = user['UserName']
                try:
                    mfa_devices = self.iam.list_mfa_devices(UserName=user_name)['MFADevices']
                    if not mfa_devices:
                        findings.append(self._create_finding(
                            "IAM", f"User: {user_name}", "IAM user does not have MFA enabled", "High",
                            "No MFA devices found", "Enable MFA for user", "1.10",
                            soc2="CC6.1", pci_dss="8.3", exploitability=10
                        ))
                except Exception:  # noqa: BLE001, S110
                    pass

                # Check direct inline policies
                inline_policies = self.iam.list_user_policies(UserName=user_name)['PolicyNames']
                if inline_policies:
                    findings.append(self._create_finding(
                        "IAM", f"User: {user_name}", "User has direct inline policies attached", "Medium",
                        f"Policies: {inline_policies}", "Use groups and managed policies instead", "1.15", soc2="CC6.3"
                    ))
                
                # Check attached managed policies for AdministratorAccess and wildcard
                attached = self.iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                for pol in attached:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        findings.append(self._create_finding(
                            "IAM", f"User: {user_name}", "User has AdministratorAccess directly attached", "High",
                            "Attached: AdministratorAccess", "Remove AdministratorAccess and apply least privilege", "1.15",
                            soc2="CC6.3", privilege=15
                        ))
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
                                        findings.append(self._create_finding(
                                            "IAM", f"Policy: {pol['PolicyName']}", "Policy grants wildcard Action and Resource permissions",
                                            "Critical", "Action: *, Resource: *", "Remove wildcard permissions", "1.22",
                                            soc2="CC6.3", privilege=15
                                        ))
                        except Exception:  # noqa: BLE001, S110
                            pass

                # Access Keys age & inactive
                keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                for key in keys:
                    age_days = (now - key['CreateDate']).days
                    if age_days > 90:
                        findings.append(self._create_finding(
                            "IAM", f"Access Key: {key['AccessKeyId']}", f"Access key is older than 90 days ({age_days} days)", "Medium",
                            f"Age: {age_days}", "Rotate access key", "1.14", soc2="CC6.1", pci_dss="8.2.4"
                        ))
                    
                    if key['Status'] == 'Inactive' and age_days > 90:
                        findings.append(self._create_finding(
                            "IAM", f"Access Key: {key['AccessKeyId']}", "Inactive access key has not been deleted after 90 days", "Low",
                            f"Inactive Age: {age_days}", "Delete inactive key", "1.14"
                        ))
            
            # Cross-account risky trust & wildcard
            roles = self.iam.list_roles()['Roles']
            for role in roles:
                doc = role.get('AssumeRolePolicyDocument', {})
                for stat in doc.get('Statement', []):
                    if stat.get('Effect') == 'Allow' and stat.get('Principal') == '*':
                        findings.append(self._create_finding(
                            "IAM", f"Role: {role['RoleName']}", "Role trust policy allows all AWS accounts (*)", "Critical",
                            "Principal: *", "Restrict trust policy to known accounts", "1.22",
                            soc2="CC6.1", privilege=15
                        ))
        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("IAM", "Global", f"Failed to scan IAM: {e!s}", "Low", "Exception thrown", "Check permissions", "N/A"))
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
                        findings.append(self._create_finding(
                            "S3", f"Bucket: {name}", "Bucket does not block all public access", "High",
                            "BPA config incomplete", "Enable Block Public Access completely", "2.1.1",
                            soc2="CC6.6", pci_dss="1.3", hipaa="164.312(a)(1)", data_sensitivity=15, exposure=20
                        ))
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        findings.append(self._create_finding(
                            "S3", f"Bucket: {name}", "Bucket does not have Block Public Access enabled", "High",
                            "No BPA configuration", "Enable Block Public Access", "2.1.1",
                            soc2="CC6.6", pci_dss="1.3", hipaa="164.312(a)(1)", data_sensitivity=15, exposure=20
                        ))
                
                # Encryption
                try:
                    self.s3.get_bucket_encryption(Bucket=name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append(self._create_finding(
                            "S3", f"Bucket: {name}", "Bucket does not have default Server-Side Encryption enabled", "Medium",
                            "No SSE config", "Enable default encryption", "2.1.2",
                            soc2="CC6.1", pci_dss="3.4", hipaa="164.312(a)(2)(iv)", data_sensitivity=10
                        ))
                
                # Versioning
                try:
                    vers = self.s3.get_bucket_versioning(Bucket=name)
                    if vers.get('Status') != 'Enabled':
                        findings.append(self._create_finding(
                            "S3", f"Bucket: {name}", "Bucket versioning is not enabled", "Low",
                            "Versioning disabled", "Enable versioning", "N/A", soc2="A1.2"
                        ))
                except Exception:  # noqa: BLE001, S110
                    pass
                
                # Logging
                try:
                    log_res = self.s3.get_bucket_logging(Bucket=name)
                    if not log_res.get('LoggingEnabled'):
                        findings.append(self._create_finding(
                            "S3", f"Bucket: {name}", "Bucket server access logging is not enabled", "Low",
                            "Logging disabled", "Enable server access logging", "2.1.3", soc2="CC7.2"
                        ))
                except Exception:  # noqa: BLE001, S110
                    pass

                # ACL check
                try:
                    acls = self.s3.get_bucket_acl(Bucket=name)
                    for grant in acls.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') in ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                            findings.append(self._create_finding(
                                "S3", f"Bucket: {name}", "Bucket ACL allows public or any authenticated AWS user access", "Critical",
                                f"Grantee: {grantee.get('URI')}", "Remove public ACLs", "2.1.1",
                                soc2="CC6.6", pci_dss="1.3", exposure=20, data_sensitivity=15
                            ))
                except Exception:  # noqa: BLE001, S110
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
                                    findings.append(self._create_finding(
                                        "S3", f"Bucket: {name}", "S3 bucket policy allows public object access", "Critical",
                                        "Principal: *", "Remove public bucket policy", "2.1.1",
                                        soc2="CC6.6", pci_dss="1.3", exposure=20, data_sensitivity=15
                                    ))
                except Exception:  # noqa: BLE001, S110
                    pass

        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("S3", "Global", f"Failed to scan S3: {e!s}", "Low", "Exception thrown", "Check permissions", "N/A"))
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
                            if from_port in [22, 3389]:
                                findings.append(self._create_finding(
                                    "EC2", f"SG: {sg['GroupId']}", f"Allows ingress from 0.0.0.0/0 on sensitive port {from_port} (SSH/RDP)", "Critical",
                                    f"Port: {from_port}", "Restrict source to known IPs", "4.1", "T1190",
                                    soc2="CC6.6", pci_dss="1.2", exposure=20, exploitability=10
                                ))
                            elif from_port in [3306, 5432, 1433, 6379, 27017, 9200, 23]:
                                findings.append(self._create_finding(
                                    "EC2", f"SG: {sg['GroupId']}", f"Allows ingress from 0.0.0.0/0 on sensitive port {from_port}", "High",
                                    f"Port: {from_port}", "Restrict source to known IPs", "4.2", "T1190",
                                    soc2="CC6.6", pci_dss="1.3", exposure=20, data_sensitivity=15
                                ))
                            elif from_port == 21:
                                findings.append(self._create_finding(
                                    "EC2", f"SG: {sg['GroupId']}", f"Allows ingress from 0.0.0.0/0 on port {from_port} (FTP)", "Medium",
                                    f"Port: {from_port}", "Restrict source to known IPs", "N/A"
                                ))
                # Egress
                for perm in sg.get('IpPermissionsEgress', []):
                    if perm.get('IpProtocol') == '-1':
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                findings.append(self._create_finding(
                                    "EC2", f"SG: {sg['GroupId']}", "Allows unrestricted egress traffic (0.0.0.0/0 on all ports)", "Low",
                                    "Egress: 0.0.0.0/0", "Restrict outbound traffic", "N/A"
                                ))
        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("EC2", "Global", f"Failed to scan Security Groups: {e!s}", "Low", "Exception thrown", "Check permissions", "N/A"))
        return findings

    def scan_cloudtrail(self):
        findings = []
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            if not trails:
                findings.append(self._create_finding(
                    "CloudTrail", "Global", "No CloudTrail trails exist", "Critical",
                    "No trails", "Create a multi-region CloudTrail", "3.1", soc2="CC7.2"
                ))
                return findings

            multi_region_enabled = any(t.get('IsMultiRegionTrail', False) for t in trails)
            if not multi_region_enabled:
                findings.append(self._create_finding(
                    "CloudTrail", "Global", "No multi-region CloudTrail is enabled", "High",
                    "IsMultiRegionTrail=False", "Enable multi-region trail", "3.1", soc2="CC7.2"
                ))
            
            for t in trails:
                name = t.get('Name')
                if not t.get('LogFileValidationEnabled'):
                    findings.append(self._create_finding(
                        "CloudTrail", f"Trail: {name}", "Log file validation is disabled", "Medium",
                        "LogFileValidationEnabled=False", "Enable log file validation", "3.2", soc2="CC7.2"
                    ))
                if not t.get('KmsKeyId'):
                    findings.append(self._create_finding(
                        "CloudTrail", f"Trail: {name}", "Logs are not encrypted with a KMS CMK", "Medium",
                        "No KmsKeyId", "Enable KMS CMK encryption", "3.7", soc2="CC6.1"
                    ))
                
                try:
                    selectors = self.cloudtrail.get_event_selectors(TrailName=name).get('EventSelectors', [])
                    has_management = any(s.get('IncludeManagementEvents') for s in selectors)
                    if not has_management:
                        findings.append(self._create_finding(
                            "CloudTrail", f"Trail: {name}", "Trail does not record management events", "High",
                            "No management events", "Enable management events", "3.1", soc2="CC7.2"
                        ))
                except Exception:  # noqa: BLE001, S110
                    pass

                try:
                    status = self.cloudtrail.get_trail_status(Name=name)
                    if not status.get('IsLogging'):
                        findings.append(self._create_finding(
                            "CloudTrail", f"Trail: {name}", "CloudTrail trail exists but logging is disabled", "Critical",
                            "IsLogging=False", "Enable logging", "3.1", soc2="CC7.2"
                        ))
                except Exception:  # noqa: BLE001, S110
                    pass

        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("CloudTrail", "Global", f"Failed to scan CloudTrail: {e!s}", "Low", "Exception thrown", "Check permissions", "N/A"))
        return findings

    def scan_rds(self):
        findings = []
        try:
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            for db in instances:
                name = db.get('DBInstanceIdentifier', 'Unknown-RDS')
                if db.get('PubliclyAccessible'):
                    findings.append(self._create_finding(
                        "RDS", f"RDS Instance: {name}", "RDS database instance is publicly accessible from the internet",
                        "Critical", f"PubliclyAccessible = {db.get('PubliclyAccessible')}",
                        "Modify DB instance to disable public accessibility", "2.3.1", "T1190",
                        soc2="CC6.6", pci_dss="1.3", hipaa="164.312(a)(1)", exposure=20, data_sensitivity=15
                    ))
                if not db.get('StorageEncrypted'):
                    findings.append(self._create_finding(
                        "RDS", f"RDS Instance: {name}", "RDS database storage is not encrypted at rest",
                        "High", f"StorageEncrypted = {db.get('StorageEncrypted')}",
                        "Create an encrypted snapshot and restore a new encrypted DB instance", "2.3.2", "T1530",
                        soc2="CC6.1", pci_dss="3.4", hipaa="164.312(a)(2)(iv)", data_sensitivity=15
                    ))
                if db.get('BackupRetentionPeriod', 0) == 0:
                    findings.append(self._create_finding(
                        "RDS", f"RDS Instance: {name}", "RDS automated backups are disabled (Retention = 0 days)",
                        "High", "BackupRetentionPeriod = 0",
                        "Set backup retention period to at least 7 days", "2.3.3", soc2="A1.2"
                    ))
                if not db.get('DeletionProtection'):
                    findings.append(self._create_finding(
                        "RDS", f"RDS Instance: {name}", "RDS deletion protection is disabled",
                        "Medium", "DeletionProtection = False",
                        "Enable deletion protection to prevent accidental termination", "2.3.4", soc2="CC6.1"
                    ))
        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("RDS", "Global", f"Failed to scan RDS: {e!s}", "Low", "Exception thrown", "Check RDS permissions", "N/A"))
        return findings

    def scan_kms(self):
        findings = []
        try:
            keys = self.kms.list_keys().get('Keys', [])
            for k in keys:
                key_id = k.get('KeyId')
                try:
                    meta = self.kms.describe_key(KeyId=key_id).get('KeyMetadata', {})
                    if meta.get('KeyManager') == 'CUSTOMER' and meta.get('KeyState') == 'Enabled':
                        rot = self.kms.get_key_rotation_status(KeyId=key_id)
                        if not rot.get('KeyRotationEnabled'):
                            findings.append(self._create_finding(
                                "KMS", f"KMS Key: {key_id}", "KMS Customer Managed Key does not have automatic yearly rotation enabled",
                                "Medium", "KeyRotationEnabled = False",
                                "Enable automatic KMS key rotation", "3.8", "T1552", soc2="CC6.1", pci_dss="3.6.4"
                            ))
                except Exception:  # noqa: BLE001, S110
                    pass
        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("KMS", "Global", f"Failed to scan KMS: {e!s}", "Low", "Exception thrown", "Check KMS permissions", "N/A"))
        return findings

    def scan_guardduty(self):
        findings = []
        try:
            detectors = self.guardduty.list_detectors().get('DetectorIds', [])
            if not detectors:
                findings.append(self._create_finding(
                    "GuardDuty", "Global", "AWS GuardDuty continuous threat detection is not enabled",
                    "High", "No detectors found", "Enable GuardDuty detector across all active regions",
                    "3.9", "T1562.001", soc2="CC7.2"
                ))
            else:
                for det_id in detectors:
                    det = self.guardduty.get_detector(DetectorId=det_id)
                    if det.get('Status') != 'ENABLED':
                        findings.append(self._create_finding(
                            "GuardDuty", f"Detector: {det_id}", "AWS GuardDuty detector is suspended or disabled",
                            "High", f"Status = {det.get('Status')}", "Enable GuardDuty detector",
                            "3.9", "T1562.001", soc2="CC7.2"
                        ))
        except Exception as e:  # noqa: BLE001
            findings.append(self._create_finding("GuardDuty", "Global", f"Failed to scan GuardDuty: {e!s}", "Low", "Exception thrown", "Check GuardDuty permissions", "N/A"))
        return findings
