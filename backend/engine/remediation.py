class RemediationEngine:
    """
    Enterprise Remediation Engine for CloudSentinel.
    Provides actionable guidance, exact CLI commands, and Terraform snippets.
    Default behavior is non-destructive (recommendations only).
    """

    REMEDIATIONS = {  # noqa: RUF012
        "public_s3": {
            "title": "Disable public access",
            "steps": [
                "Enable Block Public Access at bucket level",
                "Review bucket policy and remove wildcard principals",
                "Ensure ACL denies AllUsers and AuthenticatedUsers grants"
            ],
            "cli_command": "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "terraform": 'resource "aws_s3_bucket_public_access_block" "remediation" {\n  bucket = aws_s3_bucket.example.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}'
        },
        "open_ssh": {
            "title": "Restrict SSH exposure",
            "steps": [
                "Remove 0.0.0.0/0 ingress rule on port 22",
                "Allow trusted corporate CIDRs or VPN only",
                "Prefer AWS Systems Manager Session Manager or Azure Bastion"
            ],
            "cli_command": "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "terraform": 'ingress {\n  description = "SSH from Bastion"\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]\n}'
        },
        "open_rdp": {
            "title": "Restrict RDP exposure",
            "steps": [
                "Remove 0.0.0.0/0 for port 3389",
                "Use Azure Bastion or AWS Systems Manager Fleet Manager",
                "Enforce Just-in-Time (JIT) VM access"
            ],
            "cli_command": "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0",
            "terraform": 'ingress {\n  description = "RDP from Private Subnet"\n  from_port = 3389\n  to_port = 3389\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]\n}'
        },
        "iam_owner": {
            "title": "Apply Least Privilege",
            "steps": [
                "Review necessity of Owner or AdministratorAccess role",
                "Scope permissions down to specific resources or resource groups",
                "Enforce IAM Roles and Managed Identities instead of long-lived access keys"
            ],
            "cli_command": "aws iam detach-user-policy --user-name <username> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "terraform": 'resource "aws_iam_user_policy_attachment" "least_privilege" {\n  user = aws_iam_user.example.name\n  policy_arn = aws_iam_policy.read_only.arn\n}'
        },
        "azure_rbac_owner": {
            "title": "Remove Subscription Owner Role Assignment",
            "steps": [
                "Review necessity of Owner or Contributor role at subscription scope",
                "Remove broad subscription-level role assignment",
                "Assign least-privilege custom roles scoped to resource groups"
            ],
            "cli_command": "az role assignment delete --assignee <principal-id> --role 'Owner' --scope /subscriptions/<sub-id>",
            "terraform": 'resource "azurerm_role_assignment" "least_privilege" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Reader"\n  principal_id         = "<principal-id>"\n}'
        },
        "public_blob": {
            "title": "Disable Public Blob Access",
            "steps": [
                "Navigate to Storage Account in Azure Portal",
                "Under Settings, select Configuration",
                "Set 'Allow Blob public access' to Disabled",
                "Enforce through Azure Policy across the management group"
            ],
            "cli_command": "az storage account update --name <storage-account> --resource-group <rg-name> --allow-blob-public-access false",
            "terraform": 'resource "azurerm_storage_account" "remediation" {\n  # ...\n  allow_nested_items_to_be_public = false\n}'
        },
        "rds_public": {
            "title": "Disable Public Accessibility on RDS",
            "steps": [
                "Modify DB instance to disable PubliclyAccessible attribute",
                "Ensure RDS instance resides within private database subnets",
                "Update routing tables so database subnets have no IGW routes"
            ],
            "cli_command": "aws rds modify-db-instance --db-instance-identifier <db-id> --no-publicly-accessible --apply-immediately",
            "terraform": 'resource "aws_db_instance" "remediation" {\n  # ...\n  publicly_accessible = false\n}'
        },
        "rds_unencrypted": {
            "title": "Enable Encryption at Rest for RDS",
            "steps": [
                "Take a final snapshot of the unencrypted RDS database",
                "Copy the snapshot while specifying a KMS Customer Managed Key",
                "Restore a new RDS instance from the encrypted snapshot"
            ],
            "cli_command": "aws rds copy-db-snapshot --source-db-snapshot-identifier <snapshot-id> --target-db-snapshot-identifier <enc-snapshot-id> --kms-key-id <kms-key-arn>",
            "terraform": 'resource "aws_db_instance" "remediation" {\n  # ...\n  storage_encrypted = true\n  kms_key_id = aws_kms_key.rds.arn\n}'
        },
        "kms_rotation": {
            "title": "Enable Automatic KMS Key Rotation",
            "steps": [
                "Enable automatic yearly key rotation for the KMS Customer Managed Key",
                "AWS will automatically rotate backing key material without changing Key ID or ARN"
            ],
            "cli_command": "aws kms enable-key-rotation --key-id <key-id>",
            "terraform": 'resource "aws_kms_key" "remediation" {\n  description = "Enterprise CMK"\n  enable_key_rotation = true\n}'
        },
        "guardduty": {
            "title": "Enable AWS GuardDuty Threat Detection",
            "steps": [
                "Enable GuardDuty detector across all active AWS regions",
                "Configure automated alerts to SNS or Security Hub for High severity findings"
            ],
            "cli_command": "aws guardduty create-detector --enable",
            "terraform": 'resource "aws_guardduty_detector" "remediation" {\n  enable = true\n}'
        },
        "keyvault_softdelete": {
            "title": "Enable Soft-Delete and Purge Protection on Key Vault",
            "steps": [
                "Enable soft-delete with 90-day retention to prevent accidental loss",
                "Enable purge protection so keys and secrets cannot be permanently deleted prematurely"
            ],
            "cli_command": "az keyvault update --name <vault-name> --enable-purge-protection true",
            "terraform": 'resource "azurerm_key_vault" "remediation" {\n  # ...\n  soft_delete_retention_days = 90\n  purge_protection_enabled = true\n}'
        },
        "sql_firewall": {
            "title": "Restrict Azure SQL Firewall Ingress",
            "steps": [
                "Remove 0.0.0.0/0 from Azure SQL Server firewall rules",
                "Disable 'Allow Azure services and resources to access this server' if not required",
                "Use Private Endpoints (Private Link) for secure connectivity"
            ],
            "cli_command": "az sql server firewall-rule delete --name <rule-name> --server <server-name> --resource-group <rg-name>",
            "terraform": 'resource "azurerm_mssql_server" "remediation" {\n  # ...\n  public_network_access_enabled = false\n}'
        },
        "gcp_storage": {
            "title": "Disable Public Access on Cloud Storage Bucket",
            "steps": [
                "Remove allUsers and allAuthenticatedUsers from bucket IAM policy",
                "Enforce uniform bucket-level access"
            ],
            "cli_command": "gcloud storage buckets remove-iam-policy-binding <bucket> --member=allUsers --role=roles/storage.objectViewer",
            "terraform": 'resource "google_storage_bucket_iam_binding" "remediation" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  members = []\n}'
        },
        "gcp_firewall": {
            "title": "Restrict Inbound Compute Firewall Exposure",
            "steps": [
                "Remove 0.0.0.0/0 from firewall source ranges",
                "Use Identity-Aware Proxy (IAP) for administrative access"
            ],
            "cli_command": "gcloud compute firewall-rules update <rule-name> --source-ranges=<trusted-cidr>",
            "terraform": 'resource "google_compute_firewall" "remediation" {\n  name    = "allow-ssh"\n  network = "default"\n  source_ranges = ["10.0.0.0/16"]\n}'
        },
        "gcp_sql_public": {
            "title": "Disable Public IP and Restrict Authorized Networks on Cloud SQL",
            "steps": [
                "Remove 0.0.0.0/0 from authorized networks",
                "Use Cloud SQL Auth Proxy or Private Service Access (VPC)"
            ],
            "cli_command": "gcloud sql instances patch <instance-name> --no-assign-ip",
            "terraform": 'resource "google_sql_database_instance" "remediation" {\n  settings {\n    ip_configuration {\n      ipv4_enabled = false\n    }\n  }\n}'
        },
        "k8s_privileged": {
            "title": "Disable Privileged Execution in Container",
            "steps": [
                "Set securityContext.privileged to false in the container spec",
                "Use Linux capabilities (e.g. NET_ADMIN) only if absolutely required rather than full host root access",
                "Enforce Kubernetes Pod Security Standards (Restricted profile) via Admission Controllers"
            ],
            "cli_command": "kubectl patch deployment <name> -n <namespace> --type='json' -p='[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/securityContext/privileged\",\"value\":false}]'",
            "terraform": 'container {\n  name = "app"\n  security_context {\n    privileged = false\n  }\n}'
        },
        "k8s_root": {
            "title": "Enforce Non-Root Execution for Kubernetes Workload",
            "steps": [
                "Set securityContext.runAsNonRoot: true in the pod or container spec",
                "Specify a high-numbered UID via runAsUser (e.g. 10001)",
                "Build container image using non-root USER directive in Dockerfile"
            ],
            "cli_command": "kubectl patch deployment <name> -n <namespace> --type='merge' -p '{\"spec\":{\"template\":{\"spec\":{\"securityContext\":{\"runAsNonRoot\":true,\"runAsUser\":10001}}}}}'",
            "terraform": 'security_context {\n  run_as_non_root = true\n  run_as_user     = 10001\n}'
        },
        "k8s_resources": {
            "title": "Set CPU & Memory Resource Limits",
            "steps": [
                "Define resources.limits.cpu and resources.limits.memory for all containers",
                "Define resources.requests to allow Kubernetes scheduler to balance nodes properly",
                "Implement LimitRange in the namespace to enforce default minimum/maximum bounds"
            ],
            "cli_command": "kubectl patch deployment <name> -n <namespace> --type='merge' -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"app\",\"resources\":{\"limits\":{\"cpu\":\"500m\",\"memory\":\"512Mi\"}}}]}}}}}'",
            "terraform": 'resources {\n  limits = {\n    cpu    = "500m"\n    memory = "512Mi"\n  }\n}'
        },
        "default": {
            "title": "Manual Review Required",
            "steps": [
                "Review the resource configuration manually in the cloud provider console",
                "Ensure compliance with organizational security benchmarks and least-privilege standards"
            ],
            "cli_command": "N/A - Review architecture manually",
            "terraform": "# Refer to organizational IaC security baseline"
        }
    }

    def apply_remediation(self, findings: list) -> list:
        """
        Enriches findings with structured remediation steps, CLI commands, and Terraform snippets.
        """
        for finding in findings:
            issue = finding.get('issue', '').lower()
            
            matched_key = None
            provider = finding.get("provider", "")
            if provider == "GCP":
                if "bucket" in issue or "storage" in issue:
                    matched_key = "gcp_storage"
                elif "firewall" in issue or "ssh" in issue or "rdp" in issue:
                    matched_key = "gcp_firewall"
                elif "sql" in issue:
                    matched_key = "gcp_sql_public"
            elif provider == "Kubernetes":
                if "privileged" in issue:
                    matched_key = "k8s_privileged"
                elif "root" in issue:
                    matched_key = "k8s_root"
                elif "resource" in issue or "limit" in issue:
                    matched_key = "k8s_resources"
            elif "public" in issue and ("bucket" in issue or "s3" in issue):
                matched_key = "public_s3"
            elif "public blob" in issue:
                matched_key = "public_blob"
            elif "rds" in issue and "public" in issue:
                matched_key = "rds_public"
            elif "rds" in issue and ("encrypt" in issue or "unencrypted" in issue):
                matched_key = "rds_unencrypted"
            elif "guardduty" in issue:
                matched_key = "guardduty"
            elif "kms" in issue and "rotation" in issue:
                matched_key = "kms_rotation"
            elif "key vault" in issue:
                matched_key = "keyvault_softdelete"
            elif "sql database" in issue or "sql server" in issue:
                matched_key = "sql_firewall"
            elif "port 22" in issue or "ssh" in issue:
                matched_key = "open_ssh"
            elif "port 3389" in issue or "rdp" in issue:
                matched_key = "open_rdp"
            elif "administrator" in issue or "owner" in issue:
                if finding.get("provider") == "Azure" or "service principal" in issue or "rbac" in issue:
                    matched_key = "azure_rbac_owner"
                else:
                    matched_key = "iam_owner"

            if matched_key:
                rem_data = self.REMEDIATIONS[matched_key]
                finding['remediation'] = rem_data
                finding['cli_remediation'] = rem_data.get('cli_command', '')
                finding['terraform_remediation'] = rem_data.get('terraform', '')
            else:
                existing_rem = finding.get('remediation')
                if existing_rem and isinstance(existing_rem, str):
                    finding['remediation'] = {
                        "title": existing_rem,
                        "steps": ["Apply the recommended fix mentioned in title."],
                        "cli_command": finding.get("cli_remediation", ""),
                        "terraform": finding.get("terraform_remediation", "")
                    }
                else:
                    default_rem = self.REMEDIATIONS['default']
                    finding['remediation'] = default_rem
                    finding['cli_remediation'] = default_rem.get('cli_command', '')
                    finding['terraform_remediation'] = default_rem.get('terraform', '')

        return findings
