"""
Google Cloud Platform (GCP) Security Posture Scanner for CloudSentinel.
Inspects Cloud Storage, Compute Firewalls, IAM Roles, Cloud SQL, and Cloud KMS.
Uses Google Cloud Application Default Credentials (ADC) or explicit service account.
"""

import os
from typing import Any

from backend.models.finding import Finding

from .base import BaseScanner


class GCPScanner(BaseScanner):
    def __init__(self, project_id: str | None = None):
        super().__init__()
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
        self.credentials = None
        try:
            # Check for Google Application Default Credentials
            import google.auth
            self.credentials, default_project = google.auth.default()
            if not self.project_id and default_project:
                self.project_id = default_project
            self.is_authenticated = bool(self.credentials)
        except Exception:  # noqa: BLE001
            # If google-auth is not installed or ADC is missing
            self.is_authenticated = False

    def _create_finding(
        self,
        service: str,
        resource: str,
        issue: str,
        severity: str,
        evidence: Any,
        remediation: str,
        cis: str = "N/A",
        mitre: str = "N/A",
        soc2: str = "N/A",
        pci_dss: str = "N/A",
        hipaa: str = "N/A",
        exposure: int = 0,
        privilege: int = 0,
        data_sensitivity: int = 0,
        exploitability: int = 0,
        cli_remediation: str = "",
        terraform_remediation: str = "",
    ) -> dict[str, Any]:
        frameworks = {"cis_gcp": cis, "mitre": mitre}
        if soc2 != "N/A":
            frameworks["soc2"] = soc2
        if pci_dss != "N/A":
            frameworks["pci_dss"] = pci_dss
        if hipaa != "N/A":
            frameworks["hipaa"] = hipaa

        return Finding(
            provider="GCP",
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

    def scan_all(self) -> list[dict[str, Any]]:
        if not self.is_authenticated:
            return [
                self._create_finding(
                    service="IAM",
                    resource="Project: Global",
                    issue="Authentication Failed: No Google Cloud Credentials Found (gcloud auth application-default login)",
                    severity="Critical",
                    evidence="google.auth.default failed to locate ADC or service account key",
                    remediation="Authenticate using 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS",
                    cis="N/A",
                )
            ]

        findings = []
        findings.extend(self.scan_storage())
        findings.extend(self.scan_compute_firewalls())
        findings.extend(self.scan_iam())
        findings.extend(self.scan_sql())
        findings.extend(self.scan_kms())
        return findings

    def scan_storage(self) -> list[dict[str, Any]]:
        findings = []
        try:
            from google.cloud import storage
            client = storage.Client(credentials=self.credentials, project=self.project_id)
            buckets = list(client.list_buckets())

            for bucket in buckets:
                res_name = f"gs://{bucket.name}"
                policy = bucket.get_iam_policy()
                for role, members in policy.items():
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        findings.append(
                            self._create_finding(
                                "CloudStorage",
                                res_name,
                                f"Cloud Storage bucket allows public internet access ({role})",
                                "Critical",
                                f"IAM Policy allows allUsers/allAuthenticatedUsers in role {role}",
                                "Remove allUsers and allAuthenticatedUsers from bucket IAM policy",
                                cis="5.1",
                                mitre="T1530",
                                soc2="CC6.6",
                                pci_dss="1.3",
                                hipaa="164.312(a)(1)",
                                exposure=20,
                                data_sensitivity=15,
                                cli_remediation=f"gcloud storage buckets remove-iam-policy-binding {res_name} --member=allUsers --role={role}",
                                terraform_remediation='resource "google_storage_bucket_iam_binding" "remediation" {\n  # ensure allUsers is removed\n}',
                            )
                        )
                
                # Uniform bucket-level access check
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    findings.append(
                        self._create_finding(
                            "CloudStorage",
                            res_name,
                            "Cloud Storage bucket does not enforce uniform bucket-level access",
                            "Medium",
                            "uniform_bucket_level_access_enabled = False",
                            "Enable uniform bucket-level access to enforce centralized IAM",
                            cis="5.2",
                            soc2="CC6.1",
                            cli_remediation=f"gcloud storage buckets update {res_name} --uniform-bucket-level-access",
                        )
                    )
        except Exception as e:  # noqa: BLE001
            findings.append(
                self._create_finding("CloudStorage", "Global", f"Failed to scan Cloud Storage: {e!s}", "Low", "Exception thrown", "Check storage.buckets.list permissions")
            )
        return findings

    def scan_compute_firewalls(self) -> list[dict[str, Any]]:
        findings = []
        try:
            from google.cloud import compute_v1
            firewall_client = compute_v1.FirewallsClient(credentials=self.credentials)
            rules = firewall_client.list(project=self.project_id)

            for rule in rules:
                if rule.direction == "INGRESS" and not rule.disabled:
                    ranges = list(rule.source_ranges)
                    if "0.0.0.0/0" in ranges:
                        for allowed in rule.allowed:
                            proto = allowed.I_p_protocol.lower()
                            ports = list(allowed.ports)
                            if proto in ["tcp", "all"] and ("22" in ports or not ports):
                                findings.append(
                                    self._create_finding(
                                        "ComputeEngine",
                                        f"Firewall: {rule.name}",
                                        "Firewall rule allows unrestricted inbound SSH (Port 22) from the internet",
                                        "Critical",
                                        f"0.0.0.0/0 allowed to port {ports or 'all'}",
                                        "Restrict SSH access to corporate IP ranges or use Identity-Aware Proxy (IAP)",
                                        cis="3.6",
                                        mitre="T1190",
                                        soc2="CC6.6",
                                        pci_dss="1.2",
                                        exposure=20,
                                        exploitability=10,
                                        cli_remediation=f"gcloud compute firewall-rules update {rule.name} --source-ranges=<trusted-ip-range>",
                                    )
                                )
                            elif proto in ["tcp", "all"] and ("3389" in ports or not ports):
                                findings.append(
                                    self._create_finding(
                                        "ComputeEngine",
                                        f"Firewall: {rule.name}",
                                        "Firewall rule allows unrestricted inbound RDP (Port 3389) from the internet",
                                        "Critical",
                                        f"0.0.0.0/0 allowed to port {ports or 'all'}",
                                        "Restrict RDP access to corporate IP ranges or use IAP TCP forwarding",
                                        cis="3.7",
                                        mitre="T1190",
                                        soc2="CC6.6",
                                        pci_dss="1.2",
                                        exposure=20,
                                        exploitability=10,
                                        cli_remediation=f"gcloud compute firewall-rules update {rule.name} --source-ranges=<trusted-ip-range>",
                                    )
                                )
        except Exception as e:  # noqa: BLE001
            findings.append(
                self._create_finding("ComputeEngine", "Global", f"Failed to scan Compute Firewalls: {e!s}", "Low", "Exception thrown", "Check compute.firewalls.list permissions")
            )
        return findings

    def scan_iam(self) -> list[dict[str, Any]]:
        findings = []
        try:
            from google.cloud import resourcemanager_v3
            crm_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            policy = crm_client.get_iam_policy(resource=f"projects/{self.project_id}")

            for binding in policy.bindings:
                if binding.role in ["roles/owner", "roles/editor"]:
                    for member in binding.members:
                        if member.startswith("serviceAccount:") and "iam.gserviceaccount.com" in member:
                            findings.append(
                                self._create_finding(
                                    "IAM",
                                    member,
                                    f"Service Account has overprivileged primitive role '{binding.role}' at project level",
                                    "Critical",
                                    f"Member {member} granted {binding.role}",
                                    "Apply least-privilege: replace primitive roles (Owner/Editor) with specific fine-grained roles",
                                    cis="1.4",
                                    mitre="T1098",
                                    soc2="CC6.3",
                                    privilege=15,
                                    cli_remediation=f"gcloud projects remove-iam-policy-binding {self.project_id} --member={member} --role={binding.role}",
                                )
                            )
        except Exception as e:  # noqa: BLE001
            findings.append(
                self._create_finding("IAM", "Global", f"Failed to scan IAM: {e!s}", "Low", "Exception thrown", "Check resourcemanager.projects.getIamPolicy permissions")
            )
        return findings

    def scan_sql(self) -> list[dict[str, Any]]:
        findings = []
        try:
            from googleapiclient import discovery
            service = discovery.build('sqladmin', 'v1beta4', credentials=self.credentials)
            req = service.instances().list(project=self.project_id)
            resp = req.execute()

            for inst in resp.get('items', []):
                name = inst.get('name')
                ip_configs = inst.get('settings', {}).get('ipConfiguration', {})
                authorized_networks = [n.get('value') for n in ip_configs.get('authorizedNetworks', [])]

                if "0.0.0.0/0" in authorized_networks:
                    findings.append(
                        self._create_finding(
                            "CloudSQL",
                            f"CloudSQL: {name}",
                            "Cloud SQL instance authorizes public ingress from all IP addresses (0.0.0.0/0)",
                            "Critical",
                            "authorizedNetworks contains 0.0.0.0/0",
                            "Remove 0.0.0.0/0 and configure Cloud SQL Auth Proxy or Private Service Access (VPC)",
                            cis="6.2",
                            mitre="T1190",
                            soc2="CC6.6",
                            pci_dss="1.3",
                            exposure=20,
                            data_sensitivity=15,
                            cli_remediation=f"gcloud sql instances patch {name} --authorized-networks=<trusted-ip-only>",
                        )
                    )

                if not ip_configs.get('requireSsl'):
                    findings.append(
                        self._create_finding(
                            "CloudSQL",
                            f"CloudSQL: {name}",
                            "Cloud SQL instance does not require SSL/TLS encryption for incoming connections",
                            "High",
                            "requireSsl = False",
                            "Enforce SSL/TLS for all database client connections",
                            cis="6.3",
                            soc2="CC6.6",
                            pci_dss="4.1",
                            hipaa="164.312(e)(1)",
                            exploitability=10,
                            cli_remediation=f"gcloud sql instances patch {name} --require-ssl",
                        )
                    )
        except Exception as e:  # noqa: BLE001
            findings.append(
                self._create_finding("CloudSQL", "Global", f"Failed to scan Cloud SQL: {e!s}", "Low", "Exception thrown", "Check sql.instances.list permissions")
            )
        return findings

    def scan_kms(self) -> list[dict[str, Any]]:
        findings = []
        try:
            from google.cloud import kms_v1
            kms_client = kms_v1.KeyManagementServiceClient(credentials=self.credentials)
            parent = f"projects/{self.project_id}/locations/global"
            key_rings = kms_client.list_key_rings(request={"parent": parent})

            for kr in key_rings:
                keys = kms_client.list_crypto_keys(request={"parent": kr.name})
                for k in keys:
                    if not k.rotation_period:
                        findings.append(
                            self._create_finding(
                                "CloudKMS",
                                k.name,
                                "Cloud KMS key does not have an automatic rotation schedule configured",
                                "Medium",
                                "rotation_period is not set",
                                "Configure key rotation period to 90 days or less",
                                cis="1.10",
                                mitre="T1552",
                                soc2="CC6.1",
                                pci_dss="3.6.4",
                                cli_remediation=f"gcloud kms keys set-rotation-schedule {k.name.split('/')[-1]} --keyring={kr.name.split('/')[-1]} --location=global --rotation-period=7776000s",
                            )
                        )
        except Exception as e:  # noqa: BLE001
            findings.append(
                self._create_finding("CloudKMS", "Global", f"Failed to scan Cloud KMS: {e!s}", "Low", "Exception thrown", "Check cloudkms.cryptoKeys.list permissions")
            )
        return findings
