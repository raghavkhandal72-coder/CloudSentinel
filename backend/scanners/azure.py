from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

from backend.models.finding import Finding

from .base import BaseScanner


class AzureScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        try:
            self.credential = DefaultAzureCredential()
            self.sub_client = SubscriptionClient(self.credential)
            self.subscriptions = list(self.sub_client.subscriptions.list())
            self.is_authenticated = bool(self.subscriptions)
        except Exception:  # noqa: BLE001
            self.is_authenticated = False

    def scan_all(self):
        if not self.is_authenticated:
            return [Finding(
                provider="Azure",
                service="Global",
                resource="Authentication",
                issue="Authentication Failed: No Azure Credentials Found (az login)",
                severity="Critical",
                evidence="DefaultAzureCredential failed",
                remediation="Run 'az login' to authenticate",
                frameworks={"cis_azure": "N/A", "mitre": "N/A"},
                exposure=0,
                privilege=0,
                data_sensitivity=0,
                exploitability=10
            ).to_dict()]
        
        findings = []
        for sub in self.subscriptions:
            sub_id = sub.subscription_id
            findings.extend(self.scan_storage(sub_id))
            findings.extend(self.scan_nsg(sub_id))
            findings.extend(self.scan_rbac(sub_id))
            findings.extend(self.scan_monitor(sub_id))
        return findings

    def _create_finding(self, service, resource, issue, severity, evidence, remediation, cis="N/A", mitre="N/A", exposure=0, privilege=0, data_sensitivity=0, exploitability=0):
        return Finding(
            provider="Azure",
            service=service,
            resource=resource,
            issue=issue,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            frameworks={"cis_azure": cis, "mitre": mitre},
            exposure=exposure,
            privilege=privilege,
            data_sensitivity=data_sensitivity,
            exploitability=exploitability
        ).to_dict()

    def scan_storage(self, subscription_id: str):
        findings = []
        try:
            storage_client = StorageManagementClient(self.credential, subscription_id)
            accounts = storage_client.storage_accounts.list()
            for account in accounts:
                res_name = f"{subscription_id}/{account.name}"
                if not account.enable_https_traffic_only:
                    findings.append(self._create_finding(
                        "Storage", res_name, "Secure transfer required (HTTPS) is disabled", "High",
                        f"enable_https_traffic_only = {account.enable_https_traffic_only}",
                        "Enable 'Secure transfer required' in Storage Account settings", "3.1", exploitability=10
                    ))
                if account.allow_blob_public_access:
                    findings.append(self._create_finding(
                        "Storage", res_name, "Public blob access is allowed", "Critical",
                        f"allow_blob_public_access = {account.allow_blob_public_access}",
                        "Set 'allow_blob_public_access' to False", "3.7", exposure=20, data_sensitivity=15
                    ))
                if account.minimum_tls_version != 'TLS1_2':
                    findings.append(self._create_finding(
                        "Storage", res_name, "Minimum TLS version is not 1.2", "Medium",
                        f"minimum_tls_version = {account.minimum_tls_version}",
                        "Set minimum TLS version to 1.2", "3.2"
                    ))
                if account.network_rule_set and account.network_rule_set.default_action == 'Allow':
                    findings.append(self._create_finding(
                        "Storage", res_name, "Network access is allowed from all networks", "High",
                        f"default_action = {account.network_rule_set.default_action}",
                        "Restrict network access to specific IPs or Virtual Networks", "3.6"
                    ))
                if account.allow_shared_key_access:
                     findings.append(self._create_finding(
                        "Storage", res_name, "Shared key access is allowed", "Medium",
                        f"allow_shared_key_access = {account.allow_shared_key_access}",
                        "Disable shared key access and use Entra ID (Azure AD) authentication", "3.8"
                    ))
                if not account.encryption or not account.encryption.require_infrastructure_encryption:
                     findings.append(self._create_finding(
                        "Storage", res_name, "Infrastructure encryption is not enabled", "Medium",
                        "require_infrastructure_encryption = False",
                        "Enable infrastructure encryption for double encryption", "3.3"
                    ))
        except Exception:  # noqa: BLE001, S110
            pass
        return findings

    def scan_nsg(self, subscription_id: str):
        findings = []
        try:
            network_client = NetworkManagementClient(self.credential, subscription_id)
            nsgs = network_client.network_security_groups.list_all()
            for nsg in nsgs:
                res_name = f"{subscription_id}/{nsg.name}"
                for rule in nsg.security_rules:
                    if rule.access == 'Allow' and rule.direction == 'Inbound':  # noqa: SIM102
                        if rule.source_address_prefix in ['*', '0.0.0.0/0', 'Internet']:
                            port = rule.destination_port_range
                            
                            severity = "Low"
                            if port == '*' or port in ['22', '3389']:
                                severity = "Critical"
                            elif port in ['1433', '3306', '5432', '6379', '27017', '9200']:
                                severity = "High"
                            else:
                                severity = "Medium"

                            findings.append(self._create_finding(
                                "NSG", res_name, f"Allows inbound traffic from Internet to port {port}", severity,
                                f"Rule '{rule.name}' allows {rule.source_address_prefix} to {port}",
                                "Restrict source address to known IPs or use Bastion/VPN", "6.2", exposure=20
                            ))
        except Exception:  # noqa: BLE001, S110
            pass
        return findings

    def scan_rbac(self, subscription_id: str):
        findings = []
        try:
            auth_client = AuthorizationManagementClient(self.credential, subscription_id)
            # Scan across all scopes by not providing a scope, or just listing for subscription and then iterating over resources?
            # listing all role assignments for the subscription (includes resource groups and resources)
            assignments = auth_client.role_assignments.list_for_subscription()
            
            for assignment in assignments:
                role_id = assignment.role_definition_id.lower()
                scope = assignment.scope
                principal_id = assignment.principal_id
                principal_type = assignment.principal_type # User, Group, ServicePrincipal
                
                # 8e3af657-a8ff-443c-a75c-2fe8c4bcb635 is Owner
                # b24988ac-6180-42a0-ab88-20f7382dd24c is Contributor
                # 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9 is User Access Administrator
                
                role_name = None
                severity = None
                if "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" in role_id:
                    role_name = "Owner"
                    severity = "Critical"
                elif "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" in role_id:
                    role_name = "User Access Administrator"
                    severity = "High"
                elif "b24988ac-6180-42a0-ab88-20f7382dd24c" in role_id:
                    role_name = "Contributor"
                    severity = "Medium"

                if role_name:
                    issue_desc = f"Principal '{principal_id}' ({principal_type}) has {role_name} role at scope: {scope}"
                    # Elevate severity if it is a Service Principal / Managed Identity with broad scope (subscription)
                    if principal_type == 'ServicePrincipal' and len(scope.split('/')) <= 3:
                        severity = "Critical" if role_name in ["Owner", "Contributor", "User Access Administrator"] else severity
                        issue_desc = f"ServicePrincipal '{principal_id}' has privileged {role_name} role at broad scope: {scope}"

                    findings.append(Finding(
                        provider="Azure",
                        service="RBAC",
                        resource=f"RBAC Assignment: {assignment.id}",
                        issue=issue_desc,
                        severity=severity,
                        evidence=f"role_definition_id = {role_id}",
                        remediation=f"Review if {role_name} is needed at this scope. Apply least privilege.",
                        frameworks={"cis_azure": "1.23", "mitre": "T1098"},
                        privilege=15
                    ).to_dict())
        except Exception:  # noqa: BLE001, S110
            pass
        return findings

    def scan_monitor(self, subscription_id: str):
        findings = []
        try:
            monitor_client = MonitorManagementClient(self.credential, subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            diag_settings = monitor_client.diagnostic_settings.list(resource_uri=scope)
            
            categories_enabled = set()
            
            for setting in diag_settings:
                for log in setting.logs:
                    if log.enabled:
                        categories_enabled.add(log.category)
                        # Assume 0 is not compliant unless we know it means indefinite. 
                        # In Azure, 0 days retention means indefinite for storage accounts, but log analytics is different.
                        # Let's flag if retention is < 90 and not 0, or if 0 flag it just in case as requested.
                        if log.retention_policy.days < 90 and log.retention_policy.days != 0:
                            findings.append(self._create_finding(
                                "Monitor", f"{subscription_id}/{setting.name}",
                                f"Diagnostic setting '{log.category}' log retention is less than 90 days ({log.retention_policy.days} days)",
                                "Low", f"retention_policy.days = {log.retention_policy.days}",
                                "Set log retention to at least 90 days", "5.1"
                            ))
                        elif log.retention_policy.days == 0:
                            findings.append(self._create_finding(
                                "Monitor", f"{subscription_id}/{setting.name}",
                                f"Diagnostic setting '{log.category}' log retention is set to 0 (which may mean no retention policy or indefinite depending on target)",
                                "Low", "retention_policy.days = 0",
                                "Explicitly set log retention to at least 90 days if using Storage Account", "5.1"
                            ))
            
            required_categories = ['Administrative', 'Security', 'Alert', 'Policy', 'ServiceHealth', 'ResourceHealth']
            for cat in required_categories:
                if cat not in categories_enabled and f"Action+{cat}" not in categories_enabled:
                    findings.append(self._create_finding(
                        "Monitor", f"Subscription: {subscription_id}",
                        f"Activity Log for '{cat}' is not enabled",
                        "Medium", f"Missing category: {cat}",
                        f"Enable Activity Log diagnostic setting for {cat}", "5.1"
                    ))

        except Exception:  # noqa: BLE001, S110
            pass
        return findings
