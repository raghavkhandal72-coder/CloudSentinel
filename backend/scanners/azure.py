from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient

from backend.models.finding import Finding

from .base import BaseScanner


class AzureScanner(BaseScanner):
    def __init__(self, subscription_id: str | None = None):
        super().__init__()
        self.target_subscription_id = subscription_id
        try:
            self.credential = DefaultAzureCredential()
            self.sub_client = SubscriptionClient(self.credential)
            if subscription_id:
                sub_obj = type("SubscriptionItem", (), {"subscription_id": subscription_id})()
                self.subscriptions = [sub_obj]
            else:
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
            findings.extend(self.scan_keyvault(sub_id))
            findings.extend(self.scan_sql(sub_id))
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
        frameworks = {"cis_azure": cis, "mitre": mitre}
        if soc2 != "N/A":
            frameworks["soc2"] = soc2
        if pci_dss != "N/A":
            frameworks["pci_dss"] = pci_dss
        if hipaa != "N/A":
            frameworks["hipaa"] = hipaa

        return Finding(
            provider="Azure",
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
                        "Enable 'Secure transfer required' in Storage Account settings", "3.1",
                        soc2="CC6.6", pci_dss="4.1", hipaa="164.312(e)(1)", exploitability=10
                    ))
                if account.allow_blob_public_access:
                    findings.append(self._create_finding(
                        "Storage", res_name, "Public blob access is allowed", "Critical",
                        f"allow_blob_public_access = {account.allow_blob_public_access}",
                        "Set 'allow_blob_public_access' to False", "3.7",
                        soc2="CC6.6", pci_dss="1.3", hipaa="164.312(a)(1)", exposure=20, data_sensitivity=15
                    ))
                if account.minimum_tls_version != 'TLS1_2':
                    findings.append(self._create_finding(
                        "Storage", res_name, "Minimum TLS version is not 1.2", "Medium",
                        f"minimum_tls_version = {account.minimum_tls_version}",
                        "Set minimum TLS version to 1.2", "3.2",
                        soc2="CC6.6", pci_dss="4.1"
                    ))
                if account.network_rule_set and account.network_rule_set.default_action == 'Allow':
                    findings.append(self._create_finding(
                        "Storage", res_name, "Network access is allowed from all networks", "High",
                        f"default_action = {account.network_rule_set.default_action}",
                        "Restrict network access to specific IPs or Virtual Networks", "3.6",
                        soc2="CC6.6", pci_dss="1.3"
                    ))
                if account.allow_shared_key_access:
                    findings.append(self._create_finding(
                        "Storage", res_name, "Shared key access is allowed", "Medium",
                        f"allow_shared_key_access = {account.allow_shared_key_access}",
                        "Disable shared key access and use Microsoft Entra ID (Azure AD) tokens instead", "3.8",
                        soc2="CC6.1"
                    ))
                if not account.encryption.require_infrastructure_encryption:
                    findings.append(self._create_finding(
                        "Storage", res_name, "Infrastructure double encryption is disabled", "Low",
                        "require_infrastructure_encryption = False",
                        "Enable infrastructure encryption for high-security environments", "3.10",
                        soc2="CC6.1"
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
                for rule in nsg.security_rules:
                    if rule.access == 'Allow' and rule.direction == 'Inbound':
                        # Check sources: * or 0.0.0.0/0 or internet
                        sources = []
                        if rule.source_address_prefix: sources.append(rule.source_address_prefix)
                        if rule.source_address_prefixes: sources.extend(rule.source_address_prefixes)
                        
                        is_broad = any(s in ['*', '0.0.0.0/0', 'Internet'] for s in sources)
                        
                        if is_broad:
                            dest_port = rule.destination_port_range
                            ports = [dest_port] if dest_port else rule.destination_port_ranges
                            
                            # Sensitive ports to flag
                            critical_ports = ['22', '3389', '*']
                            high_ports = ['3306', '5432', '1433', '27017', '6379', '9200']
                            
                            for p in ports:
                                if p in critical_ports:
                                    findings.append(self._create_finding(
                                        "NSG", f"{nsg.name}/{rule.name}",
                                        f"Allows inbound traffic from Internet to port {p}", "Critical",
                                        f"Source: {sources}, Port: {p}",
                                        f"Restrict inbound access to port {p} to specific IP addresses", "6.1", "T1190",
                                        soc2="CC6.6", pci_dss="1.2", exposure=20, exploitability=10
                                    ))
                                elif p in high_ports:
                                    findings.append(self._create_finding(
                                        "NSG", f"{nsg.name}/{rule.name}",
                                        f"Allows inbound traffic from Internet to port {p}", "High",
                                        f"Source: {sources}, Port: {p}",
                                        f"Restrict inbound access to port {p} to specific application tiers", "6.2", "T1190",
                                        soc2="CC6.6", pci_dss="1.3", exposure=20, data_sensitivity=15
                                    ))
        except Exception:  # noqa: BLE001, S110
            pass
        return findings

    def scan_rbac(self, subscription_id: str):
        findings = []
        try:
            auth_client = AuthorizationManagementClient(self.credential, subscription_id)
            assignments = auth_client.role_assignments.list_for_subscription()
            
            # Common highly privileged Azure built-in role IDs
            OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # gitleaks:allow
            CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"  # gitleaks:allow
            USER_ACCESS_ADMIN_ROLE_ID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"  # gitleaks:allow
            
            for assign in assignments:
                role_def_id = assign.role_definition_id.split('/')[-1]
                principal_type = assign.principal_type
                scope = assign.scope
                
                # Check for subscription-level Owner
                if role_def_id == OWNER_ROLE_ID:
                    findings.append(self._create_finding(
                        "RBAC", f"Principal: {assign.principal_id}",
                        f"Principal has Owner role at scope: {scope}", "Critical",
                        f"Role: Owner, Scope: {scope}",
                        "Review if Owner is strictly necessary. Prefer custom scoped roles.", "1.23",
                        soc2="CC6.3", privilege=15
                    ))
                elif role_def_id == CONTRIBUTOR_ROLE_ID:
                    is_broad = "/resourceGroups/" not in scope
                    if is_broad and principal_type == "ServicePrincipal":
                        sev = "Critical"
                        issue = f"ServicePrincipal '{assign.principal_id}' has privileged Contributor role at broad scope: {scope}"
                    elif is_broad:
                        sev = "Medium"
                        issue = f"Principal has privileged Contributor role at broad scope: {scope}"
                    else:
                        sev = "Medium"
                        issue = f"Principal has Contributor role at scope: {scope}"

                    findings.append(self._create_finding(
                        "RBAC", f"Principal: {assign.principal_id}",
                        issue, sev,
                        f"Role: Contributor, PrincipalType: {principal_type}, Scope: {scope}",
                        "Scope Contributor permissions down to specific resource groups", "1.24",
                        soc2="CC6.3", privilege=15
                    ))
                elif role_def_id == USER_ACCESS_ADMIN_ROLE_ID:
                    findings.append(self._create_finding(
                        "RBAC", f"Principal: {assign.principal_id}",
                        f"Principal has User Access Administrator role at scope: {scope}", "High",
                        f"Role: User Access Administrator, Scope: {scope}",
                        "Limit User Access Administrator assignments as it permits granting full permissions", "1.25",
                        soc2="CC6.3", privilege=15
                    ))
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
                        if log.retention_policy.days < 90 and log.retention_policy.days != 0:
                            findings.append(self._create_finding(
                                "Monitor", f"{subscription_id}/{setting.name}",
                                f"Diagnostic setting '{log.category}' log retention is less than 90 days ({log.retention_policy.days} days)",
                                "Low", f"retention_policy.days = {log.retention_policy.days}",
                                "Set log retention to at least 90 days", "5.1", soc2="CC7.2"
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
                        f"Enable Activity Log diagnostic setting for {cat}", "5.1", soc2="CC7.2"
                    ))

        except Exception:  # noqa: BLE001, S110
            pass
        return findings

    def scan_keyvault(self, subscription_id: str):
        findings = []
        try:
            kv_client = KeyVaultManagementClient(self.credential, subscription_id)
            vaults = kv_client.vaults.list_by_subscription()
            for v in vaults:
                res_name = f"{subscription_id}/{v.name}"
                props = getattr(v, "properties", None)
                if props:
                    if not getattr(props, "enable_soft_delete", True):
                        findings.append(self._create_finding(
                            "KeyVault", res_name, "Key Vault soft delete is disabled",
                            "High", "enable_soft_delete = False",
                            "Enable soft delete on Key Vault with a 90-day retention window", "8.4",
                            soc2="CC6.1", pci_dss="3.5"
                        ))
                    if not getattr(props, "enable_purge_protection", False):
                        findings.append(self._create_finding(
                            "KeyVault", res_name, "Key Vault purge protection is not enabled",
                            "High", "enable_purge_protection = False",
                            "Enable purge protection to prevent premature permanent deletion", "8.5",
                            soc2="CC6.1"
                        ))
                    net_acls = getattr(props, "network_acls", None)
                    if net_acls and getattr(net_acls, "default_action", "Allow") == "Allow":
                        findings.append(self._create_finding(
                            "KeyVault", res_name, "Key Vault network access is allowed from all networks",
                            "Medium", "network_acls.default_action = Allow",
                            "Configure Key Vault firewall to allow trusted virtual networks and IPs only", "8.6",
                            soc2="CC6.6"
                        ))
        except Exception:  # noqa: BLE001, S110
            pass
        return findings

    def scan_sql(self, subscription_id: str):
        findings = []
        try:
            sql_client = SqlManagementClient(self.credential, subscription_id)
            servers = sql_client.servers.list()
            for srv in servers:
                res_name = f"{subscription_id}/{srv.name}"
                if getattr(srv, "public_network_access", "Enabled") == "Enabled":
                    findings.append(self._create_finding(
                        "SQL", res_name, "Azure SQL Database Server allows public network access",
                        "Critical", f"public_network_access = {srv.public_network_access}",
                        "Disable public network access and use Private Endpoints", "4.1.1", "T1190",
                        soc2="CC6.6", pci_dss="1.3", exposure=20, data_sensitivity=15
                    ))
        except Exception:  # noqa: BLE001, S110
            pass
        return findings
