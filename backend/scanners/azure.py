import os
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from .base import BaseScanner

class AzureScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        try:
            self.credential = DefaultAzureCredential()
            self.sub_client = SubscriptionClient(self.credential)
            self.subscriptions = list(self.sub_client.subscriptions.list())
            self.is_authenticated = bool(self.subscriptions)
        except Exception:
            self.is_authenticated = False

    def scan_all(self):
        if not self.is_authenticated:
            return [{"resource": "Azure Global", "issue": "Authentication Failed: No Azure Credentials Found (az login)", "severity": "Critical"}]
        
        findings = []
        for sub in self.subscriptions:
            sub_id = sub.subscription_id
            findings.extend(self.scan_storage(sub_id))
            findings.extend(self.scan_nsg(sub_id))
            findings.extend(self.scan_rbac(sub_id))
            findings.extend(self.scan_monitor(sub_id))
        return findings

    def scan_storage(self, subscription_id: str):
        findings = []
        try:
            storage_client = StorageManagementClient(self.credential, subscription_id)
            accounts = storage_client.storage_accounts.list()
            for account in accounts:
                if not account.enable_https_traffic_only:
                    findings.append({
                        "resource": f"Azure Storage: {account.name}",
                        "issue": "Secure transfer required (HTTPS) is disabled",
                        "severity": "High"
                    })
                if account.allow_blob_public_access:
                    findings.append({
                        "resource": f"Azure Storage: {account.name}",
                        "issue": "Public blob access is allowed",
                        "severity": "Critical"
                    })
        except Exception as e:
            findings.append({"resource": "Azure Storage", "issue": f"Failed to scan storage: {str(e)}", "severity": "Low"})
        return findings

    def scan_nsg(self, subscription_id: str):
        findings = []
        try:
            network_client = NetworkManagementClient(self.credential, subscription_id)
            nsgs = network_client.network_security_groups.list_all()
            for nsg in nsgs:
                for rule in nsg.security_rules:
                    if rule.access == 'Allow' and rule.direction == 'Inbound':
                        if rule.source_address_prefix in ['*', '0.0.0.0/0', 'Internet']:
                            port = rule.destination_port_range
                            if port in ['22', '3389', '*']:
                                findings.append({
                                    "resource": f"Azure NSG: {nsg.name}",
                                    "issue": f"Allows inbound traffic from Internet to sensitive port {port}",
                                    "severity": "Critical"
                                })
        except Exception as e:
            findings.append({"resource": "Azure NSG", "issue": f"Failed to scan NSG: {str(e)}", "severity": "Low"})
        return findings

    def scan_rbac(self, subscription_id: str):
        findings = []
        try:
            auth_client = AuthorizationManagementClient(self.credential, subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            assignments = auth_client.role_assignments.list_for_scope(scope)
            
            for assignment in assignments:
                role_id = assignment.role_definition_id.lower()
                # 8e3af657-a8ff-443c-a75c-2fe8c4bcb635 is Owner
                # b24988ac-6180-42a0-ab88-20f7382dd24c is Contributor
                # 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9 is User Access Administrator
                
                if "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" in role_id:
                    findings.append({
                        "resource": f"Azure RBAC (Sub: {subscription_id})",
                        "issue": f"Principal {assignment.principal_id} has Owner role at subscription level",
                        "severity": "High"
                    })
                elif "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" in role_id:
                     findings.append({
                        "resource": f"Azure RBAC (Sub: {subscription_id})",
                        "issue": f"Principal {assignment.principal_id} has User Access Administrator role at subscription level",
                        "severity": "Medium"
                    })
        except Exception as e:
            findings.append({"resource": "Azure RBAC", "issue": f"Failed to scan RBAC: {str(e)}", "severity": "Low"})
        return findings

    def scan_monitor(self, subscription_id: str):
        findings = []
        try:
            monitor_client = MonitorManagementClient(self.credential, subscription_id)
            scope = f"/subscriptions/{subscription_id}"
            diag_settings = monitor_client.diagnostic_settings.list(resource_uri=scope)
            
            has_logs = False
            for setting in diag_settings:
                for log in setting.logs:
                    if log.enabled:
                        has_logs = True
                        if log.retention_policy.days < 90 and log.retention_policy.days != 0:
                            findings.append({
                                "resource": f"Azure Monitor (Sub: {subscription_id})",
                                "issue": f"Diagnostic setting '{setting.name}' log retention is less than 90 days ({log.retention_policy.days} days)",
                                "severity": "Low"
                            })
            if not has_logs:
                findings.append({
                    "resource": f"Azure Monitor (Sub: {subscription_id})",
                    "issue": "No Active Diagnostic Settings found for Subscription Activity Logs",
                    "severity": "Medium"
                })
        except Exception as e:
            findings.append({"resource": "Azure Monitor", "issue": f"Failed to scan Monitor/Diagnostics: {str(e)}", "severity": "Low"})
        return findings
