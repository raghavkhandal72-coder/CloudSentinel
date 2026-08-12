from unittest.mock import MagicMock, patch

import pytest

from backend.scanners.azure import AzureScanner


@pytest.fixture
def scanner():
    with patch("azure.identity.DefaultAzureCredential"), \
         patch("azure.mgmt.resource.SubscriptionClient") as mock_sub:
        
        mock_sub.return_value.subscriptions.list.return_value = [
            MagicMock(subscription_id='sub-123')
        ]
        
        s = AzureScanner()
        s.is_authenticated = True
        return s

def test_storage_https_disabled(scanner):
    with patch("backend.scanners.azure.StorageManagementClient") as mock_storage:
        account_mock = MagicMock()
        account_mock.name = "teststorage"
        account_mock.enable_https_traffic_only = False
        account_mock.allow_blob_public_access = False
        account_mock.minimum_tls_version = 'TLS1_2'
        account_mock.network_rule_set.default_action = 'Deny'
        account_mock.allow_shared_key_access = False
        account_mock.encryption.require_infrastructure_encryption = True
        
        mock_storage.return_value.storage_accounts.list.return_value = [account_mock]
        
        findings = scanner.scan_storage('sub-123')
        assert any("Secure transfer required (HTTPS) is disabled" in f['issue'] for f in findings)
        assert any(f['severity'] == "High" for f in findings if "Secure transfer" in f['issue'])

def test_public_blob_access(scanner):
    with patch("backend.scanners.azure.StorageManagementClient") as mock_storage:
        account_mock = MagicMock()
        account_mock.name = "teststorage"
        account_mock.enable_https_traffic_only = True
        account_mock.allow_blob_public_access = True
        account_mock.minimum_tls_version = 'TLS1_2'
        account_mock.network_rule_set.default_action = 'Deny'
        account_mock.allow_shared_key_access = False
        account_mock.encryption.require_infrastructure_encryption = True
        
        mock_storage.return_value.storage_accounts.list.return_value = [account_mock]
        
        findings = scanner.scan_storage('sub-123')
        assert any("Public blob access is allowed" in f['issue'] for f in findings)
        assert any(f['severity'] == "Critical" for f in findings if "Public blob access" in f['issue'])

def test_storage_tls(scanner):
    with patch("backend.scanners.azure.StorageManagementClient") as mock_storage:
        account_mock = MagicMock()
        account_mock.name = "teststorage"
        account_mock.enable_https_traffic_only = True
        account_mock.allow_blob_public_access = False
        account_mock.minimum_tls_version = 'TLS1_0'
        account_mock.network_rule_set.default_action = 'Deny'
        account_mock.allow_shared_key_access = False
        account_mock.encryption.require_infrastructure_encryption = True
        
        mock_storage.return_value.storage_accounts.list.return_value = [account_mock]
        
        findings = scanner.scan_storage('sub-123')
        assert any("Minimum TLS version is not 1.2" in f['issue'] for f in findings)

def test_storage_network_access(scanner):
    with patch("backend.scanners.azure.StorageManagementClient") as mock_storage:
        account_mock = MagicMock()
        account_mock.name = "teststorage"
        account_mock.enable_https_traffic_only = True
        account_mock.allow_blob_public_access = False
        account_mock.minimum_tls_version = 'TLS1_2'
        account_mock.network_rule_set.default_action = 'Allow'
        account_mock.allow_shared_key_access = False
        account_mock.encryption.require_infrastructure_encryption = True
        
        mock_storage.return_value.storage_accounts.list.return_value = [account_mock]
        
        findings = scanner.scan_storage('sub-123')
        assert any("Network access is allowed from all networks" in f['issue'] for f in findings)


def test_nsg_open_ssh(scanner):
    with patch("backend.scanners.azure.NetworkManagementClient") as mock_network:
        rule = MagicMock(access='Allow', direction='Inbound', source_address_prefix='*', destination_port_range='22')
        nsg = MagicMock()
        nsg.name = "test-nsg"
        nsg.security_rules = [rule]
        mock_network.return_value.network_security_groups.list_all.return_value = [nsg]
        
        findings = scanner.scan_nsg('sub-123')
        assert any("Allows inbound traffic from Internet to port 22" in f['issue'] for f in findings)
        assert any(f['severity'] == "Critical" for f in findings if "port 22" in f['issue'])

def test_nsg_open_rdp(scanner):
    with patch("backend.scanners.azure.NetworkManagementClient") as mock_network:
        rule = MagicMock(access='Allow', direction='Inbound', source_address_prefix='Internet', destination_port_range='3389')
        nsg = MagicMock()
        nsg.name = "test-nsg"
        nsg.security_rules = [rule]
        mock_network.return_value.network_security_groups.list_all.return_value = [nsg]
        
        findings = scanner.scan_nsg('sub-123')
        assert any("Allows inbound traffic from Internet to port 3389" in f['issue'] for f in findings)
        assert any(f['severity'] == "Critical" for f in findings if "port 3389" in f['issue'])

def test_nsg_open_database(scanner):
    with patch("backend.scanners.azure.NetworkManagementClient") as mock_network:
        rule = MagicMock(access='Allow', direction='Inbound', source_address_prefix='0.0.0.0/0', destination_port_range='3306')
        nsg = MagicMock()
        nsg.name = "test-nsg"
        nsg.security_rules = [rule]
        mock_network.return_value.network_security_groups.list_all.return_value = [nsg]
        
        findings = scanner.scan_nsg('sub-123')
        assert any("Allows inbound traffic from Internet to port 3306" in f['issue'] for f in findings)
        assert any(f['severity'] == "High" for f in findings if "port 3306" in f['issue'])

def test_nsg_wildcard(scanner):
    with patch("backend.scanners.azure.NetworkManagementClient") as mock_network:
        rule = MagicMock(access='Allow', direction='Inbound', source_address_prefix='*', destination_port_range='*')
        nsg = MagicMock()
        nsg.name = "test-nsg"
        nsg.security_rules = [rule]
        mock_network.return_value.network_security_groups.list_all.return_value = [nsg]
        
        findings = scanner.scan_nsg('sub-123')
        assert any("Allows inbound traffic from Internet to port *" in f['issue'] for f in findings)
        assert any(f['severity'] == "Critical" for f in findings if "port *" in f['issue'])

def test_owner_assignment(scanner):
    with patch("backend.scanners.azure.AuthorizationManagementClient") as mock_auth:
        assignment = MagicMock(
            role_definition_id="/.../8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
            scope="/subscriptions/123",
            principal_id="user1",
            principal_type="User"
        )
        mock_auth.return_value.role_assignments.list_for_subscription.return_value = [assignment]
        
        findings = scanner.scan_rbac('sub-123')
        assert any("Owner role at scope" in f['issue'] for f in findings)
        assert any(f['severity'] == "Critical" for f in findings if "Owner" in f['issue'])

def test_contributor_assignment(scanner):
    with patch("backend.scanners.azure.AuthorizationManagementClient") as mock_auth:
        assignment = MagicMock(
            role_definition_id="/.../b24988ac-6180-42a0-ab88-20f7382dd24c",
            scope="/subscriptions/123/resourceGroups/rg1",
            principal_id="user2",
            principal_type="User"
        )
        mock_auth.return_value.role_assignments.list_for_subscription.return_value = [assignment]
        
        findings = scanner.scan_rbac('sub-123')
        assert any("Contributor role at scope" in f['issue'] for f in findings)
        assert any(f['severity'] == "Medium" for f in findings if "Contributor" in f['issue'])

def test_user_access_admin(scanner):
    with patch("backend.scanners.azure.AuthorizationManagementClient") as mock_auth:
        assignment = MagicMock(
            role_definition_id="/.../18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
            scope="/subscriptions/123",
            principal_id="user3",
            principal_type="User"
        )
        mock_auth.return_value.role_assignments.list_for_subscription.return_value = [assignment]
        
        findings = scanner.scan_rbac('sub-123')
        assert any("User Access Administrator role at scope" in f['issue'] for f in findings)
        assert any(f['severity'] == "High" for f in findings if "User Access Administrator" in f['issue'])

def test_rbac_scope(scanner):
    with patch("backend.scanners.azure.AuthorizationManagementClient") as mock_auth:
        assignment = MagicMock(
            role_definition_id="/.../b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
            scope="/subscriptions/123",
            principal_id="sp1",
            principal_type="ServicePrincipal"
        )
        mock_auth.return_value.role_assignments.list_for_subscription.return_value = [assignment]
        
        findings = scanner.scan_rbac('sub-123')
        assert any("privileged Contributor role at broad scope" in f['issue'] for f in findings)
        # Elevated to Critical because it's a ServicePrincipal at subscription scope
        assert any(f['severity'] == "Critical" for f in findings if "ServicePrincipal" in f['issue'])

def test_missing_diagnostics(scanner):
    with patch("backend.scanners.azure.MonitorManagementClient") as mock_monitor:
        mock_monitor.return_value.diagnostic_settings.list.return_value = []
        
        findings = scanner.scan_monitor('sub-123')
        assert any("Activity Log for 'Security' is not enabled" in f['issue'] for f in findings)

def test_short_retention(scanner):
    with patch("backend.scanners.azure.MonitorManagementClient") as mock_monitor:
        log_setting = MagicMock()
        log_setting.category = "Administrative"
        log_setting.enabled = True
        log_setting.retention_policy.days = 30
        
        setting = MagicMock()
        setting.name = "test-setting"
        setting.logs = [log_setting]
        mock_monitor.return_value.diagnostic_settings.list.return_value = [setting]
        
        findings = scanner.scan_monitor('sub-123')
        assert any("log retention is less than 90 days (30 days)" in f['issue'] for f in findings)

def test_activity_logging(scanner):
    with patch("backend.scanners.azure.MonitorManagementClient") as mock_monitor:
        log_setting = MagicMock()
        log_setting.category = "Administrative"
        log_setting.enabled = True
        log_setting.retention_policy.days = 90
        
        setting = MagicMock()
        setting.name = "test-setting"
        setting.logs = [log_setting]
        mock_monitor.return_value.diagnostic_settings.list.return_value = [setting]
        
        findings = scanner.scan_monitor('sub-123')
        assert not any("log retention is less than 90 days" in f['issue'] for f in findings)
        assert any("Activity Log for 'Security' is not enabled" in f['issue'] for f in findings)
