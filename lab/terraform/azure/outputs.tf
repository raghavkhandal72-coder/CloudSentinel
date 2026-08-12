output "vulnerable_storage_account_name" {
  value = azurerm_storage_account.vulnerable_storage.name
}

output "vulnerable_nsg_id" {
  value = azurerm_network_security_group.vulnerable_nsg.id
}

output "vulnerable_sp_id" {
  value = azuread_service_principal.vulnerable_sp.object_id
}
