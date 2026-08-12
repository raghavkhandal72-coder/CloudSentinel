terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "azuread" {}

# Resource Group
resource "azurerm_resource_group" "lab_rg" {
  name     = "cloudsentinel-vulnerable-lab-rg"
  location = var.location
}

# 1. Vulnerable Storage Account (Public Blob Access)
resource "random_id" "suffix" {
  byte_length = 4
}

resource "azurerm_storage_account" "vulnerable_storage" {
  name                     = "cslabstorage${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.lab_rg.name
  location                 = azurerm_resource_group.lab_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  # Vulnerabilities
  allow_nested_items_to_be_public = true
  enable_https_traffic_only       = false
  min_tls_version                 = "TLS1_0"

  tags = {
    Environment = "Lab"
  }
}

# 2. Vulnerable Network Security Group (Open SSH and RDP)
resource "azurerm_network_security_group" "vulnerable_nsg" {
  name                = "vulnerable-lab-nsg"
  location            = azurerm_resource_group.lab_rg.location
  resource_group_name = azurerm_resource_group.lab_rg.name

  security_rule {
    name                       = "Allow-SSH-Any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-RDP-Any"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# 3. Vulnerable RBAC (Service Principal with Contributor/Owner)
data "azurerm_client_config" "current" {}

resource "azuread_application" "vulnerable_app" {
  display_name = "cloudsentinel-vulnerable-sp"
}

resource "azuread_service_principal" "vulnerable_sp" {
  client_id = azuread_application.vulnerable_app.client_id
}

resource "azurerm_role_assignment" "vulnerable_assignment" {
  scope                = azurerm_resource_group.lab_rg.id
  role_definition_name = "Owner"
  principal_id         = azuread_service_principal.vulnerable_sp.object_id
}
