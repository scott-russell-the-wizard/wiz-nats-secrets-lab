# Synthetic Terraform Okta Provider Configuration Fixture (Context 1c)
# Validates secret detection inside HCL provider blocks and variable definitions.

terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.8.0"
    }
  }
}

# 1. Standard multi-line Terraform Okta provider block
# Tests whether scanners correlate the enclosing `provider "okta"` / `base_url = "okta.com"` block
# with `api_token = "00..."` when the key name itself does not contain `okta`.
provider "okta" {
  org_name  = "acme-admin"
  base_url  = "okta.com"
  api_token = "00nQqbxPjvHAGbNzDFW7SvJcJrkr6hDN7ZgA_lVShh"
}

# 2. Single-line Terraform Okta provider block
provider "okta" { alias = "dr" org_name = "acme-admin-dr" base_url = "okta.com" api_token = "00UHhUpvWAI96Gmgqi8o0HxzxS7-YU4w8h-6M-P31C" }

# 3. Terraform local/variable assignment where key name includes `okta`
locals {
  okta_api_token = "00Mc7hHqUI0_UK8ecR9TCOrFf7J-b2GJLAVhWRFpvC"
}
