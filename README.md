# Bootstrapper

A tool to help bootstrap Azure.

## Synopsis

Signing up for Azure for the first time can be overwhelming due to the 
numerous services available. This tool simplifies the process by providing 
credentials and setting up GitHub Actions as a basic CI/CD solution to 
begin creating the rest of the infrastructure.

It does the following:

- Registers a new Azure AD application
- Creates a new Service Principal
- Creates a new Resource Group
- Creates a new Key Vault
- Stores the Service Principal credentials in the Key Vault

## Prerequisites

This tool requires that you register an application with Azure Active 
Directory, with the following delegated permissions:

- Azure Active Directory Graph
  - `Directory.AccessAsUser.All`
- Azure Service Management
  - `user_impersonation`
- Microsoft Graph
  - `Directory.AccessAsUser.All`
  - `Directory.ReadWrite.All`
  - `Directory.Write.Restricted`
  - `email`
  - `offline_access`
  - `openid`
  - `profile`

## Usage

```bash
$ bootstrap 
```

## Installation

```bash
$ go get github.com/azure-bootstrap/bootstrap
```

## License

MIT

## Author

Werner Strydom <hello@wernerstrydom.com>




