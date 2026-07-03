# Install-NdesServer.ps1

Installs and configures the Network Device Enrollment Service (NDES) role on Windows Server to support the Microsoft Intune Certificate Connector.

## Overview

This script automates the end-to-end installation and hardening of NDES, including role installation, IIS configuration, certificate binding, registry tuning, and optional post-installation tasks. It supports both standard domain service accounts and Group Managed Service Accounts (gMSA).

> **Important:** This script is designed specifically for NDES deployments that support the Microsoft Intune Certificate Connector. The settings applied are not suitable for other NDES deployment scenarios.

## Requirements

- Windows Server with PowerShell 5.1 or later
- Must be run as Administrator
- A valid TLS certificate installed in the local machine certificate store
- A domain service account or gMSA pre-configured for NDES
- Network connectivity to the target Certification Authority (CA)

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `RaName` | Yes | Name of the NDES registration authority (RA) |
| `CaConfig` | Yes | CA configuration string in the format `CA server FQDN\CA common name` (use `certutil.exe -dump` to find) |
| `EnrollmentTemplate` | Yes | Template name (not display name) of the NDES certificate template. Alias: `Template` |
| `Thumbprint` | Yes | Thumbprint of the TLS certificate to bind to the NDES service |
| `ServiceAccount` | Yes | Service account for the NDES service. Use `domain\username` for a standard domain account (the script prompts for the password and validates it against the domain) or `domain\username$` with `-GroupManagedServiceAccount` for a gMSA |
| `GroupManagedServiceAccount` | No | Configures the SCEP IIS application pool to use a gMSA |
| `Fqdn` | No | Custom FQDN for the NDES service when deployed behind a load balancer |
| `RemoveLegacyCertificates` | No | Removes any legacy RA certificates issued to the NDES server |
| `RemoveDefaultTemplates` | No | Unpublishes the default NDES templates (CEPEncryption, EnrollmentAgentOffline, IPSECIntermediateOffline) from the CA |
| `AutoEnrollment` | No | Creates a scheduled task to restart the SCEP application pool on certificate renewal events |
| `Restart` | No | Restarts the server after installation completes |

## What the Script Does

1. Validates the service account and TLS certificate; for standard domain accounts, prompts for the password and verifies it against the domain before making any changes
2. Grants the "Log on as a service" right to standard service accounts
3. Installs the ADCS Device Enrollment role and required Windows features
4. Backs up the IIS configuration before making changes (helpful in failure scenarios)
5. Installs and tests the gMSA on the local computer (if applicable)
6. Adds the service account to the local `IIS_IUSRS` group
7. Configures NDES using `Install-AdcsNetworkDeviceEnrollmentService`
8. Sets the enrollment certificate template for all MSCEP template types
9. Enables IIS long URL support (registry and IIS request filtering)
10. Removes the HTTP site binding (if present) and disables the IIS default document (attack surface reduction)
11. Removes the NDES administration page IIS application (if present - attack surface reduction)
12. Binds the TLS certificate to the Default Web Site
13. Configures the SHA256 hash algorithm for certificate requests (default uses SHA1 which has been deprecated)
14. Disables IE Enhanced Security Configuration (required for Intune Certificate Connector installation)
15. Sets an SPN for the custom FQDN (if `-Fqdn` is specified - optional, only required for load-balanced deployments)
16. Optionally creates a scheduled task for automatic SCEP application pool restart on certificate renewal (when certificate autoenrollment is configured)
17. Optionally removes legacy RA certificates (cleanup)
18. Optionally unpublishes default NDES certificate templates from the CA (attack surface reduction)

A transcript log is written to `%ProgramData%\RMHCI\PowerShell\` for troubleshooting.

## Examples

**Standard service account with server restart:**

```powershell
.\Install-NdesServer.ps1 `
    -RaName 'Contoso NDES RA' `
    -CaConfig 'ca1.corp.contoso.com\Contoso Issuing CA' `
    -Template 'IntuneSCEPEnrollment' `
    -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' `
    -ServiceAccount 'corp\svc_ndes' `
    -Restart
```

**Group Managed Service Account (gMSA):**

```powershell
.\Install-NdesServer.ps1 `
    -RaName 'Contoso NDES RA' `
    -CaConfig 'ca1.corp.contoso.com\Contoso Issuing CA' `
    -Template 'IntuneSCEPEnrollment' `
    -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' `
    -ServiceAccount 'corp\gmsa_ndes$' `
    -GroupManagedServiceAccount
```

**gMSA with automatic certificate renewal support:**

```powershell
.\Install-NdesServer.ps1 `
    -RaName 'Contoso NDES RA' `
    -CaConfig 'ca1.corp.contoso.com\Contoso Issuing CA' `
    -Template 'IntuneSCEPEnrollment' `
    -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' `
    -ServiceAccount 'corp\gmsa_ndes$' `
    -GroupManagedServiceAccount `
    -AutoEnrollment
```

**Custom FQDN (load balancer scenario):**

```powershell
.\Install-NdesServer.ps1 `
    -RaName 'Contoso NDES RA' `
    -CaConfig 'ca1.corp.contoso.com\Contoso Issuing CA' `
    -Template 'IntuneSCEPEnrollment' `
    -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' `
    -ServiceAccount 'corp\svc_ndes' `
    -Fqdn 'ndes.corp.contoso.com'
```

**Remove legacy RA certificates and default templates:**

```powershell
.\Install-NdesServer.ps1 `
    -RaName 'Contoso NDES RA' `
    -CaConfig 'ca1.corp.contoso.com\Contoso Issuing CA' `
    -Template 'IntuneSCEPEnrollment' `
    -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' `
    -ServiceAccount 'corp\svc_ndes' `
    -RemoveLegacyCertificates `
    -RemoveDefaultTemplates
```

## Notes

- For standard domain service accounts, the script prompts for the account password with a secure credential prompt and validates it against the domain before installation begins. No password is required for gMSA deployments.
- The script is safe to run multiple times. IIS configuration steps completed on a previous run (such as removing the HTTP site binding or the NDES administration page) are skipped.
- The script supports `-WhatIf` and `-Confirm`. A transcript is written even during `-WhatIf` runs.
- A server restart is required after installation. Use `-Restart` to restart automatically, or restart manually after the script completes.
- If the installation fails after IIS configuration has been modified, restore the IIS backup with: `& appcmd.exe restore backup <BackupName>`
- To remove a failed NDES configuration and start over: `Uninstall-AdcsNetworkDeviceEnrollmentService -Force`
- The NDES service account must have **Read** and **Enroll** permissions on the enrollment certificate template.

## Additional Resources

- [Richard M. Hicks Consulting Blog](https://www.richardhicks.com/)
- [NDES GitHub Repository](https://github.com/richardhicks/ndes/)

## License

Licensed under the MIT License. See [LICENSE](https://github.com/richardhicks/ndes/blob/main/LICENSE) for details.

## Author

**Richard Hicks**  
Richard M. Hicks Consulting, Inc.  
[rich@richardhicks.com](mailto:rich@richardhicks.com)  
[https://www.richardhicks.com/](https://www.richardhicks.com/)
