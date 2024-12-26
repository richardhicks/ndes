<#PSScriptInfo

.VERSION 1.6

.GUID a52391cf-9c38-4304-8c9b-89f151461f3c

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2025 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/ndes/blob/main/LICENSE

.PROJECTURI https://github.com/richardhicks/ndes/blob/main/Install-NdesServer.ps1

.TAGS NDES, SCEP, Intune, PKI, ADCS, Certificate, Microsoft, Windows

#>

<#

.SYNOPSIS
    Installs and configures the Network Device Enrollment Service (NDES) role on Windows Server.

.PARAMETER RaName
    The name of the NDES registration authority (RA).

.PARAMETER Template
    The name of the NDES certificate template. This is different than the display name of the template shown in the Certification Authority (CA) management console.

.PARAMETER Thumbprint
    The thumbprint of the TLS certificate to use for the NDES service.

.PARAMETER ServiceAccount
    The domain account to use for the NDES service.

.PARAMETER GroupManagedServiceAccount
    This parameter is optional. If specified, the NDES service will be configured to use a Group Managed Service Account (gMSA) for the SCEP IIS application pool.

.PARAMETER CaConfig
    The configuration of the CA to use for NDES. The syntax is 'CA server FQDN\CA common name'. Use certutil.exe -dump to find the CA configuration.

.PARAMETER Fqdn
    This parameter is optional. It is the custom fully qualified domain name (FQDN) for the NDES service when configured behind a load balancer.

.PARAMETER RemoveLegacyCertificates
    This parameter is optional. If specified, any legacy certificates issued to the NDES server will be removed.

.PARAMETER AutoEnrollment
    This parameter is optional. If specified, a scheduled task will be created to restart the SCEP IIS application pool on certificate renewal events.

.PARAMETER Restart
    This parameter is optional. If specified, the server will be restarted after the NDES role is installed and configured.

.EXAMPLE
    .\Install-NdesServer.ps1 -RaName 'Richard M. Hicks Consulting NDES RA' -Template 'IntuneSCEPEnrollment' -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' -ServiceAccount 'corp\svc_ndes' -CaConfig 'ca1.corp.example.net\Richard M. Hicks Consulting Issuing CA' -Restart

    This example installs and configures the NDES role on the local server using the specified parameters. The server will be restarted after the NDES role is installed and configured.

.EXAMPLE
    .\Install-NdesServer.ps1 -RaName 'Richard M. Hicks Consulting NDES RA' -Template 'IntuneSCEPEnrollment' -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' -ServiceAccount 'corp\gmsa_ndes$' -CaConfig 'ca1.corp.example.net\Richard M. Hicks Consulting Issuing CA' -GroupManagedServiceAccount

    This example installs and configures the NDES role on the local server using a Group Managed Service Account (gMSA) for the SCEP IIS application pool.

.EXAMPLE
    .\Install-NdesServer.ps1 -RaName 'Richard M. Hicks Consulting NDES RA' -Template 'IntuneSCEPEnrollment' -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' -ServiceAccount 'corp\gmsa_ndes$' -CaConfig 'ca1.corp.example.net\Richard M. Hicks Consulting Issuing CA' -GroupManagedServiceAccount -AutoEnrollment

    This example installs and configures the NDES role on the local server using a Group Managed Service Account (gMSA) for the SCEP IIS application pool and creates a scheduled task to restart the SCEP IIS application pool on certificate renewal events.

.EXAMPLE
    .\Install-NdesServer.ps1 -RaName 'Richard M. Hicks Consulting NDES RA' -Template 'IntuneSCEPEnrollment' -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' -ServiceAccount 'corp\svc_ndes' -CaConfig 'ca1.corp.example.net\Richard M. Hicks Consulting Issuing CA' -Fqdn 'ndes.corp.example.net'

    This example installs and configures the NDES role on the local server using the specified parameters and a custom FQDN for the NDES service.

.EXAMPLE
    .\Install-NdesServer.ps1 -RaName 'Richard M. Hicks Consulting NDES RA' -Template 'IntuneSCEPEnrollment' -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' -ServiceAccount 'corp\svc_ndes' -CaConfig 'ca1.corp.example.net\Richard M. Hicks Consulting Issuing CA' -RemoveLegacyCertificates

    This example installs and configures the NDES role on the local server using the specified parameters and removes any legacy certificates issued to the NDES server.

.DESCRIPTION
    This script installs and configures the Network Device Enrollment Service (NDES) role on Windows Server. It also configures the server to use a specific TLS certificate and certificate template for NDES.

    In addition, this script performs several post-installation tasks to ensure the NDES service is properly configured, optimized, and secured.

.LINK
    https://github.com/richardhicks/ndes/blob/main/Install-NdesServer.ps1

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        1.5
    Creation Date:  November 29, 2023
    Last Updated:   November 15, 2024
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

[CmdletBinding()]

Param (

    [Parameter(Mandatory, HelpMessage = 'Enter a name for the NDES registration authority (RA)')]
    [ValidateNotNullOrEmpty()]
    [string]$RaName,
    [Parameter(Mandatory, HelpMessage = 'Enter the name of the NDES certificate enrollment template')]
    [ValidateNotNullOrEmpty()]
    [string]$Template,
    [Parameter(Mandatory, HelpMessage = 'Enter the thumbprint of the TLS certificate to use for the NDES service')]
    [ValidateNotNullOrEmpty()]
    # Ensure the thumbprint is 40 characters in length and contains only hexadecimal characters
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$Thumbprint,
    [Parameter(Mandatory, HelpMessage = 'Enter the name of the service account to use for the NDES service. Use the format domain\username. If using a Group Managed Service Account (gMSA), use the format domain\username$')]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccount,
    [switch]$GroupManagedServiceAccount,
    [Parameter(Mandatory, HelpMessage = 'Enter the configuration of the certification authority (CA) to use for NDES. The syntax is `[CA server FQDN`]\`[CA common name`]. Use certutil.exe -dump to find the CA configuration')]
    [ValidateNotNullOrEmpty()]
    [string]$CaConfig,
    [string]$Fqdn,
    [switch]$RemoveLegacyCertificates,
    [switch]$AutoEnrollment,
    [string]$Restart

)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Start transcript
Write-Verbose 'Starting transcript...'
Start-Transcript -Path $env:temp\Install-NdesServer.log

# Record script information
Write-Verbose "Starting $($MyInvocation.MyCommand)..."

If ($GroupManagedServiceAccount) {

    # Validate Group Managed Service Account (gMSA) format
    $Pattern = '^[^\\]+\\[^\\]+\$$'

    If ($ServiceAccount -match $Pattern) {

        Write-Verbose "Group Managed Service Account (gMSA) $ServiceAccount is valid."

    }

    Else {

        # Display a warning and exit if the gMSA account isn't formatted correctly
        Write-Warning "The gMSA account $ServiceAccount is not formatted correctly. The correct format is <domain>\<user>$."

        # Stop transcript
        Stop-Transcript

        # End script
        Return

    }

}

Else {

    # Prompt for NDES service account password if not using a Group Managed Service Account (gMSA) and validate
    Do {

        # Prompt user for password and confirmation
        $Password = Read-Host 'Enter the NDES service account password' -AsSecureString
        $Password2 = Read-Host 'Confirm password' -AsSecureString

        # Convert both secure strings to plain text for comparison
        $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        $PlainPassword2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))

        # Check if passwords match
        If ($PlainPassword -ne $PlainPassword2) {

            Write-Warning 'Passwords do not match. Please try again.'

        }

    }

    # Repeat until passwords match
    While ($PlainPassword -ne $PlainPassword2)

}

# Validate TLS certificate
Write-Verbose "Validating TLS certificate with thumbprint $Thumbprint..."
$Certificate = Get-ChildItem -Path cert:\LocalMachine\My\$Thumbprint -ErrorAction SilentlyContinue

If ($Null -eq $Certificate) {

    # Display a warning and exit if the certificate isn't found
    Write-Warning "Unable to find certificate with thumbprint $Thumbprint."

    # Stop transcript
    Stop-Transcript

    # End script
    Return

}

Else {

    Write-Verbose "Certificate with thumbprint $Thumbprint found."

}

# Install NDES role
Write-Verbose 'Installing NDES role...'
[void](Install-WindowsFeature -Name ADCS-Device-Enrollment -IncludeManagementTools)

# Install required IIS and PowerShell features
Write-Verbose 'Installing supporting features...'
Try {

    [void](Install-WindowsFeature -Name @('Web-Filtering', 'Web-ASP-Net', 'Web-ASP-Net45', 'Web-WMI', 'NET-HTTP-Activation', 'NET-WCF-HTTP-Activation45', 'RSAT-AD-PowerShell'))

}

Catch {

    # If an error occurs, display a warning, stop the transcript, and exit the script
    Write-Warning -Message $_.Exception.Message
    Write-Warning 'An error occurred while installing NDES supporting features. Correct the issue and run the script again.'

    # Stop transcript
    Stop-Transcript

    # End script
    Return

}

# Check local IIS_IUSRS group for NDES service account
$IISUsers = Get-LocalGroupMember -Group IIS_IUSRS -Member $ServiceAccount -ErrorAction SilentlyContinue

# Add NDES service account to local IIS_IUSRS group if required
If ($Null -eq $IISUsers) {

    Write-Verbose "Adding NDES service account $ServiceAccount to local IIS_IUSRS group..."
    Add-LocalGroupMember -Group IIS_IUSRS -Member $ServiceAccount

}

Else {

    Write-Verbose "NDES service account $ServiceAccount is already a member of the local IIS_IUSRS group."

}

# Configure NDES
Write-Verbose 'Configuring NDES...'
If ($GroupManagedServiceAccount) {

    # Define configuration parameters when using a Group Managed Service Account (gMSA)
    $Params = @{

        ApplicationPoolIdentity = $True
        RaName                  = $RaName
        SigningProviderName     = 'Microsoft Strong Cryptographic Provider'
        SigningKeyLength        = 2048
        EncryptionProviderName  = 'Microsoft Strong Cryptographic Provider'
        EncryptionKeyLength     = 2048
        CaConfig                = $CaConfig
        Force                   = $True
        ErrorAction             = 'Stop'

    }

}

Else {

    # Define configuration parameters when using a standard domain service account
    $Params = @{

        ServiceAccountName     = $ServiceAccount
        ServiceAccountPassword = $Password
        RaName                 = $RaName
        SigningProviderName    = 'Microsoft Strong Cryptographic Provider'
        SigningKeyLength       = 2048
        EncryptionProviderName = 'Microsoft Strong Cryptographic Provider'
        EncryptionKeyLength    = 2048
        CaConfig               = $CaConfig
        Force                  = $True
        ErrorAction            = 'Stop'

    }

}

Try {

    # Install NDES
    Install-AdcsNetworkDeviceEnrollmentService @Params

}

Catch {

    # If an error occurs, display a warning, stop the transcript, and exit the script
    Write-Warning -Message $_.Exception.Message
    Write-Warning 'An error occurred while installing the NDES role. Remove the configuration using the following PowerShell command and run the script again: Uninstall-AdcsNetworkDeviceEnrollmentService -Force'

    # Stop transcript
    Stop-Transcript

    # End script
    Return

}

# Set service principal name (SPN). Only required when using a custom FQDN for the NDES service
If ($Fqdn) {

    Write-Verbose "Setting service principal name (SPN) for $Fqdn..."
    Invoke-Command -ScriptBlock { setspn.exe -s http/$Fqdn $ServiceAccount }
    Invoke-Command -ScriptBlock { setspn.exe -s http/$($Fqdn -Replace '(\w+)\..+', '$1') $ServiceAccount }

}

# Disable IE enhanced security. This is required to install the Intune Certificate Connector
Write-Verbose 'Disabling IE enhanced security...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Type DWORD -Value '0'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Type DWORD -Value '0'

# Define NDES certificate templates
Write-Verbose 'Defining NDES certificate template...'
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name  EncryptionTemplate -Value $Template -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name  GeneralPurposeTemplate -Value $Template -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name  SignatureTemplate -Value $Template -Force

# Enable NDES long URL support
Write-Verbose 'Enabling IIS long URL support...'
[void](New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\' -Name MaxFieldLength -Type DWORD -Value 65534 -Force)
[void](New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\' -Name MaxRequestBytes -Type DWORD -Value 65534 -Force)

# Update NDES max URL length and max query string values in IIS request filtering
Write-Verbose 'Setting URL length and max query string values...'
[void](Invoke-Command -ScriptBlock { "$env:WinDir\system32\inetsrv\appcmd.exe set config /section:requestfiltering /requestlimits.maxurl:65534" })
[void](Invoke-Command -ScriptBLock { "$env:WinDir\system32\inetsrv\appcmd.exe set config /section:requestfiltering /requestlimits.maxquerystring:65534" })

# Remove http site binding
Write-Verbose 'Removing HTTP site binding in IIS...'
[void](Remove-IISSiteBinding -Name 'Default Web Site' -BindingInformation '*:80:' -Confirm:$false)

# Disable IIS default document
Write-Verbose 'Disabling IIS default document...'
[void](Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/defaultDocument' -Name 'Enabled' -Value 'False')

# Remove default IIS files
Write-Verbose 'Removing default IIS files...'
[void](Remove-Item -Path C:\Inetpub\wwwroot\iisstart.*)

# Check for existing certificate binding in IIS
If ((Get-WebBinding -Name 'Default Web Site' -Port 443 -Protocol 'HTTPS').Count -gt 0) {

    # Remove existing web binding
    Write-Verbose 'Removing existing HTTPS binding...'
    [void](Remove-WebBinding -Name 'Default Web Site' -Port 443 -Protocol 'HTTPS' -Confirm:$false)

}

# Configure TLS certificate binding in IIS
[void](New-WebBinding -Name 'Default Web Site' -Ipaddress '*' -Port 443 -Protocol 'HTTPS' -SslFlags 0)
(Get-WebBinding -Name 'Default Web Site').AddSslCertificate($Thumbprint, 'My')

# Restart IIS
Write-Verbose 'Restarting IIS...'
[void](Restart-Service -Name W3SVC -Force)

# Configure IIS SCEP application pool to use a Group Managed Service Account (gMSA)
If ($GroupManagedServiceAccount) {

    Write-Verbose 'Configuring IIS SCEP application pool to use a Group Managed Service Account (gMSA)...'
    [void](Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/applicationPools/add[@name="SCEP"]/processModel' -Name 'identityType' -Value 'SpecificUser')
    [void](Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/applicationPools/add[@name="SCEP"]/processModel' -Name 'userName' -Value $ServiceAccount)

}

# Configure the SHA256 hash algorithm for certificate requests
[void](New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\HashAlgorithm\' -Force)
[void](New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\HashAlgorithm\' -PropertyType String -Name HashAlgorithm -Value SHA256 -Force)

If ($AutoEnrollment) {

    # Enable verbose logging for certificate enrollment events
    Write-Verbose 'Enabling verbose logging for certificate enrollment events...'
    [void](Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\AutoEnrollment\ -Name AEEventLogLevel -Value 0)

    # Create scheduled task to restart the SCEP IIS application pool on certificate renewal events
    Write-Verbose 'Creating scheduled task to restart SCEP IIS application pool on certificate renewal events...'
    $User = 'NT AUTHORITY\SYSTEM'
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NonInteractive -NoLogo -NoProfile Restart-WebAppPool -Name SCEP'
    $CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
    $Trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
    $Trigger.Subscription =
    @"
<QueryList><Query Id="0" Path="System"><Select Path="Application">*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll'] and EventID=20]]</Select></Query></QueryList>
"@
    $Trigger.Enabled = $True

    # Register scheduled task
    Write-Verbose 'Registering scheduled task...'
    Register-ScheduledTask -TaskName 'Restart SCEP IIS Application Pool on Certificate Enrollment' -User $User -Action $Action -Trigger $Trigger -RunLevel Highest -Force

}

# Remove legacy CEP Encryption and Exchange Enrollment Agent (Offline request) certificates
If ($RemoveLegacyCertificates) {

    Write-Verbose 'Removing legacy certificates...'
    $LegacyCertificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match $RaName }
    ForEach ($LegacyCertificate in $LegacyCertificates) {

        Write-Verbose "Removing legacy certificate $($LegacyCertificate.Thumbprint)..."
        Remove-Item -Path Cert:\LocalMachine\My\$($LegacyCertificate.Thumbprint) -Force

    }

    Write-Warning 'Legacy certificates have been removed. Ensure the server has enrolled for new certificates.'

}

If ($Restart) {

    # Stop the transcript and restart the server
    Write-Verbose 'Stopping transcript...'
    Stop-Transcript
    Write-Verbose 'Restarting server...'
    Restart-Computer -Force

}

Else {

    # Display post-installation instructions
    Write-Warning 'A restart is required to complete the installation and configuration of the NDES role.'

    # Stop transcript
    Write-Verbose 'Stopping transcript...'
    Stop-Transcript

}

# SIG # Begin signature block
# MIIfdwYJKoZIhvcNAQcCoIIfaDCCH2QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEZgxCyDQNn3o1PYnK1Vvu6nY
# m9qgghpiMIIDWTCCAt+gAwIBAgIQD7inQLkVjQNRQ7xZ2fBAKTAKBggqhkjOPQQD
# AzBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9v
# dCBHMzAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGQxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQg
# R2xvYmFsIEczIENvZGUgU2lnbmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMHYwEAYH
# KoZIzj0CAQYFK4EEACIDYgAEu7SsJ6VIDaJTX48ugT4vU3a4CJSimqqKi5i1sfD8
# KhW7ubOlIi/9asC94lVoYGuXNMFmU3Ej/BrVyiAPAkCio0paRqORUyuV8gPpq6bT
# h3Yv52SfnjVR/MNjNXh25Ph3o4IBVzCCAVMwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQUm1+wNrqdBq4ZJ73AoCLAi4s4d+0wHwYDVR0jBBgwFoAUs9tIpPmh
# xdiuNkHMEWNpYim8S8YwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEAGCCsGAQUFBzAChjRodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRHbG9iYWxSb290RzMuY3J0MEIGA1UdHwQ7MDkwN6A1oDOGMWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwCgYIKoZIzj0EAwMDaAAwZQIw
# eL1JlWVxAdBGV2hlDmip3DYIwe791I7bQGU/Df+Tr8KuY4ajfsu0kVp47AcDZwd8
# AjEA558f8QdbrDTGOLy1pVDO5uo4fj55kOSkW6sCDegH/FamWords1Cy3fL6ZnSe
# 0BZjMIID/jCCA4SgAwIBAgIQDUo02oaQj8ATLLyBN5OvJDAKBggqhkjOPQQDAzBk
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xPDA6BgNVBAMT
# M0RpZ2lDZXJ0IEdsb2JhbCBHMyBDb2RlIFNpZ25pbmcgRUNDIFNIQTM4NCAyMDIx
# IENBMTAeFw0yNDEyMDYwMDAwMDBaFw0yNzEyMjQyMzU5NTlaMIGGMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTWlzc2lvbiBWaWVq
# bzEkMCIGA1UEChMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMSQwIgYDVQQD
# ExtSaWNoYXJkIE0uIEhpY2tzIENvbnN1bHRpbmcwWTATBgcqhkjOPQIBBggqhkjO
# PQMBBwNCAARQm7XKqXO7xhjOIVTO/VPu39LSs6PAQBjCf9BOyVMCiX8jCY/Y7Aja
# aetfpgTXU8IqxJvytFc9Nr2pNBbXG/98o4IB8zCCAe8wHwYDVR0jBBgwFoAUm1+w
# NrqdBq4ZJ73AoCLAi4s4d+0wHQYDVR0OBBYEFCiDJFZHyEjVMkCe28Ly5vbAiJMY
# MD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwgasGA1UdHwSBozCBoDBOoEygSoZIaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0R2xvYmFsRzNDb2RlU2lnbmluZ0VDQ1NIQTM4NDIwMjFDQTEu
# Y3JsME6gTKBKhkhodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9i
# YWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwgY4GCCsGAQUFBwEB
# BIGBMH8wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBXBggr
# BgEFBQcwAoZLaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv
# YmFsRzNDb2RlU2lnbmluZ0VDQ1NIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAw
# CgYIKoZIzj0EAwMDaAAwZQIwTDrAW/NKsehOktpZ5x2n7smNqWqA7T43H3XSmgdR
# ypwMu1i2hFXO/MQAvOIlt5ehAjEA4Tjw+SR7cGMRB+g8VQ5XuaSyn7skB4mNYtCP
# T60p9aZT1HmQ052CpprNT+upwbwpMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrwwggSk
# oAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0y
# NDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYD
# VQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmj
# tej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVH
# VzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP
# 28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITL
# utLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FL
# rphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWka
# dc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5
# PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3e
# Ym33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThA
# LhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbn
# NjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ
# 0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBR
# ME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSB
# gzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsG
# AQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5
# Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1t
# KlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTv
# ypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hW
# JQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V
# 6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6b
# Ue8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED
# +8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq
# 7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2Y
# HcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVk
# ej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6pDGCBH8wggR7
# AgEBMHgwZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTww
# OgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEz
# ODQgMjAyMSBDQTECEA1KNNqGkI/AEyy8gTeTryQwCQYFKw4DAhoFAKB4MBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDbm
# CjwohqfyvBZH2eNWYlU+OU/oMAsGByqGSM49AgEFAARGMEQCIChE/lYqUKAYE2gf
# 0gebxul47FAPYxesEmGQnalgjBBHAiA9yAyvazx+4iWC5i3+sfEbhDP7MuhuLwXM
# NOu+8QGNNKGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAuu
# Zrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDEyMjYxOTMwMTJaMC8GCSqGSIb3
# DQEJBDEiBCAFYTjPdo17SnFNCuQB6ermDFkYCzuswmsj7gJVf6CGSTANBgkqhkiG
# 9w0BAQEFAASCAgBGMmxCrd/cB8PWshnR4orQZ/WihCEQLUwFW8qCrh3b3wvGi7fH
# SwTk/Ksjl/LbZ+O9S0jtFjw1I75ablesft/DfvQhEo/xdOBjXmsU++k28JpMvb22
# oRLwpGtxF58a7tIqHo+VjdbUhKEVN8iQmlvt0+jPBtfMPaECLwwGX9S89PH7yaCL
# o5ni1nzvmgY5CX/sJo/YZxwU/pCfk1TK5HJIJ2olBqDBNXVvFcMs6/1yMpJ5Pbk/
# WQN4QKe2adxfjMdml6FDiudCnmppPqFJhIDM3D0nWqtXTde706Ievar2Uy1vMVqJ
# M9k8U70itsseq/U6TtVQhQ9JFPo+eqZ8ULgT3aGnJJOwoEFT4d2znhQEHkodjSgD
# zU6gKMb7M8EKPa+uhdjGWDbNyNnqppGf8k44pE70hFHKm0pP4etVUd/DYiCusAaJ
# lyUDdoBXRx/5vX6903aKE1Eq5UtsYQYNNBDE6nWgtJKzZ6EkixDonSqv7f4pdKM2
# fTKpEOh0vxulGa1lCn4MuUFe991lFUJqctsxmI3Dz8zGVNpi1D0fE9MFQrSCZHd7
# 0+Yt3JrAKeOpmSol1DPNAKvRYiIj9ZxUGUzrW9mI+jd7X1BtOLVDkqIFbDsOnqxj
# KBLPNYqGwjI7iSxhGHixKVLjPvY5gCPwovjZVUEAXstObrmOa7PQARifOw==
# SIG # End signature block
