<#PSScriptInfo

.VERSION 1.6.3

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
    Version:        1.6.3
    Creation Date:  November 29, 2023
    Last Updated:   August 22, 2025
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
    [switch]$Restart

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
    [void](Register-ScheduledTask -TaskName 'Restart SCEP IIS Application Pool on Certificate Enrollment' -User $User -Action $Action -Trigger $Trigger -RunLevel Highest -Force)

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

    # Stop transcript
    Write-Verbose 'Stopping transcript...'
    Stop-Transcript

    # Display post-installation instructions
    Write-Warning 'A restart is required to complete the installation and configuration of the NDES role.'

}

# SIG # Begin signature block
# MIIf2gYJKoZIhvcNAQcCoIIfyzCCH8cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCArY75vz4fEUG4y
# QU5hcHRixjQ5SZbsUkYptdHU30vyiqCCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
# A1FDvFnZ8EApMAoGCCqGSM49BAMDMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMT
# F0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQy
# ODIzNTk1OVowZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBT
# SEEzODQgMjAyMSBDQTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS7tKwnpUgNolNf
# jy6BPi9TdrgIlKKaqoqLmLWx8PwqFbu5s6UiL/1qwL3iVWhga5c0wWZTcSP8GtXK
# IA8CQKKjSlpGo5FTK5XyA+mrptOHdi/nZJ+eNVH8w2M1eHbk+HejggFXMIIBUzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSbX7A2up0GrhknvcCgIsCLizh3
# 7TAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQw
# QgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0R2xvYmFsUm9vdEczLmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATAKBggqhkjOPQQDAwNoADBlAjB4vUmVZXEB0EZXaGUOaKncNgjB7v3UjttAZT8N
# /5Ovwq5jhqN+y7SRWnjsBwNnB3wCMQDnnx/xB1usNMY4vLWlUM7m6jh+PnmQ5KRb
# qwIN6Af8VqZait2zULLd8vpmdJ7QFmMwggP+MIIDhKADAgECAhANSjTahpCPwBMs
# vIE3k68kMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2ln
# bmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MTIwNjAwMDAwMFoXDTI3MTIy
# NDIzNTk1OVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
# FAYDVQQHEw1NaXNzaW9uIFZpZWpvMSQwIgYDVQQKExtSaWNoYXJkIE0uIEhpY2tz
# IENvbnN1bHRpbmcxJDAiBgNVBAMTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGlu
# ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFCbtcqpc7vGGM4hVM79U+7f0tKz
# o8BAGMJ/0E7JUwKJfyMJj9jsCNpp61+mBNdTwirEm/K0Vz02vak0Ftcb/3yjggHz
# MIIB7zAfBgNVHSMEGDAWgBSbX7A2up0GrhknvcCgIsCLizh37TAdBgNVHQ4EFgQU
# KIMkVkfISNUyQJ7bwvLm9sCIkxgwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBqwYDVR0fBIGjMIGgME6gTKBKhkho
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWdu
# aW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwTqBMoEqGSGh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEczQ29kZVNpZ25pbmdFQ0NTSEEzODQyMDIx
# Q0ExLmNybDCBjgYIKwYBBQUHAQEEgYEwfzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFcGCCsGAQUFBzAChktodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAy
# MUNBMS5jcnQwCQYDVR0TBAIwADAKBggqhkjOPQQDAwNoADBlAjBMOsBb80qx6E6S
# 2lnnHafuyY2paoDtPjcfddKaB1HKnAy7WLaEVc78xAC84iW3l6ECMQDhOPD5JHtw
# YxEH6DxVDle5pLKfuyQHiY1i0I9PrSn1plPUeZDTnYKmms1P66nBvCkwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJcwggSTAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgxZHVg+muLWJ1eoSTUZ44MVoU
# aWcSlNH2zgxfxhHoe98wCwYHKoZIzj0CAQUABEcwRQIhAJVRcT7pKz+W7Nfp54Ir
# B5qpWLQ2G5mRMEDzJtsLRgh0AiAYEQzf74NIFJWZyVecg/5ftuUGtLu0GKeYKUMm
# MkIgPKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEC
# EAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTA4MjIyMjI2MzdaMC8GCSqG
# SIb3DQEJBDEiBCDjCHc/bC7sbBxOwfM/NgJ8TUiuGg/lKlCRBKoXh8U4ZTANBgkq
# hkiG9w0BAQEFAASCAgC3XXpF97YijzjBZixWTk2n38GKTMWe1Vi3LMdMbfErpVXV
# xmsOOAwE3vVMrRoVQvNxmjpVp9pa0Qk/V1jMkK49ECenzIDE+knbmbVqafLiff5X
# 3VJ339fYGkomXWB2ngiw4b1rYKXI7qTIm/MlS9zC3j9DaV+hz/L9QabgfERsGk25
# LHSIwbTB1zaC6WschS30L56BZ6Ty8T7OzaAlDpi/DJUct/lvbRKODneF4Y+jvZXj
# 7f8L0+en1qG7dEjMA2WwCtAXDxaRJihZvv2QtymW/P2HZoZip8auyJmiit7syzYW
# Gsq3TPstfSH2LVrRfEdLnBOeQDF9MI9ouefUmaFYfby2FdooJXa/oPgEYMhmYfjj
# lZMlkvFRl10bdvLdbHVtjh0F/1d1D1ZaUc+v4zQdq63FWurNhxBA3UGPN8wIp3ni
# 09BpdE3L0Frh81IQm+nZGwwGIH8kBhq3NCyqiOCobnZ1OkGKoo3+XYAWuvIIt2xY
# zZeNVo0YeA6lDSEbtEg9V7cUamkHlZtR3Q0Ohr5qNOVChJcporaHF0V66RTUDFqm
# 98SUJ28Y9sR/RjSfZw9J8Unot/Lhp9vldJP+Ui0MScThafxj9PX/FL0qVUIE6S5U
# ymxCpJgreoYf26j9IzV8POuXCkwtFUrUv7jbSI8AIzn11IhT1oUqpA7TrD6PBw==
# SIG # End signature block
