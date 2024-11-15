<#PSScriptInfo

.VERSION 1.5

.GUID a52391cf-9c38-4304-8c9b-89f151461f3c

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2024 Richard M. Hicks Consulting, Inc. All Rights Reserved.

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

.EXAMPLE
    .\Install-NdesServer.ps1 -RaName 'Richard M. Hicks Consulting NDES RA' -Template 'IntuneSCEPEnrollment' -Thumbprint 'B9413E2A1B2F5BFA0AD8A16118198ACC256D0CF9' -ServiceAccount 'corp\svc_ndes' -CaConfig 'ca1.corp.example.net\Richard M. Hicks Consulting Issuing CA'

    This example installs and configures the NDES role on the local server using the specified parameters.

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
    [switch]$AutoEnrollment

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
$Certificate = Get-ChildItem -Path cert:\localmachine\my\$Thumbprint -ErrorAction SilentlyContinue

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

# Display post-installation instructions
Write-Warning 'A restart is required to complete the installation and configuration of the NDES role.'

# Stop transcript
Write-Verbose 'Stopping transcript...'
Stop-Transcript

# SIG # Begin signature block
# MIInFQYJKoZIhvcNAQcCoIInBjCCJwICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUseWJNvNmypRktxXLY2hOrGUz
# 7uKggiC9MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTla
# MEIxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGln
# aUNlcnQgVGltZXN0YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC+anOf9pUhq5Ywultt5lmjtej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/
# i+utMeV5bUlYYSuuM4vQngvQepVHVzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7r
# JcXa/UKvNminKQPTv/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We
# 2r1Z6VFZj75MU/HNmtsgtFjKfITLutLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI
# 5e/6+NfQrxGFSKx+rDdNMsePW6FLrphfYtk/FLihp/feun0eV+pIF496OVh4R1Tv
# jQYpAztJpVIfdNsEvxHofBf1BWkadc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZ
# Iqi6viEk3RIySho1XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ
# +Z9dI8ZhqcaDHOoj5KGg4YuiYx3eYm33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPv
# IeoGJXaeBQjIK13SlnzODdLtuThALhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnj
# XkRFwLtsVAxFvGqsxUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi
# 6n2PzP0nVepsFk8nlcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCC
# AYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1Ud
# IwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBm
# pWNe7k+SH3agWzBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5n
# Q0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1w
# aW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2Edub
# Tggd0ShPz9Pce4FLJl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxU
# l4JlKwyjUkKhk3aYx7D8vi2mpU1tKlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz
# 57yFq6laICtKjPICYYf/qgxACHTvypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlW
# jNlHlFFv/M93748YTeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZ
# U1WM6nyw23vT6QSgwX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW
# 0P8ZZfx4zvSWzVXpAb9k4Hpvpi6bUe8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMn
# n+LmmRTkTXpFIEB06nXZrDwhCGED+8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpP
# ddOFkM2LlTbMcqFSzm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwX
# u7nMpFu3mgrlgbAW+BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2
# QwQ/l4Gxftt/8wY3grcc/nS//TVkej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPId
# ynhVAku7aRZOwqw6pDCCBwIwggTqoAMCAQICEAFmchIElUK4sup54tMHrEQwDQYJ
# KoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTAeFw0yMTEyMDIwMDAwMDBaFw0yNDEyMjAy
# MzU5NTlaMIGGMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG
# A1UEBxMNTWlzc2lvbiBWaWVqbzEkMCIGA1UEChMbUmljaGFyZCBNLiBIaWNrcyBD
# b25zdWx0aW5nMSQwIgYDVQQDExtSaWNoYXJkIE0uIEhpY2tzIENvbnN1bHRpbmcw
# ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDqy+tWoFEFtrMSSuaG3PuH
# TksQEgenx8aVXX2djaCkEueQNHwzP8T2LVy7Sx2OJ4LgPj9a0jj816JHmJ20GC11
# 6Tl6J5GM9yfyD1mmXz0oiXw03LVSU5Y1XvSPPOpnYJiI/8/lgZnA/LwvHmsgA5hM
# kzoQUMG9k22LtpGLMTuWpVcEM3PJ4eF9dg8HFpBXYi36xaorSxpOPSg0DYi72pJh
# oVAsUfjlWmV60qnt153YUUm/Y8qZivNi1rHjzHNRCratELkE3b+fvvvU0N8nS3y5
# 1GFQGpMQjlnWrMzPhFRV+CYY9P4JoTnk3IGfJjr8Db/spIiw5g5xODNCE7iMuaNM
# FnaRmosI5qo9tKar9K60wQYdjUxTvGtZQRCKdzONTOZsYbDtXztcj2yfwRxZfvU8
# S8jYa2vVMl+dP1t61cMme3bWa6SKguxRSl2VGYxufbeiv9UfMTo2/srPH60DWwF1
# Z0LcyTNrD8ybdfxZzvK2G1cYFwuYFqCkwYIJQ6To4lkCAwEAAaOCAgYwggICMB8G
# A1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBTEXt2j54gb
# 3CcRRWNyRn0yxtn7iTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNB
# MS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD4GA1Ud
# IAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNl
# cnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2
# U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAS8e384pqVHKwdB3HgJdI5yChrK4VdY3CL9UVwWvYQrfsarvUbgC11VxY0u77
# CGFjN8JUA0GdtNr2+yTnXmtMzTp7HPRC4zDKDT2aj5XFnyuo4EfPffFnIKhO3D/4
# P9JDGI7y5BHQ6Kx9vUxQc+oNDr0VM2ohAX9HMLbPNSflqAcVQuFvLzBuNB9S3YVc
# JGUVQs/O+nv/4lLhAAmcpermZgu+ilax2RsGfnYqr6WXx5+uPUriIxGGndrSfZ5E
# t62oomM6pPffkRqnJ0HgCemEfZYxAEceuiHmf9+/ft0IJphqqj0mUWdEisdTukcE
# ESlQZ/J5wWRwoXCw+IdcTUepAkI+Yxu891X1mC1aa5pEPQRBbXcnMPKhB0nFBlJc
# mEMMv5VIVLxJE0+1AU+KxlrYg7nx3UK9/kbyIrVEkc39DHjXeWPYlJLWjfCA0zdD
# l48VhdxDSI/GMViVFg8BoPHy3eiWD+1UryxKlioVgX30hGoE2LGGTLEDJUKTq4sE
# uDAT16AmDUAWgcR0B5psaBPYLSE7LPnk82gNm61kHrsb5Y3yQa0VhQsGWhEockmI
# WfjZu9d9rQmDWNnjUACwxzktQ2WouEiP9EUuKcMf2XhhvR10PjBBWwgUNWUmAM9c
# D0TVKfxUqtYTgjSxfjFdQWCN+5V91w2T1D7iwknVgdgabAsxggXCMIIFvgIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEAFmchIElUK4sup54tMHrEQwCQYFKw4DAhoFAKB4MBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIFV
# 5Hh5qtdpgbOc2DN9JmvyxQmeMA0GCSqGSIb3DQEBAQUABIIBgHPnOMOQfbh+cZyk
# gZmEj0n7tTzEXHsEtva6RY/EkmF/MJlvnJXvndQnkQOrjOTGT915fMAK/qqwV8sg
# d8wwwjx+Iv1WofXe2echWxPcHo5y+2GLegNBFd9aeH0A9EEEp3MMfweAanF3xKmM
# cIbNSlaXZRLeYKkcvK8zORw7s22vNODdJKCFfNuexZQKP2T25/DjrmdZRSchxAHB
# EUGK6SvQv8sju+y+G7pu01e5eOLnJN86Q3lUJjk6TlxXWpEUsiemobnRMt/M0vBn
# DeDx7HNo7h+fCjHlzU24e81wlyzKwMjL0BH7CG/jXuw3x2OJtuUlqFl41ok4MU+E
# Yg3QeD8UfcBC2kaoAq6L+SoEvO6drvLqJIgeTQroj15ov/nqrdrA7jWEQtYqROhR
# dwnmlOeJt5X54yY+1KqV4TvSVspwxjdH0nlAd/UySeLJF7gco8BL2tnwNZC0Sx3y
# /mhMpwv+yJypfe4DFDdG1OmefSvFu13KYWg56rdqNUeoLg5USaGCAyAwggMcBgkq
# hkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0
# MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJ
# YIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3
# DQEJBTEPFw0yNDExMTUxNTM1NTdaMC8GCSqGSIb3DQEJBDEiBCBV1qzzYuV6/3kJ
# oGSneLjbr4KrlikzWQeInUtL6YgTuTANBgkqhkiG9w0BAQEFAASCAgAdECUqKa9i
# RpUcFhzUVmhCLfnURN52iHH2L6OhgsQewV6gHetU+YAvXHAiMy8RYYo1DbksIvW1
# VyiAo6VPsAR6YZfyqvg3MiG51/WJB41oGqsA/W5wqIRhASBmqeVnPs7KOVaOe+VM
# hTGwa85I8ZRH56qCdxXFUB2m3cu1p6Dlwc6Q7ZxeR0VPCbo3CgHTgenhWr1HW8IE
# GHsgRn6fURq/sTP+bfrLUOOBy3nOPeo32iR9DuunTHXj7auK56FU1l9HF6kydZDn
# yeU32gYZ2Caecw9gSALlabMdB24FfBwxDytc6/wvDOcnAfwQ7/uo/pvR8FjuqDkw
# 4NSTIgtomVm8YA9ADLkO/DNmNL2L7pulVU+U0Cplz8NCCQZre12sTxOo/+VDVdWL
# j22j9iInYGjcckTAQKYRtKw7DPh6/eRdT6gJ8e8h/0wQUWvavMEBAmMGVUP6HOyG
# tYxq75ZLo1dO8Rk4OycB5NEfl5V/gBDqBHY1DcaIS3wMuXop9OLHeFf2NEr7By+/
# hDL1d2IOv1RWWGP3yZZBg9lFLEU9Rupm1rjwpbl9UyvLVUqWecjxUUFvvmdDfuyj
# m4HyXtWPVgfqCdDAGjGI2cagQleMH/sVV6jCyXifiscoTtntCZaAJq7Q9EO8u2X/
# nUjgXQ6TonViVRBopFz/2p4hoWsunIhLdw==
# SIG # End signature block
