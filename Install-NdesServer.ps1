<#PSScriptInfo

.VERSION 2.0.2

.GUID a52391cf-9c38-4304-8c9b-89f151461f3c

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2025-2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/ndes/blob/main/LICENSE

.PROJECTURI https://github.com/richardhicks/ndes/

.TAGS NDES, SCEP, Intune, PKI, ADCS, Certificate, Microsoft, Windows

#>

<#

.SYNOPSIS
    Installs and configures the Network Device Enrollment Service (NDES) role on Windows Server to support the Microsoft Intune Certificate Connector.

.PARAMETER RaName
    The name of the NDES registration authority (RA).

.PARAMETER EnrollmentTemplate
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

.PARAMETER RemoveDefaultTemplates
    This parameter is optional. If specified, the default NDES certificate templates (CEPEncryption, EnrollmentAgentOffline, and IPSECIntermediateOffline) will be unpublished from the CA.

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
    This script installs and configures the Network Device Enrollment Service (NDES) role on Windows Server to support the Microsoft Intune Certificate Connector. It also configures the server to use a specific TLS certificate and enrollment certificate template for NDES.

    In addition, this script performs several post-installation tasks to ensure the NDES service is properly configured, optimized, and secured.

    IMPORTANT NOTE: This script is for configuring NDES to support the Microsoft Intune Certificate Connector. Settings configured by this script will not work with other deployment scenarios.

.LINK
    https://github.com/richardhicks/ndes/blob/main/Install-NdesServer.ps1

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        2.0.2
    Creation Date:  November 29, 2023
    Last Updated:   May 27, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]

Param (

    [Parameter(Mandatory, HelpMessage = 'Enter a name for the NDES registration authority (RA)')]
    [ValidateNotNullOrEmpty()]
    [string]$RaName,
    [Parameter(Mandatory, HelpMessage = 'Enter the name of the NDES certificate enrollment template')]
    [ValidateNotNullOrEmpty()]
    [Alias('Template')]
    [string]$EnrollmentTemplate,
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
    [switch]$RemoveDefaultTemplates,
    [switch]$AutoEnrollment,
    [switch]$Restart

)

# Start transcript
Write-Verbose 'Starting transcript...'
$LogPath = "$env:ProgramData\RMHCI\PowerShell"

If (-not (Test-Path -Path $LogPath)) {

    [void](New-Item -Path $LogPath -ItemType Directory -Force)

}

Start-Transcript -Path "$LogPath\Install-NdesServer_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

If ($GroupManagedServiceAccount) {

    # Validate Group Managed Service Account (gMSA) format
    $Pattern = '^[^\\]+\\[^\\]+\$$'

    If ($ServiceAccount -match $Pattern) {

        Write-Verbose "Group Managed Service Account (gMSA) $ServiceAccount format is valid."

    }

    Else {

        # Display a warning and exit if the gMSA account isn't formatted correctly
        Write-Warning "The gMSA account $ServiceAccount is not formatted correctly. The correct format is <domain>\<user>$."
        Stop-Transcript
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

# Validate service account exists and can be resolved to a SID
Write-Verbose "Validating service account '$ServiceAccount'..."
Try {

    $NtAccount = New-Object System.Security.Principal.NTAccount($ServiceAccount)
    [void]$NtAccount.Translate([System.Security.Principal.SecurityIdentifier])

}

Catch {

    Stop-Transcript
    Throw "Could not resolve account '$ServiceAccount' to a SID. Verify the account exists and the format is 'domain\user'. Error: $_"

}

# Validate TLS certificate
Write-Verbose "Validating TLS certificate with thumbprint $Thumbprint..."
$Certificate = Get-ChildItem -Path cert:\LocalMachine\My\$Thumbprint -ErrorAction SilentlyContinue

If ($Null -eq $Certificate) {

    # Display a warning and exit if the certificate isn't found
    Write-Warning "Unable to find certificate with thumbprint $Thumbprint."
    Stop-Transcript
    Return

}

Else {

    Write-Verbose "Certificate with thumbprint $Thumbprint found."

}

# Grant the service account the "Log on as a service" right (not required for Group Managed Service Accounts (gMSA))
If (-not $GroupManagedServiceAccount) {

    Write-Verbose "Granting 'Log on as a service' right to NDES service account $ServiceAccount..."

    If (-not ([System.Management.Automation.PSTypeName]'LsaApi').Type) {

        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class LsaApi
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public LSA_UNICODE_STRING ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaOpenPolicy(
        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaAddAccountRights(
        IntPtr PolicyHandle,
        IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        uint CountOfRights);

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaNtStatusToWinError(uint Status);
}
'@

    }

    Function Grant-LogOnAsService {

        Param (

            [string]$ServiceAccount

        )

        # Resolve account name to a SID
        Try {

            $NtAccount = New-Object System.Security.Principal.NTAccount($ServiceAccount)
            $Sid = $NtAccount.Translate([System.Security.Principal.SecurityIdentifier])

        }

        Catch {

            Stop-Transcript
            Throw "Could not resolve account '$ServiceAccount' to a SID. Verify the account exists and the format is 'domain\user'. Error: $_"

        }

        # Marshal the SID to unmanaged memory
        $SidBytes = New-Object byte[] $Sid.BinaryLength
        $Sid.GetBinaryForm($SidBytes, 0)
        $SidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SidBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($SidBytes, 0, $SidPtr, $SidBytes.Length)

        Try {

            $objAttr = New-Object LsaApi+LSA_OBJECT_ATTRIBUTES
            $objAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($objAttr)
            $EmptyName = New-Object LsaApi+LSA_UNICODE_STRING
            $PolicyHandle = [IntPtr]::Zero

            # POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES = 0x00000010 | 0x00000800
            $Status = [LsaApi]::LsaOpenPolicy([ref]$EmptyName, [ref]$objAttr, 0x00000810, [ref]$PolicyHandle)

            If ($Status -ne 0) {

                $WinErr = [LsaApi]::LsaNtStatusToWinError($Status)
                Stop-Transcript
                Throw "LsaOpenPolicy failed. Win32 error: $WinErr"

            }

            Try {

                $Right = New-Object LsaApi+LSA_UNICODE_STRING
                $Right.Buffer = 'SeServiceLogonRight'
                $Right.Length = [uint16]($Right.Buffer.Length * 2)
                $Right.MaximumLength = [uint16]($Right.Buffer.Length * 2 + 2)

                $Status = [LsaApi]::LsaAddAccountRights($PolicyHandle, $SidPtr, @($Right), 1)

                If ($Status -ne 0) {

                    $WinErr = [LsaApi]::LsaNtStatusToWinError($Status)
                    Stop-Transcript
                    Throw "LsaAddAccountRights failed. Win32 error: $WinErr"

                }

                Write-Verbose "Successfully granted 'Log on as a service' to '$ServiceAccount' (SID: $($Sid.Value))."

            }

            Finally {

                [void]([LsaApi]::LsaClose($PolicyHandle))

            }

        }

        Finally {

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SidPtr)

        }

    }

    Grant-LogOnAsService -ServiceAccount $ServiceAccount

}

# Install NDES role and supporting features
Try {

    Write-Verbose 'Installing NDES role and supporting features...'
    $Install = Install-WindowsFeature -Name @('ADCS-Device-Enrollment', 'Web-Filtering', 'Web-ASP-Net', 'Web-ASP-Net45', 'Web-WMI', 'NET-HTTP-Activation', 'NET-WCF-HTTP-Activation45', 'RSAT-AD-PowerShell') -IncludeManagementTools -ErrorAction Stop

}

Catch {

    Write-Warning $_.Exception.Message
    Write-Warning 'An error occurred while installing the NDES role and supporting features. Correct the issue and run the script again.'
    Stop-Transcript
    Return

}

# Check if the installation was successful (catches silent failures not thrown as exceptions)
If (-not $Install.Success) {

    Write-Warning 'NDES role or supporting features installation failed. Review the transcript, correct the issue, and run the script again.'
    Stop-Transcript
    Return

}

# Check if the installation requires a restart
If ($Install.RestartNeeded -ne 'No') {

    Write-Warning 'A restart is required to complete the NDES role installation. Restart the server and run the script again.'
    Stop-Transcript
    Return

}

# Backup IIS configuration
Write-Verbose 'Backing up IIS configuration...'
$BackupName = "NDES_Install_$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
[void](& "$env:SystemRoot\System32\inetsrv\appcmd.exe" add backup $BackupName 2>&1)

If ($LASTEXITCODE -ne 0) {

    Write-Warning "IIS configuration backup failed (exit code $LASTEXITCODE). Proceeding, but a pre-change backup may not exist."

}

Else {

    Write-Verbose "IIS configuration backup '$BackupName' created."

}

# Install gMSA on local computer and verify functionality (requires RSAT-AD-PowerShell, installed above)
If ($GroupManagedServiceAccount) {

    # Extract the gMSA SAM account name (strip domain prefix)
    $AccountName = ($ServiceAccount -split '\\')[1]

    # Install the gMSA on the local computer to enable managed password retrieval
    Write-Verbose "Installing gMSA $ServiceAccount on local computer..."
    Try {

        Install-ADServiceAccount -Identity $AccountName -ErrorAction Stop
        Write-Verbose "gMSA $ServiceAccount successfully installed on local computer."

    }

    Catch {

        Stop-Transcript
        Throw "Failed to install gMSA '$ServiceAccount' on local computer. Verify the account exists and this computer is authorized to retrieve its managed password. Error: $_"

    }

    # Test gMSA functionality
    Write-Verbose "Testing gMSA $ServiceAccount functionality..."
    $ServiceAccountTest = Test-ADServiceAccount -Identity $AccountName

    If ($ServiceAccountTest) {

        Write-Verbose "gMSA $ServiceAccount is correctly configured and functional."

    }

    Else {

        Write-Warning "gMSA $ServiceAccount is not correctly configured. Verify this computer is a member of the gMSA's PrincipalsAllowedToRetrieveManagedPassword group and that the KDS Root Key has been created."

    }

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
    [void](Install-AdcsNetworkDeviceEnrollmentService @Params)

}

Catch {

    # If an error occurs, display a warning, stop the transcript, and exit the script
    Write-Warning -Message $_.Exception.Message
    Write-Warning 'An error occurred while installing the NDES role. Remove the configuration using the following PowerShell command and run the script again: Uninstall-AdcsNetworkDeviceEnrollmentService -Force'
    Write-Warning "If you receive an ERROR_PATH_NOT_FOUND message (0x80070003), run the following PowerShell command before running the script again: `& .\appcmd.exe restore backup $BackupName."
    Stop-Transcript
    Return

}

# Set service principal name (SPN). Only required when using a custom FQDN for the NDES service
If ($Fqdn) {

    Write-Verbose "Setting service principal name (SPN) for $Fqdn..."
    [void](& setspn.exe -s http/$Fqdn $ServiceAccount)
    [void](& setspn.exe -s http/$($Fqdn -Replace '(\w+)\..+', '$1') $ServiceAccount)

}

# Disable IE enhanced security. This is required to install the Intune Certificate Connector
Write-Verbose 'Disabling IE enhanced security...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Type DWORD -Value '0'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Type DWORD -Value '0'

# Define NDES certificate templates
Write-Verbose 'Defining NDES certificate template...'
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name  EncryptionTemplate -Value $EnrollmentTemplate -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name  GeneralPurposeTemplate -Value $EnrollmentTemplate -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\ -Name  SignatureTemplate -Value $EnrollmentTemplate -Force

# Enable NDES long URL support
Write-Verbose 'Enabling IIS long URL support...'
[void](New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\' -Name MaxFieldLength -Type DWORD -Value 65534 -Force)
[void](New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\' -Name MaxRequestBytes -Type DWORD -Value 65534 -Force)

# Update NDES max URL length and max query string values in IIS request filtering
Write-Verbose 'Setting URL length and max query string values...'
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/requestLimits' -Name 'maxUrl' -Value 65534
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/requestLimits' -Name 'maxQueryString' -Value 65534

# Remove http site binding
Write-Verbose 'Removing HTTP site binding in IIS...'
[void](Remove-WebBinding -BindingInformation '*:80:' -Protocol 'http' -Confirm:$false)

# Disable IIS default document
Write-Verbose 'Disabling IIS default document...'
[void](Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/defaultDocument' -Name 'Enabled' -Value 'False')

# Remove default IIS files
Write-Verbose 'Removing default IIS files...'
[void](Remove-Item -Path $env:systemdrive\Inetpub\wwwroot\iisstart.*)

# Remove NDES administration page IIS application
Write-Verbose 'Removing NDES administration page IIS application...'
Remove-WebApplication -Site 'Default Web Site' -Name 'CertSrv/mscep_admin' -Confirm:$false

# Check for existing certificate binding in IIS
If ((Get-WebBinding -Name 'Default Web Site' -Port 443 -Protocol 'HTTPS').Count -gt 0) {

    # Remove existing web binding
    Write-Verbose 'Removing existing HTTPS binding...'
    [void](Remove-WebBinding -Name 'Default Web Site' -Port 443 -Protocol 'HTTPS' -Confirm:$false)

}

# Configure TLS certificate binding in IIS
[void](New-WebBinding -Name 'Default Web Site' -Ipaddress '*' -Port 443 -Protocol 'HTTPS' -SslFlags 0)
(Get-WebBinding -Name 'Default Web Site').AddSslCertificate($Thumbprint, 'My')

# Configure IIS SCEP application pool to use a Group Managed Service Account (gMSA)
If ($GroupManagedServiceAccount) {

    Write-Verbose 'Configuring IIS SCEP application pool to use a Group Managed Service Account (gMSA)...'
    [void](Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/applicationPools/add[@name="SCEP"]/processModel' -Name 'identityType' -Value 'SpecificUser')
    [void](Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/applicationPools/add[@name="SCEP"]/processModel' -Name 'userName' -Value $ServiceAccount)

}

# Restart IIS
Write-Verbose 'Restarting IIS...'
[void](Restart-Service -Name W3SVC -Force)

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
    @'
<QueryList><Query Id="0" Path="System"><Select Path="Application">*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll'] and EventID=20]]</Select></Query></QueryList>
'@
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

# Unpublish default NDES certificate templates
If ($RemoveDefaultTemplates) {

    Write-Verbose 'Unpublishing default NDES certificate templates from the CA...'
    $Result = & certutil.exe -config "$CaConfig" -setcatemplates '-CEPEncryption,EnrollmentAgentOffline,IPSECIntermediateOffline' 2>&1

    If ($LASTEXITCODE -ne 0) {

        Write-Warning "Failed to remove default NDES certificate templates. Verify the NDES service account has CA administrator permissions or remove them manually. Error: $Result"

    }

    Else {

        Write-Verbose 'Default NDES certificate templates (CEPEncryption, EnrollmentAgentOffline, IPSECIntermediateOffline) successfully unpublished from the CA.'

    }

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
# MIIk7AYJKoZIhvcNAQcCoIIk3TCCJNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDKIRWeabfSIwnP
# wynICiuJF7/Ksru2b/NHjdmMG5+WKqCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggW0MIIDnKADAgECAhAOxitIKuZQm69NGxw+uiH/MA0GCSqG
# SIb3DQEBDAUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE2MDAwMDAwWhcNMjcwODE3MjM1
# OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNV
# BAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29u
# c3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMFkw
# EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOooTPiege6mCA4AriPO+Xh3mymiiZ+3k
# kn31uJifB2ojzzfY7VkAVKhgj+rcVBnofnj2b8OhvAJ4YaQ2Iwuc6aOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQJvGhl
# Ahwi6UKROatrFKBmPLmd5TA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAbaKnnRcJAMHjuWSc2PG/QhJ0jj4hQVwJIbddYDJNxPmD0cxuuorSiR9gX2nl
# ajqNI9N7Kl+FB3oheRTGh/wp4JgZMpCq0qS0zGJ/N6Js+HmVtbkFaPyYxJMXbIWq
# p9zKkoXtSXkpR6nGZnzYkn3EBcRlu4R6hIJHzM/C2PUztH/Hd4fGIryyD69iHvKx
# zotYdlHHY6+X1ACaQnuCz3TLxs3/CDKhPUXesKcISnXHmm4uCwyVdtGyl7wPuZVk
# +rfCIOeWn+XG5J7L8xwhXCPSJ5fKJ5m8/H5cICLR0I7hI4SUiybE1nG5CZ1hKhbW
# abSfNer1dHH/vSYi80YGXCej/88vZeCGQ9/rrjugsg0yN7WCPqNKjEMTYGWkrt37
# lp4cJqULS+alUbL6x1HBdoBStDE2CFmPivL7cCCtnudqCA6b3XB416/FlRo8t4Lw
# Dc2ty+RDKirWM84Zj3ANTVs5fi43rxClBQwngGdqi5TjriKHGTkEKYRIFTViy6Ie
# JDIboOkCFJU5vM7Curvh4rQnw+aM4CyjwnDwnzwcKQVZC3Iy1T4h/FvmpSgu5ouM
# wjdzaR3cSh4OPDRrfBl1YIOoZEOHcshCaHDC46t8+UyAf70BMlrB7Nj84ORTuKTi
# IlU062VzGeREc1KHJqp/S3/NtArpVUVQEgibRxQ99KJCOV8wggawMIIEmKADAgEC
# AhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0Mjkw
# MDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2Rl
# IFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYw
# n6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43i
# CH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1
# hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd
# 6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObar
# YBLj6Na59zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18eb
# MlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYo
# X7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDz
# d5Ea/ttQokbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8S
# kXbev1jLchApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZ
# YIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxW
# EQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg
# 67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTAT
# MAcGBWeBDAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6P
# vDqZ01bgAhql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V
# 1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+
# 3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcn
# P/2Q0XaG3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgU
# kpn13c5UbdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6Q
# B7BDf5WIIIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3
# kuZOX956rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKL
# QcBIhEuWTatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47v
# tevLt/B3E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0
# qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0
# YW6/aOImYIbqyK+p/pQd52MbOoZWeE4wgga0MIIEnKADAgECAhANx6xXBf8hmS5A
# QyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAx
# MTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcy
# bEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzT
# qpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftB
# dsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3
# mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6z
# MUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS
# 5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBB
# BnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqL
# XvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7ps
# NOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeE
# WvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCC
# AVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv
# 1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/
# BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0
# LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvI
# tTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/m
# S83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgX
# f9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liy
# rukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+
# Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2
# ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipD
# oq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6Ax
# nJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAl
# Z66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1
# MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZs
# q8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDAN
# BgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkw
# MzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVz
# cG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBG
# rC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwB
# SOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/
# 4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3
# K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROU
# INDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3
# w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46Yce
# NA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d
# 2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8x
# ymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+
# AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2b
# Qhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNV
# HRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSME
# GDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGlu
# Z1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESe
# Y0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FU
# FqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7Y
# MTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0zi
# TN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/
# QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlq
# AcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3
# Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roan
# cJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/
# ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7
# IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdC
# vHlshtjdNXOCIUjsarfNZzGCBJwwggSYAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAViW+VRN73keRSj761fwjk
# h/+C8Hmqu8NcLKtNqziaJDALBgcqhkjOPQIBBQAERzBFAiEAobhgTSgkx8xxbeys
# hqVVNd1IT9bJvcBRmTPzpCjrQyoCIC0nCHkc3XdUhry8lviAe+W5Zr/Okvy2fHGX
# 94spy8PGoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENB
# MQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDUyODAwMzMxNVowLwYJ
# KoZIhvcNAQkEMSIEIF0j81PSafGDUOeqGBJOqMYRvkGN8jI9dhz8pK4GVwhSMA0G
# CSqGSIb3DQEBAQUABIICAMsMI5+fG3p5N6ZleFAp1zhuFbXnhA3KKmHFl0SK2KaK
# N0B15wzQ4LTFHOWDadDfkAWW1aII6fHcxscBN6D0WBgjshGwy20RwOAbLTa2q0KA
# lp1u8BgrLtTtfoKOcWwUrdBFEtgnZ52JqY7h4sa+ebMcuMKFjOc+HaBr+caBn/6k
# QjdbrK0QZ3byMcvItNWetr4ul3sW+BtMK4LpLTO8JP3K13JHUno104jbtNnpYaVY
# eBzHwQX/W0U1U88usphEtSv3jwfwM9aLjae/EMEs25SBHEYeD4kjYa4SlPB+IFgI
# j14M6eqmY9P2wJGcLs8NmjGbFIAU5GxYqDpSVwYgfMigonV7rAvrsD+yVZ56hRNx
# tx/VsSG1+uizQ5zn/P+x4yHBGi88RjmUWbMB7a4r8ULyzn0cLxZ54lQVhsjY54ip
# vsgx9HFbnp8mUY/rxrThC5+dMiAVWaro7bOaVZ/b45K9ZR1GRe2EFDpfpkQuqOYi
# vrSgsxgw0kJMFc8WdXrszpHzce46TMW0yW0clHROlhk4K2iGI9cemiDzz3JdBDN6
# 4AR+2enEBHkDZDpJZDiEBwPlRnfYo96jFFr1/7+igUhxOu7aPvd1JQ5nZRxXolh4
# LtPUkcMRQZTFsMP3skcw2t8lkUkG9wLAzM3/z8H2Pur0aFvxYFlx3XvGeW+s5ZZP
# SIG # End signature block
