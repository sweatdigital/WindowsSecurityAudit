# Windows Security Audit Script
# Requires PowerShell to be run as Administrator

# Check for Admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!`nPlease launch PowerShell with elevated privileges." -ForegroundColor Red
    exit
}

# Output formatting
$separator = "=" * 70
$subseparator = "-" * 70

# System Information
Write-Host "`n$separator" -ForegroundColor Cyan
Write-Host "Windows Security Audit Report" -ForegroundColor Cyan
Write-Host "Generated: $(Get-Date)" -ForegroundColor Cyan
Write-Host "$separator`n" -ForegroundColor Cyan

# 1. System Updates
#Write-Host "[1] Windows Updates Check" -ForegroundColor Yellow
#$updates = Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending
#$lastUpdate = if ($updates) { $updates[0].InstalledOn } else { "No updates found" }
#Write-Host "Last installed update: $lastUpdate"
#Write-Host "Pending updates: $( (Get-WindowsUpdate -IsInstalled $false).Count )`n"
Write-Host "[1] Windows Updates Check" -ForegroundColor Yellow
try {
    $updates = Get-HotFix | Sort-Object -Property InstalledOn -Descending
    $lastUpdate = if ($updates) { $updates[0].InstalledOn } else { "No updates found" }
    Write-Host "Last installed update: $lastUpdate"
    
    # Check for pending updates (alternative method)
    if (Get-Command -Name Get-WUList -ErrorAction SilentlyContinue) {
        $pending = (Get-WUList -IsInstalled $false).Count
        Write-Host "Pending updates: $pending"
    }
    else {
        Write-Host "Pending updates: [Install PSWindowsUpdate module for details]"
        Write-Host "Run: Install-Module PSWindowsUpdate -Force" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Update check error: $_" -ForegroundColor Red
}

# 2. User Accounts
Write-Host "[2] User Account Checks" -ForegroundColor Yellow
Write-Host $subseparator
Get-LocalUser | Format-Table Name, Enabled, PasswordLastSet, PasswordRequired, LastLogon

# 3. Audit Policies
Write-Host "`n[3] Audit Policies" -ForegroundColor Yellow
Write-Host $subseparator
auditpol /get /category:* | Select-String -Pattern "Logon/Logoff|Account Management|Object Access|Policy Change"

# 4. Firewall Status
Write-Host "`n[4] Firewall Status" -ForegroundColor Yellow
Write-Host $subseparator
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# 5. Services Check
#Write-Host "`n[5] Service Checks" -ForegroundColor Yellow
#Write-Host $subseparator
#$dangerousServices = @("RemoteRegistry", "SSDPSRV", "upnphost", "Telnet", "W3SVC")
#Get-Service -Name $dangerousServices | Format-Table Name, Status, StartType
# 5. Services Check (Revised)
Write-Host "`n[5] Service Checks" -ForegroundColor Yellow
Write-Host $subseparator
$dangerousServices = @(
    "RemoteRegistry",   # Remote Registry Service
    "SSDPSRV",          # SSDP Discovery Service
    "upnphost",         # UPnP Device Host
    "Telnet",           # Telnet Service
    "W3SVC",            # World Wide Web Publishing Service
    "FTPSVC",           # FTP Service
    "SNMP"              # SNMP Service
)

# Get services without throwing errors for missing ones
$services = Get-Service -ErrorAction SilentlyContinue | 
    Where-Object { $dangerousServices -contains $_.Name }

if ($services) {
    $services | Format-Table Name, Status, StartType -AutoSize
    Write-Host "`nExplanation of services:" -ForegroundColor DarkGray
    Write-Host "- RemoteRegistry: Allows remote registry modification"
    Write-Host "- SSDPSRV/upnphost: UPnP services (potential network exposure)"
    Write-Host "- Telnet: Unencrypted remote access protocol"
    Write-Host "- W3SVC: Web server service (IIS)"
    Write-Host "- FTPSVC: FTP server service"
    Write-Host "- SNMP: Network monitoring protocol (often insecure)"
}
else {
    Write-Host "No known dangerous services found" -ForegroundColor Green
}

# 6. Network Configuration
Write-Host "`n[6] Network Configuration" -ForegroundColor Yellow
Write-Host $subseparator
Write-Host "Listening Ports:"
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Format-Table LocalAddress, LocalPort, State

# 7. Security Protocols
Write-Host "`n[7] Security Protocols Check" -ForegroundColor Yellow
Write-Host $subseparator
Write-Host "SMBv1 Enabled: $(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State)"
Write-Host "TLS 1.0/1.1 Enabled: $( [bool](Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -ErrorAction SilentlyContinue) )"

# 8. UAC Status
Write-Host "`n[8] User Account Control (UAC)" -ForegroundColor Yellow
Write-Host $subseparator
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object EnableLUA, ConsentPromptBehaviorAdmin

# 9. Antivirus Status
#Write-Host "`n[9] Antivirus Status" -ForegroundColor Yellow
#Write-Host $subseparator
#Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Format-Table displayName, productState
# 9. Antivirus Status (Revised)
Write-Host "`n[9] Antivirus Status" -ForegroundColor Yellow
Write-Host $subseparator

try {
    # Try Windows Security Center namespace (newer systems)
    $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop
    if ($antivirus) {
        $antivirus | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.displayName
                Status = if ($_.productState -ne 0) { "Enabled" } else { "Disabled" }
                SignatureVersion = $_.productVersion
            }
        } | Format-Table -AutoSize
    }
} catch {
    # Fallback for older systems (Windows 7/Server 2008 R2)
    try {
        $antivirus = Get-WmiObject -Namespace root/SecurityCenter -Class AntivirusProduct
        $antivirus | Format-Table displayName, productState, instanceGuid -AutoSize
    } catch {
        Write-Host "Security Center namespace not available"
    }
}

# Additional check for Windows Defender
try {
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus) {
        Write-Host "`nWindows Defender Status:"
        [PSCustomObject]@{
            AntivirusEnabled = $defenderStatus.AntivirusEnabled
            RealTimeProtection = $defenderStatus.RealTimeProtectionEnabled
            SignatureAge = (New-TimeSpan -Start $defenderStatus.AntivirusSignatureLastUpdated).Days
        } | Format-List
    }
} catch {
    Write-Host "Windows Defender information unavailable"
}

# Final fallback
if (-not $antivirus -and -not $defenderStatus) {
    Write-Host "Antivirus status could not be determined. Check if:"
    Write-Host "- Security Center service is running (sc query wscsvc)"
    Write-Host "- Third-party antivirus is properly registered"
}

# 10. Event Log Analysis
Write-Host "`n[10] Recent Security Events" -ForegroundColor Yellow
Write-Host $subseparator
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5 | Format-Table TimeCreated, Id, Message -Wrap


# 11. Password Policy
Write-Host "`n[11] Password Policies" -ForegroundColor Yellow
Write-Host $subseparator
net accounts

# 12. Drive Encryption
Write-Host "`n[12] BitLocker Status" -ForegroundColor Yellow
Write-Host $subseparator
if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    Get-BitLockerVolume | Format-Table MountPoint, VolumeStatus, ProtectionStatus
} else {
    Write-Host "BitLocker not available on this edition"
}

# Windows Security Audit Script with System Information
# Requires PowerShell to be run as Administrator

# Check for Admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!`nPlease launch PowerShell with elevated privileges." -ForegroundColor Red
    exit
}

# 13. Output formatting
$separator = "=" * 70
$subseparator = "-" * 70

# 14. System Information Section
Write-Host "`n$separator" -ForegroundColor Cyan
Write-Host "System Information" -ForegroundColor Cyan
Write-Host "$separator" -ForegroundColor Cyan

# 15. Basic OS Info
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem

Write-Host "`n[Basic System Info]" -ForegroundColor Yellow
Write-Host $subseparator
Write-Host "Hostname: $($computer.Name)"
Write-Host "OS Version: $($os.Caption) (Build: $($os.BuildNumber))"
Write-Host "Architecture: $($os.OSArchitecture)"
Write-Host "Install Date: $($os.InstallDate.ToString('yyyy-MM-dd'))"
Write-Host "Last Boot Time: $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'))"
Write-Host "Uptime: $((Get-Date) - $os.LastBootUpTime | Select-Object Days, Hours, Minutes | Format-List | Out-String)"

# 16. Hardware Info
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
$disks = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3}

Write-Host "`n[Hardware Info]" -ForegroundColor Yellow
Write-Host $subseparator
Write-Host "CPU: $($cpu.Name)"
Write-Host "Cores: $($cpu.NumberOfCores) Physical / $($cpu.NumberOfLogicalProcessors) Logical"
Write-Host "Total RAM: $([math]::Round($memory.Sum/1GB, 2)) GB"
Write-Host "Disk Configuration:"
$disks | Format-Table DeviceID, 
    @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB, 2)}}, 
    @{Name="Free(GB)";Expression={[math]::Round($_.FreeSpace/1GB, 2)}}, 
    @{Name="Free(%)";Expression={[math]::Round(($_.FreeSpace/$_.Size)*100, 2)}}

# 17. Network Info
$network = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null} | Select-Object -First 1
$adapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}

Write-Host "`n[Network Info]" -ForegroundColor Yellow
Write-Host $subseparator
Write-Host "Primary IP: $($network.IPv4Address.IPAddress)"
Write-Host "Gateway: $($network.IPv4DefaultGateway.NextHop)"
Write-Host "DNS Servers: $($network.DNSServer.ServerAddresses -join ', ')"
Write-Host "Active Adapters:"
$adapters | Format-Table Name, InterfaceDescription, LinkSpeed, MacAddress -AutoSize

# 18. Security Audit Section
Write-Host "`n$separator" -ForegroundColor Cyan
Write-Host "Security Audit Report" -ForegroundColor Cyan
Write-Host "Generated: $(Get-Date)" -ForegroundColor Cyan
Write-Host "$separator`n" -ForegroundColor Cyan

# [Rest of your original security checks follow here...]
# (Windows Updates Check, User Accounts, Audit Policies, etc.)


# Recommendations
Write-Host "`n$separator" -ForegroundColor Cyan
Write-Host "Security Recommendations" -ForegroundColor Cyan
Write-Host $separator
Write-Host "- Review and install pending Windows updates" -ForegroundColor Yellow
Write-Host "- Check for inactive user accounts and disable them" -ForegroundColor Yellow
Write-Host "- Verify firewall rules and disable unnecessary services" -ForegroundColor Yellow
Write-Host "- Ensure antivirus is active and up-to-date" -ForegroundColor Yellow
Write-Host "- Review event logs for suspicious activity" -ForegroundColor Yellow
Write-Host "- Consider encrypting drives with BitLocker" -ForegroundColor Yellow
Write-Host "`nNote: For comprehensive security analysis, consider using:" -ForegroundColor Cyan
Write-Host "- Microsoft Security Compliance Toolkit" -ForegroundColor Cyan
Write-Host "- Nessus Vulnerability Scanner" -ForegroundColor Cyan
Write-Host "- Windows Defender Application Control" -ForegroundColor Cyan