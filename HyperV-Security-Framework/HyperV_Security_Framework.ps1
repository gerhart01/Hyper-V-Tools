# Hyper-V Security Framework
# For authorized security assessments and compliance checks

param(
    [string]$OutputPath = ".\HyperV-SecurityReport.html",
    [switch]$Detailed,
    [switch]$ExportJson,
    [string]$LogLevel = "INFO"
)

# Initialize logging
function Write-FrameworkLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path ".\hyperv-security-analysis.log" -Value $logEntry
}

# Security Analysis Results Container
$SecurityResults = @{
    HostConfiguration = @{}
    VirtualMachines = @()
    NetworkSecurity = @{}
    StorageSecurity = @{}
    AccessControls = @{}
    ComplianceChecks = @{}
    Recommendations = @()
    Timestamp = Get-Date
}

Write-FrameworkLog "Starting Hyper-V Security Framework"

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-FrameworkLog "This script requires Administrator privileges" "ERROR"
    exit 1
}

# Check if Hyper-V is available
try {
    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
    if ($hyperVFeature.State -ne "Enabled") {
        Write-FrameworkLog "Hyper-V is not enabled on this system" "WARNING"
    }
} catch {
    Write-FrameworkLog "Unable to check Hyper-V status: $($_.Exception.Message)" "ERROR"
}

# Function: Analyze Host Configuration
function Analyze-HostConfiguration {
    Write-FrameworkLog "Analyzing host configuration..."
    
    $hostConfig = @{}
    
    try {
        # System Information
        $computerInfo = Get-ComputerInfo
        $hostConfig.SystemInfo = @{
            ComputerName = $computerInfo.CsName
            Domain = $computerInfo.CsDomain
            OSVersion = $computerInfo.WindowsVersion
            TotalPhysicalMemory = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
            ProcessorCount = $computerInfo.CsProcessors.Count
        }
        
        # Hyper-V Host Settings
        $vmHost = Get-VMHost
        $hostConfig.HyperVSettings = @{
            VirtualHardDiskPath = $vmHost.VirtualHardDiskPath
            VirtualMachinePath = $vmHost.VirtualMachinePath
            MacAddressMinimum = $vmHost.MacAddressMinimum
            MacAddressMaximum = $vmHost.MacAddressMaximum
            MaximumStorageMigrations = $vmHost.MaximumStorageMigrations
            MaximumVirtualMachineMigrations = $vmHost.MaximumVirtualMachineMigrations
            NumaSpanningEnabled = $vmHost.NumaSpanningEnabled
            EnableEnhancedSessionMode = $vmHost.EnableEnhancedSessionMode
        }
        
        # Security Features
        $hostConfig.SecurityFeatures = @{
            SecureBootEnabled = (Get-SecureBootUEFI -Name SetupMode -ea SilentlyContinue) -ne $null
            BitLockerStatus = Get-BitLockerVolume | Where-Object {$_.MountPoint -eq "C:"} | Select-Object -ExpandProperty VolumeStatus
            WindowsDefenderStatus = (Get-MpComputerStatus).AntivirusEnabled
            FirewallStatus = (Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}).Count
        }
        
        # Network Adapters
        $hostConfig.NetworkAdapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
            @{
                Name = $_.Name
                InterfaceDescription = $_.InterfaceDescription
                LinkSpeed = $_.LinkSpeed
                VlanID = $_.VlanID
            }
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing host configuration: $($_.Exception.Message)" "ERROR"
    }
    
    return $hostConfig
}

# Function: Analyze Virtual Machines
function Analyze-VirtualMachines {
    Write-FrameworkLog "Analyzing virtual machines..."
    
    $vmAnalysis = @()
    
    try {
        $vms = Get-VM
        
        foreach ($vm in $vms) {
            $vmInfo = @{
                Name = $vm.Name
                State = $vm.State
                Generation = $vm.Generation
                Version = $vm.Version
                ProcessorCount = $vm.ProcessorCount
                MemoryAssigned = [math]::Round($vm.MemoryAssigned / 1GB, 2)
                DynamicMemoryEnabled = $vm.DynamicMemoryEnabled
                SecureBoot = $vm.SecureBoot
                AutomaticStartAction = $vm.AutomaticStartAction
                AutomaticStopAction = $vm.AutomaticStopAction
                CheckpointType = $vm.CheckpointType
                Path = $vm.Path
                CreationTime = $vm.CreationTime
                
                # Network Configuration
                NetworkAdapters = @()
                
                # Storage Configuration
                HardDrives = @()
                
                # Security Configuration
                SecuritySettings = @{}
                
                # Integration Services
                IntegrationServices = @{}
            }
            
            # Analyze Network Adapters
            $networkAdapters = Get-VMNetworkAdapter -VM $vm
            foreach ($adapter in $networkAdapters) {
                $vmInfo.NetworkAdapters += @{
                    Name = $adapter.Name
                    SwitchName = $adapter.SwitchName
                    MacAddress = $adapter.MacAddress
                    VlanSetting = $adapter.VlanSetting
                    DhcpGuard = $adapter.DhcpGuard
                    RouterGuard = $adapter.RouterGuard
                    PortMirroring = $adapter.PortMirroring
                    IovWeight = $adapter.IovWeight
                }
            }
            
            # Analyze Hard Drives
            $hardDrives = Get-VMHardDiskDrive -VM $vm
            foreach ($drive in $hardDrives) {
                $vmInfo.HardDrives += @{
                    Path = $drive.Path
                    ControllerType = $drive.ControllerType
                    ControllerNumber = $drive.ControllerNumber
                    ControllerLocation = $drive.ControllerLocation
                }
            }
            
            # Security Settings
            try {
                $securityPolicy = Get-VMSecurity -VM $vm -ErrorAction SilentlyContinue
                if ($securityPolicy) {
                    $vmInfo.SecuritySettings = @{
                        EncryptStateAndVmMigrationTraffic = $securityPolicy.EncryptStateAndVmMigrationTraffic
                        VirtualizationBasedSecurityOptOut = $securityPolicy.VirtualizationBasedSecurityOptOut
                        Shielded = $securityPolicy.Shielded
                    }
                }
            } catch {
                Write-FrameworkLog "Could not retrieve security settings for VM $($vm.Name)" "WARNING"
            }
            
            # Integration Services
            $integrationServices = Get-VMIntegrationService -VM $vm
            foreach ($service in $integrationServices) {
                $vmInfo.IntegrationServices[$service.Name] = @{
                    Enabled = $service.Enabled
                    PrimaryStatusDescription = $service.PrimaryStatusDescription
                    SecondaryStatusDescription = $service.SecondaryStatusDescription
                }
            }
            
            $vmAnalysis += $vmInfo
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing virtual machines: $($_.Exception.Message)" "ERROR"
    }
    
    return $vmAnalysis
}

# Function: Analyze Network Security
function Analyze-NetworkSecurity {
    Write-FrameworkLog "Analyzing network security..."
    
    $networkSecurity = @{}
    
    try {
        # Virtual Switches
        $vSwitches = Get-VMSwitch
        $networkSecurity.VirtualSwitches = @()
        
        foreach ($switch in $vSwitches) {
            $switchInfo = @{
                Name = $switch.Name
                SwitchType = $switch.SwitchType
                AllowManagementOS = $switch.AllowManagementOS
                NetAdapterInterfaceDescription = $switch.NetAdapterInterfaceDescription
                Extensions = @()
            }
            
            # Switch Extensions
            $extensions = Get-VMSwitchExtension -VMSwitch $switch
            foreach ($ext in $extensions) {
                $switchInfo.Extensions += @{
                    Name = $ext.Name
                    Vendor = $ext.Vendor
                    Version = $ext.Version
                    Enabled = $ext.Enabled
                }
            }
            
            $networkSecurity.VirtualSwitches += $switchInfo
        }
        
        # Network Security Policies
        $networkSecurity.SecurityPolicies = @()
        
        # Port ACLs
        try {
            $portAcls = Get-VMNetworkAdapterAcl -All -ErrorAction SilentlyContinue
            $networkSecurity.PortACLs = $portAcls | ForEach-Object {
                @{
                    VMName = $_.VMName
                    AdapterName = $_.AdapterName
                    Direction = $_.Direction
                    Action = $_.Action
                    LocalAddress = $_.LocalAddress
                    RemoteAddress = $_.RemoteAddress
                    Protocol = $_.Protocol
                }
            }
        } catch {
            Write-FrameworkLog "Could not retrieve Port ACLs" "WARNING"
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing network security: $($_.Exception.Message)" "ERROR"
    }
    
    return $networkSecurity
}

# Function: Analyze Storage Security
function Analyze-StorageSecurity {
    Write-FrameworkLog "Analyzing storage security..."
    
    $storageSecurity = @{}
    
    try {
        # Virtual Hard Disks
        $vhds = Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Filter "*.vhd*" -Recurse -ErrorAction SilentlyContinue
        $storageSecurity.VirtualHardDisks = @()
        
        foreach ($vhd in $vhds) {
            $vhdInfo = Get-VHD -Path $vhd.FullName -ErrorAction SilentlyContinue
            if ($vhdInfo) {
                $storageSecurity.VirtualHardDisks += @{
                    Path = $vhd.FullName
                    VhdFormat = $vhdInfo.VhdFormat
                    VhdType = $vhdInfo.VhdType
                    FileSize = [math]::Round($vhdInfo.FileSize / 1GB, 2)
                    Size = [math]::Round($vhdInfo.Size / 1GB, 2)
                    MinimumSize = [math]::Round($vhdInfo.MinimumSize / 1GB, 2)
                    LogicalSectorSize = $vhdInfo.LogicalSectorSize
                    PhysicalSectorSize = $vhdInfo.PhysicalSectorSize
                    Attached = $vhdInfo.Attached
                }
            }
        }
        
        # Storage Permissions
        $vmPaths = @((Get-VMHost).VirtualHardDiskPath, (Get-VMHost).VirtualMachinePath)
        $storageSecurity.StoragePermissions = @()
        
        foreach ($path in $vmPaths) {
            if (Test-Path $path) {
                $acl = Get-Acl -Path $path
                $storageSecurity.StoragePermissions += @{
                    Path = $path
                    Owner = $acl.Owner
                    AccessRules = $acl.Access | ForEach-Object {
                        @{
                            IdentityReference = $_.IdentityReference.Value
                            FileSystemRights = $_.FileSystemRights
                            AccessControlType = $_.AccessControlType
                            IsInherited = $_.IsInherited
                        }
                    }
                }
            }
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing storage security: $($_.Exception.Message)" "ERROR"
    }
    
    return $storageSecurity
}

# Function: Analyze Access Controls
function Analyze-AccessControls {
    Write-FrameworkLog "Analyzing access controls..."
    
    $accessControls = @{}
    
    try {
        # Local Users and Groups
        $accessControls.LocalUsers = Get-LocalUser | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                Description = $_.Description
                LastLogon = $_.LastLogon
                PasswordLastSet = $_.PasswordLastSet
                PasswordRequired = $_.PasswordRequired
                UserMayChangePassword = $_.UserMayChangePassword
                PasswordExpires = $_.PasswordExpires
            }
        }
        
        $accessControls.LocalGroups = Get-LocalGroup | ForEach-Object {
            $groupMembers = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
            @{
                Name = $_.Name
                Description = $_.Description
                Members = $groupMembers | ForEach-Object { $_.Name }
            }
        }
        
        # Hyper-V Administrators
        $hypervAdmins = Get-LocalGroupMember -Group "Hyper-V Administrators" -ErrorAction SilentlyContinue
        $accessControls.HyperVAdministrators = $hypervAdmins | ForEach-Object { $_.Name }
        
        # Service Accounts
        $accessControls.ServiceAccounts = Get-WmiObject -Class Win32_Service | Where-Object {
            $_.Name -like "*vm*" -or $_.Name -like "*hyper*"
        } | ForEach-Object {
            @{
                Name = $_.Name
                StartName = $_.StartName
                State = $_.State
                StartMode = $_.StartMode
            }
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing access controls: $($_.Exception.Message)" "ERROR"
    }
    
    return $accessControls
}

# Function: Perform Compliance Checks
function Perform-ComplianceChecks {
    Write-FrameworkLog "Performing compliance checks..."
    
    $complianceChecks = @{
        Passed = @()
        Failed = @()
        Warnings = @()
    }
    
    try {
        # Check 1: Secure Boot for Generation 2 VMs
        $gen2VMs = Get-VM | Where-Object { $_.Generation -eq 2 }
        foreach ($vm in $gen2VMs) {
            if ($vm.SecureBoot -eq "On") {
                $complianceChecks.Passed += "VM '$($vm.Name)' has Secure Boot enabled"
            } else {
                $complianceChecks.Failed += "VM '$($vm.Name)' does not have Secure Boot enabled"
            }
        }
        
        # Check 2: Integration Services
        $vms = Get-VM | Where-Object { $_.State -eq "Running" }
        foreach ($vm in $vms) {
            $integrationServices = Get-VMIntegrationService -VM $vm
            $timeSync = $integrationServices | Where-Object { $_.Name -eq "Time Synchronization" }
            if ($timeSync -and $timeSync.Enabled) {
                $complianceChecks.Passed += "VM '$($vm.Name)' has Time Synchronization enabled"
            } else {
                $complianceChecks.Failed += "VM '$($vm.Name)' does not have Time Synchronization enabled"
            }
        }
        
        # Check 3: Dynamic Memory Configuration
        $vmsWithDynamicMemory = Get-VM | Where-Object { $_.DynamicMemoryEnabled -eq $true }
        foreach ($vm in $vmsWithDynamicMemory) {
            $memorySettings = Get-VMMemory -VM $vm
            if ($memorySettings.Buffer -ge 20) {
                $complianceChecks.Passed += "VM '$($vm.Name)' has appropriate memory buffer (>= 20%)"
            } else {
                $complianceChecks.Warnings += "VM '$($vm.Name)' has low memory buffer (< 20%)"
            }
        }
        
        # Check 4: Checkpoint Configuration
        $vms = Get-VM
        foreach ($vm in $vms) {
            if ($vm.CheckpointType -eq "Production") {
                $complianceChecks.Passed += "VM '$($vm.Name)' uses Production checkpoints"
            } else {
                $complianceChecks.Warnings += "VM '$($vm.Name)' does not use Production checkpoints"
            }
        }
        
        # Check 5: Network Security
        $vmNetworkAdapters = Get-VMNetworkAdapter -All
        foreach ($adapter in $vmNetworkAdapters) {
            if ($adapter.DhcpGuard -eq "On") {
                $complianceChecks.Passed += "Network adapter '$($adapter.Name)' on VM '$($adapter.VMName)' has DHCP Guard enabled"
            } else {
                $complianceChecks.Warnings += "Network adapter '$($adapter.Name)' on VM '$($adapter.VMName)' does not have DHCP Guard enabled"
            }
        }
        
        # Check 6: Storage Path Security
        $vmHost = Get-VMHost
        $vhdPath = $vmHost.VirtualHardDiskPath
        $vmPath = $vmHost.VirtualMachinePath
        
        foreach ($path in @($vhdPath, $vmPath)) {
            if (Test-Path $path) {
                $acl = Get-Acl -Path $path
                $everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference.Value -eq "Everyone" }
                if (-not $everyoneAccess) {
                    $complianceChecks.Passed += "Storage path '$path' does not grant access to Everyone"
                } else {
                    $complianceChecks.Failed += "Storage path '$path' grants access to Everyone"
                }
            }
        }
        
    } catch {
        Write-FrameworkLog "Error performing compliance checks: $($_.Exception.Message)" "ERROR"
    }
    
    return $complianceChecks
}

# Function: Generate Recommendations
function Generate-Recommendations {
    param($analysisResults)
    
    Write-FrameworkLog "Generating security recommendations..."
    
    $recommendations = @()
    
    # Analyze results and generate recommendations
    if ($analysisResults.ComplianceChecks.Failed.Count -gt 0) {
        $recommendations += "Address failed compliance checks: " + ($analysisResults.ComplianceChecks.Failed -join "; ")
    }
    
    if ($analysisResults.ComplianceChecks.Warnings.Count -gt 0) {
        $recommendations += "Review warning items: " + ($analysisResults.ComplianceChecks.Warnings -join "; ")
    }
    
    # Host-specific recommendations
    if (-not $analysisResults.HostConfiguration.SecurityFeatures.SecureBootEnabled) {
        $recommendations += "Enable Secure Boot on the host system"
    }
    
    if ($analysisResults.HostConfiguration.SecurityFeatures.FirewallStatus -lt 3) {
        $recommendations += "Ensure all Windows Firewall profiles are enabled"
    }
    
    # VM-specific recommendations
    $gen1VMs = $analysisResults.VirtualMachines | Where-Object { $_.Generation -eq 1 }
    if ($gen1VMs.Count -gt 0) {
        $recommendations += "Consider upgrading Generation 1 VMs to Generation 2 for enhanced security features"
    }
    
    # Network recommendations
    $externalSwitches = $analysisResults.NetworkSecurity.VirtualSwitches | Where-Object { $_.SwitchType -eq "External" }
    foreach ($switch in $externalSwitches) {
        if ($switch.Extensions.Count -eq 0) {
            $recommendations += "Consider enabling security extensions on external switch '$($switch.Name)'"
        }
    }
    
    # Storage recommendations
    $largeDynamicDisks = $analysisResults.StorageSecurity.VirtualHardDisks | Where-Object { 
        $_.VhdType -eq "Dynamic" -and $_.Size -gt 100 
    }
    if ($largeDynamicDisks.Count -gt 0) {
        $recommendations += "Monitor large dynamic disks for performance and consider converting to fixed disks"
    }
    
    return $recommendations
}

# Function: Generate HTML Report
function Generate-HTMLReport {
    param($results, $outputPath)
    
    Write-FrameworkLog "Generating HTML report..."
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Hyper-V Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .passed { color: green; }
        .failed { color: red; }
        .warning { color: orange; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background-color: #ecf0f1; }
        .recommendation { background-color: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Hyper-V Security Analysis Report</h1>
        <p>Generated on: $($results.Timestamp)</p>
    </div>

    <div class="section summary">
        <h2>Executive Summary</h2>
        <p><strong>Total VMs Analyzed:</strong> $($results.VirtualMachines.Count)</p>
        <p><strong>Compliance Checks Passed:</strong> <span class="passed">$($results.ComplianceChecks.Passed.Count)</span></p>
        <p><strong>Compliance Checks Failed:</strong> <span class="failed">$($results.ComplianceChecks.Failed.Count)</span></p>
        <p><strong>Warnings:</strong> <span class="warning">$($results.ComplianceChecks.Warnings.Count)</span></p>
        <p><strong>Total Recommendations:</strong> $($results.Recommendations.Count)</p>
    </div>

    <div class="section">
        <h2>Host Configuration</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Computer Name</td><td>$($results.HostConfiguration.SystemInfo.ComputerName)</td></tr>
            <tr><td>OS Version</td><td>$($results.HostConfiguration.SystemInfo.OSVersion)</td></tr>
            <tr><td>Total Physical Memory (GB)</td><td>$($results.HostConfiguration.SystemInfo.TotalPhysicalMemory)</td></tr>
            <tr><td>Processor Count</td><td>$($results.HostConfiguration.SystemInfo.ProcessorCount)</td></tr>
            <tr><td>Secure Boot Enabled</td><td>$($results.HostConfiguration.SecurityFeatures.SecureBootEnabled)</td></tr>
            <tr><td>Windows Defender Status</td><td>$($results.HostConfiguration.SecurityFeatures.WindowsDefenderStatus)</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Virtual Machines</h2>
        <table>
            <tr><th>Name</th><th>State</th><th>Generation</th><th>Memory (GB)</th><th>Secure Boot</th><th>Integration Services</th></tr>
"@

    foreach ($vm in $results.VirtualMachines) {
        $integrationServicesStatus = if ($vm.IntegrationServices.Count -gt 0) { "Enabled" } else { "Unknown" }
        $html += "<tr><td>$($vm.Name)</td><td>$($vm.State)</td><td>$($vm.Generation)</td><td>$($vm.MemoryAssigned)</td><td>$($vm.SecureBoot)</td><td>$integrationServicesStatus</td></tr>`n"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Compliance Check Results</h2>
        <h3 class="passed">Passed Checks ($($results.ComplianceChecks.Passed.Count))</h3>
        <ul>
"@

    foreach ($check in $results.ComplianceChecks.Passed) {
        $html += "<li class='passed'>$check</li>`n"
    }

    $html += @"
        </ul>
        <h3 class="failed">Failed Checks ($($results.ComplianceChecks.Failed.Count))</h3>
        <ul>
"@

    foreach ($check in $results.ComplianceChecks.Failed) {
        $html += "<li class='failed'>$check</li>`n"
    }

    $html += @"
        </ul>
        <h3 class="warning">Warnings ($($results.ComplianceChecks.Warnings.Count))</h3>
        <ul>
"@

    foreach ($check in $results.ComplianceChecks.Warnings) {
        $html += "<li class='warning'>$check</li>`n"
    }

    $html += @"
        </ul>
    </div>

    <div class="section">
        <h2>Security Recommendations</h2>
"@

    foreach ($recommendation in $results.Recommendations) {
        $html += "<div class='recommendation'>$recommendation</div>`n"
    }

    $html += @"
    </div>

    <div class="section">
        <h2>Network Security</h2>
        <h3>Virtual Switches</h3>
        <table>
            <tr><th>Name</th><th>Type</th><th>Management OS</th><th>Extensions</th></tr>
"@

    foreach ($switch in $results.NetworkSecurity.VirtualSwitches) {
        $extensionCount = $switch.Extensions.Count
        $html += "<tr><td>$($switch.Name)</td><td>$($switch.SwitchType)</td><td>$($switch.AllowManagementOS)</td><td>$extensionCount extensions</td></tr>`n"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Storage Security</h2>
        <p><strong>Total Virtual Hard Disks:</strong> $($results.StorageSecurity.VirtualHardDisks.Count)</p>
        <table>
            <tr><th>Path</th><th>Format</th><th>Type</th><th>Size (GB)</th><th>Attached</th></tr>
"@

    foreach ($vhd in $results.StorageSecurity.VirtualHardDisks | Select-Object -First 10) {
        $html += "<tr><td>$($vhd.Path)</td><td>$($vhd.VhdFormat)</td><td>$($vhd.VhdType)</td><td>$($vhd.Size)</td><td>$($vhd.Attached)</td></tr>`n"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Access Controls</h2>
        <h3>Hyper-V Administrators</h3>
        <ul>
"@

    foreach ($admin in $results.AccessControls.HyperVAdministrators) {
        $html += "<li>$admin</li>`n"
    }

    $html += @"
        </ul>
    </div>

    <footer style="margin-top: 50px; text-align: center; color: #666;">
        <p>Report generated by Hyper-V Security Framework</p>
    </footer>

</body>
</html>
"@

    $html | Out-File -FilePath $outputPath -Encoding UTF8
    Write-FrameworkLog "HTML report saved to: $outputPath"
}

# Main Analysis Execution
try {
    Write-FrameworkLog "Starting comprehensive security analysis..."
    
    # Perform all analyses
    $SecurityResults.HostConfiguration = Analyze-HostConfiguration
    $SecurityResults.VirtualMachines = Analyze-VirtualMachines
    $SecurityResults.NetworkSecurity = Analyze-NetworkSecurity
    $SecurityResults.StorageSecurity = Analyze-StorageSecurity
    $SecurityResults.AccessControls = Analyze-AccessControls
    $SecurityResults.ComplianceChecks = Perform-ComplianceChecks
    $SecurityResults.Recommendations = Generate-Recommendations -analysisResults $SecurityResults
    
    # Generate Reports
    Generate-HTMLReport -results $SecurityResults -outputPath $OutputPath
    
    if ($ExportJson) {
        $jsonPath = $OutputPath -replace "\.html$", ".json"
        $SecurityResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-FrameworkLog "JSON report saved to: $jsonPath"
    }
    
    Write-FrameworkLog "Security analysis completed successfully"
    Write-Host "`nSUMMARY:" -ForegroundColor Green
    Write-Host "- Total VMs Analyzed: $($SecurityResults.VirtualMachines.Count)"
    Write-Host "- Compliance Checks Passed: $($SecurityResults.ComplianceChecks.Passed.Count)" -ForegroundColor Green
    Write-Host "- Compliance Checks Failed: $($SecurityResults.ComplianceChecks.Failed.Count)" -ForegroundColor Red
    Write-Host "- Warnings: $($SecurityResults.ComplianceChecks.Warnings.Count)" -ForegroundColor Yellow
    Write-Host "- Recommendations: $($SecurityResults.Recommendations.Count)"
    Write-Host "`nDetailed report saved to: $OutputPath" -ForegroundColor Cyan
    
} catch {
    Write-FrameworkLog "Critical error during analysis: $($_.Exception.Message)" "ERROR"
    Write-Host "Analysis failed. Check the log file for details." -ForegroundColor Red
    exit 1
}

# Additional Security Analysis Functions

# Function: Analyze VM Snapshots/Checkpoints
function Analyze-VMSnapshots {
    Write-FrameworkLog "Analyzing VM snapshots and checkpoints..."
    
    $snapshotAnalysis = @()
    
    try {
        $vms = Get-VM
        foreach ($vm in $vms) {
            $snapshots = Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue
            if ($snapshots) {
                foreach ($snapshot in $snapshots) {
                    $snapshotAnalysis += @{
                        VMName = $vm.Name
                        SnapshotName = $snapshot.Name
                        SnapshotType = $snapshot.SnapshotType
                        CreationTime = $snapshot.CreationTime
                        SizeGB = if ($snapshot.SizeBytes) { [math]::Round($snapshot.SizeBytes / 1GB, 2) } else { 0 }
                        ParentSnapshotName = $snapshot.ParentSnapshotName
                        Path = $snapshot.Path
                    }
                }
            }
        }
    } catch {
        Write-FrameworkLog "Error analyzing VM snapshots: $($_.Exception.Message)" "ERROR"
    }
    
    return $snapshotAnalysis
}

# Function: Analyze Resource Pools
function Analyze-ResourcePools {
    Write-FrameworkLog "Analyzing resource pools..."
    
    $resourcePools = @{
        ProcessorPools = @()
        MemoryPools = @()
        EthernetPools = @()
        FibreChannelPools = @()
    }
    
    try {
        # Processor Resource Pools
        $processorPools = Get-VMResourcePool -ResourcePoolType Processor -ErrorAction SilentlyContinue
        if ($processorPools) {
            foreach ($pool in $processorPools) {
                $resourcePools.ProcessorPools += @{
                    Name = $pool.Name
                    ResourcePoolType = $pool.ResourcePoolType
                    Primordial = $pool.Primordial
                    AllocationPolicy = $pool.AllocationPolicy
                    ResourceMeterScope = $pool.ResourceMeterScope
                }
            }
        }
        
        # Memory Resource Pools
        $memoryPools = Get-VMResourcePool -ResourcePoolType Memory -ErrorAction SilentlyContinue
        if ($memoryPools) {
            foreach ($pool in $memoryPools) {
                $resourcePools.MemoryPools += @{
                    Name = $pool.Name
                    ResourcePoolType = $pool.ResourcePoolType
                    Primordial = $pool.Primordial
                    AllocationPolicy = $pool.AllocationPolicy
                    ResourceMeterScope = $pool.ResourceMeterScope
                }
            }
        }
        
        # Ethernet Resource Pools
        $ethernetPools = Get-VMResourcePool -ResourcePoolType Ethernet -ErrorAction SilentlyContinue
        if ($ethernetPools) {
            foreach ($pool in $ethernetPools) {
                $resourcePools.EthernetPools += @{
                    Name = $pool.Name
                    ResourcePoolType = $pool.ResourcePoolType
                    Primordial = $pool.Primordial
                    AllocationPolicy = $pool.AllocationPolicy
                    ResourceMeterScope = $pool.ResourceMeterScope
                }
            }
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing resource pools: $($_.Exception.Message)" "ERROR"
    }
    
    return $resourcePools
}

# Function: Analyze Event Logs
function Analyze-EventLogs {
    Write-FrameworkLog "Analyzing Hyper-V event logs..."
    
    $eventAnalysis = @{
        CriticalEvents = @()
        ErrorEvents = @()
        WarningEvents = @()
        RecentEvents = @()
        EventCounts = @{
            Critical = 0
            Error = 0
            Warning = 0
            Information = 0
        }
    }
    
    try {
        # Define time range (last 7 days)
        $startTime = (Get-Date).AddDays(-7)
        
        # Hyper-V related event logs
        $logNames = @(
            "Microsoft-Windows-Hyper-V-VMMS-Admin",
            "Microsoft-Windows-Hyper-V-Worker-Admin",
            "Microsoft-Windows-Hyper-V-VmSwitch-Operational",
            "Microsoft-Windows-Hyper-V-Integration-Admin"
        )
        
        foreach ($logName in $logNames) {
            try {
                $events = Get-WinEvent -LogName $logName -StartTime $startTime -ErrorAction SilentlyContinue | 
                          Select-Object -First 100
                
                if ($events) {
                    foreach ($event in $events) {
                        $eventInfo = @{
                            LogName = $event.LogName
                            Id = $event.Id
                            LevelDisplayName = $event.LevelDisplayName
                            TimeCreated = $event.TimeCreated
                            Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                            MachineName = $event.MachineName
                        }
                        
                        switch ($event.LevelDisplayName) {
                            "Critical" {
                                $eventAnalysis.CriticalEvents += $eventInfo
                                $eventAnalysis.EventCounts.Critical++
                            }
                            "Error" {
                                $eventAnalysis.ErrorEvents += $eventInfo
                                $eventAnalysis.EventCounts.Error++
                            }
                            "Warning" {
                                $eventAnalysis.WarningEvents += $eventInfo
                                $eventAnalysis.EventCounts.Warning++
                            }
                            "Information" {
                                $eventAnalysis.EventCounts.Information++
                            }
                        }
                        
                        $eventAnalysis.RecentEvents += $eventInfo
                    }
                }
            } catch {
                Write-FrameworkLog "Could not access log: $logName" "WARNING"
            }
        }
        
        # Sort events by time (most recent first)
        $eventAnalysis.RecentEvents = $eventAnalysis.RecentEvents | Sort-Object TimeCreated -Descending
        $eventAnalysis.CriticalEvents = $eventAnalysis.CriticalEvents | Sort-Object TimeCreated -Descending
        $eventAnalysis.ErrorEvents = $eventAnalysis.ErrorEvents | Sort-Object TimeCreated -Descending
        $eventAnalysis.WarningEvents = $eventAnalysis.WarningEvents | Sort-Object TimeCreated -Descending
        
    } catch {
        Write-FrameworkLog "Error analyzing event logs: $($_.Exception.Message)" "ERROR"
    }
    
    return $eventAnalysis
}

# Function: Analyze Performance Counters
function Analyze-PerformanceCounters {
    Write-FrameworkLog "Analyzing Hyper-V performance counters..."
    
    $perfAnalysis = @{
        HostCounters = @{}
        VMCounters = @()
        Timestamp = Get-Date
    }
    
    try {
        # Host-level performance counters
        $hostCounters = @(
            "\Hyper-V Hypervisor\Virtual Processors",
            "\Hyper-V Hypervisor\Logical Processors",
            "\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time",
            "\Hyper-V Hypervisor Root Virtual Processor(_Total)\% Total Run Time",
            "\Memory\Available MBytes",
            "\Memory\Committed Bytes",
            "\Processor(_Total)\% Processor Time"
        )
        
        foreach ($counter in $hostCounters) {
            try {
                $value = (Get-Counter -Counter $counter -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples.CookedValue
                $counterName = $counter.Split('\')[-1]
                $perfAnalysis.HostCounters[$counterName] = $value
            } catch {
                Write-FrameworkLog "Could not retrieve counter: $counter" "WARNING"
            }
        }
        
        # VM-specific performance counters
        $vms = Get-VM | Where-Object { $_.State -eq "Running" }
        foreach ($vm in $vms) {
            $vmCounters = @{
                VMName = $vm.Name
                ProcessorUtilization = $null
                MemoryUtilization = $null
                NetworkBytesReceived = $null
                NetworkBytesSent = $null
            }
            
            try {
                # VM Processor utilization
                $processorCounter = "\Hyper-V Hypervisor Virtual Processor($($vm.Name):Hv VP 0)\% Total Run Time"
                $vmCounters.ProcessorUtilization = (Get-Counter -Counter $processorCounter -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples.CookedValue
                
                # VM Memory utilization
                $memoryCounter = "\Hyper-V Dynamic Memory VM($($vm.Name))\Physical Memory"
                $vmCounters.MemoryUtilization = (Get-Counter -Counter $memoryCounter -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples.CookedValue
                
            } catch {
                Write-FrameworkLog "Could not retrieve performance counters for VM: $($vm.Name)" "WARNING"
            }
            
            $perfAnalysis.VMCounters += $vmCounters
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing performance counters: $($_.Exception.Message)" "ERROR"
    }
    
    return $perfAnalysis
}

# Function: Analyze Replication Status
function Analyze-ReplicationStatus {
    Write-FrameworkLog "Analyzing Hyper-V Replica status..."
    
    $replicationAnalysis = @{
        ReplicaServers = @()
        ReplicatedVMs = @()
        ReplicationHealth = @()
    }
    
    try {
        # Check if Hyper-V Replica is configured
        $replicaConfig = Get-VMReplicationServer -ErrorAction SilentlyContinue
        if ($replicaConfig) {
            $replicationAnalysis.ReplicaServers += @{
                ReplicationEnabled = $replicaConfig.ReplicationEnabled
                AllowedAuthenticationType = $replicaConfig.AllowedAuthenticationType
                DefaultStorageLocation = $replicaConfig.DefaultStorageLocation
                ReplicationAllowedFromAnyServer = $replicaConfig.ReplicationAllowedFromAnyServer
                CertificateThumbprint = $replicaConfig.CertificateThumbprint
            }
        }
        
        # Get replication status for VMs
        $vms = Get-VM
        foreach ($vm in $vms) {
            try {
                $replicationStatus = Get-VMReplication -VMName $vm.Name -ErrorAction SilentlyContinue
                if ($replicationStatus) {
                    $replicationAnalysis.ReplicatedVMs += @{
                        VMName = $vm.Name
                        State = $replicationStatus.State
                        Mode = $replicationStatus.Mode
                        FrequencySec = $replicationStatus.FrequencySec
                        PrimaryServer = $replicationStatus.PrimaryServer
                        ReplicaServer = $replicationStatus.ReplicaServer
                        ReplicaServerPort = $replicationStatus.ReplicaServerPort
                        AuthenticationType = $replicationStatus.AuthenticationType
                        Health = $replicationStatus.Health
                        LastReplicationTime = $replicationStatus.LastReplicationTime
                    }
                }
            } catch {
                # VM is not replicated, skip
            }
        }
        
        # Get replication health
        try {
            $replicationHealth = Measure-VMReplication -ErrorAction SilentlyContinue
            if ($replicationHealth) {
                foreach ($health in $replicationHealth) {
                    $replicationAnalysis.ReplicationHealth += @{
                        VMName = $health.VMName
                        Health = $health.Health
                        LagTime = $health.LagTime
                        LastReplicationTime = $health.LastReplicationTime
                        ReplicationSize = $health.ReplicationSize
                        ReplicationCount = $health.ReplicationCount
                    }
                }
            }
        } catch {
            Write-FrameworkLog "Could not retrieve replication health metrics" "WARNING"
        }
        
    } catch {
        Write-FrameworkLog "Error analyzing replication status: $($_.Exception.Message)" "ERROR"
    }
    
    return $replicationAnalysis
}

# Function: Generate Executive Summary
function Generate-ExecutiveSummary {
    param($results)
    
    $summary = @{
        OverallSecurityScore = 0
        CriticalFindings = @()
        KeyMetrics = @{}
        ActionItems = @()
        ComplianceStatus = ""
    }
    
    try {
        # Calculate overall security score (0-100)
        $totalChecks = $results.ComplianceChecks.Passed.Count + $results.ComplianceChecks.Failed.Count
        if ($totalChecks -gt 0) {
            $summary.OverallSecurityScore = [math]::Round(($results.ComplianceChecks.Passed.Count / $totalChecks) * 100, 1)
        }
        
        # Determine compliance status
        if ($summary.OverallSecurityScore -ge 90) {
            $summary.ComplianceStatus = "Excellent"
        } elseif ($summary.OverallSecurityScore -ge 80) {
            $summary.ComplianceStatus = "Good"
        } elseif ($summary.OverallSecurityScore -ge 70) {
            $summary.ComplianceStatus = "Fair"
        } else {
            $summary.ComplianceStatus = "Poor"
        }
        
        # Key metrics
        $summary.KeyMetrics = @{
            TotalVMs = $results.VirtualMachines.Count
            RunningVMs = ($results.VirtualMachines | Where-Object { $_.State -eq "Running" }).Count
            Gen2VMs = ($results.VirtualMachines | Where-Object { $_.Generation -eq 2 }).Count
            SecureBootEnabled = ($results.VirtualMachines | Where-Object { $_.SecureBoot -eq "On" }).Count
            VirtualSwitches = $results.NetworkSecurity.VirtualSwitches.Count
            TotalVHDs = $results.StorageSecurity.VirtualHardDisks.Count
            CriticalEvents = if ($results.EventLogs) { $results.EventLogs.EventCounts.Critical } else { 0 }
            ErrorEvents = if ($results.EventLogs) { $results.EventLogs.EventCounts.Error } else { 0 }
        }
        
        # Critical findings
        if ($results.ComplianceChecks.Failed.Count -gt 0) {
            $summary.CriticalFindings += "Failed compliance checks require immediate attention"
        }
        
        if ($summary.KeyMetrics.CriticalEvents -gt 0) {
            $summary.CriticalFindings += "Critical events detected in Hyper-V logs"
        }
        
        $gen1VMCount = $results.VirtualMachines.Count - $summary.KeyMetrics.Gen2VMs
        if ($gen1VMCount -gt 0) {
            $summary.CriticalFindings += "$gen1VMCount Generation 1 VMs detected (security limitations)"
        }
        
        # Action items (top 5 priorities)
        $summary.ActionItems = $results.Recommendations | Select-Object -First 5
        
    } catch {
        Write-FrameworkLog "Error generating executive summary: $($_.Exception.Message)" "ERROR"
    }
    
    return $summary
}

# Enhanced Main Execution with Additional Analyses
Write-FrameworkLog "Performing extended security analysis..."

# Add new analyses to results
$SecurityResults.VMSnapshots = Analyze-VMSnapshots
$SecurityResults.ResourcePools = Analyze-ResourcePools
$SecurityResults.EventLogs = Analyze-EventLogs
$SecurityResults.PerformanceCounters = Analyze-PerformanceCounters
$SecurityResults.ReplicationStatus = Analyze-ReplicationStatus
$SecurityResults.ExecutiveSummary = Generate-ExecutiveSummary -results $SecurityResults

Write-FrameworkLog "Extended security analysis completed successfully"

# Enhanced Summary Output
Write-Host "`n=== HYPER-V SECURITY ANALYSIS SUMMARY ===" -ForegroundColor Cyan
Write-Host "Overall Security Score: $($SecurityResults.ExecutiveSummary.OverallSecurityScore)% ($($SecurityResults.ExecutiveSummary.ComplianceStatus))" -ForegroundColor $(
    switch ($SecurityResults.ExecutiveSummary.ComplianceStatus) {
        "Excellent" { "Green" }
        "Good" { "Yellow" }
        "Fair" { "DarkYellow" }
        "Poor" { "Red" }
    }
)

Write-Host "`nKey Metrics:" -ForegroundColor White
Write-Host "  Total VMs: $($SecurityResults.ExecutiveSummary.KeyMetrics.TotalVMs)"
Write-Host "  Running VMs: $($SecurityResults.ExecutiveSummary.KeyMetrics.RunningVMs)"
Write-Host "  Generation 2 VMs: $($SecurityResults.ExecutiveSummary.KeyMetrics.Gen2VMs)"
Write-Host "  Secure Boot Enabled: $($SecurityResults.ExecutiveSummary.KeyMetrics.SecureBootEnabled)"
Write-Host "  Virtual Switches: $($SecurityResults.ExecutiveSummary.KeyMetrics.VirtualSwitches)"
Write-Host "  Total VHDs: $($SecurityResults.ExecutiveSummary.KeyMetrics.TotalVHDs)"

if ($SecurityResults.ExecutiveSummary.CriticalFindings.Count -gt 0) {
    Write-Host "`nCritical Findings:" -ForegroundColor Red
    foreach ($finding in $SecurityResults.ExecutiveSummary.CriticalFindings) {
        Write-Host "  ⚠️  $finding" -ForegroundColor Red
    }
}

Write-Host "`nCompliance Status:" -ForegroundColor White
Write-Host "  ✅ Passed: $($SecurityResults.ComplianceChecks.Passed.Count)" -ForegroundColor Green
Write-Host "  ❌ Failed: $($SecurityResults.ComplianceChecks.Failed.Count)" -ForegroundColor Red  
Write-Host "  ⚠️  Warnings: $($SecurityResults.ComplianceChecks.Warnings.Count)" -ForegroundColor Yellow

Write-Host "`nTop Action Items:" -ForegroundColor White
for ($i = 0; $i -lt [Math]::Min(3, $SecurityResults.ExecutiveSummary.ActionItems.Count); $i++) {
    Write-Host "  $($i + 1). $($SecurityResults.ExecutiveSummary.ActionItems[$i])" -ForegroundColor Yellow
}

Write-Host "`n📄 Detailed report: $OutputPath" -ForegroundColor Cyan
Write-Host "Log file: .\hyperv-security-analysis.log" -ForegroundColor Gray