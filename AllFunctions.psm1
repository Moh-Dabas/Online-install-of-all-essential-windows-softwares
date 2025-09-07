# All functions Module

Function Check-RunAsAdministrator()
{
    #Get current user context
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    #Check user is running the script is member of Administrator Group
    if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {Write-Host -F Green "`r`n*** Script is running with Administrator privileges ***`r`n"}
    else
    {
        #Create a new Elevated process to Start PowerShell
        $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
        # Specify the current script path and name as a parameter
        $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
        #Set the Process to elevated
        $ElevatedProcess.Verb = "runas"
        #Start the new elevated process
        [System.Diagnostics.Process]::Start($ElevatedProcess)
        #Exit from the current, unelevated, process
        Exit
    }
}

Function Check-RunAsAdministrator2()
{
    # Check for admin rights
    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Relaunch as admin
        $scriptPath = $MyInvocation.MyCommand.Path
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $psi.Verb = "runas"
        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
        } catch {
            Write-Host "User cancelled the UAC prompt or an error occurred."
        }
        exit
    }
}

Function Relaunch
{
    $CurFolder = Split-Path -Path $PSCommandPath -Parent
    $runningCMD = Get-Process | where -Property ProcessName -eq "cmd"
    Start-Process "$CurFolder\Install All.bat" -Verb RunAs
    $runningCMD | Stop-Process
    Exit
}

Function AddRegEntry
{
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$Name,
    [Parameter(Mandatory=$true, Position=2)]
    [string]$Value,
    [Parameter(Mandatory=$false, Position=3)]
    [string]$Type = 'DWord'
    )
    try
    {
        if(!(Test-Path -LiteralPath $Path -ea SilentlyContinue)) {New-Item $Path -force -ea SilentlyContinue | out-null}
        if(Test-Path -LiteralPath $Path -ea SilentlyContinue) {New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ea SilentlyContinue | out-null}
        if(Test-Path -LiteralPath $Path -ea SilentlyContinue) {Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Force -ea SilentlyContinue | out-null}
    }
    catch
    {
        try # Second Method
        {
            $Path = $Path.replace(':','') 
            switch ($Type)
            {
                DWord {$typeCMD = "REG_DWORD"};Qword {$typeCMD = "REG_QWORD"};Binary {$typeCMD = "REG_BINARY"};
                String {$typeCMD = "REG_SZ"};ExpandString {$typeCMD = "REG_EXPAND_SZ"};MultiString {$typeCMD = "REG_MULTI_SZ"}
            }
            if ($typeCMD -ne $null) {Reg Add $Path /v $Name /t $typeCMD /d $Value /f | out-null}
            else {Write-Host -f red "Unsupported type"}
        }
        catch
        {
            Write-Host -f red "Error: " + $Error # Might need takeown or runing as system or trusted installer
        }
    }
}

Function Remove-AppxApp {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName
    )

    Write-Host "Checking for AppxPackage matching '$AppName'..." -ForegroundColor Yellow

    $matchedPackages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$AppName*" }

    if (-not $matchedPackages) {
        Write-Warning "No installed AppxPackage found matching '*$AppName*'. Nothing to remove."
        return
    }

    Write-Host "Removing AppxPackage for Current User..." -ForegroundColor Yellow

    $matchedPackages | ForEach-Object {
        $pkgFullName = $_.PackageFullName
        Write-Host "Removing package: $pkgFullName" -ForegroundColor Cyan

        Remove-AppxPackage -Package $pkgFullName -ErrorAction SilentlyContinue

        # Wait until the package is fully removed with timeout
        $maxWaitSeconds = 60
        $waited = 0

        while ($waited -lt $maxWaitSeconds) {
            $exists = Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -eq $pkgFullName }
            if (-not $exists) { break }
            Start-Sleep -Seconds 1
            $waited++
        }

        # Final check to confirm removal
        $finalCheck = Get-AppxPackage | Where-Object { $_.PackageFullName -eq $pkgFullName }

        if ("" -ne $finalCheck) {
            Write-Warning "Package $pkgFullName still exists after timeout"
        } else {
            Write-Host "Package $pkgFullName removed successfully" -ForegroundColor Green
        }
    }

    Write-Host "Removing AppxProvisionedPackage (from system image for new users)..." -ForegroundColor Yellow

    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$AppName*" } | ForEach-Object {
        Write-Host "Removing provisioned package: $($_.PackageName)" -ForegroundColor Cyan
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
    }

    Write-Host "Operation completed." -ForegroundColor Green
}

Function Repeatiwr
{
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Uri
    )
    for ($i = 1; $i -le 20; $i++)
    {
        try
        {
            $Response = Invoke-WebRequest -UseBasicParsing -Uri $Uri
            # This will only execute if the Invoke-WebRequest is successful.
            $StatusCode = $Response.StatusCode
        }
        catch
        {
            # Write-Host -f C "StatusCode:" $_.Exception.Response.StatusCode.value__
            # Write-Host -f C "StatusDescription:" $_.Exception.Response.StatusDescription
            $StatusCode = $_.Exception.Response.StatusCode.value__
        }
        if ($StatusCode -eq "200") {break}
    }
    return $Response
}

Function AdminTakeownership
{
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path
    )
    if (Test-Path -Path $Path -PathType Leaf -ea SilentlyContinue)
    {
        takeown /a /f $Path
        icacls $Path /t /c /grant "administrators:F"
    }
    elseif (Test-Path -Path $Path -PathType Container -ea SilentlyContinue)
    {
        takeown /a /r /d y /f $Path
        icacls $Path /t /c /grant "administrators:F"
    }
    else {Write-Host -f red "Path is wrong or not supported"}
}

function Check-Internet {
    $connected = $false
    for ($i = 0; $i -lt 50; $i++) {
        $ping = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            $connected = $true
            break
        }
        Start-Sleep -Seconds 1
    }

    if ($connected) {
        Write-Output "Internet connection detected."
    } else {
        Write-Output "No internet connection"
    }
}

Function Fix-InternetConnection {
    ipconfig /release
    ipconfig /flushdns
    Clear-DnsClientCache
    ipconfig /renew
    netsh int ip reset
    netsh winsock reset
    arp -d *
    netsh interface ip delete arpcache
    # Get-NetAdapter | foreach {Restart-NetAdapter -Name $_.Name}
}

Function WifiPriority {
    Fix-InternetConnection
    $wifiInterfaces = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and
        $_.Name -match '(?i)wi' -and
        $_.Name -match '(?i)fi'
    }

    if (-not $wifiInterfaces) {
        Write-Output "No active Wi-Fi adapter found."
        return
    }

    $interfaceAlias = $wifiInterfaces | Select-Object -ExpandProperty Name -First 1

    $savedProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }

    if (-not $savedProfiles) {
        Write-Output "No saved Wi-Fi profiles found."
        return
    }

    # Check if currently connected SSID is already 5GHz
    $currentSSID = netsh wlan show interfaces |
        Select-String '^\s*SSID\s*:\s*(.+)$' |
        ForEach-Object { ($_ -split ":\s*", 2)[1].Trim() } |
        Select-Object -First 1

    $currentBand = netsh wlan show interfaces |
        Select-String '^\s*Radio type\s*:\s*(.+)$' |
        ForEach-Object { ($_ -split ":\s*", 2)[1].Trim() } |
        Select-Object -First 1

    if ($currentSSID -and $currentBand -match '5') {
        Write-Output "Already connected to 5GHz network: $currentSSID"

        $fiveGhzProfiles = $savedProfiles | Where-Object { $_ -eq $currentSSID }

        if ($fiveGhzProfiles) {
            $priority = 1
            foreach ($profile in $fiveGhzProfiles) {
                netsh wlan set profileorder name="$profile" interface="$interfaceAlias" priority=$priority | Out-Null
                netsh wlan set profileparameter name="$profile" connectionmode=auto | Out-Null
                $priority++
            }
            Write-Output "Prioritized: $currentSSID"
        }

        Check-Internet
        return
    }

    Write-Host "Restarting WiFi interfaces & WLAN AutoConfig service (wlansvc)..."
    $wifiInterfaces | foreach {Restart-NetAdapter -Name $_.Name}
    Restart-Service -Name wlansvc -Force

    # Wait until the service status is 'Running'
    do {
        Start-Sleep -Seconds 1
        $status = (Get-Service wlansvc).Status
        Write-Host "Waiting for wlansvc to start... (Current: $status)"
    } while ($status -ne 'Running')

    Start-Sleep -Seconds 5
    Write-Host "wlansvc is running. Proceeding with network scan..."

    try {
        $wlanClient = New-Object -ComObject "Wlan.WlanClient"
        foreach ($iface in $wlanClient.Interfaces) {
            Write-Host "Triggering scan on interface: $($iface.InterfaceDescription)"
            $iface.Scan()
        }
        Start-Sleep -Seconds 1
        $scanResults = netsh wlan show networks mode=bssid
        $ssidCount = ($scanResults | Select-String -Pattern '^SSID\s+\d+\s*:').Count
        if ($ssidCount -lt 2) { Start-Sleep -Seconds 4 }
    } catch {
        Write-Warning "Failed to trigger Wi-Fi scan: $_"
    }

    $scanResults = netsh wlan show networks mode=bssid

    $ssidCount = ($scanResults | Select-String -Pattern '^SSID\s+\d+\s*:').Count
    if ($ssidCount -lt 2) {
        Write-Host "Silent scan detected only $ssidCount SSID(s). Triggering visual Wi-Fi scan UI..."
        Start-Process explorer.exe "ms-availablenetworks:"
        Start-Sleep -Seconds 5
        $scanResults = netsh wlan show networks mode=bssid
    }

    $fiveGhzSSIDs = @()
    $ssid = ""

    foreach ($line in $scanResults) {
        if ($line -match "^\s*SSID\s+\d+\s*:\s*(.+)$") {
            $ssid = $Matches[1].Trim()
        } elseif ($line -match "^\s*Band\s*:\s*5 GHz") {
            if ($ssid -and -not ($fiveGhzSSIDs -contains $ssid)) {
                $fiveGhzSSIDs += $ssid
            }
        }
    }

    if (-not $fiveGhzSSIDs) {
        Write-Output "No 5GHz networks found."
        return
    }

    $fiveGhzProfiles = $savedProfiles | Where-Object { $fiveGhzSSIDs -contains $_ }

    if (-not $fiveGhzProfiles) {
        Write-Output "No matching saved 5GHz profiles found."
        return
    }

    $priority = 1
    foreach ($profile in $fiveGhzProfiles) {
        netsh wlan set profileorder name="$profile" interface="$interfaceAlias" priority=$priority | Out-Null
        netsh wlan set profileparameter name="$profile" connectionmode=auto | Out-Null
        $priority++
    }

    $profileLines = netsh wlan show profiles interface="$interfaceAlias" | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }

    if (-not $profileLines) {
        Write-Output "Failed to read profile list after update."
        return
    }

    $topProfile = $profileLines[0]
    netsh wlan connect name="$topProfile" interface="$interfaceAlias" | Out-Null
    Write-Output "Prioritized: $topProfile"

    Check-Internet
}

Function Invoke-W32TimeResync {
    param(
        [int]$MaxRetries = 60,
        [int]$DelaySeconds = 1
    )
    
    # Ensure required registry settings
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type' 'NTP' 'String' # Autoupdate time
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'Allow' 'String' # Allow location
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' 'Start' '3' 'DWord' # Autoupdate timezone

    # Start services if not running
    Start-Service -Name "W32Time" -ErrorAction SilentlyContinue | Out-Null
    Start-Service -Name "tzautoupdate" -ErrorAction SilentlyContinue | Out-Null

    $success = $false

    for ($attempt = 1; $attempt -le $MaxRetries -and -not $success; $attempt++) {
        Write-Host "Attempt $attempt of ${MaxRetries}: Running w32tm /resync to sync time"

        # Run and capture both output & exit code
        $output = & w32tm /resync 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -and $output -match "completed successfully") {
            Write-Host "Sync time success on attempt $attempt."
            $success = $true
        }
        else {
            Write-Warning "Failed on attempt $attempt. ExitCode=$exitCode. Output: $output"
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    if (-not $success) {
        Write-Error "All $MaxRetries attempts to sync time failed. Moving on..."
    }

    return $success
}

Function InitializeCommands
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Initializing *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    Set-ExecutionPolicy Bypass -Force -ea SilentlyContinue | out-null
    $ErrorActionPreference = 'SilentlyContinue'
    $progressPreference = 'SilentlyContinue'
    $ConfirmPreference = 'None'
    #UAC
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ValidateAdminCodeSignatures' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' '0' 'DWord'
    #Tls all
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
    New-Item -Path "$env:TEMP\IA" -ItemType Directory -ea SilentlyContinue | out-null
    Write-Host -f C "`r`n*** Disabling proxies ***`r`n"
    Set HTTP_PROXY=
    Set HTTPS_PROXY=
    # Set-PSRepository PSGallery -InstallationPolicy Trusted #causes nuget install to ask for confirmation
    Invoke-W32TimeResync
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\BITS' 'Start' '2' 'DWord'
    Start-Job -Name BITS {Start-Service -Name 'BITS' -ea silentlycontinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State # Service needed for fast download
    WifiPriority
}

Function Set-Hibernate
{
    # Control Hibernate Default = 'Off' ,'Boot' ,'Full'
    Param
    (
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Status = 'Off'
    )
    if ($Status -eq 'Full')
    {
        # Enable hibernate full
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '1' 'DWord'
        powercfg hibernate size 0 | out-null
        powercfg /h /type full | out-null
        powercfg.exe /hibernate on | out-null
        # Enable hibernate button
        AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '1' 'DWord'
        # Enable HyperBoot
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
    }
    elseif ($Status -eq 'Boot')
    {
        # Enable hibernate Boot
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
        powercfg hibernate size 0 | out-null
        powercfg /h /type reduced | out-null
        powercfg.exe /hibernate on | out-null
        # Disable hibernate button
        AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '0' 'DWord'
        # Enable HyperBoot
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
    }
    else
    {
        # Disable hibernate to avoid it's issues
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '0' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '0' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '0' 'DWord'
        powercfg hibernate size 0 | out-null
        powercfg.exe /hibernate off | out-null
        # Disable hibernate button
        AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '0' 'DWord'
        # Disabling HyperBoot to avoid it's issues
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '0' 'DWord'
    }
}

Function MaxPowerPlan
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Activating Max Performance Power Plan *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    # scheme_GUID
    # High Performance Power Plan GUID '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' - Aliase: scheme_min
    $MaxPlanGUID = '11111111-1111-1111-1111-111111111111'
    # Activate High
    powercfg /SetActive 'scheme_min' | out-null
    # Deleting old plan
    powercfg /delete $MaxPlanGUID | out-null
    # Duplicate High performance power plan to new plan
    powercfg /duplicatescheme 'scheme_min' $MaxPlanGUID | out-null
    powercfg /changename $MaxPlanGUID "Max Performance" "Custom Plan for maximum performace" | out-null
    ########################### Processor management sub_GUID '54533251-82be-4824-96c1-47b60b740d00' - Alias: SUB_PROCESSOR ####################################
    # ******************* Disable Core Parking ******************* Important 
    # Specify the minimum number of unparked cores allowed (in percentage) # setting_GUID: '0cc5b647-c1df-4637-891a-dec35c318583' - Alias: CPMINCORES # Must be set to 100%
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'CPMINCORES' '0x00000064' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'CPMINCORES' '0x00000064' | out-null
    # Minimum percentage of processor capabilities to use (Minimum processor state)(in percentage) # setting_GUID: '893dee8e-2bef-41e0-89c6-b55d0929964c' - Alias: PROCTHROTTLEMIN # Must be set to 100%
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PROCTHROTTLEMIN' '0x00000064' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PROCTHROTTLEMIN' '0x00000064' | out-null
    # Specify the algorithm used to select a new performance state when the ideal performance state is higher than the current performace state (Processor performance increase policy) # setting_GUID: '465e1f50-b610-473a-ab58-00d1077dc418' - Alias: PERFINCPOL # 2 Rocket
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFINCPOL' '0x00000002' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFINCPOL' '0x00000002' | out-null
    # Specify how processors select a target frequency when allowed to select above maximum frequency by current operating conditions (Processor performance boost mode) # setting_GUID: 'be337238-0d82-4146-a960-4f3749d470c7' - Alias: PERFBOOSTMODE # 2 Aggressive
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFBOOSTMODE' '0x00000002' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFBOOSTMODE' '0x00000002' | out-null
    # Specify the cooling mode for your system (System cooling policy) # setting_GUID: '94D3A615-A899-4AC5-AE2B-E4D8F634367F' - Alias: SYSCOOLPOL # 1 Active
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'SYSCOOLPOL' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'SYSCOOLPOL' '0x00000001' | out-null
    # Allow processors to use throttle states # setting_GUID: '3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb' - Alias: THROTTLING # 0 Off
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'THROTTLING' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'THROTTLING' '0x00000000' | out-null
    ########################### No subgroup sub_GUID 'fea3413e-7e05-4911-9a71-700331f1c294' - Alias: SUB_NONE ####################################
    # Power Scheme Personality # setting_GUID:'245d8541-3943-4422-b025-13a784f679b7' - Alias: PERSONALITY # High Performance
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_NONE' 'PERSONALITY' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_NONE' 'PERSONALITY' '0x00000001' | out-null
    # Specifies the policy for devices powering down while the system is running # setting_GUID: '4faab71a-92e5-4726-b531-224559672d19' - Alias: DEVICEIDLE #0 Performance ,1 Power savings
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_NONE' 'DEVICEIDLE' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_NONE' 'DEVICEIDLE' '0x00000000' | out-null
    # Require a password on wakeup # setting_GUID: '0e796bdb-100d-47d6-a2d5-f7d2daa51f51' - Alias: CONSOLELOCK #0 No ,1 Yes
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_NONE' 'CONSOLELOCK' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_NONE' 'CONSOLELOCK' '0x00000001' | out-null
    ########################### Hard disc management sub_GUID: '0012ee47-9041-4b5d-9b77-535fba8b1442' - Alias: SUB_DISK ####################################
    # The harddisk may power down after the specified time of inactivity is detected. (Turn off hard disc after) # setting_GUID: '6738e2c4-e8a5-4a42-b16a-e040e769756e' - Alias: DISKIDLE # Seconds - Never
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_DISK' 'DISKIDLE' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_DISK' 'DISKIDLE' '0x00000000' | out-null
    ########################### Sleep management sub_GUID: '238c9fa8-0aad-41ed-83f4-97be242c8f20' - Alias: SUB_SLEEP ####################################
    # System idle timeout before the system enters a low power standby state. (sleep after) # setting_GUID: '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' - Alias: STANDBYIDLE # Seconds - Never
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_SLEEP' 'STANDBYIDLE' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_SLEEP' 'STANDBYIDLE' '0x00000000' | out-null
    # System idle timeout before the system enters a low power hibernation state (hibernate after) # setting_GUID: '9d7815a6-7ee4-497e-8888-515a05f02364' - Alias: HIBERNATEIDLE # Seconds - Never
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_SLEEP' 'HIBERNATEIDLE' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_SLEEP' 'HIBERNATEIDLE' '0x00000000' | out-null
    # Unattended Sleep Timeout # setting_GUID: '7bc4a2f9-d8fc-4469-b07b-33eb785aaca0' - Alias: UNATTENDSLEEP # Seconds - Never
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_SLEEP' 'UNATTENDSLEEP' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_SLEEP' 'UNATTENDSLEEP' '0x00000000' | out-null
    ########################### Display management sub_GUID: '7516b95f-f776-4464-8c53-06167f40cc99' - Alias: SUB_VIDEO ####################################
    # Specifies Console lock display off timeout # setting_GUID: '8EC4B3A5-6868-48c2-BE75-4F3044BE88A7' - Alias: VIDEOCONLOCK # Seconds - Never
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOCONLOCK' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOCONLOCK' '0x00000000' | out-null
    # Specify how long your computer is inactive before your display turns off (Turn off display after) # setting_GUID: '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' - Alias: VIDEOIDLE # Seconds - Never
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOIDLE' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOIDLE' '0x00000000' | out-null
    # Display brightness (in percentage) # setting_GUID: 'aded5e82-b909-4619-9949-f5d71dac0bcb' - Alias: VIDEONORMALLEVEL # 100%
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEONORMALLEVEL' '0x00000064' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEONORMALLEVEL' '0x00000064' | out-null
    ########################### Power buttons and lid management sub_GUID: '4f971e89-eebd-4455-a8de-9e59040e7347' - Alias: SUB_BUTTONS ####################################
    # Enable forced shutdown for button and lid actions # setting_GUID: '833a6b62-dfa4-46d1-82f8-e09e34d029d6' - Alias: SHUTDOWN #0 off ,1 on
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'SHUTDOWN' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'SHUTDOWN' '0x00000001' | out-null
    # Lid close action # setting_GUID: '5ca83367-6e45-459f-a27b-476b1d01c936' - Alias: LIDACTION # 0 Do nothing
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'LIDACTION' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'LIDACTION' '0x00000000' | out-null
    # Power button action # setting_GUID: '7648efa3-dd9c-4e3e-b566-50f929386280' - Alias: PBUTTONACTION # 3 Shutdown
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'PBUTTONACTION' '0x00000003' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'PBUTTONACTION' '0x00000003' | out-null
    # Start menu power button action # setting_GUID: 'a7066653-8d6c-40a8-910e-a1f54b84c7e5' - Alias: UIBUTTON_ACTION # 2 Shutdown
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'UIBUTTON_ACTION' '0x00000002' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'UIBUTTON_ACTION' '0x00000002' | out-null
    ########################### PCI Express sub_GUID: '501a4d13-42af-4429-9fd1-a8218c268e20' - Alias: SUB_PCIEXPRESS ####################################
    # Link State Power Management # setting_GUID: 'ee12f906-d277-404b-b6da-e5fa1a576df5' - Alias: ASPM # 0 Off
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_PCIEXPRESS' 'ASPM' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PCIEXPRESS' 'ASPM' '0x00000000' | out-null
    ########################### Multimedia management sub_GUID: '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' ####################################
    # Specify the policy to bias video playback quality & performance # setting_GUID: '10778347-1370-4ee0-8bbd-33bdacaade49' # 1 Video playback performance and quality bias
    powercfg /setacvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '10778347-1370-4ee0-8bbd-33bdacaade49' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '10778347-1370-4ee0-8bbd-33bdacaade49' '0x00000001' | out-null
    # When playing video # setting_GUID: '10778347-1370-4ee0-8bbd-33bdacaade49' # 0 Optimize video quality
    powercfg /setacvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4' '0x00000000' | out-null
    ########################### Battery management sub_GUID: 'e73a048d-bf27-4f12-9731-8b2076e8891f' - Alias: SUB_BATTERY ####################################
    # Critical battery action # setting_GUID: '637ea02f-bbcb-4015-8e2c-a1c7b9c0b546' - Alias: BATACTIONCRIT # 2 Hibernate
    powercfg /setacvalueindex $MaxPlanGUID 'SUB_BATTERY' 'BATACTIONCRIT' '0x00000002' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BATTERY' 'BATACTIONCRIT' '0x00000002' | out-null
    ################################################################### Other ####################################################################
    # Desktop background slide show # sub_GUID: '0d7dbae2-4294-402a-ba8e-26777e8488cd' # setting_GUID: '309dce9b-bef4-4119-9921-a851fb12f0f4' # 1 Paused
    powercfg /setacvalueindex $MaxPlanGUID '0d7dbae2-4294-402a-ba8e-26777e8488cd' '309dce9b-bef4-4119-9921-a851fb12f0f4' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID '0d7dbae2-4294-402a-ba8e-26777e8488cd' '309dce9b-bef4-4119-9921-a851fb12f0f4' '0x00000001' | out-null
    # Wireless adapter power saving mode # sub_GUID: '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' # setting_GUID: '12bbebe6-58d6-4636-95bb-3217ef867c1a' # 0 Maximum performance
    powercfg /setacvalueindex $MaxPlanGUID '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' '12bbebe6-58d6-4636-95bb-3217ef867c1a' '0x00000000' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' '12bbebe6-58d6-4636-95bb-3217ef867c1a' '0x00000000' | out-null
    # intel(r) graphics power plan # sub_GUID: '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' # setting_GUID: '3619c3f2-afb2-4afc-b0e9-e7fef372de36' # 2 Maximum performance
    powercfg /setacvalueindex $MaxPlanGUID '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' '3619c3f2-afb2-4afc-b0e9-e7fef372de36' '0x00000002' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' '3619c3f2-afb2-4afc-b0e9-e7fef372de36' '0x00000002' | out-null
    # AMD power slider overlay # sub_GUID: 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' # setting_GUID: '7ec1751b-60ed-4588-afb5-9819d3d77d90' # 3 Best performance
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\c763b4ec-0e50-4b6b-9bed-2b92a6ee884e\7ec1751b-60ed-4588-afb5-9819d3d77d90' -ea SilentlyContinue)
    {
        powercfg /setacvalueindex $MaxPlanGUID 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' '7ec1751b-60ed-4588-afb5-9819d3d77d90' '0x00000003' | out-null
        powercfg /setdcvalueindex $MaxPlanGUID 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' '7ec1751b-60ed-4588-afb5-9819d3d77d90' '0x00000003' | out-null
    }
    # ATI graphics powerplay settings # sub_GUID: 'f693fb01-e858-4f00-b20f-f30e12ac06d6' # setting_GUID: '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' # 1 Best performance
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\f693fb01-e858-4f00-b20f-f30e12ac06d6\191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' -ea SilentlyContinue)
    {
        powercfg /setacvalueindex $MaxPlanGUID 'f693fb01-e858-4f00-b20f-f30e12ac06d6' '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' '0x00000001' | out-null
        powercfg /setdcvalueindex $MaxPlanGUID 'f693fb01-e858-4f00-b20f-f30e12ac06d6' '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' '0x00000001' | out-null
    }
    # Switchable dynamic graphics global settings # sub_GUID: 'e276e160-7cb0-43c6-b20b-73f5dce39954' # setting_GUID: 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' # 3 Maximize performance
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\e276e160-7cb0-43c6-b20b-73f5dce39954\a1662ab2-9d34-4e53-ba8b-2639b9e20857' -ea SilentlyContinue)
    {
        powercfg /setacvalueindex $MaxPlanGUID 'e276e160-7cb0-43c6-b20b-73f5dce39954' 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' '0x00000003' | out-null
        powercfg /setdcvalueindex $MaxPlanGUID 'e276e160-7cb0-43c6-b20b-73f5dce39954' 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' '0x00000003' | out-null
    }
    # ----------------------------
    # Set battery LEVEL thresholds
    # ----------------------------
    #   Low battery level to 10%
    powercfg /setdcvalueindex $MaxPlanGUID SUB_BATTERY BATLEVELLOW 10
    powercfg /setacvalueindex $MaxPlanGUID SUB_BATTERY BATLEVELLOW 10
    # Critical battery level to 5%
    powercfg /setdcvalueindex $MaxPlanGUID SUB_BATTERY BATLEVELCRIT 5
    powercfg /setacvalueindex $MaxPlanGUID SUB_BATTERY BATLEVELCRIT 5
    # ----------------------------
    # Set battery ACTIONS
    # ----------------------------
    # Low battery action: Do nothing
    powercfg /setdcvalueindex $MaxPlanGUID SUB_BATTERY BATACTIONLOW 0
    powercfg /setacvalueindex $MaxPlanGUID SUB_BATTERY BATACTIONLOW 0
    # Critical battery action:
    # Battery = shutdown (3), AC = do nothing (0)
    powercfg /setdcvalueindex $MaxPlanGUID SUB_BATTERY BATACTIONCRIT 3
    powercfg /setacvalueindex $MaxPlanGUID SUB_BATTERY BATACTIONCRIT 0
    # ----------------------------
    # Set battery NOTIFICATIONS
    # ----------------------------
    # Low battery notification: ON (1) for battery, OFF (0) for AC
    powercfg /setdcvalueindex $MaxPlanGUID SUB_BATTERY BATFLAGSLOW 1
    powercfg /setacvalueindex $MaxPlanGUID SUB_BATTERY BATFLAGSLOW 0
    # Critical battery notification: ON (1) for battery, OFF (0) for AC
    powercfg /setdcvalueindex $MaxPlanGUID SUB_BATTERY BATFLAGSCRIT 1
    powercfg /setacvalueindex $MaxPlanGUID SUB_BATTERY BATFLAGSCRIT 0
    # Disable power throttling
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff' '1' 'DWord'
    # System responsiveness
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'SystemResponsiveness' '0' 'DWord'
    # Enable lock button
    AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowLockOption' '1' 'DWord'
    # Enable Sleep button
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowSleepOption' '1' 'DWord'
    powercfg /SetActive $MaxPlanGUID | out-null
    powercfg /SetActive $MaxPlanGUID | out-null
    # Set Hibernate Off
    Set-Hibernate 'Off'
}

Function Ins-WindowsFeatures
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Installing Windows Features using DISM *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    Write-Host -f C "`r`n*** Installing .NetFX3 ***`r`n"
    $St1 = dism /online /get-featureinfo /featurename:NetFx3 | Select-String State | Foreach-Object { $_.ToString().split(':')[1] -replace '\s','' }
    if ($St1 -ne "Enabled" ) {DISM /Online /Enable-Feature /FeatureName:NetFx3 /NoRestart}
    else {Write-Host -f C "Already Installed"}
    Write-Host -f C "`r`n*** Installing DirectPlay ***`r`n"
    $St2 = dism /online /get-featureinfo /featurename:DirectPlay | Select-String State | Foreach-Object { $_.ToString().split(':')[1] -replace '\s','' }
    if ($St2 -ne "Enabled" ) {DISM /Online /Enable-Feature /FeatureName:DirectPlay /All /NoRestart}
    else {Write-Host -f C "Already Installed"}
}

Function Ins-Nuget
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Installing Nuget provider *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    # Nuget PackageProvider
    if ((Get-PackageProvider -Name NuGet -ListAvailable -ea silentlycontinue | select -ExpandProperty Name -First 1) -eq "NuGet") {Write-Host -f C "Nuget PackageProvider already exists"}
    else {Start-Job -Name PackageProviderNuGet {Install-PackageProvider -Name NuGet -Confirm:$False -Scope AllUsers -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State;if (get-packageprovider -Name NuGet -ea silentlycontinue) {Write-Host -f C "Successfully Installed"}}
    Import-PackageProvider -Name NuGet -Force -ea silentlycontinue | out-null
    # NuGet Module
    if ((Get-Module -Name NuGet -ListAvailable -ea silentlycontinue | select -ExpandProperty Name -First 1) -eq "NuGet") {Write-Host -f C "Nuget Module already exists"}
    else {Start-Job -Name ModuleNuGet {Install-Module -Name NuGet -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State}
    Import-Module NuGet -Force -ea silentlycontinue | out-null
}

Function Ins-Choco
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Installing Chocolatey *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    # Ensure Chocolatey is installed
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Chocolatey not found. Installing..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force;
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    try {$ChocoInstalled = Get-Command -Name choco -ea silentlycontinue} catch {}
    if ($ChocoInstalled) {write-host "Choco is already installed"}
    else {
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Start-Sleep 1
        Relaunch
    }
    Choco feature enable -n=allowGlobalConfirmation
    Get-PackageProvider -Name "Chocolatey" -ForceBootstrap | out-null
    Choco upgrade Chocolatey -y
    if (choco list --lo -r -e Chocolatey-core.extension) {Choco upgrade Chocolatey-core.extension} else {Choco install Chocolatey-core.extension}
    Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1 -Force -ea silentlycontinue | out-null
    refreshenv
}

Function Ins-Scoop-git
{
    try {$scoopInstalled = Get-Command -Name scoop -ea silentlycontinue} catch {}
    if ($scoopInstalled) {write-host "scoop is already installed"} else {write-host "`r`n *** Installing scoop *** `r`n";iex "& {$(irm get.scoop.sh)} -RunAsAdmin"}
    try {$gitInstalled = Get-Command -Name git -ea silentlycontinue} catch {}
    if ($gitInstalled) {write-host "git is already installed `r`n Trying to update git";scoop update git} else {write-host "Installing git";scoop install git}
    if (Get-Command -Name scoop) {write-host "Trying to update scoop";scoop update}
}

Function Ins-winget-ps
{
    Ins-Scoop-git
    try {$WinGetClientInstalled = Get-Command -Name Find-WinGetPackage -ea silentlycontinue} catch {}
    if (!($WinGetClientInstalled))
    {
        Start-Job -Name ModuleWinGet {Install-Module Microsoft.WinGet.Client -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
        Import-Module Microsoft.WinGet.Client -Force -ea silentlycontinue | out-null
        repair-wingetpackagemanager
        Relaunch
    }
}

Function Install-Winget
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Installing Winget and its dependencies & scoop & git *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    # Ensure winget is installed
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget not found. Installing..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle"
        Start-Job -Name InstallingWinGet {Add-AppxPackage -Path "$env:TEMP\Microsoft.DesktopAppInstaller.msixbundle" -ea silentlycontinue | out-null} | Wait-Job -Timeout 300 | Format-Table -Wrap -AutoSize -Property Name,State
    }
    New-Item -Path "$env:TEMP\IA\Winget" -ItemType Directory -ea SilentlyContinue | out-null
    $VCLibsVersion = Get-AppxPackage -Name Microsoft.VCLibs* | Sort-Object -Property Version | Select-Object -ExpandProperty Version -Last 1 | Foreach-Object { $_.ToString().split('.')[0]}
    if ([int]$VCLibsVersion -lt 14)
    {
        Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "$env:TEMP\IA\Winget\Microsoft.VCLibs.x64.14.00.Desktop.appx" -ea SilentlyContinue | out-null
        Start-Job -Name VCLibs {Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.VCLibs.x64.14.00.Desktop.appx" -ea SilentlyContinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    }
    else {Write-Host -f C "VCLibs already installed"}
    $UIXamlVersion = Get-AppxPackage -Name Microsoft.UI.Xaml* | Sort-Object -Property Version | Select-Object -ExpandProperty Version -Last 1 | Foreach-Object { $_.ToString().split('.')[0]}
    if ([int]$UIXamlVersion -lt 8)
    {
        Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "$env:TEMP\IA\Winget\Microsoft.UI.Xaml.2.8.x64.appx" -ea SilentlyContinue | out-null
        Start-Job -Name UIXaml {Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.UI.Xaml.2.8.x64.appx" -ea SilentlyContinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    }
    else {Write-Host -f C "UI Xaml already installed"}
    try {$WingetInstalled = Get-Command -Name winget -ea silentlycontinue} catch {$WingetInstalled = $false}
    try {$latestAppInstaller = Find-WinGetPackage -id "Microsoft.AppInstaller" -MatchOption Equals | Select-Object -ExpandProperty Version} catch {$AppInstallerUpdated = $false}
    try {$InstalledAppInstaller = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' | select -ExpandProperty Version } catch {$AppInstallerUpdated = $false}
    if ($latestAppInstaller -eq $InstalledAppInstaller) {$AppInstallerUpdated = $true} else {$AppInstallerUpdated = $false}
    if ($WingetInstalled -And $AppInstallerUpdated) {write-host -f C "Winget is already installed"}
    else {
        Start-Job -Name InstallWinget1 {Start-BitsTransfer -Source "https://aka.ms/getwinget" -Destination "$env:TEMP\IA\Winget\Microsoft.DesktopAppInstaller.msixbundle" -ea SilentlyContinue | out-null;Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.DesktopAppInstaller.msixbundle" -ea SilentlyContinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
        Start-Job -Name InstallWinget2 {Add-AppxPackage https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -ea SilentlyContinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
        Start-Job -Name InstallWinget3 {Start-BitsTransfer -Source "https://cdn.winget.microsoft.com/cache/source.msix" -Destination "$env:TEMP\IA\Winget\Source.msix" -ea SilentlyContinue | out-null;Add-AppxPackage -Path "$env:TEMP\IA\Winget\Source.msix" | out-null;DISM.EXE /Online /Add-ProvisionedAppxPackage /PackagePath:"$env:TEMP\IA\Winget\Source.msix" /SkipLicense | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
        Install-Script winget-install -Force
        Start-Job -Name UpdateWinget {winget-install -Force} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
        Start-Sleep 1
        Relaunch
    }
    Start-Job -Name ConfigWinget1 {Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name ConfigWinget2 {Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.Winget.Source_8wekyb3d8bbwe} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    write-host -f C "`r`n *** Updating Winget ***"
    Install-Script winget-install -Force
    Start-Job -Name UpdateWinget {winget-install -Force} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    winget-install -CheckForUpdate
    Ins-winget-ps
    winget source reset --force
    winget upgrade Microsoft.AppInstaller --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-arSALang
{
    Write-Host -f C "`r`n *** Installing Arabic-SA language *** `r`n"
    Start-Job -Name InsAr {Install-Language -Language ar-SA} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    Set-WinHomeLocation 0xcd
    Set-WinDefaultInputMethodOverride -InputTip "0401:00000401" #Default input language Arabic
    Set-WinSystemLocale -SystemLocale ar-SA
    Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True
}

Function Set-en-US-Culture #Need fix
{
    Write-Host -f C "`r`n *** Setting en-US Culture (Regional format) *** `r`n"
    Import-Module International -Force -ea silentlycontinue | out-null
    Start-Job -Name CultureENGB {Set-Culture -CultureInfo en-US} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-sleep 1
    $culture = Get-Culture
    $culture.DateTimeFormat.LongDatePattern = 'dd MMMM yyyy'
    $culture.DateTimeFormat.ShortDatePattern = 'dd/MM/yyyy'
    $culture.DateTimeFormat.LongTimePattern = 'hh:mm:ss tt'
    $culture.DateTimeFormat.ShortTimePattern = 'hh:mm tt'
    $culture.DateTimeFormat.ShortDatePattern = 'd/MM/yyyy'
    $culture.DateTimeFormat.FirstDayOfWeek = 'Saturday'
    $culture.NumberFormat.DigitSubstitution = 'Context'
    Start-Job -Name CustomCulture {Set-Culture -CultureInfo $culture} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    # Use this to see all properties    # $culture | Format-List -Property *     # $culture.DateTimeFormat     # $culture.NumberFormat
    Start-sleep 4
    AddRegEntry 'HKCU:\Control Panel\International' 'sLongDate' 'dd MMMM yyyy' 'String'
    reg add "HKCU\Control Panel\International" /V sLongDate /T REG_SZ /D "dddd dd/MMMM/yyyy" /F
    AddRegEntry 'HKCU:\Control Panel\International' 'sShortDate' 'dd/MM/yyyy' 'String'
    reg add "HKCU\Control Panel\International" /V sShortDate /T REG_SZ /D "dd/MM/yyyy" /F
    AddRegEntry 'HKCU:\Control Panel\International' 'sTimeFormat' 'hh:mm:ss tt' 'String'
    reg add "HKCU\Control Panel\International" /V sTimeFormat /T REG_SZ /D "hh:mm:ss tt" /F
    AddRegEntry 'HKCU:\Control Panel\International' 'sShortTime' 'hh:mm tt' 'String'
    reg add "HKCU\Control Panel\International" /V sShortTime /T REG_SZ /D "hh:mm tt" /F
    AddRegEntry 'HKCU:\Control Panel\International' 'iFirstDayOfWeek' '5' 'String' # Saturday
    reg add "HKCU\Control Panel\International" /V iFirstDayOfWeek /T REG_SZ /D "5" /F
    AddRegEntry 'HKCU:\Control Panel\International' 'NumShape' '0' 'String' # Native digits number shape # 0 - Context # 1 - default # 2 - Always local
    reg add "HKCU\Control Panel\International" /V NumShape /T REG_SZ /D "0" /F
    reg add "HKCU\Control Panel\International" /V iCalendarType /T REG_SZ /D "1" /F
    AddRegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowTextPrediction' '1' 'DWord'
    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
    Start-sleep 2
    Stop-Process -ProcessName explorer -Force -ea SilentlyContinue | out-null
}

Function Ins-enUSLang
{
    Write-Host -f C "`r`n *** Installing English-US language *** `r`n"
    Start-Job -Name InsEng {Install-Language -Language en-US -CopyToSettings} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    Set-WinSystemLocale en-US
    Set-WinUILanguageOverride en-US
    Set-WinDefaultInputMethodOverride "0409:00000409"
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguage' '0409' 'String'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguageFallback' '@ "en-US"' 'MultiString'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'Default' '0409' 'String'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale' 'default' '00000409' 'String'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale' 'Default' '00000409' 'String'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'Languages' '@ "en-US"' 'MultiString'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup\en-US' '0409:00000409' '1' 'DWord'
}

Function Unins-enGBLang
{
    Write-Host -f C "`r`n *** Removing English-GB language *** `r`n"
    Uninstall-Language -Language en-GB;lpksetup.exe /u en-GB /s /r
    Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language\English_UK"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKCU:\Control Panel\International\User Profile\en-GB"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKCU:\Control Panel\International\User Profile System Backup\en-GB"  -Recurse -force -ea SilentlyContinue | out-null
}

Function Tweak-Language
{
    AddRegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowAutoCorrection' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowCasing' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowShiftLock' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowTextPrediction' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowAutoCorrection' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowCasing' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowShiftLock' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowTextPrediction' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\Input Method' 'EnableHexNumpad' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Input\Settings' 'EnableHwkbTextPrediction' '1' 'DWord'
}

Function Ins-LatestPowershell
{
    Write-Host -f C "`r`n *** Installing Latest Stable Powershell *** `r`n"
    winget install --id 'Microsoft.Powershell' --silent --accept-source-agreements --accept-package-agreements
    
}

Function Ins-Terminal
{
    Write-Host -f C "`r`n *** Installing Windows Terminal *** `r`n"
    winget install -e --id 'Microsoft.WindowsTerminal' --silent --accept-source-agreements --accept-package-agreements
    AddRegEntry 'HKCU:Console\%%Startup' "DelegationConsole" "{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}" 'String'
    AddRegEntry 'HKCU:Console\%%Startup' "DelegationTerminal" "{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}" 'String'
}

Function Ins-DotNetRuntime
{
    Write-Host -f C "`r`n *** Installing .Net Runtime All versions *** `r`n"
    if (choco list --lo -r -e dotnet-all) {Choco upgrade dotnet-all} else {Choco install dotnet-all -y}
    (Find-WinGetPackage "Microsoft.DotNet.DesktopRuntime").Id | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
    (Find-WinGetPackage "Microsoft.DotNet.Runtime").Id | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
    (Find-WinGetPackage "Microsoft.DotNet.AspNetCore").Id | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
}

Function Ins-VCPPRuntime
{
    Write-Host -f C "`r`n *** Installing Visual C++ Runtime All versions *** `r`n"
    if (choco list --lo -r -e vcredist-all) {Choco upgrade vcredist-all} else {Choco install vcredist-all -y}
    (Find-WinGetPackage "Microsoft.VCRedist").Id | Where-Object {-not $_.EndsWith("arm64")} | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
}

Function Ins-JavaRuntime
{
    Write-Host -f C "`r`n *** Installing Java Runtime Environment *** `r`n"
    winget install -e --id Oracle.JavaRuntimeEnvironment --silent --accept-source-agreements --accept-package-agreements
    if (choco list --lo -r -e javaruntime) {Choco upgrade javaruntime} else {Choco install javaruntime -y}
}

Function Ins-XNA
{
    Write-Host -f C "`r`n *** Installing Microsoft XNA Framework Redistributable *** `r`n"
    if (choco list --lo -r -e xna) {Choco upgrade xna} else {Choco install xna -y}
    winget install -e --id Microsoft.XNARedist --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-AdobeAIRRuntime
{
    Write-Host -f C "`r`n *** Installing Adobe AIR Runtime *** `r`n"
    if (choco list --lo -r -e adobeair) {Choco upgrade adobeair} else {Choco install adobeair -y}
    winget install -e --id HARMAN.AdobeAIR --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-WScan
{
    Write-Host -f C "`r`n *** Installing Windows Scan *** `r`n"
    winget install -e --name 'Windows Scan' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-HpSmart
{
    Write-Host -f C "`r`n *** Installing Hp Smart App *** `r`n"
    winget install -e --name 'HP Smart' --silent --accept-source-agreements --accept-package-agreements
}


Function Ins-NotepadPP
{
    Write-Host -f C "`r`n *** Installing Notepad++ *** `r`n"
    winget install -e --name 'Notepad++' --silent --accept-source-agreements --accept-package-agreements
    if (choco list --lo -r -e notepadplusplus.install) {Choco upgrade notepadplusplus.install} else {Choco install notepadplusplus.install -y}
}

Function Ins-Chrome
{
    Write-Host -f C "`r`n *** Installing Chrome *** `r`n"
    if (choco list --lo -r -e googlechrome) {Choco upgrade googlechrome --ignore-checksums} else {Choco install googlechrome --ignore-checksums -y}
    winget install -e --id 'Google.Chrome' --silent --accept-source-agreements --accept-package-agreements
    # remove logon chrome
    Remove-Item -LiteralPath "HKLM:\Software\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}"  -Recurse -force -ea SilentlyContinue | out-null
    # disable chrome services
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService' '4' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\gupdate' 'Start' '4' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem' 'Start' '4' 'DWord'
    # remove chrome tasks
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineCore'} | Unregister-ScheduledTask -Confirm:$false -ea SilentlyContinue | out-null
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineUA'} | Unregister-ScheduledTask -Confirm:$false -ea SilentlyContinue | out-null
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdaterTaskSystem'} | Unregister-ScheduledTask -Confirm:$false -ea SilentlyContinue | out-null
    # Allow popups on all chrome profiles (will prompt to close Chrome if running)
    Set-ChromePopupSettings -Action Allow
}

Function Set-ChromePopupSettings {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Allow", "Block", "Default", "ShowGUI")]
        [string]$Action = "ShowGUI",
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    # Execute based on action parameter
    switch ($Action) {
        "Allow" {
            Update-PopupSettings -settingValue 1
        }
        "Block" {
            Update-PopupSettings -settingValue 2
        }
        "Default" {
            Update-PopupSettings -settingValue "default"
        }
        "ShowGUI" {
            Show-PopupSettingsGUI
        }
    }
    
    # Function to get Chrome profiles
    function Get-ChromeProfiles {
        $userDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        if (Test-Path $userDataPath) {
            $profiles = Get-ChildItem -Path $userDataPath -Directory | Where-Object {
                $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$"
            }
            return $profiles
        }
        return @()
    }

    # Function to update popup settings
    function Update-PopupSettings {
        param($settingValue, $progressBar, $statusBox)
        
        if (-not $Force) {
            # Check if Chrome is running
            $chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
            if ($chromeProcesses) {
                if ($statusBox) {
                    $statusBox.Text += "Chrome is running. Please close Chrome first or use -Force parameter.`n"
                } else {
                    Write-Warning "Chrome is running. Please close Chrome first or use -Force parameter."
                }
                return $false
            }
        } else {
            # Force close Chrome
            Stop-Process -Name "chrome" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        if ($statusBox) {
            $statusBox.Text += "Updating Chrome popup settings...`n"
        } else {
            Write-Host "Updating Chrome popup settings..." -ForegroundColor Yellow
        }
        
        $profiles = Get-ChromeProfiles
        $processed = 0
        
        foreach ($profile in $profiles) {
            $profileName = $profile.Name
            $prefsPath = "$($profile.FullName)\Preferences"
            
            if ($statusBox) {
                $statusBox.Text += "Processing $profileName... "
            } else {
                Write-Host "Processing $profileName... " -NoNewline
            }
            
            if (Test-Path $prefsPath) {
                try {
                    $json = Get-Content $prefsPath -Raw | ConvertFrom-Json
                    
                    # Create the content_settings structure if it doesn't exist
                    if (-not $json.profile.content_settings) {
                        $json.profile | Add-Member -MemberType NoteProperty -Name 'content_settings' -Value @{ 
                            exceptions = @{
                                popups = @()
                            }
                        }
                    }
                    
                    if ($settingValue -eq "default") {
                        # Remove our custom popup settings (restore defaults)
                        if ($json.profile.content_settings.exceptions.popups) {
                            $newExceptions = @()
                            foreach ($exception in $json.profile.content_settings.exceptions.popups) {
                                if ($exception.origin -notin @("https://*", "http://*")) {
                                    $newExceptions += $exception
                                }
                            }
                            $json.profile.content_settings.exceptions.popups = $newExceptions
                        }
                    } else {
                        # Update popup settings
                        $popupExceptions = @(
                            @{
                                origin = "https://*"
                                setting = $settingValue
                            },
                            @{
                                origin = "http://*"
                                setting = $settingValue
                            }
                        )
                        $json.profile.content_settings.exceptions.popups = $popupExceptions
                    }
                    
                    # Save the updated preferences
                    $json | ConvertTo-Json -Depth 10 | Set-Content $prefsPath -Encoding ASCII
                    
                    if ($statusBox) {
                        $statusBox.Text += "SUCCESS`n"
                    } else {
                        Write-Host "SUCCESS" -ForegroundColor Green
                    }
                    $processed++
                } catch {
                    if ($statusBox) {
                        $statusBox.Text += "ERROR: $($_.Exception.Message)`n"
                    } else {
                        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                if ($statusBox) {
                    $statusBox.Text += "Preferences file not found`n"
                } else {
                    Write-Host "Preferences file not found" -ForegroundColor Yellow
                }
            }
            
            if ($progressBar) {
                $progressBar.Value = (($processed / $profiles.Count) * 100)
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        
        if ($statusBox) {
            if ($processed -gt 0) {
                $statusBox.Text += "`nOperation completed. $processed profiles updated.`n"
            } else {
                $statusBox.Text += "`nNo profiles were updated.`n"
            }
        } else {
            if ($processed -gt 0) {
                Write-Host "Operation completed. $processed profiles updated." -ForegroundColor Green
            } else {
                Write-Host "No profiles were updated." -ForegroundColor Yellow
            }
        }
        
        return $true
    }

    # GUI function
    function Show-PopupSettingsGUI {
        # Add required assemblies for GUI
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        [System.Windows.Forms.Application]::MessageBox("This will modify Chrome settings. Ensure Chrome is closed before continuing.", "Chrome Popup Settings Manager", "Ok", "Information")
        # Main form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Chrome Popup Settings Manager"
        $form.Size = New-Object System.Drawing.Size(650, 500)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox = $false

        # Header
        $headerLabel = New-Object System.Windows.Forms.Label
        $headerLabel.Location = New-Object System.Drawing.Point(20, 20)
        $headerLabel.Size = New-Object System.Drawing.Size(600, 30)
        $headerLabel.Text = "Manage Chrome Popup Settings Across All Profiles"
        $headerLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
        $form.Controls.Add($headerLabel)

        # Info label
        $infoLabel = New-Object System.Windows.Forms.Label
        $infoLabel.Location = New-Object System.Drawing.Point(20, 60)
        $infoLabel.Size = New-Object System.Drawing.Size(600, 40)
        $infoLabel.Text = "This tool will modify Chrome's configuration to allow or block popups across all user profiles."
        $form.Controls.Add($infoLabel)

        # Status box
        $statusBox = New-Object System.Windows.Forms.RichTextBox
        $statusBox.Location = New-Object System.Drawing.Point(20, 110)
        $statusBox.Size = New-Object System.Drawing.Size(600, 200)
        $statusBox.ReadOnly = $true
        $statusBox.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
        $form.Controls.Add($statusBox)

        # Buttons
        $allowButton = New-Object System.Windows.Forms.Button
        $allowButton.Location = New-Object System.Drawing.Point(20, 330)
        $allowButton.Size = New-Object System.Drawing.Size(180, 40)
        $allowButton.Text = "Allow Popups Everywhere"
        $allowButton.BackColor = [System.Drawing.Color]::LightGreen
        $form.Controls.Add($allowButton)

        $blockButton = New-Object System.Windows.Forms.Button
        $blockButton.Location = New-Object System.Drawing.Point(220, 330)
        $blockButton.Size = New-Object System.Drawing.Size(180, 40)
        $blockButton.Text = "Block Popups Everywhere"
        $blockButton.BackColor = [System.Drawing.Color]::LightCoral
        $form.Controls.Add($blockButton)

        $defaultButton = New-Object System.Windows.Forms.Button
        $defaultButton.Location = New-Object System.Drawing.Point(420, 330)
        $defaultButton.Size = New-Object System.Drawing.Size(200, 40)
        $defaultButton.Text = "Restore Default Settings"
        $form.Controls.Add($defaultButton)

        # Progress bar
        $progressBar = New-Object System.Windows.Forms.ProgressBar
        $progressBar.Location = New-Object System.Drawing.Point(20, 390)
        $progressBar.Size = New-Object System.Drawing.Size(600, 20)
        $progressBar.Style = "Continuous"
        $form.Controls.Add($progressBar)

        # Footer
        $footerLabel = New-Object System.Windows.Forms.Label
        $footerLabel.Location = New-Object System.Drawing.Point(20, 420)
        $footerLabel.Size = New-Object System.Drawing.Size(600, 40)
        $footerLabel.Text = "Note: Chrome must be closed for these changes to take effect. Changes will apply to all profiles."
        $footerLabel.ForeColor = [System.Drawing.Color]::DarkRed
        $form.Controls.Add($footerLabel)

        # Button events
        $allowButton.Add_Click({
            $statusBox.Text = "Allowing popups on all sites across all Chrome profiles...`n"
            Update-PopupSettings -settingValue 1 -progressBar $progressBar -statusBox $statusBox
        })

        $blockButton.Add_Click({
            $statusBox.Text = "Blocking popups on all sites across all Chrome profiles...`n"
            Update-PopupSettings -settingValue 2 -progressBar $progressBar -statusBox $statusBox
        })

        $defaultButton.Add_Click({
            $statusBox.Text = "Restoring default popup settings across all Chrome profiles...`n"
            Update-PopupSettings -settingValue "default" -progressBar $progressBar -statusBox $statusBox
        })

        # Show the form
        $form.Add_Shown({$form.Activate()})
        [void] $form.ShowDialog()
    }
}

# Export the function if we're in a module context
if ($MyInvocation.MyCommand.CommandType -eq "Script") {
    # Add aliases for easier use
    Set-Alias -Name Set-ChromePopups -Value Set-ChromePopupSettings
    Set-Alias -Name chrome-popups -Value Set-ChromePopupSettings
    
    Write-Host "Chrome Popup Settings function loaded. Use Set-ChromePopupSettings to manage popup settings." -ForegroundColor Green
    Write-Host "Available actions: Allow, Block, Default, ShowGUI" -ForegroundColor Yellow
    Write-Host "Example: Set-ChromePopupSettings -Action Allow -Force" -ForegroundColor Cyan
}

Function Tweak-Edge
{
    Write-Host -f C "`r`n *** Tweaking Edge *** `r`n"
    # edge
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'AutofillCreditCardEnabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser' 'AllowAddressBarDropdown' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' 'AllowPrelaunch' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
    # remove logon edge
    Remove-Item -LiteralPath "HKLM:\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}"  -Recurse -force -ea SilentlyContinue | out-null
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' 'AllowTabPreloading' '0' 'DWord'
    # disable edge services
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService' 'Start' '4' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate' 'Start' '4' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem' 'Start' '4' 'DWord'
    # remove edge tasks
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore'} | Unregister-ScheduledTask -Confirm:$false -ea silentlycontinue | out-null
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA'} | Unregister-ScheduledTask -Confirm:$false -ea silentlycontinue | out-null
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateBrowserReplacementTask'} | Unregister-ScheduledTask -Confirm:$false -ea silentlycontinue | out-null
}

Function Ins-AcrobatRdr
{
    Write-Host -f C "`r`n *** Installing Adobe Acrobat Reader DC *** `r`n"
    try {$Acrobat = Get-Package -Name 'Adobe Acrobat (64-bit)' -ea silentlycontinue} catch {}
    if ($Acrobat) {Write-Host -f C "Adobe Acrobat (64-bit) found installed"}
    else
    {
        if (choco list --lo -r -e adobereader) {Choco upgrade adobereader} else {Choco install adobereader -y}
        winget install -e --id 'Adobe.Acrobat.Reader.64-bit' --silent --accept-source-agreements --accept-package-agreements
    }
}

Function Unins-Acrobat
{
    Write-Host -f C "`r`n *** Killing Acrobat processes *** `r`n"
    kill -name acro* -force;
    kill -name adobe* -force;
    try {Choco uninstall adobereader | Out-Null} catch {}
    # Get installed programs for both 32-bit and 64-bit architectures
    $paths = @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\')
    $installedPrograms = foreach ($registryPath in $paths) {
        try {
            Get-ChildItem -LiteralPath $registryPath -ea silentlycontinue | Get-ItemProperty | Where-Object { $_.PSChildName -ne $null }
        } catch {Write-warning "Error reaging registry"}
    }
    # Filter programs with Adobe Acrobat in their display name
    $adobeacrobatEntries = $installedPrograms | Where-Object {$_.DisplayName -like '*Adobe Acrobat*'}
    # Try to uninstall Adobe Acrobat for each matching entry
    foreach ($entry in $adobeacrobatEntries) {
        $ProductCode = $entry.PSChildName
        $DisplayName = $entry.DisplayName
        try {
            # Use the MSIExec command to uninstall the product
            Write-Host -f C "`r`n *** Uninstalling $DisplayName *** `r`n"
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $ProductCode /qb-! /norestart" -Wait -PassThru
        } catch {Write-warning "Failed to uninstall $DisplayName with product code $ProductCode. Error: $_"}
    }
    # Uninstall Using winget
    winget uninstall -e --id "Adobe.Acrobat.Reader.32-bit"
    winget uninstall -e --id "Adobe.Acrobat.Reader.64-bit"
    winget uninstall -e --id "Adobe.Acrobat.Pro"
    Write-Host -f C "`r`n *** Removing All Acrobat left overs *** `r`n"
    #16etkp4rCcon2NyGGh0oYSocHhB_054cm
    Start-BitsTransfer -Source 'https://www.googleapis.com/drive/v3/files/16etkp4rCcon2NyGGh0oYSocHhB_054cm?alt=media&key=AIzaSyBjpiLnU2lhQG4uBq0jJDogcj0pOIR9TQ8' -Destination "$env:TEMP\AdobeAcroCleaner.exe"  -ea SilentlyContinue | out-null
    Start-Job -Name CleanerAcrobatPro {if (Test-Path -Path "$env:TEMP\AdobeAcroCleaner.exe" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcroCleaner.exe" -ArgumentList "/silent","/product=0","/cleanlevel=1" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name CleanerAcrobatPro {if (Test-Path -Path "$env:TEMP\AdobeAcroCleaner.exe" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcroCleaner.exe" -ArgumentList "/silent","/product=1","/cleanlevel=1" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
}

function Fix-AdobeAcrobatProPdfThumbnails {
    [CmdletBinding()]
    param (
        [int]$DiskCleanupSageSetNumber = 65535
    )

    function Clear-ThumbnailCacheWithDiskCleanup {
        param (
            [int]$SageSetNumber
        )
        Write-Host "Deleting thumbnail cache files..." -ForegroundColor Yellow
        try {
            $thumbCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
            Get-ChildItem -Path $thumbCachePath -Include "*thumbcache*.db" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Host "Thumbnail cache files deleted."
        } catch {
            Write-Warning ("Failed to delete thumbnail cache files: " + $_)
        }

        Write-Host "Configuring Disk Cleanup to clean 'Thumbnail Cache'..." -ForegroundColor Yellow
        $regSagesetPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $thumbnailsKey = "Thumbnail Cache"
        try {
            $cleanupKeyPath = Join-Path $regSagesetPath $thumbnailsKey
            if (Test-Path $cleanupKeyPath) {
                New-ItemProperty -Path $cleanupKeyPath -Name "StateFlags$SageSetNumber" -Value 2 -PropertyType DWord -Force | Out-Null
                Write-Host "Configured Disk Cleanup to clean 'Thumbnail Cache' for sageset number $SageSetNumber."
            } else {
                Write-Warning ("Thumbnail Cache key not found in registry: " + $cleanupKeyPath)
                return
            }
        } catch {
            Write-Warning ("Failed to configure Disk Cleanup registry key: " + $_)
            return
        }

        Write-Host "Running Disk Cleanup silently for Thumbnails..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:$SageSetNumber" -Wait -WindowStyle Hidden
            Write-Host "Disk Cleanup completed silently."
        } catch {
            Write-Warning ("Failed to run Disk Cleanup silently: " + $_)
        }
    }

    # --- Begin main fix process ---

    Write-Host "Starting Adobe Acrobat Pro PDF thumbnail fix..." -ForegroundColor Cyan
    
    # Stop relevant services
    Stop-Service -Name "AppReadiness" -Force -ErrorAction SilentlyContinue
    # Stop Explorer temporarily
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue

    # 1. Clear thumbnail cache
    Clear-ThumbnailCacheWithDiskCleanup -SageSetNumber $DiskCleanupSageSetNumber
    # Windows specific icon cache rebuild
    Write-Host "Rebuilding Windows Icon Cache..." -ForegroundColor Cyan

    # Clear all icon cache files
    $cachePaths = @(
        "$env:LOCALAPPDATA\IconCache.db",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*"
    )

    foreach ($path in $cachePaths) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    # Reset thumbnail related registry settings
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailCache"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Icon cache rebuilt. Icons may take a moment to reappear." -ForegroundColor Green

    # 2. Enable thumbnails in Folder Options via registry
    Write-Host "Enabling thumbnails in Folder Options via registry..." -ForegroundColor Yellow
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $regPath -Name "IconsOnly" -Value 0
        Write-Host "Thumbnails enabled in Folder Options."
    } catch {
        Write-Warning ("Failed to set Folder Options registry key: " + $_)
    }

    # 3. Re-register Adobe PDF Thumbnail Handler DLLs
    Write-Host "Re-registering Adobe PDF thumbnail handler DLLs for Acrobat Pro..." -ForegroundColor Yellow

    $dllPaths = @(
        "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\AdobeThumbnail.dll",
        "C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeThumbnail.dll",
        "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\pdfprevhndlr.dll",
        "C:\Program Files\Adobe\Acrobat DC\Acrobat\pdfprevhndlr.dll"
    )

    foreach ($dll in $dllPaths) {
        if (Test-Path $dll) {
            try {
                Write-Host "Unregistering $dll"
                & regsvr32.exe /u /s "$dll"
                Start-Sleep -Seconds 2
                Write-Host "Registering $dll"
                & regsvr32.exe /s "$dll"
                Write-Host "$dll re-registered successfully."
            } catch {
                Write-Warning ("Failed to re-register " + $dll + ": " + $_)
            }
        } else {
            Write-Host "DLL not found: $dll (skipping)"
        }
    }

    # 4. Set Adobe Acrobat Pro as default PDF handler (optional)
    Write-Host "Setting Adobe Acrobat Pro as default PDF handler for .pdf files..." -ForegroundColor Yellow

    function Get-AcrobatProPath {
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe"
        )
        foreach ($p in $paths) {
            try {
                $path = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).'(Default)'
                if ($path -and (Test-Path $path)) {
                    return $path
                }
            } catch {}
        }
        return $null
    }

    $acroProPath = Get-AcrobatProPath
    if ($acroProPath) {
        try {
            $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
    <Association Identifier=".pdf" ProgId="AcroExch.Document.DC" ApplicationName="Adobe Acrobat Pro DC" />
</DefaultAssociations>
"@
            $xmlPath = "$env:TEMP\pdf_default_assoc.xml"
            $xmlContent | Out-File -FilePath $xmlPath -Encoding UTF8

            Write-Host "Applying PDF default association using DISM..."
            Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Import-DefaultAppAssociations:$xmlPath" -Wait

            Remove-Item $xmlPath -Force

            Write-Host "Default PDF handler set to Adobe Acrobat Pro DC."
        } catch {
            Write-Warning ("Failed to set default PDF handler: " + $_)
        }
    } else {
        Write-Warning "Adobe Acrobat Pro executable not found in registry. Skipping default PDF handler change."
    }

    # 5. Restart Explorer to apply changes
    Write-Host "Restarting Windows Explorer to apply changes..." -ForegroundColor Yellow
    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
    try {
        Get-Process explorer | Stop-Process -Force
        Start-Sleep -Seconds 2
        Start-Process explorer.exe
        Write-Host "Explorer restarted."
    } catch {
        Write-Warning ("Failed to restart Explorer: " + $_)
    }

    Write-Host "Adobe Acrobat Pro PDF thumbnail fix completed." -ForegroundColor Green
}

Function Refresh-Desktop {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DesktopFocus {
    [DllImport("user32.dll")]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    
    [DllImport("user32.dll")]
    public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    
    public static void Refresh() {
        IntPtr hDesktop = FindWindow("Progman", "Program Manager");
        if (hDesktop != IntPtr.Zero) {
            SetForegroundWindow(hDesktop);

            const byte VK_F5 = 0x74;
            const uint KEYEVENTF_KEYUP = 0x2;

            keybd_event(VK_F5, 0, 0, UIntPtr.Zero);        // Key down
            keybd_event(VK_F5, 0, KEYEVENTF_KEYUP, UIntPtr.Zero); // Key up
        }
    }
}
"@
    [DesktopFocus]::Refresh()
    Write-Host "Desktop refreshed successfully!" -ForegroundColor Green
}

Function Ins-AcrobatPro
{
    Unins-Acrobat
    #Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Host -f C "`r`n *** Installing Adobe Acrobat Pro DC *** `r`n"
    Try{Set-MpPreference -DisableRealtimeMonitoring $true -ea SilentlyContinue | out-null} Catch{}
    Stop-Service -Name "WinDefend" -Force -ea SilentlyContinue | out-null
    #1J__cfWkRhPfKRi0kANnxcu53rZ74Cyz1
    Start-BitsTransfer -Source 'https://www.googleapis.com/drive/v3/files/1J__cfWkRhPfKRi0kANnxcu53rZ74Cyz1?alt=media&key=AIzaSyBjpiLnU2lhQG4uBq0jJDogcj0pOIR9TQ8' -Destination "$env:TEMP\AdobeAcrobatProDCx64.exe"  -ea SilentlyContinue | out-null
    Start-Job -Name AcrobatPro {if (Test-Path -Path "$env:TEMP\AdobeAcrobatProDCx64.exe" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcrobatProDCx64.exe" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    Remove-Item -path $ENV:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db -Force -ea silentlycontinue | Out-Null
    $printer = Get-CimInstance -Class Win32_Printer -Filter "Name='Adobe PDF'"
    Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter
    (New-Object -ComObject WScript.Network).SetDefaultPrinter('Adobe PDF')
    Fix-AdobeAcrobatProPdfThumbnails
    Start-Sleep 5
    Refresh-Desktop
}

Function Ins-WinRAR
{
    Write-Host -f C "`r`n *** Installing WinRAR *** `r`n"
    if (choco list --lo -r -e winrar) {Choco upgrade winrar --ignore-checksums} else {Choco install winrar --ignore-checksums -y}
    winget install -e --id 'RARLab.WinRAR' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-KLiteMega
{
    Write-Host -f C "`r`n *** Installing K-Lite Codec Pack Mega *** `r`n"
    if (choco list --lo -r -e k-litecodecpackmega) {Choco upgrade k-litecodecpackmega} else {Choco install k-litecodecpackmega -y}
    winget install -e --id 'CodecGuide.K-LiteCodecPack.Mega' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-VLC
{
    Write-Host -f C "`r`n *** Installing VLC *** `r`n"
    winget install -e --id 'VideoLAN.VLC' --silent --accept-source-agreements --accept-package-agreements
    winget install -e --id 'XPDM1ZW6815MQM' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-PaintDotNet
{
    Write-Host -f C "`r`n *** Installing Paint.net *** `r`n"
    winget install -e --id 'dotPDN.PaintDotNet' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-GIMP
{
    Write-Host -f C "`r`n *** Installing GIMP *** `r`n"
    winget install -e --id 'GIMP.GIMP' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-OpenAl
{
    Write-Host -f C "`r`n *** Installing OpenAl *** `r`n"
    if (choco list --lo -r -e openal) {Choco upgrade openal} else {Choco install openal -y}
}

Function Ins-WhatsApp
{
    Write-Host -f C "`r`n *** Installing MS store WhatsApp *** `r`n"
    winget install -e --name 'WhatsApp' --id '9NKSQGP7F2NH' --source 'msstore' --silent --accept-source-agreements --accept-package-agreements
    # Pin MS store Whatsapp to taskbar
    Pin-to-taskbar -IDorPath "WhatsAppDesktop" -PinType "AppUserModelID" -SearchID
}

Function Unins-Devhome
{
    Write-Host -f C "`r`n *** Uninstalling Dev Home *** `r`n"
    Remove-AppxApp -AppName "DevHome"
    winget uninstall --id 'Microsoft.DevHome'
}

Function Unins-DropboxPromotion
{
    Write-Host -f C "`r`n *** Uninstalling Dropbox promotion *** `r`n"
    Remove-AppxApp -AppName "DropboxOEM"
}

Function Unins-Cortana
{
    Write-Host -f C "`r`n *** Uninstalling & disabling Cortana & tweaking search *** `r`n"
    Remove-AppxApp -AppName "Microsoft.549981C3F5F10"
    winget uninstall cortana
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortanaAboveLock' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search' 'CortanaConsent' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowSearchToUseLocation' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCloudSearch' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'EnableDynamicContentInWSB' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings' 'IsDynamicSearchBoxEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' '0' 'DWord'
}

Function Unins-Copilot
{
    Write-Host -f C "`r`n *** Uninstalling & disabling Copilot *** `r`n"
    Remove-AppxApp -AppName "Copilot"
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
    AddRegEntry 'HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
    # remove copilot from taskbar
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowCopilotButton' '0' 'DWord'
    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
    Stop-Process -ProcessName explorer -Force -ea SilentlyContinue | out-null
}

Function Unins-Xbox
{
    Write-Host -f C "`r`n *** Uninstalling Xbox & Game Bar *** `r`n"
    Remove-AppxApp -AppName "Xbox"
    AddRegEntry "HKLM:\System\CurrentControlSet\Services\xbgm" "Start" '4' 'DWORD'
    Set-Service -Name XblAuthManager -StartupType Disabled -ea silentlycontinue | out-null
    Set-Service -Name XblGameSave -StartupType Disabled -ea silentlycontinue | out-null
    Set-Service -Name XboxGipSvc -StartupType Disabled -ea silentlycontinue | out-null
    Set-Service -Name XboxNetApiSvc -StartupType Disabled -ea silentlycontinue | out-null
    # Disabling scheduled tasks
    Get-ScheduledTask -TaskName 'XblGameSaveTask' | Disable-ScheduledTask -ea silentlycontinue | out-null
    #  Disable Game DVR
    AddRegEntry 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR' 'value' '0' 'DWord'
    AddRegEntry 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR' 'AllowgameDVR' '0' 'DWORD'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' '0' 'DWord'
    #  Disable Game Bar
    AddRegEntry 'HKCU:\Software\Microsoft\GameBar' 'AllowAutoGameMode' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled' '0' 'DWord'
}

Function Unins-MSTeams
{
    Write-Host -f C "`r`n *** Uninstalling Microsoft Teams *** `r`n"
    if (Get-Module -Name UninstallTeams -ListAvailable -ea silentlycontinue) {Write-Host -f C "UninstallTeams Module already exists"}
    else {Start-Job -Name UninstallTeams {Install-Module -Name UninstallTeams -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 400 | Format-List -Property Name,State}
    Import-Module UninstallTeams -Force -ea silentlycontinue | out-null
    Install-Script UninstallTeams -Confirm:$False -Force -ea silentlycontinue | out-null
    UninstallTeams -DisableChatWidget -AllUsers
    UninstallTeams -DisableOfficeTeamsInstall
    UninstallTeams
}

Function UpdateAll
{
    Write-Host -f C "`r`n *** Updating all installed applications *** `r`n"
    winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --force
    choco upgrade all -y
    refreshenv
}

Function Ins-DirectX
{
    Write-Host -f C "`r`n *** Installing DirectX Extra Files *** `r`n"
    if (choco list --lo -r -e directx) {Choco upgrade directx} else {Choco install directx -y}
    scoop bucket add games
    scoop install games/dxwrapper
    scoop update dxwrapper
    Start-Job -Name DX-Extra {winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements}
    # Run on command prompt
    #cmd /c "winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements 2>nul"
    # Run on Windows Terminal
    #wt winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements
    #Start-Process 'wt.exe' -Verb RunAs -WindowStyle Minimized -ArgumentList '-p "Windows PowerShell"','winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements'
    # Run on Latest PowerShell
    #try {$PSLatestInstalled = Get-Command -Name pwsh -ea silentlycontinue} catch {}
    #if ($PSLatestInstalled) {pwsh -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -Command "winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements"}
}

Function Windows-Update
{
    Write-Host -f C "`r`n *** Starting Windows Updates *** `r`n"
    # Update reg entries
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpgrade' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpgradePeriod' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpdatePeriod' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate' 'AutoDownload' '4' 'DWord' #Store auto download updates
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload' '4' 'DWord' #Store auto download updates all users policy
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DoNotConnectToWindowsUpdateInternetLocations' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971F918-A847-4430-9279-4A52D1EFE18D' 'RegisteredWithAU' '1' 'DWord' #Microsoft Update
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\855E8A7C-ECB4-4CA3-B045-1DFA50104289' 'RegisteredWithAU' '1' 'DWord' #Windows Store (DCat Prod)
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' 'Start' '3' 'DWord'
    # Start Services
    Start-Service -Name "wuauserv" -ea silentlycontinue | out-null
    Start-Service -Name "UsoSvc" -ea silentlycontinue | out-null
    # Use PSWindowsUpdate Module
    If (-not (Get-Module -ListAvailable -Name PSWindowsUpdateModule)) {Start-Job -Name PSWindowsUpdateModule {Install-Module -Name PSWindowsUpdate -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State}
    Import-Module PSWindowsUpdate -Force -ea silentlycontinue | out-null
    Get-WUServiceManager | Foreach-Object {Add-WUServiceManager -ServiceID $_.ServiceID -Confirm:$false -ea silentlycontinue | out-null}
    Start-Job -Name WindowsUpdate {Get-WindowsUpdate -Install -ForceInstall -AcceptAll -IgnoreReboot -Silent -ea silentlycontinue}
    (New-Object -ComObject Microsoft.Update.ServiceManager).Services | Select Name,ServiceID | foreach {if($_.Name -match "Store"){$StoreServiceID=$_.ServiceID}} #Get Store Service ID
    Start-Job -Name WindowsStoreAppsUpdate {Get-WindowsUpdate -ServiceID $StoreServiceID -Install -ForceInstall -AcceptAll -IgnoreReboot -Silent -ea silentlycontinue}
    # Use kbupdate Module
    try {
        if (-not (Get-Module -ListAvailable -Name kbupdate)) {Install-Module kbupdate -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue}
        Import-Module kbupdate -Force -ea silentlycontinue | out-null
        Get-KbNeededUpdate | Install-KbUpdate -AllNeeded
    } catch {}
    # Old Windows
    (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    usoclient ScanInstallWait
    UsoClient RefreshSettings
    UsoClient StartScan
    UsoClient StartDownload
    usoclient StartInstall
    wuauclt /detectnow /updatenow
}

Function DeepTweaks
{
    Write-Host -f C "`r`n *** Applying Deep Tweaks *** `r`n"
    Write-Host -f C "`r`n *** Stop Integrity check *** `r`n"
    bcdedit /set nointegritychecks on
    Write-Host -f C "`r`n *** Disable nx (DEP) *** `r`n"
    cmd /c 'bcdedit /set {current} nx AlwaysOff'
    Write-Host -f C "`r`n *** tsc Enhanced *** `r`n"
    bcdedit /set tscsyncpolicy Enhanced
    Write-Host -f C "`r`n *** Disable hypervisor *** `r`n"
    bcdedit /set hypervisorlaunchtype off
}

Function Dis-BitLocker
{
    Write-Host -f C "`r`n *** Disabling BitLocker *** `r`n"
    Get-BitLockerVolume | foreach {manage-bde -unlock $_.MountPoint -recoverypassword (Get-BitLockerVolume -MountPoint $_.MountPoint).KeyProtector.RecoveryPassword -ea SilentlyContinue} | out-null
    Get-BitLockerVolume | foreach {manage-bde -off $_.MountPoint} | out-null
    #Clear-BitLockerAutoUnlock -ea SilentlyContinue | out-null
    #Get-BitLockerVolume | foreach {Disable-BitLocker -MountPoint $_.MountPoint -ea SilentlyContinue} | out-null
}

Function EnableSMB1Protocol-Client
{
    #Insecure (only old devices use it).
    AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'SMB1' '1' 'DWORD'
    if ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).state -ne "Enabled") {Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol}
    if ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client).state -ne "Enabled") {Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client}
    if ((Get-SmbServerConfiguration).EnableSMB1Protocol -ne $true) {Set-SmbServerConfiguration -EnableSMB1Protocol $true}
    if ((Get-SmbServerConfiguration).AuditSmb1Access -ne $true) {Set-SmbServerConfiguration -AuditSmb1Access $true}
    Set-SmbServerConfiguration  -EnableSMB1Protocol -Force -Confirm:$false
}

Function CLUA
{
    Write-Host -f C "`r`n *** Activating Classic local users authenticate *** `r`n"
    net user guest /active:yes
    Write-Host -f C "`r`n" | net user guest *
    net user guest /passwordreq:no
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'forceguest' '0' 'DWord' #Use local users authenticate not guest
    net user guest /active:no
}

Function Del-WinDomainCred
{
    Write-Host -f C "`r`n *** Deleting windows Domain credintials (sometimes it's stuck) *** `r`n"
    Write-Host -f C "`r`n Maped drives and saved shared folders credintials will be affected `r`n"
    cmdkey /list | ForEach-Object{
        if($_ -like "*Target: Domain:target=*"){
            $c = ($_ -replace (' ')).split(":", 2)[1]
            cmdkey.exe /delete $c | Out-Null
        }
    }
}

Function Fix-Share
{
    Write-Host -f C "`r`n *** Fixining Windows file sharing *** `r`n"
    CLUA #Classic local users authenticate (Disable the ForceGuest feature)
    Del-WinDomainCred #Delete windows Domain credintials (sometimes it's stuck). Maped drives and saved shared folders credintials will be affected
    if ((Get-SmbServerConfiguration).EnableSMB2Protocol -ne $true) {Set-SmbServerConfiguration -EnableSMB2Protocol $true}
    (get-netconnectionprofile).Name | foreach {set-netconnectionprofile -name $_ -NetworkCategory private} #Make currently connected networks private
    #(New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults(); netsh advfirewall reset #Reset firewall settings (Needed sometimes).
    netsh advfirewall set currentprofile state on
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    Start-Job -Name NFR1 {Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Enable-NetFirewallRule}
    Start-Job -Name NFR2 {Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule}
    Start-Job -Name NFR3 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Private}
    Start-Job -Name NFR4 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Private}
    Start-Job -Name NFR5 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Domain}
    Start-Job -Name NFR6 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Domain}
    Start-Job -Name NFR7 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Public}
    Start-Job -Name NFR8 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Public}
    Start-Job -Name NFR9 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Any}
    Start-Job -Name NFR10 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Any}
    # Make sure required protocols are enabled in the adapter (they should be by default)
    Start-Job -Name NetAdapter1 {Get-NetAdapter | foreach {Enable-NetAdapterBinding -Name $_.Name -DisplayName "File and Printer Sharing for Microsoft Networks" -ea SilentlyContinue | out-null}}
    Start-Job -Name NetAdapter2 {Get-NetAdapter | foreach {Enable-NetAdapterBinding -Name $_.Name -DisplayName "Client for Microsoft Networks" -ea SilentlyContinue | out-null}}
    Remove-Item "$env:windir\System32\GroupPolicyUsers" -Recurse -Force -ea SilentlyContinue | out-null
    Remove-Item "$env:windir\System32\GroupPolicy" -Recurse -Force -ea SilentlyContinue | out-null
    gpupdate /force
    # Get-ComputerInfo -Property CsWorkgroup | Select-Object -ExpandProperty CsWorkgroup
    Add-Computer -WorkGroupName "WORKGROUP" -ea SilentlyContinue | out-null
    Set-SmbClientConfiguration -EnableInsecureGuestLogons:$true -Force -Confirm:$false
    Set-SmbClientConfiguration -SkipCertificateCheck:$true -Force -Confirm:$false
    Set-SmbClientConfiguration -EnableSecuritySignature:$true -Force -Confirm:$false
    Set-SmbClientConfiguration -RequireSecuritySignature:$false -Force -Confirm:$false
    Set-SmbClientConfiguration -ForceSMBEncryptionOverQuic:$false -Force -Confirm:$false
    Set-SmbServerConfiguration -AutoShareServer:$true -Force -Confirm:$false
    Set-SmbServerConfiguration -AutoShareWorkstation:$true -Force -Confirm:$false
    Set-SmbServerConfiguration -EnableAuthenticateUserSharing:$true -Force -Confirm:$false
    Set-SmbServerConfiguration -EnableForcedLogoff:$true -Force -Confirm:$false
    Set-SmbServerConfiguration -EnableSecuritySignature:$true -Force -Confirm:$false
    Set-SmbServerConfiguration -EnableSMB2Protocol:$true -Force -Confirm:$false
    Set-SmbServerConfiguration -EncryptData:$false -Force -Confirm:$false
    Set-SmbServerConfiguration -RejectUnencryptedAccess:$false -Force -Confirm:$false
    Set-SmbServerConfiguration -RequireSecuritySignature:$false -Force -Confirm:$false
    Set-SmbServerConfiguration -RestrictNamedpipeAccessViaQuic:$false -Force -Confirm:$false
    Set-SmbServerConfiguration -RequireSecuritySignature:$false -Force -Confirm:$false
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private' 'AutoSetup' '1' 'DWord' #Setup network connected devices automatically
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinClientSec' '0x20000000' 'DWord' #128
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinServerSec' '0x20000000' 'DWord' #128
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableAuthenticateUserSharing' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' '1' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RejectUnencryptedAccess' '0' 'DWord'
    AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'AutoShareWks' '1' 'DWORD'
    AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'AutoShareServer' '1' 'DWORD'
    AddRegEntry 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' 'EnableSecuritySignature' '1' 'DWord'
    AddRegEntry 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' 'RequireSecuritySignature' '0' 'DWord'
    AddRegEntry 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' 'AllowInsecureGuestAuth' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' '1' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'disabledomaincreds' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'everyoneincludesanonymous' '1' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymous' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymoussam' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SamConnectedAccountsExist' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' '1' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\upnphost' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\lmhosts' 'Start' '2' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'scforceoption' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' 'DevicePasswordLessBuildVersion' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' 'DevicePasswordLessUpdateType' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions' 'value' '1' 'DWord'
}

Function Tweak-schtasks
{
    Write-Host -f C "`r`n *** Disabling scheduled tasks that are considered unnecessary *** `r`n"
    Get-ScheduledTask -TaskName 'Consolidator' | Disable-ScheduledTask -ea SilentlyContinue | out-null
    Get-ScheduledTask -TaskName 'UsbCeip' | Disable-ScheduledTask -ea SilentlyContinue | out-null
    Get-ScheduledTask -TaskName 'DmClient' | Disable-ScheduledTask -ea SilentlyContinue | out-null
    Get-ScheduledTask -TaskName 'DmClientOnScenarioDownload' | Disable-ScheduledTask -ea SilentlyContinue | out-null
}

Function Registry-Tweaks
{
    Write-Host -f C "`r`n *** Applying Registry Tweaks *** `r`n"

    # ===============================
    # DESKTOP ICONS & LAYOUT
    # ===============================

    AddRegEntry "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" "Sort" "0x40000002" 'DWord'
    # Desktop icon sort order. 0x40000002 = sort by Name (ascending).

    $sortBinary = [byte[]] (0x02,0x00,0x00,0x40)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Name "Sort" -Value $sortBinary -Type Binary
    # Same as above in binary form (02 00 00 40 = Name ascending).

    AddRegEntry "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" "FFlags" "0x40200225" 'DWord'
    # Desktop view flags (auto-arrange/align/show icons etc.). Composite flag value.

    AddRegEntry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" '1' 'DWord'
    # Hide Microsoft Edge desktop icon (CLSID).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" '1' 'DWord'
    # Hide OneDrive icon on desktop (CLSID). 0=show, 1=hide.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" '0' 'DWord'
    # Show "User Files" (profile) icon on desktop.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" '0' 'DWord'
    # Show "This PC" icon on desktop.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" '0' 'DWord'
    # Show "Network" icon on desktop.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" '0' 'DWord'
    # Show "Control Panel" icon on desktop.

    # ===============================
    # SMARTSCREEN & REPUTATION-BASED PROTECTION
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' 'String'
    # Explorer SmartScreen (file reputation) policy. "Off" = disabled.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' '0' 'DWord'
    # System policy to disable SmartScreen for apps (0=disabled).

    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
    # Microsoft Edge SmartScreen off for current user.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
    # Microsoft Edge SmartScreen off (machine-wide).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell' 'value' '0' 'DWord'
    # PolicyManager: disable SmartScreen in Shell/Explorer.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl' 'value' '0' 'DWord'
    # PolicyManager: disable app install control (reputation checks).

    AddRegEntry 'HKCU:\Software\Microsoft\Edge\SmartScreenEnabled' 'Default' '0' 'String'
    # Legacy Edge setting: SmartScreen disabled (per-user).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
    # Legacy Edge (Spartan) phishing filter disabled.

    AddRegEntry 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
    # Legacy Edge per-AppContainer phishing filter disabled.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter' 'EnabledV9' '0' 'DWord'
    # Internet Explorer phishing filter disabled.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' '0' 'DWord'
    # Disable SmartScreen for Win32 web content evaluation.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'PreventOverride' '0' 'DWord'
    # Allow user to bypass SmartScreen warnings (0=allow override).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe' 'Debugger' 'ctfmon' 'String'
    # IFEO "Debugger" redirection effectively disables smartscreen.exe (advanced/forceful).

    # ===============================
    # LOCK SCREEN & LOGON EXPERIENCE
    # ===============================

    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10" 'String'
    # Number of cached domain logons allowed.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData' 'AllowLockScreen' '0' 'DWord'
    # Disable lock screen (when possible).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreen' '1' 'DWord'
    # Policy: disable lock screen (1=enabled policy).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableAcrylicBackgroundOnLogon' '1' 'DWord'
    # Disable acrylic blur on Logon screen background.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableLogonBackgroundImage' '0' 'DWord'
    # Keep logon background image (0=use image, 1=solid color).

    Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -force -ea SilentlyContinue | out-null
    # Remove legal notice caption (if exists).

    Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -force -ea SilentlyContinue | out-null
    # Remove legal notice text (if exists).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'dontdisplaylastusername' '0' 'DWord'
    # Show last signed-in user on logon (0=show).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'shutdownwithoutlogon' '1' 'DWord'
    # Allow shutdown from logon screen.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'undockwithoutlogon' '1' 'DWord'
    # Allow undock from logon screen (laptops/docks).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableFirstLogonAnimation' '0' 'DWord'
    # Disable first sign-in animation.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLockedUserId' '3' 'DWord'
    # Show account details on lock screen: 3 = do not display name/email.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableForcedLogoff' '1' 'DWord'
    # Force logoff of users when logon hours expire.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' '0' 'DWord'
    # Disable Start/Lock screen suggestions/ads.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenEnabled' '0' 'DWord'
    # Disable Windows Spotlight on lock screen.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenOverlayEnabled' '0' 'DWord'
    # Disable lock screen tips on Spotlight.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' '1' 'DWord'
    # Disable camera on lock screen.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen' 'SlideshowDuration' '0' 'DWord'
    # Lock screen slideshow duration (0 = default/disabled slideshow).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\AccessPage\Camera' 'CameraEnabled' '0' 'DWord'
    # Disable camera access on sign-in UI.

    # ===============================
    # DOWNLOADED FILES / ATTACHMENTS
    # ===============================

    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -force -ea SilentlyContinue | out-null
    # Clear existing machine Attachment policies (reset).

    Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -force -ea SilentlyContinue | out-null
    # Clear existing user Attachment policies (reset).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' '1' 'DWord'
    # Preserve Zone.Identifier (Mark-of-the-Web) on downloads (1=save). NOTE: enables MOTW.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' '1' 'DWord'
    # Same at user level.

    AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations' 'DefaultFileTypeRisk' '24914' 'DWord'
    # File association security risk level (affects warning prompts).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations' 'DefaultFileTypeRisk' '24914' 'DWord'
    # Same at user level.

    # ===============================
    # HARDWARE ACCELERATED GPU SCHEDULING (HAGS)
    # ===============================

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' '2' 'DWord'
    # Enable HAGS (2=enable, 1=default/driver, 0=disable).

    # ===============================
    # BACKGROUND APPS
    # ===============================

    AddRegEntry 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled' '0' 'DWord'
    # Allow background apps (0=enabled). Set to 1 to block; kept 0 to avoid issues.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'BackgroundAppGlobalToggle' '1' 'DWord'
    # Enable background search components.

    # ===============================
    # FAST STARTUP / BOOT ANIMATION
    # ===============================

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HybridBootAnimationTime' '0' 'DWord'
    # Set Fast Startup animation duration (0 = minimal/none).

    # ===============================
    # SPECTRE/MELTDOWN (KERNEL MITIGATIONS)
    # ===============================

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride' '3' 'DWord'
    # Disable certain CPU vulnerability mitigations (bitmask). 3 commonly disables Spectre/Meltdown mitigations.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverrideMask' '3' 'DWord'
    # Mask for above override (which bits are considered).

    # ===============================
    # OFFLINE MAPS
    # ===============================

    AddRegEntry 'HKLM:\SYSTEM\Maps' 'AutoUpdateEnabled' '0' 'DWord'
    # Disable automatic offline maps updates.

    # ===============================
    # TELEMETRY / DIAGNOSTICS / FEEDBACK / Privacy
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' '0' 'DWord'
    # Telemetry level (0=Security/Minimum; Home/Pro may map to Basic).

    AddRegEntry 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' '0' 'DWord'
    # Feedback frequency count (0 = never prompt).

    Remove-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -force -ea SilentlyContinue | out-null
    # Remove feedback timing window (reset).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'AllowCommercialDataPipeline' '0' 'DWord'
    # Disable commercial data pipeline (diagnostics sharing).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'FeedbackHubAlwaysSaveDiagnosticsLocally' '0' 'DWord'
    # Do not force Feedback Hub to save diagnostics locally.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'LimitEnhancedDiagnosticDataWindowsAnalytics' '1' 'DWord'
    # Limit diagnostic data used by Windows Analytics.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' 'PreventHandwritingDataSharing' '1' 'DWord'
    # Prevent sharing handwriting data.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' 'PreventHandwritingErrorReports' '1' 'DWord'
    # Block handwriting error reports.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' '0' 'DWord'
    # Disable Timeline/Activity feed (global).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' '0' 'DWord'
    # Block publishing user activities.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' '0' 'DWord'
    # Block uploading user activities.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' 'Start' '0' 'DWord'
    # Disable Diagnostics Tracking autologger.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'UserFeedbackAllowed' '0' 'DWord'
    # Disable user feedback in Edge.

    AddRegEntry 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' '1' 'DWord'
    # Block implicit inking data collection.

    AddRegEntry 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' '1' 'DWord'
    # Block implicit text input data collection.

    AddRegEntry 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' '0' 'DWord'
    # Do not harvest contacts for personalization.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' '0' 'DWord'
    # Disable input personalization.

    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' '1' 'DWord'
    # Disable local AI features analyzing user data (current user).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' '1' 'DWord'
    # Disable local AI data analysis (machine-wide).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' '1' 'DWord'
    # Limit diagnostic log collection.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' '1' 'DWord'
    # Disable OneSettings (content/experiment) downloads.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' '1' 'DWord'
    # Do not show feedback notifications.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry' '0' 'DWord'
    # Redundant telemetry minimum (backup location).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' '0' 'DWord'
    # Disable tailored experiences based on diagnostics (system).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' '0' 'DWord'
    # Disable tailored experiences (user).

    AddRegEntry 'HKCU:\Software\Microsoft\Siuf\Rules' 'PeriodInNanoSeconds' '0' 'DWord'
    # Set feedback period to 0 (never prompt).

    AddRegEntry 'HKCU:\Software\Microsoft\MediaPlayer\Preferences' 'UsageTracking' '0' 'DWord'
    # Disable Windows Media Player usage tracking.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_TrackDocs' '0' 'DWord'
    # Do not track recently opened items for Start.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack' 'Start' '4' 'DWord'
    # Disable Connected User Experiences and Telemetry service (DiagTrack). 4=Disabled.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'HideRecentlyAddedApps' '0' 'DWord'
    # Show recently added apps (0=show). (Note: later you also disable some Start suggestions.)

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpyNetReporting' '0' 'DWord'
    # Disable Microsoft MAPS cloud reporting.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' '2' 'DWord'
    # Prompt before sending samples (2=never send automatically).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' 'DontReportInfectionInformation' '1' 'DWord'
    # Malicious Software Removal Tool: don't report infection info.

    # ===============================
    # PRINTING
    # ===============================

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'SpoolerPriority' '128' 'DWord'
    # Raise print spooler priority (higher value = more priority).

    AddRegEntry 'HKCU:\Control Panel\International' 'iPaperSize' '9' 'String'
    # Default paper size (9 = A4).

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International' 'iPaperSize' '9' 'String'
    # Machine default paper size A4.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'KMPrintersAreBlocked' '0' 'DWord'
    # Do not block KM (Konica Minolta) printers.

    # ===============================
    # STARTUP / PERFORMANCE CLEANUP
    # ===============================

    Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -ea SilentlyContinue | out-null
    # Clear per-user startup entries.

    Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification"  -Recurse -force -ea SilentlyContinue | out-null
    # Clear per-user startup notifications list.

    Remove-Item -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -ea SilentlyContinue | out-null
    # Clear 32-bit machine-wide startup entries.

    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -ea SilentlyContinue | out-null
    # Clear machine-wide startup entries.

    # ===============================
    # SERVICES START TYPE / DISABLES
    # ===============================

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager' 'Start' '3' 'DWord'
    # License Manager service: Manual (3).

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent' 'Start' '3' 'DWord'
    # OpenSSH Authentication Agent: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPAppHelperCap' 'Start' '3' 'DWord'
    # HP Telemetry/Helper services: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPCustomCapDriver' 'Start' '3' 'DWord'
    # HP custom capture driver: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPDiagsCap' 'Start' '3' 'DWord'
    # HP diagnostics capture: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPNetworkCap' 'Start' '3' 'DWord'
    # HP network capture: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPPrintScanDoctorService' 'Start' '3' 'DWord'
    # HP Print and Scan Doctor service: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\hpqcaslwmiex' 'Start' '3' 'DWord'
    # HP CASL WMI Ex: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSmartDeviceAgentBase' 'Start' '3' 'DWord'
    # HP Smart Device Agent: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSupportSolutionsFrameworkService' 'Start' '3' 'DWord'
    # HP Support Solutions Framework: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSysInfoCap' 'Start' '3' 'DWord'
    # HP System Info capture: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HpTouchpointAnalyticsService' 'Start' '3' 'DWord'
    # HP Touchpoint Analytics: Manual (instead of auto).

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\RstMwService' 'Start' '3' 'DWord'
    # Intel RST (Management/WMI) service: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Intel R Capability Licensing Service TCP IP Interface' 'Start' '3' 'DWord'
    # Intel Capability Licensing Service: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SECOMNService' 'Start' '3' 'DWord'
    # Intel/Third-party service (common): Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\USER_ESRV_SVC_QUEENCREEK' 'Start' '3' 'DWord'
    # Intel Energy Server Service (power telemetry): Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Intel R SUR QC SAM' 'Start' '3' 'DWord'
    # Intel System Usage Report (SUR) service: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\jhi_service' 'Start' '3' 'DWord'
    # Intel Dynamic Application Loader Host Interface: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SystemUsageReportSvc_QUEENCREEK' 'Start' '3' 'DWord'
    # Intel System Usage Report Svc: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service' 'Start' '3' 'DWord'
    # Apple Mobile Device service: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\MozillaMaintenance' 'Start' '3' 'DWord'
    # Mozilla Maintenance service: Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WsAppService3' 'Start' '3' 'DWord'
    # Wacom/Workspace App service (common name): Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ESRV_SVC_QUEENCREEK' 'run' '0' 'DWord'
    # Intel ESRV flag 'run' off.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ESRV_SVC_QUEENCREEK' 'Start' '3' 'DWord'
    # Intel ESRV start type Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch' 'Start' '3' 'DWord'
    # Windows Search start type Manual.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SysMain' 'Start' '4' 'DWord'
    # SysMain (Superfetch) disabled.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice' 'Start' '4' 'DWord'
    # WAP Push Message Routing service disabled.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVPN App Service' 'Start' '4' 'DWord'
    # ExpressVPN App Service disabled.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVPN System Service' 'Start' '4' 'DWord'
    # ExpressVPN System Service disabled.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVPN VPN Service' 'Start' '4' 'DWord'
    # ExpressVPN VPN Service disabled.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc' 'Start' '4' 'DWord'
    # Windows Error Reporting service disabled.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' '1' 'DWord'
    # Disable Windows Error Reporting (policy).

    # ===============================
    # Improve shutdown & responsiveness
    # ===============================
    
    AddRegEntry 'HKCU:\Control Panel\Desktop' 'AutoEndTasks' '1' 'String'
    # Automatically end tasks at logoff/shutdown.

    AddRegEntry 'HKCU:\Control Panel\Desktop' 'SmoothScroll' '0' 'DWord'
    # Disable smooth scrolling in UI.

    AddRegEntry 'HKCU:\Control Panel\Desktop' 'WaitToKillAppTimeout' '1500' 'String'
    # App kill timeout (ms) when logging off/shutdown.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control' 'WaitToKillServiceTimeout' '1500' 'String'
    # Service kill timeout (ms) on shutdown.

    AddRegEntry 'HKCU:\Control Panel\Desktop' 'HungAppTimeout' '1500' 'String'
    # Hung app timeout (ms) before "Not responding".

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoRestartShell' '1' 'DWord'
    # Automatically restart Explorer shell if it crashes.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'IRQ8Priority' '1' 'DWord'
    # Give system clock (IRQ8) priority boost (legacy tweak).

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher' '0' 'DWord'
    # Disable Prefetcher (0=disable).

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnableSuperfetch' '0' 'DWord'
    # Disable Superfetch (SysMain) (legacy; service also disabled above).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter' 'NoMobilityCenter' '1' 'DWord'
    # Disable Windows Mobility Center UI.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoInstrumentation' '1' 'DWord'
    # Disable shell instrumentation (reduces certain data collection).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' 'AllowWindowsInkWorkspace' '0' 'DWord'
    # Disable Windows Ink Workspace.

    AddRegEntry 'HKCU:\Software\Microsoft\input\TIPC' 'Enabled' '0' 'DWord'
    # Disable Text Input Processor features (TIPC).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' 'CEIPEnable' '0' 'DWord'
    # Disable Customer Experience Improvement Program.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' '1' 'DWord'
    # Disable application inventory.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableUAR' '1' 'DWord'
    # Disable Program Compatibility Assistant (User Account Reporting).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' '0' 'DWord'
    # Disable Application Impact Telemetry.

    # ===============================
    # TASKBAR / SEARCH
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoChangeStartMenu' '0' 'DWord'
    # Allow Start menu changes (0=allow).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAl' '0' 'DWord'
    # Taskbar alignment: 0=Left, 1=Center.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowTaskViewButton' '0' 'DWord'
    # Hide Task View button on taskbar.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' '0' 'DWord'
    # Hide Chat (Meet/Teams) button.

    AddRegEntry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds' 'EnableFeeds' '0' 'DWord'
    # Hide News and Interests/Feeds.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' '1' 'DWord'
    # Hide Meet Now (user policy).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' '1' 'DWord'
    # Hide Meet Now (machine policy).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' 'PeopleBand' '0' 'DWord'
    # Hide People band on taskbar (0=hide).

    AddRegEntry 'HKLM:\Software\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' '0' 'DWord'
    # Disable Widgets/Feeds (policy).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'SearchboxTaskbarMode' '1' 'DWord'
    # Taskbar search: 0=hide, 1=icon only, 2=search box, 3=icon+label.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarDa' '0' 'DWord'
    # Disable Widgets button on taskbar.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' 'ShellFeedsTaskbarViewMode' '2' 'DWord'
    # Feeds taskbar view mode (2=off/hidden).

    # ===============================
    # BIOMETRICS
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' 'Enabled' '1' 'DWord'
    # Allow biometric features (Windows Hello).

    # ===============================
    # CLIPBOARD
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowClipboardHistory' '1' 'DWord'
    # Enable clipboard history.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard' '0' 'DWord'
    # Disable clipboard sync across devices.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ClipboardHistory' 'SyncPolicy' '5' 'DWord'
    # Clipboard sync policy: 5 = disabled/not allowed.

    # ===============================
    # SETTING SYNC (MICROSOFT ACCOUNT)
    # ===============================

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization' 'Enabled' '0' 'DWord'
    # Disable sync for Personalization.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings' 'Enabled' '0' 'DWord'
    # Disable sync for Browser settings.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials' 'Enabled' '0' 'DWord'
    # Disable sync for passwords/credentials.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language' 'Enabled' '0' 'DWord'
    # Disable sync for Language.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility' 'Enabled' '0' 'DWord'
    # Disable sync for Accessibility.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows' 'Enabled' '0' 'DWord'
    # Disable sync for Windows settings group.

    # ===============================
    # GENERAL TWEAKS
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AutoDownloadAndUpdateMapData' '0' 'DWord'
    # Disable automatic map data download/update.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableUwpStartupTasks' '1' 'DWord'
    # Enable UWP apps registering startup tasks. (to avoid issues)

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'SupportUwpStartupTasks' '1' 'DWord'
    # support UWP startup tasks. (to avoid issues)

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableVirtualization' '1' 'DWord'
    # Enable UAC virtualization for legacy apps.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' '0' 'DWord'
    # Prevent silent installation of suggested apps.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' '0' 'DWord'
    # Disable soft landing tips/first-run suggestions.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' '0' 'DWord'
    # Disable post-OOBE "Get even more out of Windows" (SCOOBE).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' '0' 'DWord'
    # Disable Remote Assistance invitations.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' '1' 'DWord'
    # Deny Remote Desktop (RDP) connections.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' 'NoGenTicket' '0' 'DWord'
    # Allow generation of Windows Store licensing tickets (UWP license gen). (to Avoid issues).

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AllowUntriggeredNetworkTrafficOnSettingsPage' '0' 'DWord'
    # Block background network traffic on Maps settings page.

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' 'EnableActiveProbing' '0' 'DWord'
    # Disable active Internet connectivity probing (NCSI). May affect captive portal detection.

    AddRegEntry 'HKU:\.DEFAULT\Control Panel\Keyboard' 'InitialKeyboardIndicators' '2147483650' 'String'
    # NumLock state at logon for default profile (2147483650 = NumLock ON for all users).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput' 'EnableTouchKeyboardAutoInvokeInDesktopMode' '0' 'DWord'
    # Prevent touch keyboard from auto-appearing in desktop mode.

    AddRegEntry 'HKLM:\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' '0' 'DWord'
    # Unpin OneDrive from File Explorer navigation pane.

    AddRegEntry 'HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}' 'SortOrderIndex' '84' 'DWord'
    # Libraries display order index in navigation pane.

    AddRegEntry 'HKLM:\SOFTWARE\Classes\AllFilesystemObjects' 'DefaultDropEffect' '0' 'DWord'
    # Default drag & drop effect (0=ask/none, 1=copy, 2=move, 4=link). Here 0 leaves default behavior.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'ShowDriveLettersFirst' '0' 'DWord'
    # Show drive letters: 0=after label (default), 1=before, 2=hide network, 4=hide local.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'Link' 'hex 3:00,00,00,00' 'String'
    # Remove " - Shortcut" suffix on new shortcuts (per-user).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'Link' 'hex 3:00,00,00,00' 'String'
    # Remove " - Shortcut" suffix (machine-wide).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'DisablePreviewDesktop' '0' 'DWord'
    # Peek at desktop when hovering taskbar (0=allow).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoPreviewPane' '0' 'DWord'
    # Allow Preview Pane in Explorer (0=allow).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoLowDiskSpaceChecks' '1' 'DWord'
    # Disable low disk space warnings.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' 'ModelDownloadAllowed' '0' 'DWord'
    # Block speech model downloads (OneCore).

    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'fullprivilegeauditing' '0' 'DWord'
    # LSA privilege use auditing disabled (0). (1 enables detailed audits).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowAllTrustedApps' '1' 'DWord'
    # Allow sideloading of trusted apps.

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowDevelopmentWithoutDevLicense' '1' 'DWord'
    # Allow developer mode for sideloading without Dev license.

    # ===============================
    # NOTIFICATIONS
    # ===============================

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'NOC_GLOBAL_SETTING_TOASTS_ENABLED' '0' 'DWord'
    # Turn off all toast notifications (user).
    
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' 'ToastEnabled' '0' 'DWord'
    # Disable toast notifications globally (note: many specific toasts are disabled).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK' '0' 'DWord'
    # Block notifications above lock screen.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSyncProviderNotifications' '0' 'DWord'
    # Disable OneDrive/Sync provider marketing notifications.

    # ===============================
    # ADVERTISING / SUGGESTIONS
    # ===============================

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' '0' 'DWord'
    # Disable advertising ID (system).

    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' 'AllowAdvertising' '0' 'DWord'
    # Block Bluetooth advertising features.

    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging' 'AllowMessageSync' '0' 'DWord'
    # Disable message sync (SMS) to cloud.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353698Enabled' '0' 'DWord'
    # Disable suggested content tile (various IDs below are different slots).

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' '0' 'DWord'
    # Disable suggested content tile.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' '0' 'DWord'
    # Disable suggested content tile.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' '0' 'DWord'
    # Disable suggested content tile.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' '0' 'DWord'
    # Disable suggested content tile.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' '0' 'DWord'
    # Disable suggested content tile.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' '0' 'DWord'
    # Disable suggested content tile.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338387Enabled' '0' 'DWord'
    # Disable suggested content tile.

    # ===============================
    # FOCUS ASSIST
    # ===============================

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\QuietHours' 'QuietHoursEnabled' '1' 'DWord'
    # Enable Focus Assist.

    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\QuietHours' 'QuietHoursActive' '1' 'DWord'
    # Focus Assist active (Priority only by default).
}


Function ShrinkC-MakeNew
{
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$DriveLetter
    )
    if (Get-Volume -DriveLetter $DriveLetter -ea SilentlyContinue) {Write-warning "Partition $DriveLetter already exist";return}
    $CSizeMax = (Get-PartitionSupportedSize -DriveLetter C).SizeMax
    $CSizeMin = (Get-PartitionSupportedSize -DriveLetter C).SizeMin
    $CShrink = ($CSizeMax - $CSizeMin)/1000000000 #Shrinkable amount in GB
    if ($CShrink -gt 70)
    {
        Resize-Partition -DriveLetter C -Size ($CSizeMax - 50GB) -ea SilentlyContinue | out-null
        $CDiskNumber = (Get-Volume | where DriveLetter -eq "C" | Get-Partition | Get-Disk).Number
        New-Partition -DiskNumber $CDiskNumber -UseMaximumSize -DriveLetter $DriveLetter -ea SilentlyContinue | out-null
        Format-Volume -DriveLetter $DriveLetter -FileSystem NTFS -Force -ea SilentlyContinue | out-null
    }
    else {Write-Host -f C "`r`n Not Enough shrinkable Space on Partition C"}
}

Function D-ScanFolder
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "************************* Creating Drive D (If not found) & Creating shared Scan folder in it **************************"
    Write-Host -f C "======================================================================================================================`r`n" 
    if (!(Get-Volume -DriveLetter D -ea SilentlyContinue)) {ShrinkC-MakeNew "D"}
    elseif ((Get-Volume -DriveLetter D -ea SilentlyContinue).DriveType -ne "Fixed")
    {
        try{$successful = $true;Set-WmiInstance -InputObject (Get-WmiObject -Class Win32_volume -Filter "DriveLetter = 'd:'" ) -Arguments @{DriveLetter='Z:'}}
        catch{$successful = $false;Write-Host -f C "Busy Removable Partition D"}
        if ($successful) {ShrinkC-MakeNew "D"}
    }
    if ((Get-Volume -DriveLetter D -ea SilentlyContinue).DriveType -eq "Fixed")
    {
        if (!(Test-Path -Path "D:\Scans" -ea SilentlyContinue)) {New-Item -Path "D:\" -Name "Scans" -ItemType Directory -ea SilentlyContinue | out-null}
        Remove-SmbShare -Name "Scans" -Confirm:$False -Force -ea silentlycontinue | out-null
        if (!([System.IO.Directory]::Exists("\\localhost\Scans"))) {New-SmbShare -Name "Scans" -Path "D:\Scans" -FullAccess "Everyone" -ea SilentlyContinue | out-null}
        else {Grant-SmbShareAccess -Name "Scans" -AccountName "Everyone" -AccessRight Full -Force -ea SilentlyContinue | out-null}
        $s=(New-Object -COM WScript.Shell).CreateShortcut("$env:PUBLIC\Desktop\Scans.lnk");$s.TargetPath="D:\Scans\";$s.Save()
    }
    Remove-SmbShare -Name "Users" -Confirm:$False -Force -ea silentlycontinue | out-null
}

Function Adj-Hosts
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Adjusting Hosts file *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    Write-Host -f C "`r`n Taking ownership of hosts file"
    AdminTakeownership -Path "$env:WinDir\System32\drivers\etc\hosts"
    $HostsFile =
@"
#<localhost>
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 localhost
127.0.0.1 local
#</localhost>
   
#<block-iobit>
127.0.0.1 pf.iobit.com
127.0.0.1 iunins.iobit.com
127.0.0.1 sd.iobit.com
127.0.0.1 idb.iobit.com
127.0.0.1 asc55.iobit.com
127.0.0.1 is360.iobit.com
127.0.0.1 asc.iobit.com
#</block-iobit>
    
#<block-wondershare>
127.0.0.1 account.wondershare.com
127.0.0.1 platform.wondershare.com
127.0.0.1 cbs.wondershare.com
127.0.0.1 macplatform.wondershare.com
127.0.0.1 pc-api.wondershare.cc
127.0.0.1 analytics.wondershare.cc
127.0.0.1 cloud-api.wondershare.cc
127.0.0.1 sparrow.wondershare.com
127.0.0.1 wae.wondershare.cc
127.0.0.1 api.wondershare.com
127.0.0.1 antipiracy.wondershare.com
127.0.0.1 wondershare.com
127.0.0.1 mail.insidews.wondershare.com
#</block-wondershare>
    
#<block-adobe>
127.0.0.1 activate.adobe.com
127.0.0.1 practivate.adobe.com
127.0.0.1 ereg.adobe.com
127.0.0.1 wip3.adobe.com
127.0.0.1 activate.wip3.adobe.com
127.0.0.1 3dns-3.adobe.com
127.0.0.1 3dns-2.adobe.com
127.0.0.1 adobe-dns.adobe.com
127.0.0.1 adobe-dns-2.adobe.com
127.0.0.1 adobe-dns-3.adobe.com
127.0.0.1 ereg.wip3.adobe.com
127.0.0.1 activate-sea.adobe.com
127.0.0.1 wwis-dubc1-vip60.adobe.com
127.0.0.1 activate-sjc0.adobe.com
127.0.0.1 hl2rcv.adobe.com
127.0.0.1 lm.licenses.adobe.com
127.0.0.1 na2m-pr.licenses.adobe.com
127.0.0.1 lmlicenses.wip4.adobe.com
127.0.0.1 na1r.services.adobe.com
127.0.0.1 hlrcv.stage.adobe.com
127.0.0.1 3dns-1.adobe.com
127.0.0.1 3dns-4.adobe.com
127.0.0.1 3dns-5.adobe.com
127.0.0.1 3dns.adobe.com
127.0.0.1 activate-sea.adobe.de
127.0.0.1 activate-sjc0.adobe.de
127.0.0.1 activate.adobe.de
127.0.0.1 activate.wip.adobe.com
127.0.0.1 activate.wip1.adobe.com
127.0.0.1 activate.wip2.adobe.com
127.0.0.1 activate.wip3.adobe.de
127.0.0.1 activate.wip4.adobe.com
127.0.0.1 adobe-dns-1.adobe.com
127.0.0.1 adobe-dns-2.adobe.de
127.0.0.1 adobe-dns-3.adobe.de
127.0.0.1 adobe-dns-4.adobe.com
127.0.0.1 adobe-dns.adobe.de
127.0.0.1 adobe.activate.com
127.0.0.1 adobeereg.com
127.0.0.1 cmdls.adobe.com
127.0.0.1 wip.adobe.com
127.0.0.1 wip1.adobe.com
127.0.0.1 wip2.adobe.com
127.0.0.1 wip4.adobe.com
127.0.0.1 genuine.adobe.com
127.0.0.1 www.adobeereg.com
127.0.0.1 www.wip.adobe.com
127.0.0.1 www.wip1.adobe.com
127.0.0.1 www.wip2.adobe.com
127.0.0.1 www.wip3.adobe.com
127.0.0.1 www.wip4.adobe.com
127.0.0.1 ereg.wip.adobe.com
127.0.0.1 ereg.wip1.adobe.com
127.0.0.1 ereg.wip2.adobe.com
127.0.0.1 ereg.wip4.adobe.com
127.0.0.1 cc-api-data.adobe.io
127.0.0.1 practivate.adobe.ntp
127.0.0.1 practivate.adobe.ipp
127.0.0.1 prod.adobegenuine.com
127.0.0.1 practivate.adobe.newoa
127.0.0.1 uds.licenses.adobe.com
127.0.0.1 k.sni.global.fastly.net
127.0.0.1 ereg.adobe.de
127.0.0.1 hl2rcv.adobe.de
127.0.0.1 ims-na1-prprod.adobelogin.com
127.0.0.1 na2m-stg2.licenses.adobe.com
127.0.0.1 na4r.services.adobe.com
127.0.0.1 practivate.adobe
127.0.0.1 practivate.adobe.
127.0.0.1 practivate.adobe.de
127.0.0.1 prod-rel-ffc-ccm.oobesaas.adobe.com
127.0.0.1 s-2.adobe.com
127.0.0.1 s-3.adobe.com
127.0.0.1 wwis-dubc1-vip100.adobe.com
127.0.0.1 wwis-dubc1-vip101.adobe.com
127.0.0.1 wwis-dubc1-vip102.adobe.com
127.0.0.1 wwis-dubc1-vip103.adobe.com
127.0.0.1 wwis-dubc1-vip104.adobe.com
127.0.0.1 wwis-dubc1-vip105.adobe.com
127.0.0.1 wwis-dubc1-vip106.adobe.com
127.0.0.1 wwis-dubc1-vip107.adobe.com
127.0.0.1 wwis-dubc1-vip108.adobe.com
127.0.0.1 wwis-dubc1-vip109.adobe.com
127.0.0.1 wwis-dubc1-vip110.adobe.com
127.0.0.1 wwis-dubc1-vip111.adobe.com
127.0.0.1 wwis-dubc1-vip112.adobe.com
127.0.0.1 wwis-dubc1-vip113.adobe.com
127.0.0.1 wwis-dubc1-vip114.adobe.com
127.0.0.1 wwis-dubc1-vip115.adobe.com
127.0.0.1 wwis-dubc1-vip116.adobe.com
127.0.0.1 wwis-dubc1-vip117.adobe.com
127.0.0.1 wwis-dubc1-vip118.adobe.com
127.0.0.1 wwis-dubc1-vip119.adobe.com
127.0.0.1 wwis-dubc1-vip120.adobe.com
127.0.0.1 wwis-dubc1-vip121.adobe.com
127.0.0.1 wwis-dubc1-vip122.adobe.com
127.0.0.1 wwis-dubc1-vip123.adobe.com
127.0.0.1 wwis-dubc1-vip124.adobe.com
127.0.0.1 wwis-dubc1-vip125.adobe.com
127.0.0.1 wwis-dubc1-vip30.adobe.com
127.0.0.1 wwis-dubc1-vip31.adobe.com
127.0.0.1 wwis-dubc1-vip32.adobe.com
127.0.0.1 wwis-dubc1-vip33.adobe.com
127.0.0.1 wwis-dubc1-vip34.adobe.com
127.0.0.1 wwis-dubc1-vip35.adobe.com
127.0.0.1 wwis-dubc1-vip36.adobe.com
127.0.0.1 wwis-dubc1-vip37.adobe.com
127.0.0.1 wwis-dubc1-vip38.adobe.com
127.0.0.1 wwis-dubc1-vip39.adobe.com
127.0.0.1 wwis-dubc1-vip40.adobe.com
127.0.0.1 wwis-dubc1-vip41.adobe.com
127.0.0.1 wwis-dubc1-vip42.adobe.com
127.0.0.1 wwis-dubc1-vip43.adobe.com
127.0.0.1 wwis-dubc1-vip44.adobe.com
127.0.0.1 wwis-dubc1-vip45.adobe.com
127.0.0.1 wwis-dubc1-vip46.adobe.com
127.0.0.1 wwis-dubc1-vip47.adobe.com
127.0.0.1 wwis-dubc1-vip48.adobe.com
127.0.0.1 wwis-dubc1-vip49.adobe.com
127.0.0.1 wwis-dubc1-vip50.adobe.com
127.0.0.1 wwis-dubc1-vip51.adobe.com
127.0.0.1 wwis-dubc1-vip52.adobe.com
127.0.0.1 wwis-dubc1-vip53.adobe.com
127.0.0.1 wwis-dubc1-vip54.adobe.com
127.0.0.1 wwis-dubc1-vip55.adobe.com
127.0.0.1 wwis-dubc1-vip56.adobe.com
127.0.0.1 wwis-dubc1-vip57.adobe.com
127.0.0.1 wwis-dubc1-vip58.adobe.com
127.0.0.1 wwis-dubc1-vip59.adobe.com
127.0.0.1 wwis-dubc1-vip60.adobe.de
127.0.0.1 wwis-dubc1-vip61.adobe.com
127.0.0.1 wwis-dubc1-vip62.adobe.com
127.0.0.1 wwis-dubc1-vip63.adobe.com
127.0.0.1 wwis-dubc1-vip64.adobe.com
127.0.0.1 wwis-dubc1-vip65.adobe.com
127.0.0.1 wwis-dubc1-vip66.adobe.com
127.0.0.1 wwis-dubc1-vip67.adobe.com
127.0.0.1 wwis-dubc1-vip68.adobe.com
127.0.0.1 wwis-dubc1-vip69.adobe.com
127.0.0.1 wwis-dubc1-vip70.adobe.com
127.0.0.1 wwis-dubc1-vip71.adobe.com
127.0.0.1 wwis-dubc1-vip72.adobe.com
127.0.0.1 wwis-dubc1-vip73.adobe.com
127.0.0.1 wwis-dubc1-vip74.adobe.com
127.0.0.1 wwis-dubc1-vip75.adobe.com
127.0.0.1 wwis-dubc1-vip76.adobe.com
127.0.0.1 wwis-dubc1-vip77.adobe.com
127.0.0.1 wwis-dubc1-vip78.adobe.com
127.0.0.1 wwis-dubc1-vip79.adobe.com
127.0.0.1 wwis-dubc1-vip80.adobe.com
127.0.0.1 wwis-dubc1-vip81.adobe.com
127.0.0.1 wwis-dubc1-vip82.adobe.com
127.0.0.1 wwis-dubc1-vip83.adobe.com
127.0.0.1 wwis-dubc1-vip84.adobe.com
127.0.0.1 wwis-dubc1-vip85.adobe.com
127.0.0.1 wwis-dubc1-vip86.adobe.com
127.0.0.1 wwis-dubc1-vip87.adobe.com
127.0.0.1 wwis-dubc1-vip88.adobe.com
127.0.0.1 wwis-dubc1-vip89.adobe.com
127.0.0.1 wwis-dubc1-vip90.adobe.com
127.0.0.1 wwis-dubc1-vip91.adobe.com
127.0.0.1 wwis-dubc1-vip92.adobe.com
127.0.0.1 wwis-dubc1-vip93.adobe.com
127.0.0.1 wwis-dubc1-vip94.adobe.com
127.0.0.1 wwis-dubc1-vip95.adobe.com
127.0.0.1 wwis-dubc1-vip96.adobe.com
127.0.0.1 wwis-dubc1-vip97.adobe.com
127.0.0.1 wwis-dubc1-vip98.adobe.com
127.0.0.1 wwis-dubc1-vip99.adobe.com
127.0.0.1 ic.adobe.io
127.0.0.1 cc-api-data.adobe.io
127.0.0.1 cc-api-data-stage.adobe.io
127.0.0.1 notify.adobe.io
127.0.0.1 prod.adobegenuine.com
127.0.0.1 gocart-web-prod-ue1-alb-1461435473.us-east-1.elb.amazonaws.com
127.0.0.1 assets.adobedtm.com
127.0.0.1 adobe-dns-01.adobe.com
127.0.0.1 adobe.demdex.net
127.0.0.1 adobe.tt.omtrdc.net
127.0.0.1 adobedc.demdex.net
127.0.0.1 adobeid-na1.services.adobe.com
127.0.0.1 auth-cloudfront.prod.ims.adobejanus.com
127.0.0.1 auth.services.adobe.com
127.0.0.1 cai-splunk-proxy.adobe.io
127.0.0.1 cc-cdn.adobe.com
127.0.0.1 cc-cdn.adobe.com.edgekey.net
127.0.0.1 cclibraries-defaults-cdn.adobe.com
127.0.0.1 cclibraries-defaults-cdn.adobe.com.edgekey.net
127.0.0.1 cn-assets.adobedtm.com.edgekey.net
127.0.0.1 crlog-crcn.adobe.com
127.0.0.1 crs.cr.adobe.com
127.0.0.1 edgeproxy-irl1.cloud.adobe.io
127.0.0.1 ethos.ethos02-prod-irl1.ethos.adobe.net
127.0.0.1 geo2.adobe.com
127.0.0.1 lcs-cops.adobe.io
127.0.0.1 lcs-robs.adobe.io
127.0.0.1 pv2bqhsp36w.prod.cloud.adobe.io
127.0.0.1 services.prod.ims.adobejanus.com
127.0.0.1 ssl-delivery.adobe.com.edgekey.net
127.0.0.1 sstats.adobe.com
127.0.0.1 stls.adobe.com-cn.edgesuite.net
127.0.0.1 stls.adobe.com-cn.edgesuite.net.globalredir.akadns.net
127.0.0.1 use-stls.adobe.com.edgesuite.net
#</block-adobe>

127.0.0.1 209-34-83-73.ood.opsource.net
127.0.0.1 tss-geotrust-crl.thawte.com
127.0.0.1 crl.verisign.net
127.0.0.1 ocsp.spo1.verisign.com
127.0.0.1 ood.opsource.net
127.0.0.1 bam.nr-data.net
127.0.0.1 workflow-ui-prod.licensingstack.com
127.0.0.1 https://prod2-live-chat.sprinklr.com
127.0.0.1 activation.cyberlink.com
127.0.0.1 secure.asap-utilities.com
127.0.0.1 server2.asap-utilities.com
"@
    Set-Content -Path "$env:WinDir\System32\drivers\etc\hosts" -Value $HostsFile -Force -ea SilentlyContinue | out-null
}

Function uninsSara-Office
{
    Write-Host -f C "`r`n *** Removing currently installed MS office products using SaraCmd *** `r`n"
    # Run SaraCMD non-interactive Script
    New-Item -Path "$env:TEMP\IA\office" -ItemType Directory -ea SilentlyContinue | out-null
    Invoke-WebRequest -Uri "https://aka.ms/SaRAEnterpriseHelper" -OutFile "$env:TEMP\IA\office\ExecuteSaraCmd.zip"
    Expand-Archive -LiteralPath "$env:TEMP\IA\office\ExecuteSaraCmd.zip" -DestinationPath "$env:TEMP\IA\office" -Force -ea SilentlyContinue | out-null
    $SNIfile = "$env:TEMP\IA\office\ExecuteSaraCmd.ps1"
    $find = '$SaraScenarioArgument = ""';$replace = '$SaraScenarioArgument = "-S OfficeScrubScenario -Script -AcceptEula -OfficeVersion All"'
    (Get-Content $SNIfile).replace($find, $replace) | Set-Content -Path $SNIfile -Force -ea SilentlyContinue | out-null
    & "$SNIfile"
}

Function uninsITPRO-Office
{
    Write-Host -f C "`r`n *** Removing currently installed MS office products using ITPRO codes *** `r`n"
    $outputdir = "$env:TEMP\IA\office"
    $weburl = "https://github.com/OfficeDev/Office-IT-Pro-Deployment-Scripts/tree/master/Office-ProPlus-Deployment/Remove-PreviousOfficeInstalls/"
    for ($i = 1; $i -le 30; $i++){
        $WebPage1 = Repeatiwr -Uri $weburl
        $Filelinks = $WebPage1.Links | Where-Object {$_.href -like '*exe' -or $_.href -like '*vbs' -or $_.href -like '*ps1'} | Select-Object -ExpandProperty href | Select-Object -Unique
        if ($Filelinks -ne $null) {break}
    }
    $Filelinks | ForEach-Object {
        $outputFile = Split-Path $_ -leaf
        Write-Host -f C "Downloading file '$outputFile'"
        $fileFullname = Join-Path -Path $outputdir -ChildPath $outputFile
        $fileUrl  = '{0}/{1}' -f $weburl.TrimEnd('/'), $outputFile
        $fileUrl = $fileUrl.replace("tree", "raw")
        Invoke-WebRequest $fileUrl -OutFile $fileFullname
    }
    & "$outputdir\Remove-PreviousOfficeInstalls.ps1"
}

Function Stop-OfficeProcess
{
    Write-Host "Stopping running Office applications ..."
    $OfficeProcessesArray = "lync", "winword", "excel", "msaccess", "mstore", "infopath", "setlang", "msouc", "ois", "onenote", "outlook", "powerpnt", "mspub", "groove", "visio", "winproj", "graph", "teams"
    foreach ($ProcessName in $OfficeProcessesArray) {
        if (get-process -Name $ProcessName -ErrorAction SilentlyContinue) {
            if (Stop-Process -Name $ProcessName -Force -ErrorAction SilentlyContinue) {
                Write-Output "Process $ProcessName was stopped."
            }
            else {
                Write-Warning "Process $ProcessName could not be stopped."
            }
        } 
    }
}

Function Unins-MSOffice
{
    Write-Host -f C "`r`n *** Uninstalling Microsoft Office *** `r`n"
    Stop-OfficeProcess
    
    #Expand-Archive -LiteralPath "$env:TEMP\IA\office\OfficeToolPlus.zip" -DestinationPath "$env:TEMP\IA\office" -Force
    #Start-Job -Name OfficeToolPlus {if (Test-Path -Path "$env:TEMP\IA\office" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\IA\office" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
    #./"Office Tool Plus.Console.exe" deploy /rmall /display false
    #./"Office Tool Plus.Console.exe" ospp /clall
}

Function Uninscomponents-Office
{
    Get-Package -Name "*Office*" -ErrorAction SilentlyContinue | Uninstall-Package
    # Remove MS Store Office 365
    Remove-AppxApp -AppName "Microsoft.Office.Desktop"
    Get-AppxProvisionedPackage -online | %{if ($_.packagename -match "Microsoft.Office.Desktop") {$_ | Remove-AppxProvisionedPackage -AllUsers}}
}

Function ActivateOfficeKMS
{
    Write-Host -f C "`r`n *** Activating office using KMS *** `r`n"
    $Officeospp64 = "$Env:Programfiles\Microsoft Office\Office16\ospp.vbs";$Officeospp32 = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\ospp.vbs"
    if (Test-Path -Path $Officeospp64 -ea SilentlyContinue) {$office64 = $true}
    elseif (Test-Path -Path $Officeospp32 -ea SilentlyContinue) {$office64 = $false}
    else {Write-Host -f C "Office16 ospp.vbs not found";return}
    
    if ($office64) {$Licenses = (Get-ChildItem "$Env:Programfiles\Microsoft Office\root\Licenses16\ProPlus2021VL_KMS*.xrm-ms").fullname}
    else {$Licenses = (Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Office\root\Licenses16\ProPlus2021VL_KMS*.xrm-ms").fullname}
    If ($office64) {$officeospp =$Officeospp64} else {$officeospp =$Officeospp32}
    $Licenses | ForEach-Object {
        cscript //nologo "$officeospp" /inslic:"$_" | out-null
        cscript //nologo "$env:WinDir\System32\slmgr.vbs" /ckms | out-null
        cscript //nologo "$officeospp" /setprt:1688 | out-null
        cscript //nologo "$officeospp" /unpkey:6F7TH | out-null
        cscript //nologo "$officeospp" /inpkey:FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH | out-null
    }
    for ($i = 1; $i -le 10; $i++) {
        switch ($i)
        {
            1 {$KMS="kms8.MSGuides.com"};2 {$KMS="kms9.MSGuides.com"};3 {$KMS="107.175.77.7"};4 {$KMS="e8.us.to"};5 {$KMS="e9.us.to"}
            6 {$KMS="kms.digiboy.ir"};7 {$KMS="kms.ddns.net"};8 {$KMS="kms.lotro.cc"};9 {$KMS="zh.us.to"}
        }
        cscript //nologo "$officeospp" /sethst:$KMS | out-null
        $Response = cscript //nologo "$officeospp" /act | Select-String -Pattern "successful"
        if ($Response -ne $null) {Write-Host -f C "MS Office Successfully Activated using KMS server: $KMS";break}
    }
}

Function Config-Office
{
    # Office
    AddRegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'EnableAutomaticUpdates' '0' 'DWord'
    AddRegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'HideEnableDisableUpdates' '1' 'DWord'
    AddRegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'PreventTeamsInstall' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings' 'InlineTextPrediction' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel' 'AutoSaveInterval' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel' 'ExcelWorkbookAutoRecoverDirty' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'A4Letter' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'AutoRecoverTime' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'DeveloperTools' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'DisableBootToOfficeStart' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'EnableAccChecker' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'Maximized' '3' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'Xl9_hijri' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'AraDate' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'BackgroundOpen' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'BkgrndPag' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DeveloperTools' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DisableBootToOfficeStart' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DisableDarkMode' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'NumForm' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'PreferredView' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'Ruler' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'ShowBkg' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\Common\ClientTelemetry' 'DisableTelemetry' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'ActiveDictationLanguage' 'en-US' 'String'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'QMEnable' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerData' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerDataOptIn' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerDataOptInReason' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'UI Theme' '3' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'UpdateReliabilityData' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'IncludeEmail' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'SurveyEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'ControllerConnectedServicesEnabled' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'DisconnectedState' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'DownloadContentDisabled' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'UserContentDisabled' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'EnableFileObfuscation' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'EnableUpload' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'Enablelogging' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry' 'SendTelemetry' '3' 'DWord'
    AddRegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'autorecoverdelay' '1' 'DWord'
    AddRegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'autorecoverenabled' '1' 'DWord'
    AddRegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'autorecovertime' '1' 'DWord'
    AddRegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'disableboottoofficestart' '1' 'DWord'
    AddRegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'keepunsavedchanges' '1' 'DWord'
    AddRegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'recognizesmarttags' '2' 'DWord'
    AddRegEntry 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Wizards' 'PageSize' 'A4' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'DataConnectionWarnings' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'WorkbookLinkWarnings' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'RichDataConnectionWarnings' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'DisableDDEServerLaunch' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'VBAWarnings' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'AccessVBOM' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'OpenInProtectedView' '2' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL4Workbooks' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL4Worksheets' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL4Macros' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL3Workbooks' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL3Worksheets' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL3Macros' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL2Workbooks' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL2Worksheets' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL2Macros' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView' 'DisableInternetFilesInPV' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView' 'DisableAttachmentsInPV' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView' 'DisableUnsafeLocationsInPV' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations' 'AllowNetworkLocations' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location90' 'Path' 'C:\\' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location90' 'AllowSubfolders' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location91' 'Path' 'D:\\' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location91' 'AllowSubfolders' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location92' 'Path' '\\' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location92' 'AllowSubfolders' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location93' 'Path' '//' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location93' 'AllowSubfolders' '1' 'DWord'
    
    Get-printer | ForEach-Object {set-printconfiguration -printerobject $_ -Papersize A4 -DuplexingMode OneSided}
    $Printers = Get-Printer;Foreach ($Printer in $Printers){Set-PrintConfiguration -PrinterName $Printer.name -PaperSize A4 -DuplexingMode OneSided}
}

Function Deploy-Office
{
    Write-Host -f C "`r`n *** Downloading & extracting Office Deployment Tool *** `r`n"
    for ($i = 1; $i -le 50; $i++) {
        $webpage2 = Repeatiwr -Uri "https://www.microsoft.com/en-us/download/details.aspx?id=49117"
        $FileLink =$webpage2.Links | Where-Object href -like '*officedeploymenttool*exe' | select -Last 1 -expand href
        if ($Filelink -ne $null) {break}
    }
    if ($Filelink -ne $null) {Invoke-WebRequest -Uri $FileLink -OutFile "$env:TEMP\IA\office\officedeploymenttool.exe"}
    if (Test-Path -Path "$env:TEMP\IA\office\officedeploymenttool.exe" -ea SilentlyContinue) {Start-Process -Wait -FilePath "$env:TEMP\IA\office\officedeploymenttool.exe" -ArgumentList "/extract:$env:TEMP\IA\office","/quiet","/passive","/norestart" -ea SilentlyContinue | out-null}
    Write-Host -f C "`r`n *** Installing Office ... *** `r`n"
    if (Test-Path -Path "$env:TEMP\IA\office\setup.exe" -ea SilentlyContinue) {Start-Process -WindowStyle Minimized -Wait -FilePath "$env:TEMP\IA\office\setup.exe" -ArgumentList "/configure","$env:TEMP\IA\office\configuration.xml" -ea SilentlyContinue | out-null}
    else {Write-Host -f C "`r`n Failed to download & extract Office Deployment Tool"}
}

Function configurationFile21PP
{
    $ConfigurationFile =
@"
<Configuration ID="d66f0ad9-6e2f-47dc-a4fe-de1b73dfddff">
<Add OfficeClientEdition="64" Channel="PerpetualVL2021">
<Product ID="ProPlus2021Volume" PIDKEY="FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH">
<Language ID="MatchOS" />
<Language ID="ar-sa" />
<Language ID="en-us" />
<ExcludeApp ID="Lync" />
<ExcludeApp ID="OneDrive" />
<ExcludeApp ID="OneNote" />
<ExcludeApp ID="Publisher" />
</Product>
<Product ID="ProofingTools">
<Language ID="ar-sa" />
<Language ID="en-us" />
</Product>
</Add>
<Property Name="SharedComputerLicensing" Value="0" />
<Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
<Property Name="DeviceBasedLicensing" Value="0" />
<Property Name="SCLCacheOverride" Value="0" />
<Property Name="AUTOACTIVATE" Value="0" />
<Updates Enabled="FALSE" />
<RemoveMSI />
<Remove All="TRUE">
</Remove>
<AppSettings>
<User Key="software\microsoft\office\16.0\excel\options" Name="recognizesmarttags" Value="2" Type="REG_DWORD" App="office16" Id="L_EnableAdditionalActionsInExcel" />
<User Key="software\microsoft\office\16.0\common\autocorrect" Name="capitalizesentence" Value="1" Type="REG_DWORD" App="office16" Id="L_Capitalizefirstletterofsentence" />
<User Key="software\microsoft\office\16.0\common\autocorrect" Name="capitalizenamesofdays" Value="1" Type="REG_DWORD" App="office16" Id="L_Capitalizenamesofdays" />
<User Key="software\microsoft\office\16.0\common\internet" Name="donotupdatelinksonsave" Value="0" Type="REG_DWORD" App="office16" Id="L_Updatelinksonsave" />
<User Key="software\microsoft\shared tools\proofing tools\1.0\office" Name="flagrepeatedword" Value="1" Type="REG_DWORD" App="office16" Id="L_FlagRepeatedWords" />
<User Key="software\microsoft\office\16.0\word\options\vpref" Name="wspell_1112_8" Value="3" Type="REG_DWORD" App="office16" Id="L_Arabicmodes" />
<User Key="software\microsoft\office\16.0\common\ptwatson" Name="ptwoptin" Value="0" Type="REG_DWORD" App="office16" Id="L_ImproveProofingTools" />
<User Key="software\microsoft\office\16.0\common\general" Name="shownfirstrunoptin" Value="1" Type="REG_DWORD" App="office16" Id="L_DisableOptinWizard" />
<User Key="software\microsoft\office\16.0\common" Name="qmenable" Value="0" Type="REG_DWORD" App="office16" Id="L_EnableCustomerExperienceImprovementProgram" />
<User Key="software\microsoft\office\16.0\common" Name="updatereliabilitydata" Value="0" Type="REG_DWORD" App="office16" Id="L_UpdateReliabilityPolicy" />
<User Key="software\microsoft\office\16.0\common\signatures" Name="verifyversion" Value="0" Type="REG_DWORD" App="office16" Id="L_SetSignatureVerificationLevel" />
<User Key="software\microsoft\office\16.0\common\security\filevalidation" Name="disablereporting" Value="1" Type="REG_DWORD" App="office16" Id="L_TurnOffErrorReportingForFilesThatFailFileValidation" />
</AppSettings>
<Display Level="None" AcceptEULA="TRUE" />
</Configuration>
"@
    Set-Content -Path "$env:TEMP\IA\office\Configuration.xml" -Value $ConfigurationFile -Force -ea SilentlyContinue | out-null
}

Function configurationFile24PP
{
    $ConfigurationFile =
@"
<Configuration ID="0ba18fea-354d-4d3a-bb5f-b5c04d3eca9d">
<Add OfficeClientEdition="64" Channel="PerpetualVL2024">
<Product ID="ProPlus2024Volume" PIDKEY="XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB">
<Language ID="MatchOS" />
<Language ID="ar-sa" />
<Language ID="en-us" />
<ExcludeApp ID="Lync" />
<ExcludeApp ID="OneDrive" />
<ExcludeApp ID="OneNote" />
<ExcludeApp ID="Publisher" />
</Product>
<Product ID="ProofingTools">
<Language ID="ar-sa" />
<Language ID="en-us" />
</Product>
</Add>
<Property Name="SharedComputerLicensing" Value="0" />
<Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
<Property Name="DeviceBasedLicensing" Value="0" />
<Property Name="SCLCacheOverride" Value="0" />
<Property Name="AUTOACTIVATE" Value="0" />
<Updates Enabled="FALSE" />
<Remove All="TRUE">
</Remove>
<RemoveMSI />
<AppSettings>
<User Key="software\microsoft\office\16.0\excel\options" Name="recognizesmarttags" Value="2" Type="REG_DWORD" App="office16" Id="L_EnableAdditionalActionsInExcel" />
<User Key="software\microsoft\office\16.0\common\autocorrect" Name="capitalizesentence" Value="1" Type="REG_DWORD" App="office16" Id="L_Capitalizefirstletterofsentence" />
<User Key="software\microsoft\office\16.0\common\autocorrect" Name="capitalizenamesofdays" Value="1" Type="REG_DWORD" App="office16" Id="L_Capitalizenamesofdays" />
<User Key="software\microsoft\office\16.0\common\internet" Name="donotupdatelinksonsave" Value="0" Type="REG_DWORD" App="office16" Id="L_Updatelinksonsave" />
<User Key="software\microsoft\shared tools\proofing tools\1.0\office" Name="flagrepeatedword" Value="1" Type="REG_DWORD" App="office16" Id="L_FlagRepeatedWords" />
<User Key="software\microsoft\office\16.0\word\options\vpref" Name="wspell_1112_8" Value="3" Type="REG_DWORD" App="office16" Id="L_Arabicmodes" />
<User Key="software\microsoft\office\16.0\common\ptwatson" Name="ptwoptin" Value="0" Type="REG_DWORD" App="office16" Id="L_ImproveProofingTools" />
<User Key="software\microsoft\office\16.0\common\general" Name="shownfirstrunoptin" Value="1" Type="REG_DWORD" App="office16" Id="L_DisableOptinWizard" />
<User Key="software\microsoft\office\16.0\common" Name="qmenable" Value="0" Type="REG_DWORD" App="office16" Id="L_EnableCustomerExperienceImprovementProgram" />
<User Key="software\microsoft\office\16.0\common" Name="updatereliabilitydata" Value="0" Type="REG_DWORD" App="office16" Id="L_UpdateReliabilityPolicy" />
<User Key="software\microsoft\office\16.0\common\signatures" Name="verifyversion" Value="0" Type="REG_DWORD" App="office16" Id="L_SetSignatureVerificationLevel" />
<User Key="software\microsoft\office\16.0\common\security\filevalidation" Name="disablereporting" Value="1" Type="REG_DWORD" App="office16" Id="L_TurnOffErrorReportingForFilesThatFailFileValidation" />
</AppSettings>
<Display Level="None" AcceptEULA="TRUE" />
</Configuration>
"@
    Set-Content -Path "$env:TEMP\IA\office\Configuration.xml" -Value $ConfigurationFile -Force -ea SilentlyContinue | out-null
}

Function New-OfficeShortcuts {
    # Function to read install path from registry for a given app
    function Get-OfficeAppPath($appName) {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$appName.exe",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$appName.exe"
        )
        foreach ($reg in $regPaths) {
            try {
                $path = (Get-ItemProperty -Path $reg -ErrorAction Stop).'(default)'
                if (Test-Path $path) { return $path }
            } catch { }
        }
        return $null
    }

    # Try registry first
    $wordPath  = Get-OfficeAppPath "WINWORD"
    $excelPath = Get-OfficeAppPath "EXCEL"
    If ($wordPath) {Write-Host -f C "Registry Word Path:$wordPath"}
    If ($excelPath) {Write-Host -f C "Registry Excel Path:$excelPath"}

    # Build common paths from environment variables
    $programFiles64 = ${env:ProgramFiles}
    $programFiles32 = ${env:ProgramFiles(x86)}

    $commonPaths = @(
        (Join-Path $programFiles64 "Microsoft Office\root\Office16"),
        (Join-Path $programFiles32 "Microsoft Office\root\Office16")
    )

    # Fallback for Word
    if (-not $wordPath) {
        foreach ($p in $commonPaths) {
            $try = Join-Path $p "WINWORD.EXE"
            if (Test-Path $try) { 
                Write-Warning "Word path not found in registry. Using fallback: $try"
                $wordPath = $try
                break
            }
        }
    }

    # Fallback for Excel
    if (-not $excelPath) {
        foreach ($p in $commonPaths) {
            $try = Join-Path $p "EXCEL.EXE"
            if (Test-Path $try) { 
                Write-Warning "Excel path not found in registry. Using fallback: $try"
                $excelPath = $try
                break
            }
        }
    }

    # If still missing, stop
    if (-not $wordPath -or -not $excelPath) {
        Write-Warning "Could not find Word or Excel executable. Please check your Office installation."
        return
    }

    # Paths for Desktop & Start Menu
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $startMenuPath = Join-Path ${env:ProgramData} "Microsoft\Windows\Start Menu\Programs"

    # Create shortcuts
    $WshShell = New-Object -ComObject WScript.Shell

    # Word - Desktop
    $wordShortcut = $WshShell.CreateShortcut("$desktopPath\Word.lnk")
    $wordShortcut.TargetPath = $wordPath
    $wordShortcut.IconLocation = $wordPath
    $wordShortcut.Save()

    # Word - Start Menu
    $wordStartShortcut = $WshShell.CreateShortcut("$startMenuPath\Word.lnk")
    $wordStartShortcut.TargetPath = $wordPath
    $wordStartShortcut.IconLocation = $wordPath
    $wordStartShortcut.Save()

    # Excel - Desktop
    $excelShortcut = $WshShell.CreateShortcut("$desktopPath\Excel.lnk")
    $excelShortcut.TargetPath = $excelPath
    $excelShortcut.IconLocation = $excelPath
    $excelShortcut.Save()

    # Excel - Start Menu
    $excelStartShortcut = $WshShell.CreateShortcut("$startMenuPath\Excel.lnk")
    $excelStartShortcut.TargetPath = $excelPath
    $excelStartShortcut.IconLocation = $excelPath
    $excelStartShortcut.Save()

    Write-Host "Shortcuts for Word and Excel created on Desktop and Start Menu."
}

Function Ins-Office21PP
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Start Installing Office 2021 Pro Plus *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    Unins-MSOffice
    uninsSara-Office
    uninsITPRO-Office
    Uninscomponents-Office
    configurationFile21PP
    Deploy-Office
    ActivateOfficeKMS
    Config-Office
    New-OfficeShortcuts
}

Function Ins-Office24PP
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Start Installing Office 2024 Pro Plus *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    Unins-MSOffice
    uninsSara-Office
    uninsITPRO-Office
    Uninscomponents-Office
    configurationFile24PP
    Deploy-Office
    ActivateOfficeKMS
    Config-Office
    New-OfficeShortcuts
}

Function OpenMSStoreUpdate
{
    Write-Host -f C "`r`n *** MS Store Apps Updates *** `r`n"
    Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
    Start-Process "ms-windows-store://downloadsandupdates"
}

Function Pin-to-taskbar
{
    Param
    (
    [Parameter(Mandatory=$false, Position=0)]
    [string]$IDorPath,
    [Parameter(Mandatory=$false, Position=1)]
    [string]$PinType,
    [Parameter(Mandatory=$false, Position=2)]
    [switch]$SearchID = $false,
    [Parameter(Mandatory=$false, Position=3)]
    [switch]$Replace = $false,
    [Parameter(Mandatory=$false, Position=4)]
    [switch]$ClearAll = $false
    )
    If (($ClearAll -eq $false) -and (($IDorPath -eq "") -or ($PinType -eq ""))) {Write-Host -f red 'You must provide IDorPath and PinType unless you use -ClearAll';return}
    # For $IDorPath provide the appID or desktopID or part of it & set search or provide the path
    # for PinType provied "AppUserModelID" or "DesktopApplicationID" or "DesktopApplicationLinkPath"
    # To understand this visit: https://learn.microsoft.com/en-us/windows/configuration/taskbar/pinned-apps?tabs=intune&pivots=windows-11#taskbar-layout-example
    # To get UWP App ID "AppUserModelID" use PS command> Get-AppxPackage | select @{n='name';e={"$($_.PackageFamilyName)!app"}} 
    # also choose whether to keep the previous pins or to remove them by setting Replace
    # or use-ClearAll to remove all pins without adding any ie: Pin-to-taskbar -ClearAll
    # All other parameters are useless when using -ClearAll as it will just clear all pins anyway so you should use for that> Pin-to-taskbar -ClearAll
    $taskbar_layout1 =
@"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
Version="1">

"@
If ($Replace -or $ClearAll) {$Placement = '<CustomTaskbarLayoutCollection PinListPlacement="Replace">'} else {$Placement = '<CustomTaskbarLayoutCollection>'}
$taskbar_layout2 =
@"

<defaultlayout:TaskbarLayout>
<taskbar:TaskbarPinList>

"@
If (-not $ClearAll)
{
if ($SearchID) {$IDorPath = (Get-AppxPackage | select @{n='name';e={"$($_.PackageFamilyName)!app"}} | ?{$_.name -like "*$IDorPath*"}).name}
#Write-Host $IDorPath #Debug only
switch ($PinType)
{
"AppUserModelID" {$pin = '<taskbar:UWA AppUserModelID="' + $IDorPath + '" />'}
"DesktopApplicationID" {$pin = '<taskbar:DesktopApp DesktopApplicationID="' + $IDorPath + '" />'}
"DesktopApplicationLinkPath" {$pin = '<taskbar:DesktopApp DesktopApplicationLinkPath="' + $IDorPath + '" />'}
}
}
$taskbar_layout3 =
@"

</taskbar:TaskbarPinList>
</defaultlayout:TaskbarLayout>
</CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
    $taskbar_layout = $taskbar_layout1 + $Placement + $taskbar_layout2 + $pin + $taskbar_layout3
    #Write-Host $taskbar_layout #Debug only
    # prepare provisioning folder
    [System.IO.FileInfo]$provisioning = "$($env:ProgramData)\provisioning\taskbar_layout.xml"
    if (!$provisioning.Directory.Exists) {
        $provisioning.Directory.Create()
    }
    
    $taskbar_layout | Out-File $provisioning.FullName -Encoding utf8
    
    $settings = [PSCustomObject]@{
        Path= "SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Value = $provisioning.FullName
        Name= "StartLayoutFile"
        Type= [Microsoft.Win32.RegistryValueKind]::ExpandString
    },
    [PSCustomObject]@{
        Path= "SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Value = 1
        Name= "LockedStartLayout"
    } | group Path
    
    foreach ($setting in $settings) {
        $registry = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($setting.Name, $true)
        if ($null -eq $registry) {
            $registry = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($setting.Name, $true)
        }
        $setting.Group | % {
            if (!$_.Type) {
                $registry.SetValue($_.name, $_.value)
            }
            else {
                $registry.SetValue($_.name, $_.value, $_.type)
            }
        }
        $registry.Dispose()
    }
    Write-Host -f C "Restarting explorer to pin application to taskbar"
    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
    Stop-Process -ProcessName explorer -Force -ea SilentlyContinue | out-null
}

Function Ins-ExtraFonts
{
    Write-Host -f C "`r`n *** Installing Extra Fonts *** `r`n"
    if (choco list --lo -r -e dejavufonts) {Write-Host -f C "dejavufonts already installed"} else {Choco install dejavufonts}
    if (choco list --lo -r -e victormononf) {Choco upgrade victormononf} else {Choco install victormononf}
    if (choco list --lo -r -e montserrat.font) {Choco upgrade montserrat.font} else {Choco install montserrat.font}
    if (choco list --lo -r -e opensans) {Choco upgrade opensans} else {Choco install opensans}
    if (choco list --lo -r -e cascadiafonts) {Choco upgrade cascadiafonts} else {Choco install cascadiafonts}
}

Function Pin-WhatsappWebChrome
{
    Write-Host -f C "`r`n *** Pining Chrome whatsapp web to taskbar *** `r`n"
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'
    $Chrome=(Get-ItemProperty -Path $key -Name '(Default)').'(default)'
    if ($chrome -eq $null)
    {
        if (Test-Path '${env:ProgramFiles(x86)}\Google\Chrome' -ea SilentlyContinue) {
            $chrome = '${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe'
            } elseif (Test-Path '$Env:Programfiles\Google\Chrome' -ea SilentlyContinue) {
            $chrome = '$Env:Programfiles\Google\Chrome\Application\chrome.exe'
        } else {Write-Host "Not Found"}
    }
    Invoke-WebRequest -Uri "https://web.whatsapp.com/favicon-64x64.ico" -OutFile "$Env:Programfiles\Google\Chrome\WhatsApp.ico"
    $Arguments1= " --new-window --force-app-mode --app=https://web.whatsapp.com/"
    $s=(New-Object -COM WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\WhatsAppWeb.lnk")
    $s.TargetPath="$chrome";$s.Arguments=$Arguments1;$s.IconLocation="$Env:Programfiles\Google\Chrome\WhatsApp.ico";$s.Save()
    Pin-to-taskbar -IDorPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\WhatsAppWeb.lnk" -PinType "DesktopApplicationLinkPath"
}

Function Fix-MSWindows
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Fixing Windows *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    sfc /scannow
    DISM /Online /Cleanup-Image /RestoreHealth
    #Start-Job -Name ReApps {Get-AppXPackage | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
}

Function Clean-up
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Cleaning up *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    # temp fix
    AddRegEntry 'HKCU:\Control Panel\International' 'sLongDate' 'dd MMMM yyyy' 'String'
    AddRegEntry 'HKCU:\Control Panel\International' 'sShortDate' 'dd/MM/yyyy' 'String'
    AddRegEntry 'HKCU:\Control Panel\International' 'sTimeFormat' 'hh:mm:ss tt' 'String'
    AddRegEntry 'HKCU:\Control Panel\International' 'sShortTime' 'hh:mm tt' 'String'
    AddRegEntry 'HKCU:\Control Panel\International' 'iFirstDayOfWeek' '5' 'String' # Saturday
    AddRegEntry 'HKCU:\Control Panel\International' 'NumShape' '0' 'String' # Native digits number shape # 0 - Context # 1 - default # 2 - Always local
    reg add "HKCU\Control Panel\International" /V iCalendarType /T REG_SZ /D "1" /F
    AddRegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowTextPrediction' '1' 'DWord'
    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
    # Wait for all background jobs to finish
    Wait-Job -State Running
    # Optionally receive and display the results of all jobs
    Get-Job | ForEach-Object {
    Write-Output "Result from job $($_.Id):"
    Receive-Job -Job $_
    Remove-Job -Job $_
    }
    Clear-PrintQueue
    Start-sleep 1
    Stop-Process -ProcessName explorer -Force -ea SilentlyContinue | out-null
    Start-Process explorer.exe
    Write-Host "Explorer restarted."
    Refresh-Desktop
    Change_computer_name
    Remove-Item -LiteralPath "$env:TEMP\IA" -Force -Recurse -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "$env:TEMP" -Force -Recurse -ea SilentlyContinue | out-null
    }

Function Change_computer_name {

# Load Windows Forms
Add-Type -AssemblyName System.Windows.Forms

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Change Computer Name"
$form.Size = New-Object System.Drawing.Size(400, 220)
$form.StartPosition = "CenterScreen"

# Label - Current Computer Name
$label = New-Object System.Windows.Forms.Label
$label.Text = "Current Computer Name:"
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(150,20)
$form.Controls.Add($label)

# TextBox - New Computer Name
$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Text = $env:COMPUTERNAME
$textBox.Location = New-Object System.Drawing.Point(160,18)
$textBox.Size = New-Object System.Drawing.Size(200,20)
$form.Controls.Add($textBox)

# Button - Change Computer Name
$buttonChange = New-Object System.Windows.Forms.Button
$buttonChange.Text = "Change Computer Name"
$buttonChange.Location = New-Object System.Drawing.Point(110,60)
$buttonChange.Size = New-Object System.Drawing.Size(160,30)
$buttonChange.Add_Click({
    $newName = $textBox.Text.Trim()
    if ($newName -eq $env:COMPUTERNAME) {
        [System.Windows.Forms.MessageBox]::Show("New name is the same as current.", "No Change")
        return
    }

    try {
        Rename-Computer -NewName $newName -Force -PassThru
        [System.Windows.Forms.MessageBox]::Show("Computer name changed to: $newName`nA reboot is required to apply the change.", "Success")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to change computer name:`n$_", "Error")
    }
})
$form.Controls.Add($buttonChange)

# Button - Restart Now
$buttonRestart = New-Object System.Windows.Forms.Button
$buttonRestart.Text = "Restart Now"
$buttonRestart.Location = New-Object System.Drawing.Point(110,110)
$buttonRestart.Size = New-Object System.Drawing.Size(160,30)
$buttonRestart.Add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to restart now?", "Confirm Restart", "YesNo")
    if ($result -eq "Yes") {
        Restart-Computer -Force
    }
})
$form.Controls.Add($buttonRestart)

# Show the form
[void]$form.ShowDialog()
}

Function Clear-PrintQueue {
    <#
    .SYNOPSIS
        Force-clears all print jobs (soft + hard methods).
    .DESCRIPTION
        - Stops the spooler
        - Attempts to remove jobs using PrintJob cmdlets
        - Kills lingering processes that may lock spool files
        - Deletes raw spool files
        - Restarts the spooler and explorer shell
    #>

    Write-Output "Stopping Print Spooler service..."
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue

    # Kill related processes (ignore errors if they don't exist)
    $processes = @(
        "splwow64",
        "PrintQueueActionCenter",
        "printfilterpipelinesvc",
        "smartscreen",
        "printui",
        "spoolsv",
        "explorer"
    )

    foreach ($p in $processes) {
        Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2

    Write-Output "Clearing stuck print jobs..."

    # First try normal PowerShell print job cleanup
    Get-Printer | ForEach-Object {
        Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue |
        Remove-PrintJob -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Then do the hard clear in case jobs are still locked
    $spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"
    if (Test-Path $spoolPath) {
        Remove-Item "$spoolPath\*" -Force -ErrorAction SilentlyContinue -Confirm:$false
    }

    Write-Output "Starting Print Spooler service..."
    Start-Service -Name Spooler

    Write-Output "Restarting Explorer shell..."
    Start-Process explorer.exe

    Write-Output "Done. Print queue has been fully cleared."
}




