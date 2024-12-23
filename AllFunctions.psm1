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

Function RmAppx
{
    Param
    (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$PartName,
    [Parameter(Mandatory=$false, Position=1)]
    [ValidateSet("true", "false")][string]$RmProv="true"
    )
    if ($PartName = "") {return}
    try {Start-Job -Name RmAppxjob {Get-AppxPackage -AllUsers | where-object{$_.name -match $PartName} | Foreach-Object {Remove-AppxPackage -Package $_ -AllUsers -ea Ignore}} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State}
    catch {Write-Host -f red "Appx Package " + $PartName + "  remove failed"}
    try {Start-Job -Name RmAppxprovjob {if ($RmProv -ne "false") {Get-appxprovisionedpackage -online | where-object {$_.packagename -match $PartName} | Foreach-Object {Remove-AppxProvisionedPackage -online -Packagename $_.Packagename -AllUsers -ea Ignore}}} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State}
    catch {Write-Host -f red "Appx provisioned package " + $PartName + "  remove failed"}
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
        if ($StatusCode = "200") {break}
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

Function WifiPriority
{
    netsh wlan set profileparameter name='SPC_5GHz' connectionmode=auto
    Get-NetIPInterface| Select-Object -ExpandProperty InterfaceAlias | Where-Object {$_ -match 'wi' -and $_ -match 'fi'} | foreach-object {netsh wlan set profileorder name='SPC_5GHz' interface=$_ priority=1}
    Get-NetIPInterface| Select-Object -ExpandProperty InterfaceAlias | Where-Object {$_ -match 'wi' -and $_ -match 'fi'} | foreach-object {netsh wlan set profileorder name='SPC_2.4GHz' interface=$_ priority=2}
    netsh wlan connect name="SPC_5GHz"
    Start-Sleep 2
    if (Test-Connection -ComputerName www.google.com -Quiet) {Write-Host -f C "Internet connection verified"} else {Write-Warning "No Internet Connection found"}
    if (Test-Connection -ComputerName www.microsoft.com -Quiet) {Write-Host -f C "Internet connection verified"} else {Write-Warning "No Internet Connection found"}
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
    $CurFolder = Split-Path -Path $PSCommandPath -Parent
    Write-Host -f C "`r`n*** Disabling proxies ***`r`n"
    Set HTTP_PROXY=
    Set HTTPS_PROXY=
    # Set-PSRepository PSGallery -InstallationPolicy Trusted #causes nuget install to ask for confirmation
    # Time Zone & Sync
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type' 'NTP' 'String' # Autoupdate time
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'Allow' 'String' # Allow location
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' 'Start' '3' 'DWord' # Autoupdate timezone
    Start-Service -Name "W32Time" -ea silentlycontinue | out-null
    Start-Service -Name "tzautoupdate" -ea silentlycontinue | out-null
    w32tm /resync #Sync time now
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\BITS' 'Start' '2' 'DWord'
    Start-Job -Name BITS {Start-Service -Name 'BITS' -ea silentlycontinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State # Service needed for fast download
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
    if ($Status = 'Full')
    {
        # Enable hibernate full
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
        powercfg hibernate size 0 | out-null
        powercfg /h /type full | out-null
        powercfg.exe /hibernate on | out-null
        # Enable hibernate button
        AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '1' 'DWord'
        # Disabling HyperBoot to avoid it's issues
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '0' 'DWord'
    }
    elseif ($Status = 'Boot')
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
    }
    else
    {
        # Disable hibernate
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '0' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '0' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '0' 'DWord'
        powercfg hibernate size 0 | out-null
        powercfg.exe /hibernate off | out-null
        # Disable hibernate button
        AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '0' 'DWord'
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
    # Set Hibernate full
    Set-Hibernate 'Full'
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
    else {Start-Job -Name PackageProviderNuGet {Install-PackageProvider -Name NuGet -Confirm:$False -Scope AllUsers -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State;if (get-packageprovider -Name NuGet -ea silentlycontinue) {Write-Host -f C "Successfully Installed"}}
    Import-PackageProvider -Name NuGet -Force -ea silentlycontinue | out-null
    # NuGet Module
    if ((Get-Module -Name NuGet -ListAvailable -ea silentlycontinue | select -ExpandProperty Name -First 1) -eq "NuGet") {Write-Host -f C "Nuget Module already exists"}
    else {Start-Job -Name ModuleNuGet {Install-Module -Name NuGet -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State}
    Import-Module NuGet -Force -ea silentlycontinue | out-null
}

Function Ins-Choco
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Installing Chocolatey *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
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
        Start-Job -Name ModuleWinGet {Install-Module Microsoft.WinGet.Client -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
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
    New-Item -Path "$env:TEMP\IA\Winget" -ItemType Directory -ea SilentlyContinue | out-null
    $VCLibsVersion = Get-AppxPackage -Name Microsoft.VCLibs* | Sort-Object -Property Version | Select-Object -ExpandProperty Version -Last 1 | Foreach-Object { $_.ToString().split('.')[0]}
    if ([int]$VCLibsVersion -lt 14)
    {
        Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "$env:TEMP\IA\Winget\Microsoft.VCLibs.x64.14.00.Desktop.appx" -ea SilentlyContinue | out-null
        Start-Job -Name VCLibs {Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.VCLibs.x64.14.00.Desktop.appx" -ea SilentlyContinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    }
    else {Write-Host -f C "VCLibs already installed"}
    $UIXamlVersion = Get-AppxPackage -Name Microsoft.UI.Xaml* | Sort-Object -Property Version | Select-Object -ExpandProperty Version -Last 1 | Foreach-Object { $_.ToString().split('.')[0]}
    if ([int]$UIXamlVersion -lt 8)
    {
        Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "$env:TEMP\IA\Winget\Microsoft.UI.Xaml.2.8.x64.appx" -ea SilentlyContinue | out-null
        Start-Job -Name UIXaml {Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.UI.Xaml.2.8.x64.appx" -ea SilentlyContinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    }
    else {Write-Host -f C "UI Xaml already installed"}
    try {$WingetInstalled = Get-Command -Name winget -ea silentlycontinue} catch {}
    try {$latestAppInstaller = Find-WinGetPackage -id "Microsoft.AppInstaller" -MatchOption Equals | Select-Object -ExpandProperty Version} catch {$AppInstallerUpdated = $false}
    try {$InstalledAppInstaller = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' | select -ExpandProperty Version } catch {$AppInstallerUpdated = $false}
    if ($latestAppInstaller -eq $InstalledAppInstaller) {$AppInstallerUpdated = $true} else {$AppInstallerUpdated = $false}
    if ($WingetInstalled -And $AppInstallerUpdated) {write-host -f C "Winget is already installed"}
    else {
        Start-Job -Name InstallWinget1 {Start-BitsTransfer -Source "https://aka.ms/getwinget" -Destination "$env:TEMP\IA\Winget\Microsoft.DesktopAppInstaller.msixbundle" -ea SilentlyContinue | out-null;Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.DesktopAppInstaller.msixbundle" -ea SilentlyContinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
        Start-Job -Name InstallWinget2 {Add-AppxPackage https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -ea SilentlyContinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
        Start-Job -Name InstallWinget3 {Start-BitsTransfer -Source "https://cdn.winget.microsoft.com/cache/source.msix" -Destination "$env:TEMP\IA\Winget\Source.msix" -ea SilentlyContinue | out-null;Add-AppxPackage -Path "$env:TEMP\IA\Winget\Source.msix" | out-null;DISM.EXE /Online /Add-ProvisionedAppxPackage /PackagePath:"$env:TEMP\IA\Winget\Source.msix" /SkipLicense | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
        Install-Script winget-install -Force
        Start-Job -Name UpdateWinget {winget-install -Force} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
        Start-Sleep 1
        Relaunch
    }
    Start-Job -Name ConfigWinget1 {Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name ConfigWinget2 {Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.Winget.Source_8wekyb3d8bbwe} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    write-host -f C "`r`n *** Updating Winget ***"
    Install-Script winget-install -Force
    Start-Job -Name UpdateWinget {winget-install -Force} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    winget-install -CheckForUpdate
    Ins-winget-ps
    winget source reset --force
    winget upgrade Microsoft.AppInstaller --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-arSALang
{
    Write-Host -f C "`r`n *** Installing Arabic-SA language *** `r`n"
    Start-Job -Name InsAr {Install-Language -Language ar-SA} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Set-WinHomeLocation 0xcd
    Set-WinDefaultInputMethodOverride -InputTip "0401:00000401" #Default input language Arabic
    Set-WinSystemLocale -SystemLocale ar-SA
    Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True
}

Function Set-en-GB-Culture
{
    Write-Host -f C "`r`n *** Setting en-GB Culture (Regional format) *** `r`n"
    Import-Module International -Force -ea silentlycontinue | out-null
    Start-Job -Name CultureENGB {Set-Culture -CultureInfo en-GB} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-sleep 1
    $culture = Get-Culture
    $culture.DateTimeFormat.LongDatePattern = 'dd MMMM yyyy'
    $culture.DateTimeFormat.ShortDatePattern = 'dd/MM/yyyy'
    $culture.DateTimeFormat.LongTimePattern = 'hh:mm:ss tt'
    $culture.DateTimeFormat.ShortTimePattern = 'hh:mm tt'
    $culture.DateTimeFormat.ShortDatePattern = 'd/MM/yyyy'
    $culture.DateTimeFormat.FirstDayOfWeek = 'Sunday'
    $culture.NumberFormat.DigitSubstitution = 'Context'
    Start-Job -Name CustomCulture {Set-Culture -CultureInfo $culture} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    # Use this to see all properties
    # $culture | Format-List -Property *
    # $culture.DateTimeFormat
    # $culture.NumberFormat
    Start-sleep 2
    AddRegEntry 'HKCU:\Control Panel\International' 'sLongDate' 'dd MMMM yyyy' 'String'
    reg add "HKCU\Control Panel\International" /V sLongDate /T REG_SZ /D "dd MMMM yyyy" /F
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
    Start-Job -Name InsEng {Install-Language -Language en-US -CopyToSettings} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
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
    if (choco list --lo -r -e dotnet-all) {Choco upgrade dotnet-all} else {Choco install dotnet-all}
    (Find-WinGetPackage "Microsoft.DotNet.DesktopRuntime").Id | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
    (Find-WinGetPackage "Microsoft.DotNet.Runtime").Id | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
    (Find-WinGetPackage "Microsoft.DotNet.AspNetCore").Id | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
}

Function Ins-VCPPRuntime
{
    Write-Host -f C "`r`n *** Installing Visual C++ Runtime All versions *** `r`n"
    if (choco list --lo -r -e vcredist-all) {Choco upgrade vcredist-all} else {Choco install vcredist-all}
    (Find-WinGetPackage "Microsoft.VCRedist").Id | Where-Object {-not $_.EndsWith("arm64")} | ForEach-Object {winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous}
}

Function Ins-JavaRuntime
{
    Write-Host -f C "`r`n *** Installing Java Runtime Environment *** `r`n"
    winget install -e --id Oracle.JavaRuntimeEnvironment --silent --accept-source-agreements --accept-package-agreements
    if (choco list --lo -r -e javaruntime) {Choco upgrade javaruntime} else {Choco install javaruntime}
}

Function Ins-XNA
{
    Write-Host -f C "`r`n *** Installing Microsoft XNA Framework Redistributable *** `r`n"
    if (choco list --lo -r -e xna) {Choco upgrade xna} else {Choco install xna}
    winget install -e --id Microsoft.XNARedist --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-AdobeAIRRuntime
{
    Write-Host -f C "`r`n *** Installing Adobe AIR Runtime *** `r`n"
    if (choco list --lo -r -e adobeair) {Choco upgrade adobeair} else {Choco install adobeair}
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
    if (choco list --lo -r -e notepadplusplus.install) {Choco upgrade notepadplusplus.install} else {Choco install notepadplusplus.install}
}

Function Ins-Chrome
{
    Write-Host -f C "`r`n *** Installing Chrome *** `r`n"
    if (choco list --lo -r -e googlechrome) {Choco upgrade googlechrome --ignore-checksums} else {Choco install googlechrome --ignore-checksums}
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
        if (choco list --lo -r -e adobereader) {Choco upgrade adobereader} else {Choco install adobereader}
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
    Start-Job -Name CleanerAcrobatPro {if (Test-Path -Path "$env:TEMP\AdobeAcroCleaner.exe" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcroCleaner.exe" -ArgumentList "/silent","/product=0","/cleanlevel=1" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name CleanerAcrobatPro {if (Test-Path -Path "$env:TEMP\AdobeAcroCleaner.exe" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcroCleaner.exe" -ArgumentList "/silent","/product=1","/cleanlevel=1" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
}

Function Ins-AcrobatPro
{
    Unins-Acrobat
    Write-Host -f C "`r`n *** Installing Adobe Acrobat Pro DC *** `r`n"
    #17200187s8_3DHLMwa3lUSMXRF1yYFUz2
    Start-BitsTransfer -Source 'https://www.googleapis.com/drive/v3/files/17200187s8_3DHLMwa3lUSMXRF1yYFUz2?alt=media&key=AIzaSyBjpiLnU2lhQG4uBq0jJDogcj0pOIR9TQ8' -Destination "$env:TEMP\AdobeAcrobatProDC2024.002.21005x64.exe"  -ea SilentlyContinue | out-null
    Start-Job -Name AcrobatPro {if (Test-Path -Path "$env:TEMP\AdobeAcrobatProDC2024.002.21005x64.exe" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcrobatProDC2024.002.21005x64.exe" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Remove-Item -path $ENV:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db -Force -ea silentlycontinue | Out-Null
    $printer = Get-CimInstance -Class Win32_Printer -Filter "Name='Adobe PDF'"
    Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter
    (New-Object -ComObject WScript.Network).SetDefaultPrinter('Adobe PDF')
    cmd /c "DEL /F /S /Q /A %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db"
    AddRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
    Stop-Process -ProcessName explorer -Force -ea SilentlyContinue | out-null
}

Function Ins-WinRAR
{
    Write-Host -f C "`r`n *** Installing WinRAR *** `r`n"
    if (choco list --lo -r -e winrar) {Choco upgrade winrar} else {Choco install winrar}
    winget install -e --id 'RARLab.WinRAR' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-KLiteMega
{
    Write-Host -f C "`r`n *** Installing K-Lite Codec Pack Mega *** `r`n"
    if (choco list --lo -r -e k-litecodecpackmega) {Choco upgrade k-litecodecpackmega} else {Choco install k-litecodecpackmega}
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
    if (choco list --lo -r -e openal) {Choco upgrade openal} else {Choco install openal}
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
    RmAppx "DevHome"
    winget uninstall --id 'Microsoft.DevHome'
}

Function Unins-DropboxPromotion
{
    Write-Host -f C "`r`n *** Uninstalling Dropbox promotion *** `r`n"
    RmAppx "DropboxOEM"
}

Function Unins-Cortana
{
    Write-Host -f C "`r`n *** Uninstalling & disabling Cortana & tweaking search *** `r`n"
    RmAppx "Microsoft.549981C3F5F10"
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
    RmAppx "Ai.Copilot"
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
    RmAppx "Xbox"
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
    if ((Get-Module -Name NuGet -ListAvailable -ea silentlycontinue | select -ExpandProperty Name -First 1) -eq "NuGet") {Write-Host -f C "Nuget Module already exists"}
    else {Start-Job -Name UninstallTeams {Install-Module -Name UninstallTeams -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 999 | Format-List -Property Name,State}
    Import-Module UninstallTeams -Force -ea silentlycontinue | out-null
    Install-Script UninstallTeams -Confirm:$False -Force -ea silentlycontinue | out-null
    UninstallTeams -DisableChatWidget -AllUsers
    UninstallTeams -DisableOfficeTeamsInstall
    UninstallTeams
}

Function UpdateAll
{
    Write-Host -f C "`r`n *** Updating all installed applications using Winget *** `r`n"
    winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --force
    choco upgrade all -y
}

Function Ins-DirectX
{
    Write-Host -f C "`r`n *** Installing DirectX Extra Files *** `r`n"
    if (choco list --lo -r -e directx) {Choco upgrade directx} else {Choco install directx}
    scoop bucket add games
    scoop install games/dxwrapper
    Start-Job -Name DX-Extra {winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements} | Wait-Job -Timeout 999 | Format-List -Property Name,State
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
    Start-Job -Name PSWindowsUpdateModule {Install-Module -Name PSWindowsUpdate -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue | out-null} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Import-Module PSWindowsUpdate -Force -ea silentlycontinue | out-null
    Get-WUServiceManager | Foreach-Object {Add-WUServiceManager -ServiceID $_.ServiceID -Confirm:$false -ea silentlycontinue | out-null}
    Start-Job -Name WindowsUpdate {Get-WindowsUpdate -Install -ForceInstall -AcceptAll -IgnoreReboot -Silent -ea silentlycontinue}
    (New-Object -ComObject Microsoft.Update.ServiceManager).Services | Select Name,ServiceID | foreach {if($_.Name -match "Store"){$StoreServiceID=$_.ServiceID}} #Get Store Service ID
    Start-Job -Name WindowsStoreAppsUpdate {Get-WindowsUpdate -ServiceID $StoreServiceID -Install -ForceInstall -AcceptAll -IgnoreReboot -Silent -ea silentlycontinue}
    # Use kbupdate Module
    try {
    Install-Module kbupdate -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -ea silentlycontinue
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

Function Move-OneDriveUserFolders
{
    Write-Host -f C "`r`n Moving One Drive folders to User Profile folders `r`n"
    # Make sure USER PROFILE folders are not deleted
    if (!(Test-Path -Path "$env:USERPROFILE\Desktop" -ea SilentlyContinue)) {New-Item -Path "$env:USERPROFILE" -Name "Desktop" -ItemType Directory -ea SilentlyContinue | out-null}
    if (!(Test-Path -Path "$env:USERPROFILE\Documents" -ea SilentlyContinue)) {New-Item -Path "$env:USERPROFILE" -Name "Documents" -ItemType Directory -ea SilentlyContinue | out-null}
    if (!(Test-Path -Path "$env:USERPROFILE\Videos" -ea SilentlyContinue)) {New-Item -Path "$env:USERPROFILE" -Name "Videos" -ItemType Directory -ea SilentlyContinue | out-null}
    if (!(Test-Path -Path "$env:USERPROFILE\Music" -ea SilentlyContinue)) {New-Item -Path "$env:USERPROFILE" -Name "Music" -ItemType Directory -ea SilentlyContinue | out-null}
    if (!(Test-Path -Path "$env:USERPROFILE\Downloads" -ea SilentlyContinue)) {New-Item -Path "$env:USERPROFILE" -Name "Downloads" -ItemType Directory -ea SilentlyContinue | out-null}
    # Use %OneDrive% $env:OneDrive
    if ($env:OneDrive)
    {
        Get-ChildItem -Path "$env:OneDrive\Desktop" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Desktop" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDrive\Documents" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Documents" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDrive\Videos" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Videos" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDrive\Music" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Music" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDrive\Downloads" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Downloads" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDrive" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\OneDrive" -ea SilentlyContinue
    }
    # Use %OneDriveConsumer% $env:OneDriveConsumer
    if ($env:OneDriveConsumer)
    {
        Get-ChildItem -Path "$env:OneDriveConsumer\Desktop" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Desktop" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveConsumer\Documents" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Documents" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveConsumer\Videos" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Videos" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveConsumer\Music" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Music" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveConsumer\Downloads" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Downloads" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveConsumer" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\OneDrive" -ea SilentlyContinue
    }
    # Use %OneDriveCommercial% $env:OneDriveCommercial
    if ($env:OneDriveCommercial)
    {
        Get-ChildItem -Path "$env:OneDriveCommercial\Desktop" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Desktop" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveCommercial\Documents" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Documents" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveCommercial\Videos" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Videos" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveCommercial\Music" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Music" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveCommercial\Downloads" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Downloads" -ea SilentlyContinue
        Get-ChildItem -Path "$env:OneDriveCommercial" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\OneDrive" -ea SilentlyContinue
    }
    # Use default OneDrive folder path at %USERPROFILE% $env:USERPROFILE
    if (Test-Path -Path "$env:USERPROFILE\OneDrive" -ea SilentlyContinue)
    {
        Get-ChildItem -Path "$env:USERPROFILE\OneDrive\Desktop" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Desktop" -ea SilentlyContinue
        Get-ChildItem -Path "$env:USERPROFILE\OneDrive\Documents" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Documents" -ea SilentlyContinue
        Get-ChildItem -Path "$env:USERPROFILE\OneDrive\Videos" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Videos" -ea SilentlyContinue
        Get-ChildItem -Path "$env:USERPROFILE\OneDrive\Music" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Music" -ea SilentlyContinue
        Get-ChildItem -Path "$env:USERPROFILE\OneDrive\Downloads" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Downloads" -ea SilentlyContinue
    }
    # Use any OneDrive folder in the $env:USERPROFILE
    $OneDriveFolders=Get-ChildItem -Path "$env:USERPROFILE" -Directory -ea SilentlyContinue | where-object {($_.Name -like "OneDrive*")} | select -ExpandProperty Name
    if ($OneDriveFolders)
    {
        Foreach ($OneDriveFolder in $OneDriveFolders)
        {
            Get-ChildItem -Path "$OneDriveFolder\Desktop" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Desktop" -ea SilentlyContinue
            Get-ChildItem -Path "$OneDriveFolder\Documents" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Documents" -ea SilentlyContinue
            Get-ChildItem -Path "$OneDriveFolder\Videos" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Videos" -ea SilentlyContinue
            Get-ChildItem -Path "$OneDriveFolder\Music" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Music" -ea SilentlyContinue
            Get-ChildItem -Path "$OneDriveFolder\Downloads" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Downloads" -ea SilentlyContinue
            Get-ChildItem -Path "$OneDriveFolder" -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\OneDrive" -ea SilentlyContinue
        }
    }
    # Use registry Check
    $OneDriveDesktop= Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'Desktop' -ea SilentlyContinue | select -ExpandProperty 'Desktop' | where-object {($_ -like "OneDrive*")}
    if ($OneDriveDesktop) {if ($OneDriveDesktop -match "%") {$OneDriveDesktop='$env:' + $OneDriveDesktop.replace("%","")};Get-ChildItem -Path $OneDriveDesktop -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Desktop" -ea SilentlyContinue}
    $OneDriveDocuments= Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'Personal' -ea SilentlyContinue | select -ExpandProperty 'Personal' | where-object {($_ -like "OneDrive*")}
    if ($OneDriveDocuments) {if ($OneDriveDocuments -match "%") {$OneDriveDocuments='$env:' + $OneDriveDocuments.replace("%","")};Get-ChildItem -Path $OneDriveDocuments -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Documents" -ea SilentlyContinue}
    $OneDriveVideos= Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'My Video' -ea SilentlyContinue | select -ExpandProperty 'My Video' | where-object {($_ -like "OneDrive*")}
    if ($OneDriveVideos) {if ($OneDriveVideos -match "%") {$OneDriveVideos='$env:' + $OneDriveVideos.replace("%","")};Get-ChildItem -Path $OneDriveVideos -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Videos" -ea SilentlyContinue}
    $OneDriveMusic= Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name 'My Music' -ea SilentlyContinue | select -ExpandProperty 'My Music' | where-object {($_ -like "OneDrive*")}
    if ($OneDriveMusic) {if ($OneDriveMusic -match "%") {$OneDriveMusic='$env:' + $OneDriveMusic.replace("%","")};Get-ChildItem -Path $OneDriveMusic -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Music" -ea SilentlyContinue}
    $OneDriveDownloads= Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}' -ea SilentlyContinue | select -ExpandProperty '{374DE290-123F-4565-9164-39C4925E467B}' | where-object {($_ -like "OneDrive*")}
    if ($OneDriveDownloads) {if ($OneDriveDownloads -match "%") {$OneDriveDownloads='$env:' + $OneDriveDesktop.replace("%","")};Get-ChildItem -Path $OneDriveDownloads -Recurse -ea SilentlyContinue | Move-Item -Destination "$env:USERPROFILE\Downloads" -ea SilentlyContinue}
    #Adjust the paths in registry
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'AppData' '%USERPROFILE%\AppData\Roaming' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Cache' '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Cookies' '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Favorites' '%USERPROFILE%\Favorites' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'History' '%USERPROFILE%\AppData\Local\Microsoft\Windows\History' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Local AppData' '%USERPROFILE%\AppData\Local' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'My Music' '%USERPROFILE%\Music' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'My Video' '%USERPROFILE%\Videos' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'NetHood' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Network Shortcuts' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'PrintHood' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Programs' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Recent' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'SendTo' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\SendTo' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Start Menu' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Startup' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Templates' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Templates' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{374DE290-123F-4565-9164-39C4925E467B}' '%USERPROFILE%\Downloads' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Desktop' '%USERPROFILE%\Desktop' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'My Pictures' '%USERPROFILE%\Pictures' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Personal' '%USERPROFILE%\Documents' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{F42EE2D3-909F-4907-8871-4C22FC0BF756}' '%USERPROFILE%\Documents' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{0DDD015D-B06C-45D5-8C4C-F59713854639}' '%USERPROFILE%\Pictures' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}' '%USERPROFILE%' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'AppData' '%USERPROFILE%\AppData\Roaming' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Cache' '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Cookies' '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Favorites' '%USERPROFILE%\Favorites' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'History' '%USERPROFILE%\AppData\Local\Microsoft\Windows\History' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Local AppData' '%USERPROFILE%\AppData\Local' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'My Music' '%USERPROFILE%\Music' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'My Video' '%USERPROFILE%\Videos' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'NetHood' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Network Shortcuts' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'PrintHood' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Programs' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Recent' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'SendTo' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\SendTo' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Start Menu' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Startup' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Templates' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Templates' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' '{374DE290-123F-4565-9164-39C4925E467B}' '%USERPROFILE%\Downloads' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Desktop' '%USERPROFILE%\Desktop' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'My Pictures' '%USERPROFILE%\Pictures' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' 'Personal' '%USERPROFILE%\Documents' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' '{F42EE2D3-909F-4907-8871-4C22FC0BF756}' '%USERPROFILE%\Documents' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' '{0DDD015D-B06C-45D5-8C4C-F59713854639}' '%USERPROFILE%\Pictures' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' '{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}' '%USERPROFILE%' 'String'
}

Function Unins-OneDrive
{
    Write-Host -f C "`r`n *** Removing One Drive *** `r`n"
    # Kill running process onedrive
    Stop-Process -Force -Name OneDrive -ea SilentlyContinue | out-null
    cmd /c 'taskkill /f /im OneDrive.exe >nul 2>nul'
    winget uninstall OneDrive
    (Find-WinGetPackage "OneDrive").Id | ForEach-Object {winget uninstall -e --id $_ --silent}
    $OneDriveUninstallString= Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe' -Name 'UninstallString' | select -ExpandProperty 'UninstallString'
    $OneDriveUninstallString= $OneDriveUninstallString -split('/',0)[0, -1]
    $OneDriveUninstallString[0].trim()
    $OneDriveUninstallString[1] = '/' + $OneDriveUninstallString[1]
    Start-Process $OneDriveUninstallString[0] -Verb RunAs -WindowStyle Minimized -ArgumentList $OneDriveUninstallString[1]
    Start-Process 'OneDriveSetup.exe' -Verb RunAs -WindowStyle Minimized -ArgumentList '/uninstall'
    Move-OneDriveUserFolders
    Get-ScheduledTask | Where-Object {$_.Taskname -match 'OneDrive'} | Unregister-ScheduledTask -Confirm:$false -ea SilentlyContinue | out-null
    # Clean Remaining
    Remove-Item -LiteralPath "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "$env:PROGRAMDATA\Microsoft\OneDrive" -Force -Recurse -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "$env:HOMEDRIVE\OneDriveTemp" -Force -Recurse -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKEY_CLASSES_ROOT:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKEY_CLASSES_ROOT:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\OneDrive'  -Recurse -force -ea SilentlyContinue | out-null
    #AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' '1' 'DWord'
    #AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' 'KFMBlockOptIn' '1' 'DWord'
    #AddRegEntry 'HKLM:\SOFTWARE\Microsoft\OneDrive' 'PreventNetworkTrafficPreUserSignIn' '1' 'DWord'
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
    Start-Job -Name NFR1 {Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Enable-NetFirewallRule} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR2 {Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR3 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Private} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR4 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Private} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR5 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Domain} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR6 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Domain} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR7 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Public} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR8 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Public} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR9 {Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Any} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    Start-Job -Name NFR10 {Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Any} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    # Make sure required protocols are enabled in the adapter (they should be by default)
    Get-NetAdapter | foreach {Enable-NetAdapterBinding -Name $_.Name -DisplayName "File and Printer Sharing for Microsoft Networks"}
    Get-NetAdapter | foreach {Enable-NetAdapterBinding -Name $_.Name -DisplayName "Client for Microsoft Networks"}
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
    ipconfig /release
    ipconfig /flushdns
    ipconfig /renew
    netsh int ip reset
    netsh winsock reset
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
    #Desktop Icons
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" '0' 'DWord'
    # SmartScreen
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' 'String'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell' 'value' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl' 'value' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Edge\SmartScreenEnabled' 'Default' '0' 'String'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
    AddRegEntry 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter' 'EnabledV9' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'PreventOverride' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe' 'Debugger' 'ctfmon' 'String'
    # Lock Screen & logon
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData' 'AllowLockScreen' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreen' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableAcrylicBackgroundOnLogon' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableLogonBackgroundImage' '0' 'DWord'
    Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -force -ea SilentlyContinue | out-null
    Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -force -ea SilentlyContinue | out-null
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'dontdisplaylastusername' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'shutdownwithoutlogon' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'undockwithoutlogon' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableFirstLogonAnimation' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLockedUserId' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableForcedLogoff' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenOverlayEnabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen' 'SlideshowDuration' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\AccessPage\Camera' 'CameraEnabled' '0' 'DWord'
    # Blocked Downloaded Files
    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -force -ea SilentlyContinue | out-null
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' '1' 'DWord'
    AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations' 'DefaultFileTypeRisk' '24914' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations' 'DefaultFileTypeRisk' '24914' 'DWord'
    #  Turn On Hardware Accelerated GPU Scheduling  HAGS
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' '2' 'DWord'
    # Apps run in the background
    AddRegEntry 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled' '0' 'DWord' # enabled to avoid issues
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'BackgroundAppGlobalToggle' '1' 'DWord'
    # Fast startup animation time
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HybridBootAnimationTime' '0' 'DWord'
    #  Disable spectre and meltdown
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverrideMask' '3' 'DWord'
    #  TURN OFF Automatically update maps
    AddRegEntry 'HKLM:\SYSTEM\Maps' 'AutoUpdateEnabled' '0' 'DWord'
    #  Telemetry & Track & Feedback
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' '0' 'DWord'
    AddRegEntry 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' '0' 'DWord'
    Remove-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -force -ea SilentlyContinue | out-null
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'AllowCommercialDataPipeline' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'FeedbackHubAlwaysSaveDiagnosticsLocally' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'LimitEnhancedDiagnosticDataWindowsAnalytics' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' 'PreventHandwritingDataSharing' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' 'PreventHandwritingErrorReports' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' 'Start' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'UserFeedbackAllowed' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Siuf\Rules' 'PeriodInNanoSeconds' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\MediaPlayer\Preferences' 'UsageTracking' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_TrackDocs' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack' 'Start' '4' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'HideRecentlyAddedApps' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpyNetReporting' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' '2' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' 'DontReportInfectionInformation' '1' 'DWord'
    # Print
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'SpoolerPriority' '128' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\International' 'iPaperSize' '9' 'String'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International' 'iPaperSize' '9' 'String'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'KMPrintersAreBlocked' '0' 'DWord'
    # Startup & performance
    Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -ea SilentlyContinue | out-null
    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -ea SilentlyContinue | out-null
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPAppHelperCap' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPCustomCapDriver' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPDiagsCap' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPNetworkCap' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPPrintScanDoctorService' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\hpqcaslwmiex' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSmartDeviceAgentBase' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSupportSolutionsFrameworkService' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSysInfoCap' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HpTouchpointAnalyticsService' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\RstMwService' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Intel R Capability Licensing Service TCP IP Interface' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SECOMNService' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\USER_ESRV_SVC_QUEENCREEK' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Intel R SUR QC SAM' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\jhi_service' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SystemUsageReportSvc_QUEENCREEK' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\MozillaMaintenance' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WsAppService3' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ESRV_SVC_QUEENCREEK' 'run' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ESRV_SVC_QUEENCREEK' 'Start' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch' 'WSearch' '3' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SysMain' 'Start' '4' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice' 'Start' '4' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc' 'Start' '4' 'DWord' #Error reporting
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' '1' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\Desktop' 'AutoEndTasks' '1' 'String'
    AddRegEntry 'HKCU:\Control Panel\Desktop' 'SmoothScroll' '0' 'DWord'
    AddRegEntry 'HKCU:\Control Panel\Desktop' 'WaitToKillAppTimeout' '1500' 'String'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control' 'WaitToKillServiceTimeout' '1500' 'String'
    AddRegEntry 'HKCU:\Control Panel\Desktop' 'HungAppTimeout' '1500' 'String'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoRestartShell' '1' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'IRQ8Priority' '1' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnableSuperfetch' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter' 'NoMobilityCenter' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoInstrumentation' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' 'AllowWindowsInkWorkspace' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\input\TIPC' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' 'CEIPEnable' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableUAR' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AutoDownloadAndUpdateMapData' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableUwpStartupTasks' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'SupportUwpStartupTasks' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableVirtualization' '1' 'DWord'
    # Taskbar & notifications
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoChangeStartMenu' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' 'ToastEnabled' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSyncProviderNotifications' '0' 'DWord'
    # Left alignment 
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAl' '0' 'DWord'
    # Hide task view
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowTaskViewButton' '0' 'DWord'
    # Hide chat
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' '0' 'DWord'
    # Hide news and interests
    AddRegEntry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds' 'EnableFeeds' '0' 'DWord'
    # Hide meet now
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' '1' 'DWord'
    # Hide People
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' 'PeopleBand' '0' 'DWord'
    # Hide widgets
    AddRegEntry 'HKLM:\Software\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' '0' 'DWord'
    # Search box Taskbar Mode ,0 hide ,1 icon only ,2 search box ,3 icon and label
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'SearchboxTaskbarMode' '1' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarDa' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' 'ShellFeedsTaskbarViewMode' '2' 'DWord'
    # Advertising
    AddRegEntry 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSyncProviderNotifications' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' 'AllowAdvertising' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging' 'AllowMessageSync' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353698Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338387Enabled' '0' 'DWord'
    # Biometrics
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' 'Enabled' '1' 'DWord'
    # Clipboard
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowClipboardHistory' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ClipboardHistory' 'SyncPolicy' '5' 'DWord'
    # SettingSync
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility' 'Enabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows' 'Enabled' '0' 'DWord'
    # Tweaks
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' 'NoGenTicket' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AllowUntriggeredNetworkTrafficOnSettingsPage' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' 'EnableActiveProbing' '0' 'DWord'
    AddRegEntry 'HKU:\.DEFAULT\Control Panel\Keyboard' 'InitialKeyboardIndicators' '2147483650' 'String'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput' 'EnableTouchKeyboardAutoInvokeInDesktopMode' '0' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}' 'SortOrderIndex' '84' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Classes\AllFilesystemObjects' 'DefaultDropEffect' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'ShowDriveLettersFirst' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'Link' 'hex 3:00,00,00,00' 'String'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'Link' 'hex 3:00,00,00,00' 'String'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'DisablePreviewDesktop' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoPreviewPane' '0' 'DWord'
    AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoLowDiskSpaceChecks' '1' 'DWord'
    AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' 'ModelDownloadAllowed' '0' 'DWord'
    AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'fullprivilegeauditing' '0' 'DWord'
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
    #Start-Job -Name OfficeToolPlus {if (Test-Path -Path "$env:TEMP\IA\office" -ea SilentlyContinue) {Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\IA\office" -ea SilentlyContinue | out-null}} | Wait-Job -Timeout 999 | Format-Table -Wrap -AutoSize -Property Name,State
    #./"Office Tool Plus.Console.exe" deploy /rmall /display false
    #./"Office Tool Plus.Console.exe" ospp /clall
}

Function Uninscomponents-Office
{
    Get-Package -Name "*Office*" | Uninstall-Package
    # Remove MS Store Office 365
    RmAppx "Microsoft.Office.Desktop"
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
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'A4Letter' '0' 'DWord'
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
    if ($Filelink -ne $null) {$Response = Invoke-WebRequest -Uri $FileLink -OutFile "$env:TEMP\IA\office\officedeploymenttool.exe"}
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
}

Function OpenMSStoreUpdate #Not used
{
    Write-Host -f C "`r`n *** MS Store Apps Updates *** `r`n"
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
}

Function Clean-up
{
    Write-Host -f C "`r`n======================================================================================================================"
    Write-Host -f C "***************************** Cleaning up *****************************"
    Write-Host -f C "======================================================================================================================`r`n"
    Remove-Item -LiteralPath "$env:TEMP\IA" -Force -Recurse -ea SilentlyContinue | out-null
}