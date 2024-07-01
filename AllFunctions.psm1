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
        if(!(Test-Path -LiteralPath $Path)) {New-Item $Path -force -ea SilentlyContinue | out-null}
        if(Test-Path -LiteralPath $Path) {New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ea SilentlyContinue | out-null}
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
        else {Write-Host -F Cyan "Unsupported type"}
        }
        catch
        {
            Write-Host -F Cyan "Error: " + $Error # Might need takeown or runing as system or trusted installer
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
    $PartName = '*' + $PartName + '*'
    try
    {
    Get-AppxPackage -AllUsers | where-object{$_.name -like $PartName} | Foreach-Object {Remove-AppxPackage -Package $_ -AllUsers -EA Ignore}
    }
    catch {Write-Host -F Cyan "Appx Package " + $PartName + "  remove failed"}
    try
    {
        if ($RmProv -ne "false") {Get-appxprovisionedpackage -online | where-object {$_.packagename -like $PartName} | Foreach-Object {Remove-AppxProvisionedPackage -online -Packagename $_.Packagename -AllUsers -EA Ignore}}
    }
    catch {Write-Host -F Cyan "Appx provisioned package " + $PartName + "  remove failed"}
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
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '1' 'DWord'
        AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
        powercfg hibernate size 0 | out-null
        powercfg /h /type full | out-null
        powercfg.exe /hibernate on | out-null
        # Enable hibernate button
        AddRegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '1' 'DWord'
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
            $Response = Invoke-WebRequest -Uri $Uri
            # This will only execute if the Invoke-WebRequest is successful.
            $StatusCode = $Response.StatusCode
        }
        catch
        {
            # Write-Host -F Cyan "StatusCode:" $_.Exception.Response.StatusCode.value__
            # Write-Host -F Cyan "StatusDescription:" $_.Exception.Response.StatusDescription
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
    if (Test-Path -Path $Path -PathType Leaf)
    {
        takeown /a /f $Path
        Write-Host "y" -NoNewline | icacls $Path /t /c /grant "administrators:F"
    }
    elseif (Test-Path -Path $Path -PathType Container)
    {
        takeown /a /r /d y /f $Path
        Write-Host -F Cyan "y`r`n" | icacls $Path /t /c /grant "administrators:F"
    }
    else {Write-Host -F Cyan "Path is wrong or not supported"}
}

Function InitializeCommands
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Initializing *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
Set-ExecutionPolicy Bypass -Force -EA SilentlyContinue | out-null
$ErrorActionPreference = 'Continue'
$progressPreference = 'silentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
Set-PSRepository PSGallery -InstallationPolicy Trusted
New-Item -Path "$env:TEMP\IA" -ItemType Directory -EA SilentlyContinue | out-null
$CurFolder = Split-Path -Path $PSCommandPath -Parent
Write-Host -F Cyan "`r`n*** Disabling proxies ***`r`n"
Set HTTP_PROXY=
Set HTTPS_PROXY=
}

Function MaxPowerPlan
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Activating Max Performance Power Plan *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
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
if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\c763b4ec-0e50-4b6b-9bed-2b92a6ee884e\7ec1751b-60ed-4588-afb5-9819d3d77d90')
{
    powercfg /setacvalueindex $MaxPlanGUID 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' '7ec1751b-60ed-4588-afb5-9819d3d77d90' '0x00000003' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' '7ec1751b-60ed-4588-afb5-9819d3d77d90' '0x00000003' | out-null
}
# ATI graphics powerplay settings # sub_GUID: 'f693fb01-e858-4f00-b20f-f30e12ac06d6' # setting_GUID: '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' # 1 Best performance
if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\f693fb01-e858-4f00-b20f-f30e12ac06d6\191f65b5-d45c-4a4f-8aae-1ab8bfd980e6')
{
    powercfg /setacvalueindex $MaxPlanGUID 'f693fb01-e858-4f00-b20f-f30e12ac06d6' '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' '0x00000001' | out-null
    powercfg /setdcvalueindex $MaxPlanGUID 'f693fb01-e858-4f00-b20f-f30e12ac06d6' '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' '0x00000001' | out-null
}
# Switchable dynamic graphics global settings # sub_GUID: 'e276e160-7cb0-43c6-b20b-73f5dce39954' # setting_GUID: 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' # 3 Maximize performance
if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\e276e160-7cb0-43c6-b20b-73f5dce39954\a1662ab2-9d34-4e53-ba8b-2639b9e20857')
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
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Installing Windows Features using DISM *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
Write-Host -F Cyan "`r`n*** Installing .NetFX3 ***`r`n"
$St1 = dism /online /get-featureinfo /featurename:NetFx3 | Select-String State | Foreach-Object { $_.ToString().split(':')[1] -replace '\s','' }
if ($St1 -ne "Enabled" ) {DISM /Online /Enable-Feature /FeatureName:NetFx3 /NoRestart}
else {Write-Host -F Cyan "Already Installed"}
Write-Host -F Cyan "`r`n*** Installing DirectPlay ***`r`n"
$St2 = dism /online /get-featureinfo /featurename:DirectPlay | Select-String State | Foreach-Object { $_.ToString().split(':')[1] -replace '\s','' }
if ($St2 -ne "Enabled" ) {DISM /Online /Enable-Feature /FeatureName:DirectPlay /All /NoRestart}
else {Write-Host -F Cyan "Already Installed"}
}

Function Ins-Nuget
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Installing Nuget provider *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
$NuGetInstalled = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction Ignore
if (-not $NuGetInstalled) {
    Install-PackageProvider -Name NuGet -Confirm:$False -Force -EA silentlycontinue | out-null
    if (get-packageprovider -Name NuGet) {Write-Host -F Cyan "Successfully Installed"}
}
else {Write-Host -F Cyan "Already Installed"}
}

Function Install-Winget
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Installing Winget and its dependencies *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
New-Item -Path "$env:TEMP\IA\Winget" -ItemType Directory -EA SilentlyContinue | out-null
$VCLibsVersion = Get-AppxPackage -Name Microsoft.VCLibs* | Sort-Object -Property Version | Select-Object -ExpandProperty Version -Last 1 | Foreach-Object { $_.ToString().split('.')[0]}
if ([int]$VCLibsVersion -lt 14)
{
    Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "$env:TEMP\IA\Winget\Microsoft.VCLibs.x64.14.00.Desktop.appx" -EA SilentlyContinue | out-null
    Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.VCLibs.x64.14.00.Desktop.appx" -EA SilentlyContinue | out-null
}
else {Write-Host -F Cyan "VCLibs already installed"}
$UIXamlVersion = Get-AppxPackage -Name Microsoft.UI.Xaml* | Sort-Object -Property Version | Select-Object -ExpandProperty Version -Last 1 | Foreach-Object { $_.ToString().split('.')[0]}
if ([int]$UIXamlVersion -lt 8)
{
    Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "$env:TEMP\IA\Winget\Microsoft.UI.Xaml.2.8.x64.appx" -EA SilentlyContinue | out-null
    Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.UI.Xaml.2.8.x64.appx" -EA SilentlyContinue | out-null
}
else {Write-Host -F Cyan "UI Xaml already installed"}
if (!(Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe))
{
    Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$env:TEMP\IA\Winget\Microsoft.DesktopAppInstaller.msixbundle" -EA SilentlyContinue | out-null
    Add-AppxPackage "$env:TEMP\IA\Winget\Microsoft.DesktopAppInstaller.msixbundle" -EA SilentlyContinue | out-null
}
else {Write-Host -F Cyan "winget already installed"}
}

Function Ins-Terminal
{
Write-Host -F Cyan "Installing Windows Terminal"
winget install -e --id 'Microsoft.WindowsTerminal' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-arSALang
{
Write-Host -F Cyan "`r`n*** Installing Arabic-SA language ***`r`n"
Install-Language -Language ar-SA
}

Function Ins-enUSLang
{
Write-Host -F Cyan "`r`n*** Installing English-US language ***`r`n"
Install-Language -Language en-US -CopyToSettings
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguage' '0409' 'String'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguageFallback' '@ "en-US"' 'MultiString'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'Default' '0409' 'String'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale' ' default' '00000409' 'String'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale' ' Default' '00000409' 'String'
AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'Languages' '@ "en-US"' 'MultiString'
AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup\en-US' '0409:00000409' '1' 'DWord'
}

Function Unins-enGBLang
{
Write-Host -F Cyan "`r`n*** Removing English-GB language ***`r`n"
Uninstall-Language -Language en-GB;lpksetup.exe /u en-GB /s /r
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language\English_UK"  -Recurse -force -EA SilentlyContinue | out-null
Remove-Item -LiteralPath "HKCU:\Control Panel\International\User Profile System Backup\en-GB"  -Recurse -force -EA SilentlyContinue | out-null
}

Function Tweak-Language
{
AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowAutoCorrection' '1' 'DWord'
AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowTextPrediction' '1' 'DWord'
AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowCasing' '1' 'DWord'
AddRegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowShiftLock' '1' 'DWord'
}

Function Ins-DotNetRuntime
{
Write-Host -F Cyan "Installing .Net Runtime All versions"
if (choco list --lo -r -e dotnet-all) {Choco upgrade dotnet-all} else {Choco install dotnet-all}
winget install -e --id Microsoft.DotNet.DesktopRuntime.3_1 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.DesktopRuntime.5 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.DesktopRuntime.6 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.DesktopRuntime.7 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.DesktopRuntime.8 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.DesktopRuntime.Preview --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.Runtime.3_1 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.Runtime.5 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.Runtime.6 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.Runtime.7 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.Runtime.8 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.Runtime.Preview --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.AspNetCore.3_1 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.AspNetCore.5 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.AspNetCore.6 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.AspNetCore.7 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.AspNetCore.8 --silent --accept-source-agreements --accept-package-agreements
winget install -e --id Microsoft.DotNet.AspNetCore.Preview --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-VCPPRuntime
{
Write-Host -F Cyan "Installing Visual C++ Runtime All versions"
if (choco list --lo -r -e vcredist-all) {Choco upgrade vcredist-all} else {Choco install vcredist-all}
winget install -e --id "Microsoft.VCRedist.2005.x86" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2005.x64" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2008.x86" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2008.x64" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2010.x86" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2010.x64" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2012.x86" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2012.x64" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2013.x86" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2013.x64" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2015+.x86" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
winget install -e --id "Microsoft.VCRedist.2015+.x64" --silent --uninstall-previous --accept-source-agreements --accept-package-agreements
}

Function Ins-JavaRuntime
{
Write-Host -F Cyan "Installing Java Runtime Environment"
winget install -e --id Oracle.JavaRuntimeEnvironment --silent --accept-source-agreements --accept-package-agreements
if (choco list --lo -r -e javaruntime) {Choco upgrade javaruntime} else {Choco install javaruntime}
}

Function Ins-XNA
{
Write-Host -F Cyan "Installing Microsoft XNA Framework Redistributable"
winget install -e --id Microsoft.XNARedist --silent --accept-source-agreements --accept-package-agreements
if (choco list --lo -r -e xna) {Choco upgrade xna} else {Choco install xna}
}

Function Ins-AdobeAIRRuntime
{
Write-Host -F Cyan "Installing Adobe AIR Runtime"
if (choco list --lo -r -e adobeair) {Choco upgrade adobeair} else {Choco install adobeair}
}

Function Ins-DirectX
{
Write-Host -F Cyan "`r`n*** Installing DirectX ***`r`n"
Start-Process 'wt.exe' -Wait -Verb RunAs -WindowStyle Minimized -ArgumentList 'winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements'
}

Function Ins-WhatsApp
{
Write-Host -F Cyan "Installing WhatsApp"
winget install -e --name 'WhatsApp' --id '9NKSQGP7F2NH' --source 'msstore' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-WScan
{
Write-Host -F Cyan "Installing Windows Scan"
winget install -e --name 'Windows Scan' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-NotepadPP
{
Write-Host -F Cyan "Installing Notepad++"
winget install -e --name 'Notepad++' --silent --accept-source-agreements --accept-package-agreements
if (choco list --lo -r -e notepadplusplus.install) {Choco upgrade notepadplusplus.install} else {Choco install notepadplusplus.install}
}

Function Ins-Chrome
{
Write-Host -F Cyan "Installing Chrome"
winget install -e --id 'Google.Chrome' --silent --accept-source-agreements --accept-package-agreements
if (choco list --lo -r -e googlechrome) {Choco upgrade googlechrome --ignore-checksums} else {Choco install googlechrome}
# remove logon chrome
Remove-Item -LiteralPath "HKLM:\Software\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}"  -Recurse -force -EA SilentlyContinue | out-null
# disable chrome services
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService' '4' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\gupdate' 'Start' '4' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem' 'Start' '4' 'DWord'
# remove chrome tasks
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineCore'} | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | out-null
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineUA'} | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | out-null
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdaterTaskSystem'} | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | out-null
}

Function Tweak-Edge
{
Write-Host -F Cyan 'Tweaking Edge'
# edge
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'AutofillCreditCardEnabled' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser' 'AllowAddressBarDropdown' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' 'AllowPrelaunch' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
# remove logon edge
Remove-Item -LiteralPath "HKLM:\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}"  -Recurse -force -EA SilentlyContinue | out-null
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' 'AllowTabPreloading' '0' 'DWord'
# disable edge services
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService' 'Start' '4' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate' 'Start' '4' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem' 'Start' '4' 'DWord'
# remove edge tasks
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore'} | Unregister-ScheduledTask -Confirm:$false -EA silentlycontinue | out-null
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA'} | Unregister-ScheduledTask -Confirm:$false -EA silentlycontinue | out-null
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateBrowserReplacementTask'} | Unregister-ScheduledTask -Confirm:$false -EA silentlycontinue | out-null
}

Function Ins-Acrobat
{
Write-Host -F Cyan "Installing Adobe Acrobat Reader DC"
$Acrobat = Get-Package -Name 'Adobe Acrobat (64-bit)'
if ($Acrobat -ne $null) {Write-Host -F Cyan "Adobe Acrobat (64-bit) found installed"}
else
{
    winget install -e --id 'Adobe.Acrobat.Reader.64-bit' --silent --accept-source-agreements --accept-package-agreements
    if (choco list --lo -r -e adobereader) {Choco upgrade adobereader} else {Choco install adobereader}
}
}

Function Ins-WinRAR
{
Write-Host -F Cyan "Installing WinRAR"
winget install -e --id 'RARLab.WinRAR' --silent --accept-source-agreements --accept-package-agreements
if (choco list --lo -r -e winrar) {Choco upgrade winrar} else {Choco install winrar}
}

Function Ins-KLiteMega
{
Write-Host -F Cyan "Installing K-Lite Codec Pack Mega"
winget install -e --id 'CodecGuide.K-LiteCodecPack.Mega' --silent --accept-source-agreements --accept-package-agreements
if (choco list --lo -r -e k-litecodecpackmega) {Choco upgrade k-litecodecpackmega} else {Choco install k-litecodecpackmega}
}

Function Ins-VLC
{
Write-Host -F Cyan "Installing VLC"
winget install -e --id 'VideoLAN.VLC' --silent --accept-source-agreements --accept-package-agreements
winget install -e --id 'XPDM1ZW6815MQM' --silent --accept-source-agreements --accept-package-agreements
}

Function Ins-OpenAl
{
Write-Host -F Cyan "Installing OpenAl"
if (choco list --lo -r -e openal) {Choco upgrade openal} else {Choco install openal}
}

Function Ins-ExtraFonts
{
Write-Host -F Cyan "Installing Extra Fonts"
if (choco list --lo -r -e dejavufonts) {Write-Host -F Cyan "dejavufonts already installed"} else {Choco install dejavufonts}
if (choco list --lo -r -e victormononf) {Choco upgrade victormononf} else {Choco install victormononf}
}

Function Winget-UpdateAll
{
Write-Host -F Cyan "`r`n*** Updating all installed applications using Winget ***`r`n"
winget upgrade --all --disable-interactivity --silent --accept-source-agreements --accept-package-agreements --force
}

Function Windows-Update
{
Write-Host -F Cyan "`r`n*** Starting Windows Updates ***`r`n"
Start-Service -Name "wuauserv" -EA silentlycontinue | out-null
Start-Service -Name "UsoSvc" -EA silentlycontinue | out-null
Install-Module -Name PSWindowsUpdate -Repository PSGallery -Confirm:$False -Force -EA silentlycontinue
Import-Module PSWindowsUpdate -Force -EA silentlycontinue
Get-WUServiceManager | Foreach-Object {Add-WUServiceManager -ServiceID $_.ServiceID -Confirm:$false -EA silentlycontinue | out-null}
Get-WindowsUpdate -Install -ForceInstall -WithHidden -AcceptAll -IgnoreReboot -Silent -EA silentlycontinue
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
usoclient ScanInstallWait
UsoClient RefreshSettings
UsoClient StartScan
UsoClient StartDownload
usoclient StartInstall
wuauclt /detectnow /updatenow
}

Function Unins-MSTeams
{
Write-Host -F Cyan "`r`n*** Uninstalling Microsoft Teams ***`r`n"
Install-Module -Name UninstallTeams -Repository PSGallery -Confirm:$False -Force -EA silentlycontinue | out-null
Import-Module UninstallTeams -Force -EA silentlycontinue | out-null
Install-Script UninstallTeams -Confirm:$False -Force -EA silentlycontinue | out-null
UninstallTeams -DisableChatWidget -AllUsers
UninstallTeams -DisableOfficeTeamsInstall
UninstallTeams
}

Function Unins-Cortana
{
Write-Host -F Cyan "`r`n*** Uninstalling & disabling Cortana & tweaking search ***`r`n"
RmAppx 'Microsoft.549981C3F5F10'
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
Write-Host -F Cyan "`r`n*** Uninstalling & disabling Copilot ***`r`n"
RmAppx 'Ai.Copilot'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
AddRegEntry 'HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
# remove copilot from taskbar
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowCopilotButton' '0' 'DWord'
}

Function Unins-Xbox
{
Write-Host -F Cyan "`r`n*** Uninstalling Xbox & Game Bar ***`r`n"
RmAppx 'Xbox'
AddRegEntry "HKLM:\System\CurrentControlSet\Services\xbgm" "Start" '4' 'DWORD'
Set-Service -Name XblAuthManager -StartupType Disabled -EA silentlycontinue | out-null
Set-Service -Name XblGameSave -StartupType Disabled -EA silentlycontinue | out-null
Set-Service -Name XboxGipSvc -StartupType Disabled -EA silentlycontinue | out-null
Set-Service -Name XboxNetApiSvc -StartupType Disabled -EA silentlycontinue | out-null
# Disabling scheduled tasks
Get-ScheduledTask -TaskName 'XblGameSaveTask' | Disable-ScheduledTask -EA silentlycontinue | out-null
#  Disable Game DVR
AddRegEntry 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR' 'value' '0' 'DWord'
AddRegEntry 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR' 'AllowgameDVR' '0' 'DWORD'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' '0' 'DWord'
#  Disable Game Bar
AddRegEntry 'HKCU:\Software\Microsoft\GameBar' 'AllowAutoGameMode' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled' '0' 'DWord'
}

Function Unins-OneDrive
{
Write-Host -F Cyan "`r`n*** Removing One Drive ***`r`n"
# Kill running process onedrive
Stop-Process -Force -Name OneDrive -EA SilentlyContinue | out-null
cmd /c '"taskkill /f /im OneDrive.exe" >nul 2>nul'
Get-ScheduledTask | Where-Object {$_.Taskname -match 'OneDrive'} | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | out-null
cmd /c '"%SystemRoot%\System32\OneDriveSetup.exe /uninstall" >nul 2>nul'
cmd /c '"%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall" >nul 2>nul'
cmd /c 'Move /y "%OneDrive%\Desktop" "%USERPROFILE%\Desktop" >nul 2>nul'
cmd /c 'Move /y "%OneDrive%\Documents" "%USERPROFILE%\Documents" >nul 2>nul'
cmd /c 'Move /y "%OneDrive%\Videos" "%USERPROFILE%\Videos" >nul 2>nul'
cmd /c 'Move /y "%OneDrive%\Music" "%USERPROFILE%\Music" >nul 2>nul'
cmd /c 'Move /y "%OneDrive%\Downloads" "%USERPROFILE%\Downloads" >nul 2>nul'
cmd /c 'Move /y "%OneDriveConsumer%\Desktop" "%USERPROFILE%\Desktop" >nul 2>nul'
cmd /c 'Move /y "%OneDriveConsumer%\Documents" "%USERPROFILE%\Documents" >nul 2>nul'
cmd /c 'Move /y "%OneDriveConsumer%\Videos" "%USERPROFILE%\Videos" >nul 2>nul'
cmd /c 'Move /y "%OneDriveConsumer%\Music" "%USERPROFILE%\Music" >nul 2>nul'
cmd /c 'Move /y "%OneDriveConsumer%\Downloads" "%USERPROFILE%\Downloads" >nul 2>nul'
cmd /c 'Move /y "%OneDriveCommercial%\Desktop" "%USERPROFILE%\Desktop" >nul 2>nul'
cmd /c 'Move /y "%OneDriveCommercial%\Documents" "%USERPROFILE%\Documents" >nul 2>nul'
cmd /c 'Move /y "%OneDriveCommercial%\Videos" "%USERPROFILE%\Videos" >nul 2>nul'
cmd /c 'Move /y "%OneDriveCommercial%\Music" "%USERPROFILE%\Music" >nul 2>nul'
cmd /c 'Move /y "%OneDriveCommercial%\Downloads" "%USERPROFILE%\Downloads" >nul 2>nul'
cmd /c 'rd "C:\OneDriveTemp" /Q /S >nul 2>nul'
cmd /c 'rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >nul 2>nul'
cmd /c 'rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >nul 2>nul'
cmd /c 'REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>nul'
cmd /c 'REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>nul'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'AppData' '%USERPROFILE%\AppData\Roaming' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Cache' '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Cookies' '%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Favorites' '%USERPROFILE%\Favorites' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'History' '%USERPROFILE%\AppData\Local\Microsoft\Windows\History' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Local AppData' '%USERPROFILE%\AppData\Local' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'My Music' '%USERPROFILE%\Music' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'My Video' '%USERPROFILE%\Videos' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'NetHood' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Network Shortcuts' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'PrintHood' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Programs' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Recent' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'SendTo' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\SendTo' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Start Menu' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Startup' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Templates' '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Templates' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{374DE290-123F-4565-9164-39C4925E467B}' '%USERPROFILE%\Downloads' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Desktop' '%USERPROFILE%\Desktop' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'My Pictures' '%USERPROFILE%\Pictures' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Personal' '%USERPROFILE%\Documents' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{F42EE2D3-909F-4907-8871-4C22FC0BF756}' '%USERPROFILE%\Documents' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{0DDD015D-B06C-45D5-8C4C-F59713854639}' '%USERPROFILE%\Pictures' 'ExpandString'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}' '%USERPROFILE%' 'ExpandString'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\OneDrive' 'PreventNetworkTrafficPreUserSignIn' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' 'KFMBlockOptIn' '1' 'DWord'
}

Function DeepTweaks
{
Write-Host -F Cyan "`r`n*** Applying Deep Tweaks ***`r`n"
Write-Host -F Cyan "`r`n*** Stop Integrity check ***`r`n"
bcdedit /set nointegritychecks on
Write-Host -F Cyan "`r`n*** Disable nx (DEP) ***`r`n"
cmd /c 'bcdedit /set {current} nx AlwaysOff'
Write-Host -F Cyan "`r`n*** tsc Enhanced ***`r`n"
bcdedit /set tscsyncpolicy Enhanced
Write-Host -F Cyan "`r`n*** Disable hyper virtualization ***`r`n"
bcdedit /set hypervisorlaunchtype off
}

Function Dis-BitLocker
{
Write-Host -F Cyan "`r`n*** Disabling BitLocker ***`r`n"
Get-BitLockerVolume | foreach {manage-bde -unlock $_.MountPoint -recoverypassword (Get-BitLockerVolume -MountPoint $_.MountPoint).KeyProtector.RecoveryPassword -EA SilentlyContinue} | out-null
Clear-BitLockerAutoUnlock -EA SilentlyContinue | out-null
Get-BitLockerVolume | foreach {Disable-BitLocker -MountPoint $_.MountPoint -EA SilentlyContinue} | out-null
Get-BitLockerVolume | foreach {manage-bde -off $_.MountPoint} | out-null
}

Function Activate-Guest
{
Write-Host -F Cyan "`r`n*** Activating Guest account ***`r`n"
net user guest /active:yes
Write-Host -F Cyan "`r`n" | net user guest *
net user guest /passwordreq:no
}

Function Tweak-schtasks
{
Write-Host -F Cyan "Disabling scheduled tasks that are considered unnecessary"
Get-ScheduledTask -TaskName 'Consolidator' | Disable-ScheduledTask -EA SilentlyContinue | out-null
Get-ScheduledTask -TaskName 'UsbCeip' | Disable-ScheduledTask -EA SilentlyContinue | out-null
Get-ScheduledTask -TaskName 'DmClient' | Disable-ScheduledTask -EA SilentlyContinue | out-null
Get-ScheduledTask -TaskName 'DmClientOnScenarioDownload' | Disable-ScheduledTask -EA SilentlyContinue | out-null
}

Function Registry-Tweaks
{
Write-Host -F Cyan "Applying Registry Tweaks"
# SmartScreen
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell' 'value' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl' 'value' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Edge\SmartScreenEnabled' ' Default' '0' 'String'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
AddRegEntry 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter' 'EnabledV9' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'PreventOverride' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe' 'Debugger' 'ctfmon' 'String'
# Lock Screen & logon
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData' 'AllowLockScreen' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreen' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableAcrylicBackgroundOnLogon' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableLogonBackgroundImage' '0' 'DWord'
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -force -EA SilentlyContinue | out-null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -force -EA SilentlyContinue | out-null
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'dontdisplaylastusername' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'scforceoption' '0' 'DWord'
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
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -force -EA SilentlyContinue | out-null
Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -force -EA SilentlyContinue | out-null
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
Remove-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -force -EA SilentlyContinue | out-null
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
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpyNetReporting' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' '2' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' 'DontReportInfectionInformation' '1' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack' 'Start' '4' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'HideRecentlyAddedApps' '0' 'DWord'
# Office
AddRegEntry 'HKCU:\Software\Microsoft\Office\Common\ClientTelemetry' 'DisableTelemetry' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry' 'SendTelemetry' '3' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'QMEnable' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'UpdateReliabilityData' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings' 'InlineTextPrediction' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'Enablelogging' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'EnableUpload' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'EnableFileObfuscation' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'SurveyEnabled' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'Enabled' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'IncludeEmail' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'DisconnectedState' '2' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'UserContentDisabled' '2' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'DownloadContentDisabled' '2' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'ControllerConnectedServicesEnabled' '2' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'UI Theme' '3' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerDataOptInReason' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerDataOptIn' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerData' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'ActiveDictationLanguage' 'en-US' 'String'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'AraDate' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'NumForm' '2' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DisableBootToOfficeStart' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DeveloperTools' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'Ruler' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DisableDarkMode' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'BkgrndPag' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'BackgroundOpen' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'ShowBkg' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'PreferredView' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'Xl9_hijri' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'EnableAccChecker' '0' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'Maximized' '3' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'DisableBootToOfficeStart' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'DeveloperTools' '1' 'DWord'
AddRegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'A4Letter' '0' 'DWord'
AddRegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'PreventTeamsInstall' '1' 'DWord'
AddRegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'EnableAutomaticUpdates' '0' 'DWord'
AddRegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'HideEnableDisableUpdates' '1' 'DWord'
# Print
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'SpoolerPriority' '128' 'DWord'
AddRegEntry 'HKCU:\Control Panel\International' 'iPaperSize' '9' 'String'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International' 'iPaperSize' '9' 'String'
# Startup & performance
Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -EA SilentlyContinue | out-null
Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification"  -Recurse -force -EA SilentlyContinue | out-null
Remove-Item -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -EA SilentlyContinue | out-null
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  -Recurse -force -EA SilentlyContinue | out-null
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
# Share & UAC
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableAuthenticateUserSharing' '1' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' '1' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' '0' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' '0' 'DWord'
AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'SMB1' '1' 'DWORD'
AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'SMB2' '1' 'DWORD'
AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'SMB3' '1' 'DWORD'
AddRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'AutoShareWks' '0' 'DWORD'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'fullprivilegeauditing' '1' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' '0' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'disabledomaincreds' '0' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'everyoneincludesanonymous' '1' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'forceguest' '0' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymous' '0' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymoussam' '0' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SamConnectedAccountsExist' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ValidateAdminCodeSignatures' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' '1' 'DWord'
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
# Update
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpgrade' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpgradePeriod' '1' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpdatePeriod' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate' 'AutoDownload' '2' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971F918-A847-4430-9279-4A52D1EFE18D' 'RegisteredWithAU' '1' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' 'Start' '3' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc' 'Start' '3' 'DWord'
AddRegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' 'Start' '3' 'DWord'
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
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' 'DevicePasswordLessBuildVersion' '0' 'DWord'
AddRegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' 'DevicePasswordLessUpdateType' '1' 'DWord'
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
}

Function ShrinkC-MakeNew
{
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string]$DriveLetter
    )
    if (Get-Volume -DriveLetter $DriveLetter -EA SilentlyContinue) {Write-Host -F Cyan "Partition $DriveLetter already exist";return}
    $CSizeMax = (Get-PartitionSupportedSize -DriveLetter C).SizeMax
    $CSizeMin = (Get-PartitionSupportedSize -DriveLetter C).SizeMin
    $CShrink = ($CSizeMax - $CSizeMin)/1000000000 #Shrinkable amount in GB
    if ($CShrink -gt 70)
    {
        Resize-Partition -DriveLetter C -Size ($CSizeMax - 50GB) -EA SilentlyContinue | out-null
        $CDiskNumber = (Get-Volume | where DriveLetter -eq "C" | Get-Partition | Get-Disk).Number
        New-Partition -DiskNumber $CDiskNumber -UseMaximumSize -DriveLetter $DriveLetter -EA SilentlyContinue | out-null
        Format-Volume -DriveLetter $DriveLetter -FileSystem NTFS -Force -EA SilentlyContinue | out-null
    }
    else {Write-Host -F Cyan "Not Enough shrinkable Space on Partition C"}
}

Function D-ScanFolder
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "************************* Creating Drive D (If not found) & Creating shared Scan folder in it **************************"
Write-Host -F Cyan "======================================================================================================================`r`n" 
if (!(Get-Volume -DriveLetter D)) {ShrinkC-MakeNew "D"}
elseif ((Get-Volume -DriveLetter D).DriveType -ne "Fixed")
{
    try{$successful = $true;Set-Partition -DriveLetter D -NewDriveLetter Z}
    catch{$successful = $false;Write-Host -F Cyan "Busy Removable Partition D"}
    if ($successful) {ShrinkC-MakeNew "D"}
}
if ((Get-Volume -DriveLetter D).DriveType -eq "Fixed")
{
if (!(Test-Path -Path "D:\Scans")) {New-Item -Path "D:\" -Name "Scans" -ItemType Directory -EA SilentlyContinue | out-null}
Remove-SmbShare -Name "Scans" -Force -EA silentlycontinue | out-null
if (!([System.IO.Directory]::Exists("\\localhost\Scans"))) {New-SmbShare -Name "Scans" -Path "D:\Scans" -FullAccess "Everyone" -EA SilentlyContinue | out-null}
else {Grant-SmbShareAccess -Name "Scans" -AccountName "Everyone" -AccessRight Full -Force -EA SilentlyContinue | out-null}
$s=(New-Object -COM WScript.Shell).CreateShortcut("$($env:USERPROFILE)\Desktop\Scans.lnk");$s.TargetPath="D:\Scans\";$s.Save()
}
Remove-SmbShare -Name "Users" -Force -ErrorAction silentlycontinue | out-null
}

Function Adj-Hosts
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Adjusting Hosts file *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
Write-Host -F Cyan "Taking ownership of hosts file"
AdminTakeownership -Path "$env:WinDir\System32\drivers\etc\hosts"
$HostsFile = @"
#<localhost>
127.0.0.1   localhost
127.0.0.1   localhost.localdomain
255.255.255.255 broadcasthost
::1     localhost
127.0.0.1   local
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
127.0.0.1 assets.adobedtm.com
127.0.0.1 4vzokhpsbs.adobe.io
127.0.0.1 69tu0xswvq.adobe.io
127.0.0.1 5zgzzv92gn.adobe.io
127.0.0.1 dyzt55url8.adobe.io
127.0.0.1 gw8gfjbs05.adobe.io
127.0.0.1 dxyeyf6ecy.adobe.io
127.0.0.1 1hzopx6nz7.adobe.io
127.0.0.1 p13n.adobe.io
127.0.0.1 1b9khekel6.adobe.io
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
127.0.0.1 9ngulmtgqi.adobe.io
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
Set-Content -Path "$env:WinDir\System32\drivers\etc\hosts" -Value $HostsFile -Force -EA SilentlyContinue | out-null
}

Function uninsSara-Office
{
Write-Host -F Cyan "Removing currently installed MS office products using SaraCmd"
# Remove MS Store Office 365
RmAppx "Microsoft.Office.Desktop"
# Run SaraCMD non-interactive Script
New-Item -Path "$env:TEMP\IA\office" -ItemType Directory -EA SilentlyContinue | out-null
Invoke-WebRequest -Uri "https://aka.ms/SaRAEnterpriseHelper" -OutFile "$env:TEMP\IA\office\ExecuteSaraCmd.zip"
Expand-Archive -LiteralPath "$env:TEMP\IA\office\ExecuteSaraCmd.zip" -DestinationPath "$env:TEMP\IA\office" -Force -EA SilentlyContinue | out-null
$SNIfile = "$env:TEMP\IA\office\ExecuteSaraCmd.ps1"
$find = '$SaraScenarioArgument = ""';$replace = '$SaraScenarioArgument = "-S OfficeScrubScenario -Script -AcceptEula -OfficeVersion All"'
(Get-Content $SNIfile).replace($find, $replace) | Set-Content -Path $SNIfile -Force -EA SilentlyContinue | out-null
& "$SNIfile"
}

Function uninsITPRO-Office
{
Write-Host -F Cyan "Removing currently installed MS office products using ITPRO codes"
$outputdir = "$env:TEMP\IA\office"
$weburl = "https://github.com/OfficeDev/Office-IT-Pro-Deployment-Scripts/tree/master/Office-ProPlus-Deployment/Remove-PreviousOfficeInstalls/"
for ($i = 1; $i -le 30; $i++){
    $WebPage1 = Repeatiwr -Uri $weburl
    $Filelinks = $WebPage1.Links | Where-Object {$_.href -like '*exe' -or $_.href -like '*vbs' -or $_.href -like '*ps1'} | Select-Object -ExpandProperty href | Select-Object -Unique
    if ($Filelinks -ne $null) {break}
}
$Filelinks | ForEach-Object {
    $outputFile = Split-Path $_ -leaf
    Write-Host -F Cyan "Downloading file '$outputFile'"
    $fileFullname = Join-Path -Path $outputdir -ChildPath $outputFile
    $fileUrl  = '{0}/{1}' -f $weburl.TrimEnd('/'), $outputFile
    $fileUrl = $fileUrl.replace("tree", "raw")
    Invoke-WebRequest $fileUrl -OutFile $fileFullname
}
& "$outputdir\Remove-PreviousOfficeInstalls.ps1"
}

Function ActivateofficeKMS
{
Write-Host -F Cyan "Activating office using KMS"
$Officeospp64 = "$Env:Programfiles\Microsoft Office\Office16\ospp.vbs";$Officeospp32 = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\ospp.vbs"
if (Test-Path -Path $Officeospp64) {$office64 = $true}
elseif (Test-Path -Path $Officeospp32) {$office64 = $false}
else {Write-Host -F Cyan "Office16 ospp.vbs not found";return}

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
if ($Response -ne $null) {Write-Host -F Cyan "MS Office Successfully Activated using KMS server: $KMS";break}
}
}

Function Ins-Office21PP
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Start Installing Office 2021 Pro Plus *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
uninsSara-Office
# uninsITPRO-Office #Disabled due to Antimalware issues
$ConfigurationFile = @"
<Configuration ID="d66f0ad9-6e2f-47dc-a4fe-de1b73dfddff">
  <Remove All="TRUE" />
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
    <Product ID="LanguagePack">
      <Language ID="MatchOS" />
      <Language ID="ar-sa" />
      <Language ID="en-us" />
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
  <Property Name="AUTOACTIVATE" Value="1" />
  <Updates Enabled="FALSE" />
  <RemoveMSI />
  <AppSettings>
    <User Key="software\microsoft\office\16.0\excel\options" Name="recognizesmarttags" Value="2" Type="REG_DWORD" App="office16" Id="L_EnableAdditionalActionsInExcel" />
    <User Key="software\microsoft\office\16.0\common\autocorrect" Name="capitalizesentence" Value="1" Type="REG_DWORD" App="office16" Id="L_Capitalizefirstletterofsentence" />
    <User Key="software\microsoft\office\16.0\common\autocorrect" Name="capitalizenamesofdays" Value="1" Type="REG_DWORD" App="office16" Id="L_Capitalizenamesofdays" />
    <User Key="software\microsoft\shared tools\proofing tools\1.0\office" Name="flagrepeatedword" Value="1" Type="REG_DWORD" App="office16" Id="L_FlagRepeatedWords" />
    <User Key="software\microsoft\office\16.0\word\options\vpref" Name="wspell_1112_8" Value="3" Type="REG_DWORD" App="office16" Id="L_Arabicmodes" />
    <User Key="software\microsoft\office\16.0\common\ptwatson" Name="ptwoptin" Value="0" Type="REG_DWORD" App="office16" Id="L_ImproveProofingTools" />
    <User Key="software\microsoft\office\16.0\common\general" Name="shownfirstrunoptin" Value="1" Type="REG_DWORD" App="office16" Id="L_DisableOptinWizard" />
    <User Key="software\microsoft\office\16.0\common" Name="qmenable" Value="0" Type="REG_DWORD" App="office16" Id="L_EnableCustomerExperienceImprovementProgram" />
    <User Key="software\microsoft\office\16.0\common" Name="updatereliabilitydata" Value="0" Type="REG_DWORD" App="office16" Id="L_UpdateReliabilityPolicy" />
    <User Key="software\microsoft\office\16.0\common\security\filevalidation" Name="disablereporting" Value="1" Type="REG_DWORD" App="office16" Id="L_TurnOffErrorReportingForFilesThatFailFileValidation" />
  </AppSettings>
  <Display Level="None" AcceptEULA="TRUE" />
</Configuration>
"@
Write-Host -F Cyan "Downloading & extracting Office Deployment Tool"
Set-Content -Path "$env:TEMP\IA\office\Configuration.xml" -Value $ConfigurationFile -Force -EA SilentlyContinue | out-null
for ($i = 1; $i -le 50; $i++) {
    $webpage2 = Repeatiwr -Uri "https://www.microsoft.com/en-us/download/details.aspx?id=49117"
    $FileLink =  $webpage2.Links | Where-Object href -like '*officedeploymenttool*exe' | select -Last 1 -expand href
    if ($Filelink -ne $null) {break}
}
if ($Filelink -ne $null) {$Response = Invoke-WebRequest -Uri $FileLink -OutFile "$env:TEMP\IA\office\officedeploymenttool.exe"}
if (Test-Path -Path "$env:TEMP\IA\office\officedeploymenttool.exe") {Start-Process -Wait -FilePath "$env:TEMP\IA\office\officedeploymenttool.exe" -ArgumentList "/extract:$env:TEMP\IA\office","/quiet","/passive","/norestart" -EA SilentlyContinue | out-null}
Write-Host -F Cyan "`r`n*** Installing Office 2021 Pro Plus ... ***`r`n"
if (Test-Path -Path "$env:TEMP\IA\office\setup.exe") {Start-Process -WindowStyle Minimized -Wait -FilePath "$env:TEMP\IA\office\setup.exe" -ArgumentList "/configure","$env:TEMP\IA\office\configuration.xml" -EA SilentlyContinue | out-null}
else {Write-Host -F Cyan "Failed to download & extract Office Deployment Tool"}
ActivateofficeKMS
}

Function Clean-up
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Cleaning up *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
Remove-Item -LiteralPath "$env:TEMP\IA" -Force -Recurse
Remove-Item -LiteralPath "$env:TEMP\" -Force -Recurse -ErrorAction silentlycontinue | out-null
}

Function OpenMSStoreUpdate #Not used
{
Write-Host -F Cyan "`r`n*** MS Store Apps Updates ***`r`n"
Start-Process "ms-windows-store://downloadsandupdates"
}

Function Ins-Choco
{
Write-Host -F Cyan "`r`n======================================================================================================================"
Write-Host -F Cyan "***************************** Installing Chocolatey *****************************"
Write-Host -F Cyan "======================================================================================================================`r`n"
if (Get-Command -Name choco.exe) {write-host "Choco is already installed"}
else {iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))}
Get-PackageProvider -Name "Chocolatey" -ForceBootstrap | out-null
Choco feature enable -n=allowGlobalConfirmation
Choco upgrade Chocolatey
if (choco list --lo -r -e Chocolatey-core.extension) {Choco upgrade Chocolatey-core.extension} else {Choco install Chocolatey-core.extension}
}