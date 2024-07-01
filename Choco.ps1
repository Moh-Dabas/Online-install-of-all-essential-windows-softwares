# Initialize

Function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {Write-host -F Green "`r`n*** Script is running with Administrator privileges ***`r`n"}
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

#Check Script is running with Elevated Privileges
Check-RunAsAdministrator

write-host "Initializing"
Set-ExecutionPolicy Bypass -Force
$ErrorActionPreference = 'Continue'
$progressPreference = 'silentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "`r`n======================================================================================================================"
Write-Host "***************************** Installing Chocolatey *****************************"
Write-Host "======================================================================================================================"
if (Get-Command -Name choco.exe) {write-host "Choco is already installed"}
else {iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))}
Get-PackageProvider -Name "Chocolatey" -ForceBootstrap | out-null
Choco feature enable -n=allowGlobalConfirmation
Choco upgrade Chocolatey
if (choco list --lo -r -e Chocolatey-core.extension) {Choco upgrade Chocolatey-core.extension} else {Choco install Chocolatey-core.extension}