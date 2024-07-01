# Install choco - Must be on seperate file so that powershell close and reopen after installing choco to ensure choco is working
$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
try{Import-Module -Name $ScriptDirectory\AllFunctions.psm1 -DisableNameChecking -Global -Force}
catch{Write-Host "AllFunctions.psm1 file not found";Start-Sleep 5;exit}

#Check Script is running with Elevated Privileges
Check-RunAsAdministrator
InitializeCommands
Ins-Choco #Install Chocolatey