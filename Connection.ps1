# Main commands

# Get Caller CMD
param($RecievedCmdfullPath)
$global:GRCmdfullPath = $RecievedCmdfullPath
$SetCmdfullPath = $env:CALLER_SCRIPT
$global:GSCmdfullPath = $SetCmdfullPath
# Save the path for the ps1
$global:CallerScriptPath = $MyInvocation.MyCommand.Path

# Set global flag for Debug
$global:ScriptDebug = $true

# Show debug for script paths
if ($ScriptDebug) {
	Write-Host "Starting CMD full path we recieved from the CMD: $GRCmdfullPath"
	Write-Host "Starting CMD full path which was set by the CMD: $GSCmdfullPath"
	Write-Host "Caller Script path: $CallerScriptPath"
}

# Powershell variables
if ($ScriptDebug) {
	$global:ErrorActionPreference = 'Continue'
	$global:progressPreference = 'Continue'
} else {
	$global:ErrorActionPreference = 'SilentlyContinue'
	$global:progressPreference = 'SilentlyContinue'
}

$global:ConfirmPreference = 'None'
$global:Force = $true

Set-Location -Path $PSScriptRoot

# Try Importing AllFunctions.psm1
$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
If (-not (Test-Path $ScriptDirectory\AllFunctions.psm1 -ea SilentlyContinue)) {Write-Host "Functions file not found at: $ScriptDirectory";$ScriptDirectory = $PSScriptRoot}
if (-not (Test-Path $ScriptDirectory\AllFunctions.psm1 -ea SilentlyContinue)) {Write-Host "Functions file not found at: $ScriptDirectory";Start-Sleep 10; exit}

try {
	Import-Module -Name $ScriptDirectory\AllFunctions.psm1 -DisableNameChecking -Global -Force
} catch { Write-Host "AllFunctions.psm1 file not found or failed to Import it"; Start-Sleep 10; exit }

Check-RunAsAdministrator #Check Script is running with Elevated Privileges

InitializeCommands

Fix-Share #Fix Windows file sharing

Clean-up




