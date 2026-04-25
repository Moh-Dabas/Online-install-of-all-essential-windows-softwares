# Common Functions

function Check-RunAsAdministrator {
	#Get current user context
	$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
	#Check user is running the script is member of Administrator Group
	if ($currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
		Write-Host -ForegroundColor Green "`r`n*** Script is running with Administrator privileges ***`r`n"
		return
	} else { Relaunch }
}

function Relaunch {
	$parentProcess = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq (Get-Process -Id $PID).Parent.Id }

	if ($GRCmdfullPath) {
		# Started from the CMD file
		Write-Warning "Relaunching this script from the cmd file: $GRCmdfullPath"
		Start-Process -Verb RunAs -FilePath $GRCmdfullPath
	} elseif ($GSCmdfullPath) {
		# Started from the CMD file
		Write-Warning "Relaunching this script from the cmd file: $GSCmdfullPath"
		Start-Process -Verb RunAs -FilePath $GSCmdfullPath
	} elseif ($CallerScriptPath) {
		# Started from the PSS.ps1 file
		Write-Warning "Relaunching this script from the ps1 file: $CallerScriptPath"
		Start-Process PowerShell.exe -Verb RunAs -ArgumentList @(
			"-NoProfile",
			"-ExecutionPolicy Bypass",
			"-File `"$CallerScriptPath`""
		)
	} else {
		$CurFolder = Split-Path -Path $PSCommandPath -Parent
		Write-Warning "No Saved Path found. Relaunching this script from current directory: $CurFolder\PSS.ps1"
		Start-Process PowerShell.exe -Verb RunAs -ArgumentList @(
			"-NoProfile",
			"-ExecutionPolicy Bypass",
			"-File `"$CurFolder\PSS.ps1`""
		)
	}

	$parentProcess | Stop-Process
	exit
}

function Add-RegEntry {
	[CmdletBinding(DefaultParameterSetName = "Path")]
	param (
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Path")]
		[string]$Path,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Literal")]
		[string]$LiteralPath,

		[Parameter(Mandatory = $true, Position = 1)]
		[string]$Name,

		[Parameter(Mandatory = $true, Position = 2)]
		[object]$Value,

		[Parameter(Mandatory = $false, Position = 3)]
		[Alias("PropertyType")]
		[ValidateSet("DWord", "Qword", "Binary", "String", "ExpandString", "MultiString")]
		[string]$Type,

		[Parameter(Mandatory = $false)]
		[switch]$Force = $true
	)

	# Auto-detect type if not provided
	if (-not $PSBoundParameters.ContainsKey('Type')) {
		switch ($Value.GetType().Name) {
			"Int32" { $Type = "DWord" }
			"Int64" { $Type = "Qword" }
			"Byte[]" { $Type = "Binary" }
			"String[]" { $Type = "MultiString" }
			"String" { $Type = "String" }
			default { $Type = "String" }  # fallback
		}
	}

	try {
		$TargetPath = if ($PSCmdlet.ParameterSetName -eq "Literal") { $LiteralPath } else { $Path }

		if (Get-ItemProperty -Path $TargetPath -Name $Name -EA SilentlyContinue) {
			Set-ItemProperty -LiteralPath $TargetPath -Name $Name -Value $Value -Force:$Force -EA SilentlyContinue | Out-Null
		} else {
			if (!(Test-Path $TargetPath -EA SilentlyContinue)) {
				New-Item $TargetPath -Force:$Force -EA SilentlyContinue | Out-Null
			}
			New-ItemProperty -LiteralPath $TargetPath -Name $Name -Value $Value -PropertyType $Type -Force:$Force -EA SilentlyContinue | Out-Null
		}
	} catch {
		try {
			Write-Host "PowerShell Method Failed, trying CMD method ..." -ForegroundColor Red
			$RegPath = $TargetPath.Replace(":", "")

			switch ($Type) {
				DWord { $typeCMD = "REG_DWORD" }
				Qword { $typeCMD = "REG_QWORD" }
				Binary { $typeCMD = "REG_BINARY" }
				String { $typeCMD = "REG_SZ" }
				ExpandString { $typeCMD = "REG_EXPAND_SZ" }
				MultiString { $typeCMD = "REG_MULTI_SZ" }
			}

			if ($Type -eq "Binary" -and $Value -is [byte[]]) {
				$Value = ($Value | ForEach-Object { $_.ToString("X2") }) -join ""
			}

			if ($Type -eq "MultiString" -and $Value -is [array]) {
				$Value = ($Value -join "\0") + "\0\0"
			}

			if ($Force) {
				REG ADD $RegPath /v $Name /t $typeCMD /d $Value /f | Out-Null
			} else {
				REG ADD $RegPath /v $Name /t $typeCMD /d $Value | Out-Null
			}
		} catch {
			Write-Host -ForegroundColor Red "Might need takeown or running as SYSTEM or TrustedInstaller`nError: $Error"
		}
	}
}

function Remove-RegEntry {
	[CmdletBinding(DefaultParameterSetName = "Path")]
	param (
		# Parameter sets
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Path")]
		[string]$Path,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Literal")]
		[string]$LiteralPath,

		# Common parameters
		[Parameter(Mandatory = $true, Position = 1)]
		[string]$Name,

		[Parameter(Mandatory = $false)]
		[switch]$Force = $true
	)

	try {
		# Select correct path
		$TargetPath = if ($PSCmdlet.ParameterSetName -eq "Literal") { $LiteralPath } else { $Path }

		# PowerShell deletion
		Remove-ItemProperty -LiteralPath $TargetPath -Name $Name -Force:$Force -EA SilentlyContinue | Out-Null
	} catch {
		try {
			# Fallback to reg.exe
			Write-Host "PowerShell Method Failed, trying CMD method ..." -ForegroundColor Red
			$RegPath = $TargetPath.Replace(":", "")

			if ($Force) {
				REG DELETE $RegPath /v $Name /f
			} else {
				REG DELETE $RegPath /v $Name
			}
		} catch {
			Write-Host -ForegroundColor Red "Might need takeown or running as SYSTEM or TrustedInstaller`nError: $Error"
		}
	}
}

function Restart-ExplorerSilently {
	Write-Host -f C "Restarting Explorer to apply system-wide changes..."
	Add-RegEntry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "RestorePreviousFolderOpenState" '0' 'DWORD'
	Add-RegEntry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "PersistBrowsers" '0' 'DWORD'
	Add-RegEntry "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWORD'
	Add-RegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'

	# Force terminate Explorer processes
	try {
		Write-Host -f C "Force terminating all Explorer processes..."
		taskkill /f /im explorer.exe
	} catch { Write-Warning "`n Failed to terminate Explorer processes: $($_.Exception.Message)" }

	# Brief pause to ensure complete termination
	Start-Sleep -Milliseconds 1000
	# Restart Windows Explorer
	try {
		Write-Host -f C "Restarting Windows Explorer..."
		Start-Process explorer.exe "$env:SystemRoot\System32\userinit.exe"
		# Just in case, close all explorer windows
		$shell = New-Object -ComObject Shell.Application
		for ($i = 1; $i -le 500; $i++) {
			$shell.Windows() | ForEach-Object { $_.Quit() }
			Start-Sleep -Milliseconds 1
		}
	} catch { Write-Error "Failed to restart Windows Explorer: $($_.Exception.Message)" }
	Write-Host -f C "Windows Explorer restarted successfully."
	return
}

function Remove-AppxApp {
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

		Remove-AppxPackage -Package $pkgFullName -EA SilentlyContinue

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
		Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -EA SilentlyContinue
	}

	Write-Host "Operation completed." -ForegroundColor Green
}

function Invoke-ReliableHttpClient {
	param (
		[string]$Uri,
		[int]$MaxRetries = 5,
		[int]$TimeoutSec = 15
	)

	Add-Type -AssemblyName System.Net.Http

	$Handler = New-Object System.Net.Http.HttpClientHandler
	$Client = New-Object System.Net.Http.HttpClient($Handler)
	$Client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

	for ($i = 1; $i -le $MaxRetries; $i++) {
		try {
			$Response = $Client.GetAsync($Uri).Result
			if ($Response.IsSuccessStatusCode) {
				$Html = $Response.Content.ReadAsStringAsync().Result

				# --- Try to load HtmlAgilityPack ---
				$HAPLoaded = $false
				try {
					if (-not ("HtmlAgilityPack.HtmlDocument" -as [type])) {
						try {
							# Try NuGet install (if available)
							Install-Package -Name HtmlAgilityPack -Force -Scope CurrentUser -ProviderName NuGet -ErrorAction Stop | Out-Null
						} catch {
							Write-Verbose "HtmlAgilityPack NuGet install failed: $($_.Exception.Message)"
						}

						# Try loading from local NuGet cache
						$DllPath = Get-ChildItem -Path "$env:USERPROFILE\.nuget\packages\htmlagilitypack\" -Recurse -Filter "HtmlAgilityPack.dll" -ErrorAction SilentlyContinue |
						Sort-Object LastWriteTime -Descending |
						Select-Object -First 1 -ExpandProperty FullName

						if ($DllPath) {
							Add-Type -Path $DllPath
						}
					}

					if ("HtmlAgilityPack.HtmlDocument" -as [type]) {
						$Doc = New-Object HtmlAgilityPack.HtmlDocument
						$Doc.LoadHtml($Html)
						$Links = foreach ($node in $Doc.DocumentNode.SelectNodes("//a[@href]")) {
							[PSCustomObject]@{
								href      = $node.GetAttributeValue("href", "")
								innerText = $node.InnerText.Trim()
							}
						}
						$HAPLoaded = $true
					}
				} catch {
					Write-Verbose "HtmlAgilityPack load failed, will fallback to regex"
				}

				# --- Fallback: regex link extraction ---
				if (-not $HAPLoaded) {
					$Links = [regex]::Matches($Html, '<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>') |
					ForEach-Object {
						[PSCustomObject]@{
							href      = $_.Groups[1].Value
							innerText = ($_.Groups[2].Value -replace '\s+', ' ').Trim()
						}
					}
				}

				return [PSCustomObject]@{
					Content = $Html
					Links   = $Links
				}
			}
		} catch {
			Write-Verbose "Attempt $i failed: $($_.Exception.Message)"
		}

		if ($i -lt $MaxRetries) {
			Start-Sleep -Seconds ([Math]::Pow(2, $i)) # exponential backoff
		}
	}

	throw "Failed to get $Uri after $MaxRetries attempts."
}

function Invoke-ReliableWebRequest {
	param (
		[Parameter(Mandatory)]
		[string]$Uri,

		[int]$MaxRetries = 10,

		[int]$InitialDelaySeconds = 1
	)

	$Delay = $InitialDelaySeconds
	for ($i = 1; $i -le $MaxRetries; $i++) {
		try {
			$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -ErrorAction Stop
			if ($Response.StatusCode -eq 200) {
				return $Response
			}
		} catch {
			if ($_.Exception.Response) {
				$StatusCode = $_.Exception.Response.StatusCode.value__
				$Description = $_.Exception.Response.StatusDescription
				Write-Verbose "Attempt $i failed: [$StatusCode] $Description"
			} else {
				Write-Verbose "Attempt $i failed: $($_.Exception.Message)"
			}
		}

		if ($i -lt $MaxRetries) {
			Start-Sleep -Seconds $Delay
			$Delay *= 2  # exponential backoff
		}
	}

	throw "Failed to get $Uri after $MaxRetries attempts."
}

function AdminTakeownership {
	param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$Path
	)
	if (Test-Path -Path $Path -PathType Leaf -EA SilentlyContinue) {
		takeown /a /f $Path
		icacls $Path /t /c /grant "*S-1-5-32-544:F"
	} elseif (Test-Path -Path $Path -PathType Container -EA SilentlyContinue) {
		takeown /a /r /d y /f $Path
		icacls $Path /t /c /grant "*S-1-5-32-544:F"
	} else { Write-Host -f red "Path is wrong or not supported" }
}

function Check-Internet {
	$InternetAccess = (Get-NetConnectionProfile).IPv4Connectivity -contains "Internet"
	if ($InternetAccess) { "Internet look connected but better test it" } else { "Internet disconnected waiting" }
	Write-Output "Testing Internet connection"
	$connected = $false
	for ($i = 0; $i -lt 50; $i++) {
		$ping = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -EA SilentlyContinue
		if ($ping) {
			$connected = $true
			break
		}
		Start-Sleep -Seconds 1
	}

	if ($connected) {
		Write-Output "Internet connection detected."
		return $true
	} else {
		Write-Output "No internet connection"
		return $false
	}
}

function Test-MicrosoftFileUrl {
	param(
		[string]$Url,
		[int]$TimeoutSec = 15
	)

	Add-Type -AssemblyName System.Net.Http

	$Handler = New-Object System.Net.Http.HttpClientHandler
	$Handler.AllowAutoRedirect = $true   # follow redirects

	$Client = New-Object System.Net.Http.HttpClient($Handler)
	$Client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

	try {
		# Use GET but only read headers (no full download)
		$Response = $Client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

		$FinalUrl = $Response.RequestMessage.RequestUri.AbsoluteUri
		$Status = [int]$Response.StatusCode

		if ($Status -eq 200 -and $FinalUrl.StartsWith("https://download.microsoft.com")) {
			return $true
		} else {
			return $false
		}
	} catch {
		return $false
	} finally {
		$Client.Dispose()
		$Handler.Dispose()
	}
}

function Ins-WCap {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$CapabilityName,

		[Parameter(Mandatory = $false)]
		[string]$Source,

		[Parameter(Mandatory = $false)]
		[int]$TimeoutSeconds = 300,

		[Parameter(Mandatory = $false)]
		[switch]$Force,

		[Parameter(Mandatory = $false)]
		[switch]$SkipWUReset
	)

	Write-Verbose "Starting unattended installation of capability: $CapabilityName"

	# 1. Check for pending reboot (warning only, no interactive prompt)
	Write-Verbose "Checking for pending reboots..."
	$rebootPendingPaths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
		"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
	)

	$pendingReboot = $false
	foreach ($path in $rebootPendingPaths) {
		if (Test-Path $path) {
			Write-Warning "Pending reboot detected at registry path: $path"
			$pendingReboot = $true
		}
	}

	# Check via CIM
	try {
		$cimSession = New-CimSession -ErrorAction SilentlyContinue
		$pendingRebootCim = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession |
		Select-Object -ExpandProperty RebootRequired -ErrorAction SilentlyContinue
		if ($cimSession) { Remove-CimSession -CimSession $cimSession }

		if ($pendingRebootCim) {
			Write-Warning "System indicates a reboot is required (CIM check)"
			$pendingReboot = $true
		}
	} catch {
		# CIM check failed, continue
	}

	if ($pendingReboot -and -not $Force) {
		Write-Error "System has pending reboot. Use -Force to bypass or reboot system first."
		return $false
	} elseif ($pendingReboot -and $Force) {
		Write-Warning "Proceeding with installation despite pending reboot (Force flag used)"
	}

	# 2. Reset Windows Update components if not skipped
	if (-not $SkipWUReset) {
		Write-Verbose "Resetting Windows Update components..."
		try {
			Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
			if (Test-Path "C:\Windows\SoftwareDistribution") {
				Remove-Item "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
			}
			Start-Service -Name wuauserv -ErrorAction SilentlyContinue
			Start-Sleep -Seconds 2
		} catch {
			Write-Warning "Failed to reset Windows Update components: $_"
		}
	}

	# 3. Check if capability is already installed
	Write-Verbose "Checking if capability is already installed..."
	try {
		$existingCaps = Get-WindowsCapability -Online -Name "*$CapabilityName*" -ErrorAction SilentlyContinue

		if ($existingCaps) {
			foreach ($cap in $existingCaps) {
				if ($cap.State -eq "Installed") {
					Write-Verbose "Capability '$($cap.Name)' is already installed"
					if (-not $Force) {
						return $true  # Already installed, success
					}
					Write-Verbose "Force flag set, will reinstall"
				} elseif ($cap.State -eq "Installing") {
					Write-Warning "Capability '$($cap.Name)' appears stuck in 'Installing' state"
				}
			}
		}
	} catch {
		# Continue if check fails
	}

	# 4. Prepare DISM command
	Write-Verbose "Building DISM command..."
	$dismArgs = @("/Online", "/Add-Capability", "/CapabilityName:$CapabilityName", "/NoRestart")

	if ($Source) {
		$dismArgs += "/Source:`"$Source`""
		Write-Verbose "Using source: $Source"
	}

	# Add logging
	$logPath = "$env:TEMP\DISM_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
	$dismArgs += "/LogPath:`"$logPath`""
	$dismArgs += "/LogLevel:1"  # Errors only for unattended

	# 5. Execute DISM
	Write-Verbose "Starting DISM installation with timeout: ${TimeoutSeconds}s"

	try {
		$processInfo = New-Object System.Diagnostics.ProcessStartInfo
		$processInfo.FileName = "dism.exe"
		$processInfo.Arguments = ($dismArgs -join ' ')
		$processInfo.UseShellExecute = $false
		$processInfo.RedirectStandardOutput = $true
		$processInfo.RedirectStandardError = $true
		$processInfo.CreateNoWindow = $true

		$process = New-Object System.Diagnostics.Process
		$process.StartInfo = $processInfo

		# Start the process
		if ($process.Start()) {
			# Read output asynchronously
			$stdOutTask = $process.StandardOutput.ReadToEndAsync()
			$stdErrTask = $process.StandardError.ReadToEndAsync()

			# Wait with timeout
			if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
				Write-Error "Installation timed out after $TimeoutSeconds seconds"
				$process.Kill()
				return $false
			}

			# Get output
			$stdOut = $stdOutTask.GetAwaiter().GetResult()
			$stdErr = $stdErrTask.GetAwaiter().GetResult()
			$exitCode = $process.ExitCode

			# Check results
			if ($exitCode -eq 0) {
				Write-Verbose "Installation completed successfully"
				Write-Verbose "Log file: $logPath"

				# Quick verification
				try {
					$installed = Get-WindowsCapability -Online -Name "*$CapabilityName*" -ErrorAction SilentlyContinue |
					Where-Object { $_.State -eq "Installed" }
					if ($installed) {
						Write-Verbose "Verified: $($installed.Name) is installed"
					}
				} catch {
					# Verification optional
				}

				return $true
			} else {
				Write-Error "DISM failed with exit code: $exitCode"
				if ($stdErr) {
					Write-Verbose "Error output: $stdErr"
				}
				Write-Verbose "Log file: $logPath"
				return $false
			}
		} else {
			Write-Error "Failed to start DISM process"
			return $false
		}
	} catch {
		Write-Error "Exception during DISM execution: $_"
		return $false
	}
}

function Convert-GoogleDriveUrl {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Url,

		[Parameter(Mandatory = $true)]
		[string]$Key
	)

	# Define regex pattern to extract the file ID from various Google Drive URL formats
	$pattern = 'https://drive\.google\.com/file/d/(?<FileId>[a-zA-Z0-9_-]+)'

	if ($Url -match $pattern) {
		$fileId = $matches.FileId
		return "https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&key=${Key}"
	} else {
		Write-Error "URL does not match Google Drive file pattern. Example: https://drive.google.com/file/d/FILE_ID"
		return $null
	}
}

function Refresh-Desktop {
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

function Invoke-ShellAssocChanged {
	<#
    .SYNOPSIS
        Notifies Explorer that file associations or shell handlers have changed.

    .DESCRIPTION
        Calls SHChangeNotify with SHCNE_ASSOCCHANGED to refresh the system’s
        awareness of file type/handler changes without requiring logout/reboot.
    #>

	Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public static class Shell32 {
        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(
            int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
    }
"@

	# SHCNE_ASSOCCHANGED = 0x08000000
	# SHCNF_IDLIST       = 0x0000
	[Shell32]::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero)
}

function Pin-to-taskbar {
	param
	(
		[Parameter(Mandatory = $false, Position = 0)]
		[string]$IDorPath,
		[Parameter(Mandatory = $false, Position = 1)]
		[string]$PinType,
		[Parameter(Mandatory = $false, Position = 2)]
		[switch]$SearchID = $false,
		[Parameter(Mandatory = $false, Position = 3)]
		[switch]$Replace = $false,
		[Parameter(Mandatory = $false, Position = 4)]
		[switch]$ClearAll = $false
	)
	if (($ClearAll -eq $false) -and (($IDorPath -eq "") -or ($PinType -eq ""))) { Write-Host -f red 'You must provide IDorPath and PinType unless you use -ClearAll'; return }
	# For $IDorPath provide the appID or desktopID or part of it & set search or provide the path
	# for PinType provied "AppUserModelID" or "DesktopApplicationID" or "DesktopApplicationLinkPath"
	# To understand this visit: https://learn.microsoft.com/en-us/windows/configuration/taskbar/pinned-apps?tabs=intune&pivots=windows-11#taskbar-layout-example
	# To get UWP App ID "AppUserModelID" use PS command> Get-AppxPackage | select @{n='name';e={"$($_.PackageFamilyName)!app"}}
	# also choose whether to keep the previous pins or to remove them by setting Replace
	# or use-ClearAll to remove all pins without adding any ie: Pin-to-taskbar -ClearAll
	# All other parameters are useless when using -ClearAll as it will just clear all pins anyway so you should use for that> Pin-to-taskbar -ClearAll
	$taskbar_layout1 = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
Version="1">

"@
	if ($Replace -or $ClearAll) { $Placement = '<CustomTaskbarLayoutCollection PinListPlacement="Replace">' } else { $Placement = '<CustomTaskbarLayoutCollection>' }
	$taskbar_layout2 = @"

<defaultlayout:TaskbarLayout>
<taskbar:TaskbarPinList>

"@
	if (-not $ClearAll) {
		if ($SearchID) { $IDorPath = (Get-AppxPackage | select @{n = 'name'; e = { "$($_.PackageFamilyName)!app" } } | ? { $_.name -like "*$IDorPath*" }).name }
		#Write-Host $IDorPath #Debug only
		switch ($PinType) {
			"AppUserModelID" { $pin = '<taskbar:UWA AppUserModelID="' + $IDorPath + '" />' }
			"DesktopApplicationID" { $pin = '<taskbar:DesktopApp DesktopApplicationID="' + $IDorPath + '" />' }
			"DesktopApplicationLinkPath" { $pin = '<taskbar:DesktopApp DesktopApplicationLinkPath="' + $IDorPath + '" />' }
		}
	}
	$taskbar_layout3 = @"

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
		Path  = "SOFTWARE\Policies\Microsoft\Windows\Explorer"
		Value = $provisioning.FullName
		Name  = "StartLayoutFile"
		Type  = [Microsoft.Win32.RegistryValueKind]::ExpandString
	},
	[PSCustomObject]@{
		Path  = "SOFTWARE\Policies\Microsoft\Windows\Explorer"
		Value = 1
		Name  = "LockedStartLayout"
	} | group Path

	foreach ($setting in $settings) {
		$registry = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($setting.Name, $true)
		if ($null -eq $registry) {
			$registry = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($setting.Name, $true)
		}
		$setting.Group | % {
			if (!$_.Type) {
				$registry.SetValue($_.name, $_.value)
			} else {
				$registry.SetValue($_.name, $_.value, $_.type)
			}
		}
		$registry.Dispose()
	}
	Restart-ExplorerSilently
}

function Uninstall-Programs {
	param(
		[Parameter(Mandatory = $true)]
		[string]$partName,
		[Parameter(Mandatory = $false)]
		[string]$AddParam,
		[Parameter(Mandatory = $false)]
		[switch]$MSIExec
	)

	# Define registry paths to search for the Program installations
	$uninstallPaths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
		"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	)

	# Find all installations of the program
	try {
		$Programs = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$partName*" }
	} catch { Write-Warning "Error reaging registry" }
	if (-not $Programs) {
		Write-Host "No installations found for program with name $Name."
		return $false
	}

	# Uninstall all installations of the program
	if ($MSIExec) {
		# Uninstall using MSIExec command
		foreach ($program in $Programs) {
			$ProductCode = $program.PSChildName
			$DisplayName = $program.DisplayName
			try {
				# Use the MSIExec command to uninstall the product
				Write-Host -f C "`r`n *** Uninstalling $DisplayName *** `r`n"
				$parameters = "/x $ProductCode /qb-! /norestart"
				# Add received parameters
				if ($AddParam) { $parameters += $AddParam }
				Start-Process -Verb RunAs -FilePath "msiexec.exe" -ArgumentList $parameters -Wait -PassThru
				Write-Host -f Green "Successfully uninstalled: $($program.DisplayName)"
			} catch { Write-Warning "Failed to uninstall $DisplayName with product code $ProductCode. Error: $($_.Exception.Message)" }
		}
	} else {
		foreach ($program in $Programs) {
			$QuietUninstallString = $program.QuietUninstallString
			$UninstallString = $program.UninstallString
			if ($QuietUninstallString) {
				# Uninstall using QuietUninstallString
				try {
					# Extract the executable path and parameters
					$executablePath = $QuietUninstallString.Split('"')[1]
					$parameters = $QuietUninstallString.Substring($executablePath.Length + 2) | Select-Object -First 1
					# Add received parameters
					if ($AddParam) { $parameters += $AddParam }
					Write-Host "Running: $executablePath $parameters"
					Start-Process -Verb RunAs -FilePath $executablePath -ArgumentList $parameters -Wait -PassThru
					Write-Host -f Green "Successfully uninstalled: $($program.DisplayName)"
				} catch { Write-Host -f Red "Failed to uninstall: $($program.DisplayName) - $($_.Exception.Message)" }
			} elseif ($UninstallString) {
				# Uninstall using UninstallString
				try {
					# Extract the executable path and parameters
					$executablePath = $UninstallString.Split('"')[1]
					$parameters = $UninstallString.Substring($executablePath.Length + 2) | Select-Object -First 1
					# Add received parameters
					if ($AddParam) { $parameters += $AddParam }
					Write-Host "Running: $executablePath $parameters"
					Start-Process -Verb RunAs -FilePath $executablePath -ArgumentList $parameters -PassThru
					Write-Host -f Green "Successfully uninstalled: $($program.DisplayName)"
				} catch { Write-Host -f Red "Failed to uninstall: $($program.DisplayName) - $($_.Exception.Message)" }
			}
		}
	}

	return $true
}

function Set-Wallpaper {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ImagePath,
		[ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
		[string]$Style = 'Fill'
	)

	Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
public class Wallpaper {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);

    public static void SetWallpaper(string path, string style) {
        SystemParametersInfo(0x0014, 0, path, 0x01 | 0x02);

        // Set wallpaper style
        RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);

        switch(style) {
            case "Fill":
                key.SetValue(@"WallpaperStyle", "10");
                key.SetValue(@"TileWallpaper", "0");
                break;
            case "Fit":
                key.SetValue(@"WallpaperStyle", "6");
                key.SetValue(@"TileWallpaper", "0");
                break;
            case "Stretch":
                key.SetValue(@"WallpaperStyle", "2");
                key.SetValue(@"TileWallpaper", "0");
                break;
            case "Tile":
                key.SetValue(@"WallpaperStyle", "0");
                key.SetValue(@"TileWallpaper", "1");
                break;
            case "Center":
                key.SetValue(@"WallpaperStyle", "0");
                key.SetValue(@"TileWallpaper", "0");
                break;
            case "Span":
                key.SetValue(@"WallpaperStyle", "22");
                key.SetValue(@"TileWallpaper", "0");
                break;
        }

        key.Close();

        // Refresh desktop
        SystemParametersInfo(0x0014, 0, path, 0x01 | 0x02);
    }
}
"@

	[Wallpaper]::SetWallpaper($ImagePath, $Style)
}

# ==================================================================================
# Function: Interact-UIA
# ==================================================================================
function Interact-UIA {
	param(
		[string]$uri,                					# URI scheme (shell activation) or real executable path to launch application (optional). Examples: ms-windows-store://downloadsandupdates or C:\Windows\explorer.exe

		[switch]$noWindow,								# Search for controls directly from desktop root, bypassing window search
		[switch]$HostWindow,							# if set use the host Window (ApplicationFrameWindow) else by default we will use Win32 or Core
		[switch]$fallBackInOrder,						# Allow multi window search scenarios with a fallback order
		[IntPtr]$WindowHandle = [IntPtr]::Zero,			# Direct window handle to use instead of searching
		[string]$ProcessName,							# Get Window from process name
		[string]$partAppId,								# Get Window from Partial App user model Id Similar to package Id

		# Timing and wait parameters for dynamic UI scenarios
		[int]$ExtraDelay = 0,				  			# Delay in milliseconds after finding window (allows UI initialization)
		[int]$Timeout = 1000,			  				# Timeout in milliseconds for window search operations
		[int]$ProcessTimout = 0,						# Timeout in milliseconds for each of waiting for process to become Input Idle & to have main window
		[switch]$WaitWindowReady,						# Dynamic wait until window is ready.

		# Window identification properties - use multiple properties for accurate window targeting
		[array]$WinProperty = @(),						# Window property names to filter by e.g. ("ClassName", "Name", "AutomationId", "ControlType", "FrameworkId")
		[array]$WinValue = @(),							# Window property values corresponding to WinProperty array

		# Control identification properties - use multiple properties for accurate element targeting
		[array]$ControlProperty = @(),					# Control property names to filter by e.g. ("ClassName", "Name", "AutomationId", "ControlType", "FrameworkId")
		[array]$ControlValue = @(),						# Control property values corresponding to ControlProperty array

		# Child control identification properties - for finding elements within parent controls
		[array]$ChildProperty = @(),					# Child control property names to filter by e.g. ("ClassName", "Name", "AutomationId", "ControlType", "FrameworkId")
		[array]$ChildValue = @(),						# Child control property values corresponding to ChildProperty array

		# Pattern operations - generic pattern support for all UI Automation patterns
		[string]$Pattern,								# Pattern interface to use (e.g., "Invoke", "Toggle", "Value")
		[string]$PatternMethod,							# Pattern method to invoke (e.g., "Invoke", "Toggle", "SetValue", "Select")
		[array]$PatternMethodArgs = @(),				# Arguments to pass to the pattern method
		[string]$PatternProperty,						# Pattern property to check condition against or return value from
		[ValidateSet("Equals", "NotEquals", "Contains", "GreaterThan", "LessThan")]
		[string]$ConditionOperator = "Equals",			# Comparison operator for conditional pattern execution
		[string]$ConditionValue,						# Pattern Property value for conditional execution
		[switch]$GetPatternPropertyValue,				# Return pattern property value instead of executing method
		[switch]$CheckPatternSupported,					# Check if specified pattern is supported by the control

		# Discovery and verification operations
		[switch]$EnumListAllWindows,					# List all windows using Enum
		[switch]$ListWindows,							# List all windows matching criteria with their properties
		[switch]$ListControls,			  				# List all controls in target window matching criteria
		[switch]$ListChildren,							# List all child controls of found parent control(s)
		[switch]$WindowExist,			  				# Check if window exists and return existence status with element
		[switch]$ControlExist,            				# Check if control exists and return existence status with element(s)
		[switch]$ChildExist,							# Check if child control exists and return existence status with element(s)
		[switch]$MultiElements,							# Process all elements that match the conditions (not just first match)
		[switch]$ChildrenOnly,							# Search for Direct children only not the entire Descendants in the tree
		[switch]$NoWarn,								# Suppress warning if window or element isn't found (useful for retry scenarios)
		[switch]$DebugSwitch
	)

	Add-Type -AssemblyName UIAutomationClient
	Add-Type -AssemblyName UIAutomationTypes

	# ----------------------------------------------------------------
	# Section 1: Parameter Validation and Initialization
	# Validate parameter combinations
	# Made to be not affected by order to avoid issues in case of future modifications
	# ----------------------------------------------------------------

	# Only validate noWindow conflicts if noWindow is used
	if ($noWindow) {
		if (($fallBackInOrder -or $WindowHandle -ne [IntPtr]::Zero) -or $ProcessName -or $partAppId -or ($WinProperty.Count -gt 0)) {
			Write-Warning "⚠️ The -noWindow switch cannot be used with -fallBackInOrder, -WindowHandle, -ProcessName, -partAppId or -WinProperty"
			return $false
		}
	}

	# Only validate WindowHandle conflicts if WindowHandle is actually provided and not fallBackInOrder
	if (-not $fallBackInOrder -and $WindowHandle -ne [IntPtr]::Zero) {
		if ($noWindow -or $ProcessName -or $partAppId -or ($WinProperty.Count -gt 0)) {
			Write-Warning "⚠️ The -WindowHandle parameter cannot be used with -noWindow, -ProcessName, -partAppId or -WinProperty unless -fallBackInOrder is set"
			return $false
		}
	}

	# Only validate ProcessName conflicts if ProcessName is actually provided and not fallBackInOrder
	if (-not $fallBackInOrder -and $ProcessName) {
		if ($noWindow -or ($WindowHandle -ne [IntPtr]::Zero) -or $partAppId -or ($WinProperty.Count -gt 0)) {
			Write-Warning "⚠️ The -ProcessName parameter cannot be used with -noWindow, -WindowHandle, -partAppId or -WinProperty unless -fallBackInOrder is set"
			return $false
		}
	}

	# Only validate partAppId conflicts if partAppId is actually provided and not fallBackInOrder
	if (-not $fallBackInOrder -and $partAppId) {
		if ($noWindow -or ($WindowHandle -ne [IntPtr]::Zero) -or $ProcessName -or ($WinProperty.Count -gt 0)) {
			Write-Warning "⚠️ The -partAppId parameter cannot be used with -noWindow, -WindowHandle, -ProcessName or -WinProperty unless -fallBackInOrder is set"
			return $false
		}
	}

	# Only validate WinProperty conflicts if WinProperty is actually provided and not fallBackInOrder (Not actually needed in this order)
	if (-not $fallBackInOrder -and $WinProperty.Count -gt 0) {
		if ($noWindow -or ($WindowHandle -ne [IntPtr]::Zero) -or $ProcessName -or $partAppId) {
			Write-Warning "⚠️ The -WinProperty parameter cannot be used with -noWindow, -WindowHandle, -ProcessName or -partAppId unless -fallBackInOrder is set"
			return $false
		}
	}

	# ----------------------------------------------------------------
	# Section 2: Application Launch
	# ----------------------------------------------------------------

	# Launch application from URI
	if ($uri) {
		try {
			$PathType = Get-TargetType -Target $uri
			if (($PathType -ne "URI") -and ($PathType -ne "Executable")) {
				Write-Host "Provided URI value: $uri `nis not a supported URI scheme or an executable path" -ForegroundColor Red
				return $false
			}

			if ($DebugSwitch) { Write-Host "Minimizing all open windows" }
			(New-Object -ComObject "Shell.Application").MinimizeAll()

			Write-Host "🚀 Launching application from URI: $uri" -ForegroundColor Cyan
			if ($PathType -eq "URI") {
				# Simple URI launch
				Start-Process $uri
				if ($DebugSwitch) { Write-Host "✅ URI launched successfully" -ForegroundColor Green }
			} else {
				# Start an excutable
				$proc = Start-Process $uri -PassThru
				if ($DebugSwitch) { Write-Host "✅ Excutable launched successfully" -ForegroundColor Green }
				if ($ProcessTimout -ne 0) {
					Write-Host "⏳ Waiting for excutable main window..." -ForegroundColor Yellow
					# Wait until the process is ready for input (max $ProcessTimout)
					if (-not $proc.WaitForInputIdle($ProcessTimout)) {
						if ($DebugSwitch) { Write-Host "Process did not become idle after $ProcessTimout milliseconds." -ForegroundColor Red }
					}
					$windowFound = $false
					$waitStartTime = Get-Date
					while (((Get-Date) - $waitStartTime).TotalMilliseconds -lt $ProcessTimout -and (-not $windowFound) -and (-not $noWindow)) {
						if ($proc.MainWindowHandle -ne 0) {
							if ($DebugSwitch) { Write-Host "Process main Window found with title: $proc.MainWindowTitle" }
							$windowFound = $true
						}
					}
				}
				if (-not $windowFound) {
					if ($DebugSwitch) { Write-Host "Process had no Win32 main window after $ProcessTimout milliseconds." -ForegroundColor Red }
				}
			}

		} catch {
			if ($DebugSwitch) { Write-Warning "⚠️ Failed to launch application from URI: $uri - $($_.Exception.Message)" }
			return $false
		}
	}

	# Get desktop root element for UI Automation operations
	$root = [System.Windows.Automation.AutomationElement]::RootElement

	# ----------------------------------------------------------------
	# Section 3: List Windows: Shows a list of all Open windows found matching conditions and their properties
	# ----------------------------------------------------------------
	if ($ListWindows) {
		if ($DebugSwitch) { Write-Host "Listing Windows" }
		if (-not $appWin -and ($WinProperty.Count -gt 0 -or $WinValue.Count -gt 0)) {
			if ($WinProperty.Count -ne $WinValue.Count) {
				Write-Warning "⚠️ WinProperty and WinValue arrays must have the same number of elements"
				return $false
			} elseif ($DebugSwitch) { Write-Host "🔍 Searching for window with specified conditions..." -ForegroundColor Yellow }

			$allWindows = UIAElementSearch -source $root -ElementProperty $WinProperty -ElementSearchValue $WinValue -MultiElements:$true -ChildrenOnly:$true -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch

		} else { $allWindows = UIAElementSearch -source $root -MultiElements:$true -ChildrenOnly:$true -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch }

		$out = @()
		foreach ($win in $allWindows) {
			$out += [pscustomobject] @{
				Name          = $win.Current.Name
				ClassName     = $win.Current.ClassName
				ControlType   = $win.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
				AutomationId  = $win.Current.AutomationId
				WindowElement = $win
			}
		}
		return $out
	}

	if ($EnumListAllWindows) {
		return Get-AllTopWindows
	}

	# ----------------------------------------------------------------
	# Section 4: Window Acquisition
	# ----------------------------------------------------------------
	# Window acquisition priority logic:
	# 1. If noWindow specified: Use desktop root (no window context)
	# 2. If WindowHandle provided: Use specified window handle
	# 3. if ProcessName provided: Search for the window using Process Name
	# 4. if partAppId provided: Search for the window using part App Id
	# 5. If WinProperty provided: Search for the window using matching conditions
	# 6. If these parameters not provided: Search for the window that is foreground
	# if fallBackInOrder will go in this order for the provided multi window search scenarios
	# Rely on Parameter Validation

	$appWin = $null
	$elapsed = 0

	# Case 1: Use desktop root if noWindow specified
	if ($noWindow) {
		$appWin = $root
		if ($DebugSwitch) { Write-Host "ℹ️  Using desktop root as search scope" -ForegroundColor Cyan }
	}

	# Case 2: Use specified window handle (since there is hwnd so the window is already open)
	if ($WindowHandle -ne [IntPtr]::Zero) {
		try {
			Write-Host "🔍 Using specified window handle: 0x$($WindowHandle.ToString('X8'))" -ForegroundColor Cyan
			$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($WindowHandle)
			if ($appWin) {
				if ($DebugSwitch) { Write-Host "✅ Successfully acquired window: $($appWin.Current.Name) Class: $($appWin.Current.ClassName) `n hwnd: 0x$($WindowHandle.ToString('X8'))" -ForegroundColor Green }
			} else {
				if ($DebugSwitch) { Write-Warning "⚠️ Could not acquire window from handle: 0x$($WindowHandle.ToString('X8'))" }
				return $false
			}
		} catch {
			if ($DebugSwitch) { Write-Warning "⚠️ Error accessing window handle: 0x$($WindowHandle.ToString('X8')) - $($_.Exception.Message)" }
			return $false
		}

		$appFrameHwnd = Get-UWPPairedWindow -SourceHWnd $WindowHandle -Direction "ToAppFrame"
		if ($appFrameHwnd -eq [IntPtr]::Zero) { $appFrameHwnd = $WindowHandle }
		$coreWindowHwnd = Get-UWPPairedWindow -SourceHWnd $WindowHandle -Direction "ToCoreWindow"
		if ($coreWindowHwnd -eq [IntPtr]::Zero) { $coreWindowHwnd = $WindowHandle }
	}

	# Case 3: Search & wait for window by Process Name
	if (-not $appWin -and $ProcessName) {
		# Execute search with timeout
		if ($DebugSwitch) { Write-Host "🔍 Searching for window by Process Name..." -ForegroundColor Yellow }
		while (($elapsed -lt $Timeout) -and ($null -eq $appWin)) {
			if ($HostWindow) {
				$appFrameHwnd = (Get-AppHwnd -ProcessName $ProcessName).HWND
				$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($appFrameHwnd)
			} else {
				$coreWindowHwnd = (Get-AppHwnd -ProcessName $ProcessName).RealHWND
				$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($coreWindowHwnd)
			}
			if (-not $appWin) {
				Start-Sleep -Milliseconds 200; $elapsed += 200
			} else {
				if ($DebugSwitch) { Write-Host "✅ Found window: $($appWin.Current.Name) Class: $($appWin.Current.ClassName)" -ForegroundColor Green }
				break
			}
		}
	}

	# Case 4: Search & wait for window by part App Id
	if (-not $appWin -and $partAppId) {
		# Execute search with timeout
		if ($DebugSwitch) { Write-Host "🔍 Searching for window by Part App Id..." -ForegroundColor Yellow }
		while (($elapsed -lt $Timeout) -and ($null -eq $appWin)) {
			if ($HostWindow) {
				$appFrameHwnd = (Get-HwndByAppUserModelId -partAppId $partAppId).HWND
				$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($appFrameHwnd)
			} else {
				$coreWindowHwnd = (Get-HwndByAppUserModelId -partAppId $partAppId).RealHWND
				$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($coreWindowHwnd)
			}
			if (-not $appWin) {
				Start-Sleep -Milliseconds 200; $elapsed += 200
			} else {
				if ($DebugSwitch) { Write-Host "✅ Found window: $($appWin.Current.Name) Class: $($appWin.Current.ClassName)" -ForegroundColor Green }
				break
			}
		}
	}

	# Case 5: Search & wait for window by specified conditions
	if (-not $appWin -and ($WinProperty.Count -gt 0 -or $WinValue.Count -gt 0)) {
		if ($WinProperty.Count -ne $WinValue.Count) {
			Write-Warning "⚠️ WinProperty and WinValue arrays must have the same number of elements"
			return $false
		} elseif ($DebugSwitch) { Write-Host "🔍 Searching for window with specified conditions..." -ForegroundColor Yellow }

		# Execute Window search with conditions during timeout
		$elapsed = 0
		while ($elapsed -lt $Timeout -and $null -eq $appWin) {
			$appWin = UIAElementSearch -source $root -ElementProperty $WinProperty -ElementSearchValue $WinValue -MultiElements:$false -ChildrenOnly:$true -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch
			if (-not $appWin) {
				Start-Sleep -Milliseconds 200; $elapsed += 200
			} else {
				if ($DebugSwitch) { Write-Host "✅ Found conditions target window: $($appWin.Current.Name) Class: $($appWin.Current.ClassName)" -ForegroundColor Green }
				break
			}
		}

		$NativeHwnd = $appWin.Current.NativeWindowHandle
		$appFrameHwnd = Get-UWPPairedWindow -SourceHWnd $NativeHwnd -Direction "ToAppFrame"
		if ($appFrameHwnd -eq [IntPtr]::Zero) { $appFrameHwnd = $NativeHwnd }
		$coreWindowHwnd = Get-UWPPairedWindow -SourceHWnd $NativeHwnd -Direction "ToCoreWindow"
		if ($coreWindowHwnd -eq [IntPtr]::Zero) { $coreWindowHwnd = $NativeHwnd }
	}

	# Case 6: Search & wait for the window that is foreground if no specific parameters provided or search failed for all others with fallBackInOrder
	if ((-not $appWin) -and (-not $noWindow) -and ($fallBackInOrder -or (-not $ProcessName -and $WinProperty.Count -eq 0 -and $WindowHandle -eq [IntPtr]::Zero))) {
		# Execute search with timeout
		if ($DebugSwitch) { Write-Host "🔍 Searching for foreground window..." -ForegroundColor Yellow }
		while ($elapsed -lt $Timeout -and $null -eq $appWin) {
			if ($HostWindow) {
				$appFrameHwnd = Get-UWPPairedWindow -SourceHWnd ((Get-ForegroundWindow).HWND) -Direction "ToAppFrame"
				if ($appFrameHwnd -eq [IntPtr]::Zero) { $appFrameHwnd = ((Get-ForegroundWindow).HWND) }
				$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($appFrameHwnd)
			} else {
				$coreWindowHwnd = Get-UWPPairedWindow -SourceHWnd ((Get-ForegroundWindow).HWND) -Direction "ToCoreWindow"
				if ($coreWindowHwnd -eq [IntPtr]::Zero) { $coreWindowHwnd = ((Get-ForegroundWindow).HWND) }
				$appWin = [System.Windows.Automation.AutomationElement]::FromHandle($coreWindowHwnd)
			}
			if (-not $appWin) {
				Start-Sleep -Milliseconds 200; $elapsed += 200
			} else {
				if ($DebugSwitch) { Write-Host "✅ Found Foreground window: $($appWin.Current.Name) Class: $($appWin.Current.ClassName)" -ForegroundColor Green }
				break
			}
		}
	}

	# ----------------------------------------------------------------
	# Return window existence check with element reference
	# ----------------------------------------------------------------
	if ($WindowExist) {
		return [PSCustomObject]@{
			Exists  = [bool]$appWin
			Element = $appWin
		}
	}

	# ----------------------------------------------------------------
	# Validate window was found
	# ----------------------------------------------------------------
	if (-not $appWin) {
		if (-not $NoWarn) { Write-Warning "⚠️ Window not found" }
		return $false
	}

	# ----------------------------------------------------------------
	# IMPORTANT: Allow UI initialization time if specified
	# This is crucial for heavy windows like MS Store
	# ----------------------------------------------------------------
	# Must work on Core or Win32 not framehost
	if ($WaitWindowReady) {
		Write-Host "⏳ Waiting for window to become ready..."
		if ($coreWindowHwnd) {
			Wait-WindowReady -Hwnd $coreWindowHwnd
			if ($DebugSwitch) {
				$WEl = [System.Windows.Automation.AutomationElement]::FromHandle($coreWindowHwnd)
				[pscustomobject] @{
					Name      = $WEl.Current.Name
					ClassName = $WEl.Current.ClassName
					HWND      = [IntPtr] $coreWindowHwnd
					RealHWND  = [IntPtr] $WEl.Current.NativeWindowHandle
				}
			}
		} else {
			$coreWindowHwnd = Get-UWPPairedWindow -SourceHWnd $appFrameHwnd -Direction "ToCoreWindow"
			if ($DebugSwitch) {
				$WEl = [System.Windows.Automation.AutomationElement]::FromHandle($coreWindowHwnd)
				[pscustomobject] @{
					Name      = $WEl.Current.Name
					ClassName = $WEl.Current.ClassName
					HWND      = [IntPtr] $coreWindowHwnd
					RealHWND  = [IntPtr] $WEl.Current.NativeWindowHandle
				}
			}
		}
	}

	if ($ExtraDelay -gt 0) {
		if ($DebugSwitch) { Write-Host "⏳ Allowing $ExtraDelay ms for UI initialization..." -ForegroundColor Cyan }
		Start-Sleep -Milliseconds $ExtraDelay
	}

	# ----------------------------------------------------------------
	# If only URI/WindowHandle was provided without any operations, return success
	# ----------------------------------------------------------------
	$hasControlOperation = $ControlProperty.Count -gt 0 -or $ChildProperty.Count -gt 0 -or $Pattern -or `
	$GetPatternPropertyValue -or $CheckPatternSupported -or $ListControls -or `
	$ListChildren -or $ControlExist -or $ChildExist

	if (-not $hasControlOperation) {
		if ($DebugSwitch) { Write-Host "✅ Successfully launched and prepared window for operations" -ForegroundColor Green }
		return $true
	}

	# ----------------------------------------------------------------
	# If Pure Window Operation skip control and child
	# ----------------------------------------------------------------
	$PureWindowOperation = -not ($ControlProperty.Count -gt 0 -or $ChildProperty.Count -gt 0 -or $ListControls -or $ListChildren)
	if ($PureWindowOperation) {
		if ($DebugSwitch) { Write-Host "Window Operation" }
		$ElementsForAction = @()
		$ElementsForAction = $appWin
	}

	# ----------------------------------------------------------------
	# Section 5: Control Listing
	# ----------------------------------------------------------------
	if ($ListControls) {
		$ElementsForAction = @()
		if (($ControlProperty -and $ControlProperty.Count -gt 0) -or ($ControlValue -and $ControlValue.Count -gt 0)) {
			if ($ControlProperty.Count -ne $ControlValue.Count) {
				Write-Warning "⚠️ ControlProperty and ControlValue arrays must have the same number of elements"
				return $false
			} elseif ($DebugSwitch) { Write-Host "Listing Controls" }

			# Execute Control listing with conditions
			$ElementsForAction = UIAElementSearch -source $appWin -ElementProperty $ControlProperty -ElementSearchValue $ControlValue -MultiElements -ChildrenOnly:$ChildrenOnly -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch
			# Execute Control listing without conditions
			$ElementsForAction = UIAElementSearch -source $appWin -MultiElements -ChildrenOnly:$ChildrenOnly -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch
		}

		if ($ElementsForAction.Count -gt 0) {
			if ($DebugSwitch) { Write-Host "Control(s) found" }
		} else {
			if (-not $NoWarn) { Write-Warning "⚠️ Control(s) Not found" }
			return $false
		}

		$out = @()
		foreach ($ctrl in $ElementsForAction) {
			$out += [pscustomobject] @{
				AutomationId	= $ctrl.Current.AutomationId
				ClassName    = $ctrl.Current.ClassName
				ControlType  = $ctrl.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
				Name         = $ctrl.Current.Name
				FrameworkId  = $ctrl.Current.FrameworkId
				Patterns     = ($ctrl.GetSupportedPatterns().ProgrammaticName -join ", ")
				Element      = $ctrl
			}
		}
		return $out
	}

	# ----------------------------------------------------------------
	# Section 6: Controls Search and Verification
	# ----------------------------------------------------------------
	# Search for parent control(s) using specified property conditions

	if (($ControlProperty -and $ControlProperty.Count -gt 0) -or ($ControlValue -and $ControlValue.Count -gt 0)) {
		$ElementsForAction = @()
		if ($ControlProperty.Count -ne $ControlValue.Count) {
			Write-Warning "⚠️ ControlProperty and ControlValue arrays must have the same number of elements"
			return $false
		} elseif ($DebugSwitch) { Write-Host "Searching for control" }

		# Execute Control search with conditions
		$ElementsForAction = UIAElementSearch -source $appWin -ElementProperty $ControlProperty -ElementSearchValue $ControlValue -MultiElements:$MultiElements -ChildrenOnly:$ChildrenOnly -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch

		if ($ControlExist) {
			# Return control existence check with element references
			return [PSCustomObject]@{
				Exists   = [bool] ($ElementsForAction.Count -gt 0)
				Elements = $ElementsForAction
			}
		} elseif ($ElementsForAction.Count -gt 0) {
			if ($DebugSwitch) { Write-Host "Control(s) found" }
		} else {
			if (-not $NoWarn) { Write-Warning "⚠️ Control(s) Not found" }
			return $false
		}
	}

	# ----------------------------------------------------------------
	# Section 7: Child Listing
	# ----------------------------------------------------------------

	# List children operation - display all direct child controls of found parent(s)
	if ($ListChildren) {

		if (($ChildProperty -and $ChildProperty.Count -gt 0) -or ($ChildValue -and $ChildValue.Count -gt 0)) {
			if ($ChildProperty.Count -ne $ChildValue.Count) {
				Write-Warning "⚠️ ChildProperty and ChildValue arrays must have the same number of elements"
				return $false
			} elseif ($DebugSwitch) { Write-Host "Listing Children" }

			if (-not $ElementsForAction) {
				if (-not $NoWarn) { Write-Warning "⚠️ Parent control(s) not found for listing children" }
				return $false
			}

			# Store parent references
			$parentControls = $ElementsForAction
			# Execute child search with conditions
			$ElementsForAction = @()
			foreach ($parent in $parentControls) {
				$foundChildren = UIAElementSearch -source $parent -ElementProperty $ChildProperty -ElementSearchValue $ChildValue -MultiElements:$MultiElements -ChildrenOnly:$ChildrenOnly -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch
				$ElementsForAction += $foundChildren
			}

		} else {

			# Store parent references
			$parentControls = $ElementsForAction
			# Execute child search without conditions
			foreach ($parent in $parentControls) {
				$foundChildren = UIAElementSearch -source $parent -MultiElements:$MultiElements -ChildrenOnly:$ChildrenOnly -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch
				$ElementsForAction += $foundChildren
			}

		}

		if ($ElementsForAction.Count -gt 0) {
			if ($DebugSwitch) { Write-Host "Children found" }
		} else {
			if (-not $NoWarn) { Write-Warning "⚠️ Children Not found" }
			return $false
		}

		# Format and return child control information
		$out = @()
		foreach ($child in $ElementsForAction) {
			$out += [pscustomobject] @{
				AutomationId = $child.Current.AutomationId
				ClassName    = $child.Current.ClassName
				ControlType  = $child.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
				Name         = $child.Current.Name
				FrameworkId  = $child.Current.FrameworkId
				Patterns     = ($child.GetSupportedPatterns().ProgrammaticName -join ", ")
				Element      = $child
			}
		}
		return $out
	}

	# ----------------------------------------------------------------
	# Section 8: Child Controls Search and Verification
	# ----------------------------------------------------------------
	# Search for child controls within found parent control(s)
	if (($ChildProperty -and $ChildProperty.Count -gt 0) -or ($ChildValue -and $ChildValue.Count -gt 0)) {
		if ($ChildProperty.Count -ne $ChildValue.Count) {
			Write-Warning "⚠️ ChildProperty and ChildValue arrays must have the same number of elements"
			return $false
		} elseif ($DebugSwitch) { Write-Host "Searching for child" }

		if (-not $ElementsForAction) {
			if (-not $NoWarn) { Write-Warning "⚠️ Parent control(s) not found for child search" }
			return $false
		}

		# Store parent references
		$parentControls = $ElementsForAction
		# Execute child search
		$ElementsForAction = @()
		foreach ($parent in $parentControls) {
			$foundChildren = UIAElementSearch -source $parent -ElementProperty $ChildProperty -ElementSearchValue $ChildValue -MultiElements:$MultiElements -ChildrenOnly:$ChildrenOnly -NoWarn:$NoWarn -DebugSwitch:$DebugSwitch
			$ElementsForAction += $foundChildren
		}

		if ($ChildExist) {
			# Return child existence check with element references
			return [PSCustomObject]@{
				Exists   = [bool]($ElementsForAction.Count -gt 0)
				Elements = $ElementsForAction
			}
		} elseif ($ElementsForAction.Count -gt 0) {
			if ($DebugSwitch) { Write-Host "Children found" }
		} else {
			if (-not $NoWarn) { Write-Warning "⚠️ Children Not found" }
			return $false
		}
	}

	# ----------------------------------------------------------------
	# Section 9: Pattern Operations - Generic UI Automation Pattern Support
	# ----------------------------------------------------------------

	# Validate Elements were found for pattern operations
	if (-not $ElementsForAction) {
		if (-not $NoWarn) { Write-Warning "⚠️ Elements not found with specified properties" }
		return $false
	}

	try {
		$results = @()
		foreach ($element in $ElementsForAction) {
			# Pattern support verification
			if ($CheckPatternSupported) {
				$patternType = Get-PatternType -PatternName $Pattern
				if (-not $patternType) {
					if (-not $NoWarn) { Write-Warning "⚠️ Pattern '$Pattern' not recognized" }
					return $false
				}
				$ElementSupportedPatterns = $element.GetSupportedPatterns()
				$isSupported = $ElementSupportedPatterns | Where-Object { $_.ProgrammaticName -eq $patternType.ProgrammaticName }
				if ($DebugSwitch) { Write-Host "Used pattern: $Pattern" }
				if ($DebugSwitch) { Write-Host "PatternType: "; $patternType.ProgrammaticName }
				if ($DebugSwitch) { Write-Host "Supported Patterns: "; (($element.GetSupportedPatterns()).ProgrammaticName -join ", ") }
				if ($DebugSwitch) { Write-Host "Matched Pattern: "; $isSupported.ProgrammaticName }
				$results += [bool]$isSupported
				continue
			}

			# Pattern property retrieval
			if ($GetPatternPropertyValue -and $PatternProperty) {
				$patternType = Get-PatternType -PatternName $Pattern
				if (-not $patternType) {
					if (-not $NoWarn) { Write-Warning "⚠️ Pattern '$Pattern' not recognized" }
					return $false
				}

				$ExecutePattern = $element.GetCurrentPattern($patternType)
				$StrExp = '$propertyValue = $ExecutePattern.' + $PatternProperty
				Invoke-Expression -Command $StrExp
				if ($DebugSwitch) { Write-Host "Pattern Property Value: "; $propertyValue }
				$results += $propertyValue
				continue
			}

			# Pattern method execution with optional conditional logic
			if ($Pattern -and $PatternMethod) {
				$patternType = Get-PatternType -PatternName $Pattern
				if (-not $patternType) {
					if (-not $NoWarn) { Write-Warning "⚠️ Pattern '$Pattern' not recognized" }
					return $false
				}

				$ExecutePattern = $element.GetCurrentPattern($patternType)

				# Check condition if specified (execute only if condition matches)
				$shouldExecute = $true
				if ($PatternProperty -and $ConditionValue) {
					$StrExp = '$currentValue = $ExecutePattern.' + $PatternProperty
					Invoke-Expression -Command $StrExp
					if ($DebugSwitch) { Write-Host "Pattern Property Value: "; $currentValue }
					$shouldExecute = Test-Condition -CurrentValue $currentValue -ExpectedValue $ConditionValue -Operator $ConditionOperator
				}

				if ($shouldExecute) {
					# Invoke pattern method with or without arguments
					if ($PatternMethodArgs.Count -gt 0) {
						$ExecutePattern.$PatternMethod.Invoke($PatternMethodArgs)
					} else {
						$ExecutePattern.$PatternMethod.Invoke()
					}
					if ($DebugSwitch) { Write-Host "✅ Executed $Pattern $PatternMethod() on element: Name='$($element.Current.Name)' AutomationId='$($element.Current.AutomationId)'" -ForegroundColor Green }
					$results += $true
				} else {
					if ($DebugSwitch) { Write-Host "⏭️  Condition not met for $Pattern $PatternMethod() on element: Name='$($element.Current.Name)'" -ForegroundColor Yellow }
					$results += $false
				}
				continue
			}
		}

		# Return operation results
		if ($CheckPatternSupported -or $GetPatternPropertyValue) {
			if ($results.Count -eq 1) { return $results[0] } else { return $results }
		} else {
			return $results -contains $true
		}
	} catch {
		Write-Warning "⚠️ Error performing pattern operation: $($_.Exception.Message)"
		if (-not $ExecutePattern) { Write-Host "Failed to Get Current Pattern for the element" }
		return $false
	}
}

# ==================================================================================
# Helper function for Dynamic Conditions Search (UIA Element Finder Function)
# ==================================================================================
function UIAElementSearch {
	param(
		[object]$source = `
		([System.Windows.Automation.AutomationElement]::RootElement),	# The Starting point of the search, Default is desktop.
		[array]$ElementProperty = @(),									# Element property names to filter by e.g. ("ClassName", "Name", "AutomationId", "ControlType", "FrameworkId")
		[array]$ElementSearchValue = @(),								# Element property search condition values corresponding to Element Property array
		[switch]$MultiElements,											# Process all elements that match the conditions (not just first match)
		[switch]$ChildrenOnly,											# Search for Direct children only not the entire Descendants in the tree
		[switch]$NoWarn,												# Suppress warning if window or element isn't found (useful for retry scenarios)
		[switch]$DebugSwitch
	)

	# Load UI Automation assemblies
	Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue
	Add-Type -AssemblyName UIAutomationTypes -ErrorAction SilentlyContinue

	$ElementConditions = @()
	# Build Element search conditions from dynamic property arrays
	if ($ElementProperty -and $ElementProperty.Count -gt 0) {
		if ($DebugSwitch) { Write-Host "Searching for Element" }
		if ($ElementProperty.Count -ne $ElementSearchValue.Count) {
			Write-Warning "⚠️ Element properties and Element Search Values arrays must have the same number of elements"
			return $false
		}

		for ($i = 0; $i -lt $ElementProperty.Count; $i++) {
			if ($ElementProperty[$i] -notmatch 'Property$') { $ElementProperty[$i] = $ElementProperty[$i] + "Property" }
			$SearchConditionValue = Convert-UIAConditionType -Property $ElementProperty[$i] -Value $ElementSearchValue[$i]
			$Elementconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::($ElementProperty[$i]), $SearchConditionValue)
		}
	}

	# Create search condition from individual conditions
	if ($Elementconditions.Count -gt 1) {
		$ElementCondition = New-Object System.Windows.Automation.AndCondition($Elementconditions)
	} elseif ($Elementconditions.Count -eq 1) {
		$ElementCondition = $Elementconditions[0]
	} else {
		$ElementCondition = [System.Windows.Automation.Condition]::TrueCondition
	}

	# Execute search for single or multiple elements based on MultiElements switch
	if ($MultiElements) {
		if ($ChildrenOnly) {
			$Elements = $source.FindAll([System.Windows.Automation.TreeScope]::Children, $ElementCondition)
		} else {
			$Elements = $source.FindAll([System.Windows.Automation.TreeScope]::Descendants, $ElementCondition)
		}
	} else {
		if ($ChildrenOnly) {
			$Elements = $source.FindFirst([System.Windows.Automation.TreeScope]::Children, $ElementCondition)
		} else {
			$Elements = $source.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $ElementCondition)
		}
	}
	if ($Elements) { if ($DebugSwitch) { Write-Host "Element(s) Found" } } else { if (-not $NoWarn) { Write-Warning "⚠️ Element(s) Not found" } }

	return $Elements
}

# ==================================================================================
# Helper function Convert-UIAConditionType
# ==================================================================================
function Convert-UIAConditionType {
		<#
        .SYNOPSIS
        Normalizes AutomationElement property values to their proper .NET types
        so UIAElementSearch and Interact-UIA can safely create conditions.

        .DESCRIPTION
        This handles the most common AutomationElement properties that throw
        exceptions if passed as strings. All other properties are returned as-is.

        .PARAMETER Property
        The AutomationElement property name (string).

        .PARAMETER Value
        The string or object value to convert.

        .OUTPUTS
        The converted value in its correct type.
    #>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Property,

		[Parameter(Mandatory)]
		[object]$Value
	)

	switch -Regex ($Property) {
		# --- UIA Element Properties that require conversion ---
		'^ControlTypeProperty$' {
			try {
				# Accepts ControlType name, e.g., "Button", "Edit", etc.
				if ($Value -is [string]) {
					return [System.Windows.Automation.ControlType]::$Value
				} else {
					return $Value
				}
			} catch {
				Write-Verbose "Invalid ControlType: $Value"
				return $Value
			}
		}

		'^(ProcessIdProperty|NativeWindowHandleProperty)$' {
			return [int]$Value
		}

		'^BoundingRectangleProperty$' {
			try {
				return [Windows.Rect]::Parse($Value)
			} catch {
				Write-Verbose "Invalid Rect string: $Value"
				return $Value
			}
		}

		'^OrientationProperty$' {
			try {
				if ($Value -is [string]) {
					return [System.Windows.Automation.OrientationType]::$Value
				} else {
					return $Value
				}
			} catch {
				Write-Verbose "Invalid OrientationType: $Value"
				return $Value
			}
		}

		'^CultureProperty$' {
			try {
				if ($Value -is [string]) {
					return [System.Globalization.CultureInfo]::new($Value)
				} else {
					return $Value
				}
			} catch {
				Write-Verbose "Invalid CultureInfo: $Value"
				return $Value
			}
		}

		'^RuntimeIdProperty$' {
			try {
				if ($Value -is [string]) {
					return ($Value -split '[,; ]+' | ForEach-Object { [int]$_ })
				} elseif ($Value -is [int[]]) {
					return $Value
				} else {
					return @([int]$Value)
				}
			} catch {
				Write-Verbose "Invalid RuntimeId: $Value"
				return $Value
			}
		}

		# --- Default (leave as-is) ---
		default {
			return $Value
		}
	}
}

# ==================================================================================
# Helper function to map pattern names to UI Automation pattern types
# ==================================================================================
function Get-PatternType {
	param([string]$PatternName)

	switch ($PatternName) {
		# Core interaction patterns
		"Invoke" { $PatternType = [System.Windows.Automation.InvokePattern]::Pattern }
		"Selection" { $PatternType = [System.Windows.Automation.SelectionPattern]::Pattern }
		"Value" { $PatternType = [System.Windows.Automation.ValuePattern]::Pattern }
		"RangeValue" { $PatternType = [System.Windows.Automation.RangeValuePattern]::Pattern }
		"Scroll" { $PatternType = [System.Windows.Automation.ScrollPattern]::Pattern }
		"ExpandCollapse" { $PatternType = [System.Windows.Automation.ExpandCollapsePattern]::Pattern }
		"Toggle" { $PatternType = [System.Windows.Automation.TogglePattern]::Pattern }
		"Window" { $PatternType = [System.Windows.Automation.WindowPattern]::Pattern }

		# Selection and item patterns
		"SelectionItem" { $PatternType = [System.Windows.Automation.SelectionItemPattern]::Pattern }

		# Text and content patterns
		"Text" { $PatternType = [System.Windows.Automation.TextPattern]::Pattern }

		# Grid and table patterns
		"Grid" { $PatternType = [System.Windows.Automation.GridPattern]::Pattern }
		"GridItem" { $PatternType = [System.Windows.Automation.GridItemPattern]::Pattern }
		"Table" { $PatternType = [System.Windows.Automation.TablePattern]::Pattern }
		"TableItem" { $PatternType = [System.Windows.Automation.TableItemPattern]::Pattern }

		# Transform and layout patterns
		"Transform" { $PatternType = [System.Windows.Automation.TransformPattern]::Pattern }

		# Container and virtualization patterns
		"ItemContainer" { $PatternType = [System.Windows.Automation.ItemContainerPattern]::Pattern }
		"VirtualizedItem" { $PatternType = [System.Windows.Automation.VirtualizedItemPattern]::Pattern }

		# Dock and specialized patterns
		"Dock" { $PatternType = [System.Windows.Automation.DockPattern]::Pattern }

		# Advanced patterns
		"TextEdit" { $PatternType = [System.Windows.Automation.TextEditPattern]::Pattern }
		"SynchronizedInput" { $PatternType = [System.Windows.Automation.SynchronizedInputPattern]::Pattern }
		"ScrollItem" { $PatternType = [System.Windows.Automation.ScrollItemPattern]::Pattern }
		default {
			$StrExp = '$PatternType = [System.Windows.Automation.' + $PatternName + 'Pattern]::Pattern'
			Invoke-Expression -Command $StrExp
		}
	}

	return $PatternType
}

	<#
# Still under development
# Get the type of the value of an element Pattern Property 
function Get-UIAPropertyValueType {
	param(
	[string]$PatternProperty 					#Pattern Value Name
	)

	switch ($PatternValueName) {
		"OrientationType"        { $PatternValueName = [System.Windows.Automation.OrientationType] }
        "ToggleState"            { $PatternValueName = [System.Windows.Automation.ToggleState] }
        "ExpandCollapseState"    { $PatternValueName = [System.Windows.Automation.ExpandCollapseState] }
        "WindowVisualState"      { $PatternValueName = [System.Windows.Automation.WindowVisualState] }
        "WindowInteractionState" { $PatternValueName = [System.Windows.Automation.WindowInteractionState] }
        "DockPosition"           { $PatternValueName = [System.Windows.Automation.DockPosition] }
        "ScrollAmount"           { $PatternValueName = [System.Windows.Automation.ScrollAmount] }
        "TextUnit"               { $PatternValueName = [System.Windows.Automation.TextUnit] }
        "SynchronizedInputType"  { $PatternValueName = [System.Windows.Automation.SynchronizedInputType] }
		default {
			$StrExp = '$UIAPropertyValueType = [System.Windows.Automation.' + $PatternValueName + ']'
			Invoke-Expression -Command $StrEx
		}
	}

	return $UIAPropertyValueType
}
#>

# ==================================================================================
# Function: Wait-WindowReady
# Helper function for dynamic waiting until window is ready
# ==================================================================================
# --- Function and class together ---
function Wait-WindowReady {
	param(
		[Parameter(Mandatory)]
		$Hwnd,         # Can be IntPtr, UIntPtr, or System.Reflection.Pointer
		[int]$Timeout = 10000
	)

	# --- Add Win32 class once ---
	if (-not ("Win32" -as [type])) {
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsHungAppWindow(IntPtr hWnd);
}
"@
	}

	# --- Normalize HWND to IntPtr ---
	if ($Hwnd -is [System.Reflection.Pointer]) {
		$hwndPtr = [System.Runtime.InteropServices.Pointer]::Unbox($Hwnd)
	} elseif ($Hwnd -is [UIntPtr]) {
		$hwndPtr = [IntPtr]::new([UInt64]$Hwnd.ToUInt64())
	} elseif ($Hwnd -is [IntPtr]) {
		$hwndPtr = $Hwnd
	} else {
		$hwndPtr = [IntPtr]::new([UInt64]$Hwnd)
	}

	# --- Get owning process ---
	$null = [Win32]::GetWindowThreadProcessId($hwndPtr, [ref]([int]$ownerPid = 0))
	if (-not $ownerPid) { return $false }

	try {
		$proc = Get-Process -Id $ownerPid -ErrorAction Stop
	} catch {
		return $false
	}

	# --- WaitForInputIdle (half timeout) ---
	$halfTimeout = [Math]::Max(500, [int]($Timeout / 2))
	try { $null = $proc.WaitForInputIdle($halfTimeout) } catch {}

	# --- Poll until window is ready ---
	$sw = [Diagnostics.Stopwatch]::StartNew()
	while ($sw.ElapsedMilliseconds -lt $Timeout) {
		$isValid = [Win32]::IsWindow($hwndPtr)
		$isVisible = [Win32]::IsWindowVisible($hwndPtr)
		$isHung = [Win32]::IsHungAppWindow($hwndPtr)

		if ($isValid -and $isVisible -and -not $isHung) {
			return $true
		}

		Start-Sleep -Milliseconds 100
	}

	return $false
}

# ==================================================================================
# Function: Test-Condition
# Helper function for conditional pattern execution
# ==================================================================================
function Test-Condition {
	param(
		$CurrentValue,
		$ExpectedValue,
		[string]$Operator = "Equals"
	)

	switch ($Operator) {
		"Equals" { return $CurrentValue -eq $ExpectedValue }
		"NotEquals" { return $CurrentValue -ne $ExpectedValue }
		"Contains" { return $CurrentValue -like "*$ExpectedValue*" }
		"GreaterThan" { return $CurrentValue -gt $ExpectedValue }
		"LessThan" { return $CurrentValue -lt $ExpectedValue }
		default { return $CurrentValue -eq $ExpectedValue }
	}
}

# ==================================================================================
# Function: Get-TargetType
# ==================================================================================
function Get-TargetType {
	param(
		[Parameter(Mandatory)]
		[string]$Target
	)

	# 1. Check if it looks like a URI (scheme://... or scheme:)
	if ([Uri]::IsWellFormedUriString($Target, [System.UriKind]::Absolute)) {
		return "URI"
	}

	# 2. If it's a fully qualified path
	if (Test-Path $Target -PathType Leaf -ErrorAction SilentlyContinue) {
		$ext = [System.IO.Path]::GetExtension($Target)
		if ($ext -match '^\.(exe|com|bat|cmd|ps1|msi|msp)$') {
			return "Executable"
		}
		return "File"
	}

	# 3. If it's a bare command (like "explorer", "notepad")
	$resolved = Get-Command $Target -ErrorAction SilentlyContinue
	if ($resolved -and $resolved.CommandType -eq 'Application') {
		return "Executable"
	}

	return "Unknown"
}

function Test-TypeExists {
	param([string]$TypeName)
	try {
		[System.Type]::GetType($TypeName, $true) | Out-Null
		return $true
	} catch {
		return $false
	}
}

# ==================================================================================
# Function: Get-ForegroundWindow
# - Return an object with [UIA WindowElement, handle, title, Class Name, Control Type & Automation Id] of the current Foreground Window
# - Helper function to get current foreground window
# ==================================================================================
function Get-ForegroundWindow {
	# --- Get Foreground Window ---
	if (-not (Test-TypeExists -TypeName "Win32")) {
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    // From first definition
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    // From second definition
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);
}
"@
	}

	# Load UI Automation assemblies
	Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue
	Add-Type -AssemblyName UIAutomationTypes -ErrorAction SilentlyContinue

	# Get the foreground window handle
	$hWnd = [Win32]::GetForegroundWindow()

	if ($hWnd -eq [IntPtr]::Zero) {
		Write-Warning "⚠️ No foreground window found"
		return [PSCustomObject] @{
			HWND = [IntPtr]::Zero
		}
	}

	# Get the window title
	$titleLength = [Win32]::GetWindowTextLength($hWnd)
	$titleBuilder = New-Object System.Text.StringBuilder($titleLength + 1)
	[Win32]::GetWindowText($hWnd, $titleBuilder, $titleBuilder.Capacity) | Out-Null
	$title = $titleBuilder.ToString()

	# Get UI Automation element and ControlType
	try {
		$WindowElement = [System.Windows.Automation.AutomationElement]::FromHandle($hWnd)
		$ControlType = $WindowElement.Current.ControlType.ProgrammaticName.Replace("ControlType.", "")
		$AutomationId = $WindowElement.Current.AutomationId
		$className = $WindowElement.Current.ClassName
		$Patterns = ($WindowElement.GetSupportedPatterns().ProgrammaticName -join ", ")
	} catch { Write-Warning "⚠️ Failed to get all the window properties" }

	if ($className -eq "Windows.UI.Core.CoreWindow") {} else {}

	# Return an object with the properties
	return [PSCustomObject] @{
		HWND         = [IntPtr] $hWnd
		Title        = $title
		ClassName    = $className
		ControlType  = $ControlType
		AutomationId = $AutomationId
		Patterns     = $Patterns
	}
}

function Get-UWPPairedWindow {
	param(
		[Parameter(Mandatory = $true)]
		[IntPtr]$SourceHWnd,

		[Parameter(Mandatory = $true)]
		[ValidateSet("ToAppFrame", "ToCoreWindow")]
		[string]$Direction
	)

	# Define Win32 API functions
	Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;

        public class WindowUtils {
            [DllImport("user32.dll")]
            public static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

            [DllImport("user32.dll")]
            public static extern IntPtr GetParent(IntPtr hWnd);

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

            [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

            [DllImport("user32.dll")]
            public static extern bool IsWindowVisible(IntPtr hWnd);

            public const uint GW_CHILD = 5;
            public const uint GW_HWNDFIRST = 0;
            public const uint GW_HWNDNEXT = 2;
        }
"@ -ErrorAction SilentlyContinue

	if ($SourceHWnd -eq [IntPtr]::Zero) {
		return [IntPtr]::Zero
	}

	switch ($Direction) {
		"ToAppFrame" {
			# Get ApplicationFrameWindow from CoreWindow

			# First try: Get direct parent
			$parentHwnd = [WindowUtils]::GetParent($SourceHWnd)
			if ($parentHwnd -ne [IntPtr]::Zero) {
				$className = New-Object System.Text.StringBuilder 256
				[WindowUtils]::GetClassName($parentHwnd, $className, $className.Capacity) | Out-Null
				if ($className.ToString() -eq "ApplicationFrameWindow") {
					return $parentHwnd
				}
			}

			# Second try: Get the CoreWindow title and find matching ApplicationFrameWindow
			$coreWindowTitle = New-Object System.Text.StringBuilder 256
			[WindowUtils]::GetWindowText($SourceHWnd, $coreWindowTitle, $coreWindowTitle.Capacity) | Out-Null
			$targetTitle = $coreWindowTitle.ToString()

			if ([string]::IsNullOrEmpty($targetTitle)) {
				return [IntPtr]::Zero
			}

			# Enumerate all ApplicationFrameWindow instances and match by title
			$hwnd = [WindowUtils]::GetWindow([IntPtr]::Zero, [WindowUtils]::GW_HWNDFIRST)
			while ($hwnd -ne [IntPtr]::Zero) {
				if ([WindowUtils]::IsWindowVisible($hwnd)) {
					$className = New-Object System.Text.StringBuilder 256
					[WindowUtils]::GetClassName($hwnd, $className, $className.Capacity) | Out-Null

					if ($className.ToString() -eq "ApplicationFrameWindow") {
						$windowTitle = New-Object System.Text.StringBuilder 256
						[WindowUtils]::GetWindowText($hwnd, $windowTitle, $windowTitle.Capacity) | Out-Null

						if ($windowTitle.ToString() -eq $targetTitle) {
							return $hwnd
						}
					}
				}
				$hwnd = [WindowUtils]::GetWindow($hwnd, [WindowUtils]::GW_HWNDNEXT)
			}
		}

		"ToCoreWindow" {
			# Get CoreWindow from ApplicationFrameWindow

			# First try: Get direct child with CoreWindow class
			$childHwnd = [WindowUtils]::GetWindow($SourceHWnd, [WindowUtils]::GW_CHILD)
			while ($childHwnd -ne [IntPtr]::Zero) {
				$className = New-Object System.Text.StringBuilder 256
				[WindowUtils]::GetClassName($childHwnd, $className, $className.Capacity) | Out-Null
				if ($className.ToString() -eq "Windows.UI.Core.CoreWindow") {
					return $childHwnd
				}
				$childHwnd = [WindowUtils]::GetWindow($childHwnd, [WindowUtils]::GW_HWNDNEXT)
			}

			# Second try: Get ApplicationFrameWindow title and find matching CoreWindow
			$appFrameTitle = New-Object System.Text.StringBuilder 256
			[WindowUtils]::GetWindowText($SourceHWnd, $appFrameTitle, $appFrameTitle.Capacity) | Out-Null
			$targetTitle = $appFrameTitle.ToString()

			if ([string]::IsNullOrEmpty($targetTitle)) {
				return [IntPtr]::Zero
			}

			# Enumerate all CoreWindow instances and match by title
			$hwnd = [WindowUtils]::GetWindow([IntPtr]::Zero, [WindowUtils]::GW_HWNDFIRST)
			while ($hwnd -ne [IntPtr]::Zero) {
				if ([WindowUtils]::IsWindowVisible($hwnd)) {
					$className = New-Object System.Text.StringBuilder 256
					[WindowUtils]::GetClassName($hwnd, $className, $className.Capacity) | Out-Null

					if ($className.ToString() -eq "Windows.UI.Core.CoreWindow") {
						$windowTitle = New-Object System.Text.StringBuilder 256
						[WindowUtils]::GetWindowText($hwnd, $windowTitle, $windowTitle.Capacity) | Out-Null

						if ($windowTitle.ToString() -eq $targetTitle) {
							return $hwnd
						}
					}
				}
				$hwnd = [WindowUtils]::GetWindow($hwnd, [WindowUtils]::GW_HWNDNEXT)
			}
		}
	}

	return [IntPtr]::Zero
}

# ==================================================================================
# Function: Get-AllTopWindows
# ==================================================================================
function Get-AllTopWindows {
	# --- Enumerate all top-level windows ---
	if (-not (Test-TypeExists -TypeName "Win32")) {
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    // From first definition
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    // From second definition
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);
}
"@
	}

	$allWindows = New-Object System.Collections.ArrayList

	$callback = [Win32+EnumWindowsProc] {
		param($hWnd, $lParam)

		$wndPid = 0
		[Win32]::GetWindowThreadProcessId($hWnd, [ref]$wndPid) | Out-Null

		$sbTitle = New-Object System.Text.StringBuilder 512
		[Win32]::GetWindowText($hWnd, $sbTitle, $sbTitle.Capacity) | Out-Null
		$title = $sbTitle.ToString()

		$sbClass = New-Object System.Text.StringBuilder 256
		[Win32]::GetClassName($hWnd, $sbClass, $sbClass.Capacity) | Out-Null
		$class = $sbClass.ToString()

		$obj = [PSCustomObject]@{
			HWND      = [IntPtr] $hWnd
			PID       = $wndPid
			Title     = $title
			ClassName = $class
			Visible   = [Win32]::IsWindowVisible($hWnd)
		}

		$null = $allWindows.Add($obj)
		return $true
	}

	[Win32]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null

	return $allWindows
}

# ==================================================================================
# Function: Get-AppHwnd
# - Return Results mainly hwnd
# - Helper function to get window from Process Name or Process ID
# ==================================================================================
function Get-AppHwnd {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, ParameterSetName = "ProcessName")]
		[string]$ProcessName,
		[Parameter(Mandatory = $true, ParameterSetName = "ProcessId")]
		[int]$ProcessId,
		[Parameter(Mandatory = $false)]
		[switch]$DebugSwitch = $false
	)

	# Load UI Automation assemblies
	Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue
	Add-Type -AssemblyName UIAutomationTypes -ErrorAction SilentlyContinue

	$results = @()
	# use ProcessName
	if ($ProcessName) {
		$procs = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
		if (-not $procs) { Write-Warning "No process found with name: $ProcessName"; return }
	}
	# use ProcessId
	if ($ProcessId) {
		$procs = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
		if (-not $procs) { Write-Warning "No process found with PID: $ProcessId"; return }
	}

	$allWindows = Get-AllTopWindows

	# Case 1:  --- Main logic --- Process Win32
	foreach ($proc in $procs) {
		# --- Win32 apps ---
		if ($proc.MainWindowHandle -ne 0) {
			$results += [PSCustomObject]@{
				HWND     = [IntPtr] $proc.MainWindowHandle
				PID      = $proc.Id
				RealHWND = [IntPtr] $proc.MainWindowHandle
				RealPID  = $proc.Id
				Title    = $proc.MainWindowTitle
				Class    = "Win32 MainWindow"
				Method   = "Main"
			}
			return $results
		}

		# Case 2: --- UWP direct CoreWindow --- Process UWP exposed Windows.UI.Core.CoreWindow (found by enum)
		# This can change by interactions with the window and go 3rd case. Hard to detect but we cover both anyway
		$coreWindows = $allWindows | Where-Object { $_.PID -eq $proc.Id -and $_.ClassName -eq "Windows.UI.Core.CoreWindow" }
		foreach ($cw in $coreWindows) {
			$results += [PSCustomObject]@{
				HWND     = [IntPtr] $cw.HWND
				PID      = $cw.PID
				RealHWND = [IntPtr] $cw.HWND
				RealPID  = $cw.PID
				Title    = $cw.Title
				Class    = $cw.Class
				Method   = "Core"
			}
			# Returns at the first finding
			return $results
		}

		# Case 3: --- Hosted UWP (ApplicationFrameWindow) --- Process UWP with core window below the hosted window
		# This can change by interactions with the window and go 2nd case. Hard to detect but we cover both anyway
		$hostWindows = $allWindows | Where-Object { $_.ClassName -eq "ApplicationFrameWindow" }
		foreach ($hw in $hostWindows) {
			try {
				$ae = [System.Windows.Automation.AutomationElement]::FromHandle($hw.HWND)
				$core = $ae.FindFirst([System.Windows.Automation.TreeScope]::Subtree, [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id))
				if ($core) {
					$results += [PSCustomObject]@{
						HWND     = [IntPtr] $hw.HWND
						PID      = $hw.PID
						RealHWND = [IntPtr] $core.Current.NativeWindowHandle
						RealPID  = $proc.Id
						Title    = $hw.Title
						Class    = $hw.Class
						Method   = "Hosted"
					}
					# Returns at the first finding
					return $results
				}
			} catch {} # Silent
		}
	}

	if ($DebugSwitch -and $ProcessName) { Write-Warning "No windows found for process $ProcessName" }
	if ($DebugSwitch -and $ProcessId) { Write-Warning "No windows found for process with PID $ProcessId" }
	$results = [PSCustomObject]@{
		HWND     = [IntPtr]::Zero
		RealHWND = [IntPtr]::Zero
	}
	return $results
}

# ==================================================================================
# Get-HwndByAppUserModelId
# ==================================================================================
function Get-HwndByAppUserModelId {
	param(
		[Parameter(Mandatory = $true)]
		[string]$partAppId,
		[switch]$CaseSensitive = $false,
		[switch]$DebugSwitch = $false
	)

	# Compile the Windows API methods if not already compiled
	try {
		[UWPAppManager] | Out-Null
	} catch {
		# Compile the type if it doesn't exist
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

public static class UWPAppManager
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetApplicationUserModelId(IntPtr hProcess, ref uint applicationUserModelIdLength, StringBuilder applicationUserModelId);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public static List<UWPAppInfo> GetRunningUWPApps()
    {
        var results = new List<UWPAppInfo>();

        // Get all processes
        var processes = System.Diagnostics.Process.GetProcesses();

        foreach (var process in processes)
        {
            // Skip Idle processes and processes without a valid ID
            if (process.Id == 0 || process.ProcessName == "Idle")
                continue;

            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
                if (hProcess == IntPtr.Zero)
                    continue;

                try
                {
                    uint length = 256;
                    StringBuilder sb = new StringBuilder((int)length);
                    int result = GetApplicationUserModelId(hProcess, ref length, sb);

                    if (result == 0) // Success
                    {
                        results.Add(new UWPAppInfo
                        {
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            AppUserModelId = sb.ToString()
                        });
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch
            {
                // Ignore access denied errors
            }
        }

        return results;
    }
}

public class UWPAppInfo
{
    public string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public string AppUserModelId { get; set; }
    public string WindowTitle { get; set; }
}
"@ -ReferencedAssemblies @("System.Runtime.InteropServices")
	}

	$results = @()

	if ($DebugSwitch) { Write-Host "Searching for AppUserModelId pattern: $partAppId" -ForegroundColor Yellow }
	if (-not $CaseSensitive) {
		if ($DebugSwitch) { Write-Host "(Case-insensitive search)" -ForegroundColor Gray }
	}

	# Get all running UWP apps
	try {
		$uwpApps = [UWPAppManager]::GetRunningUWPApps()
	} catch {
		Write-Host "Error getting UWP apps: $($_.Exception.Message)" -ForegroundColor Red
		return [PSCustomObject]@{
			HWND     = [IntPtr]::Zero
			RealHWND = [IntPtr]::Zero
		}
	}

	# Filter by AppUserModelId pattern
	if ($CaseSensitive) {
		$matchingApps = $uwpApps | Where-Object { $_.AppUserModelId -clike "*$partAppId*" }
	} else {
		$matchingApps = $uwpApps | Where-Object { $_.AppUserModelId -like "*$partAppId*" }
	}

	if ($matchingApps.Count -eq 0) {
		Write-Host "No processes found with AppUserModelId containing: '$partAppId'" -ForegroundColor Yellow
		Write-Host "Available AppUserModelIds:" -ForegroundColor Gray
		$uwpApps | Select-Object -ExpandProperty AppUserModelId | Sort-Object | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
		return [PSCustomObject]@{
			HWND     = [IntPtr]::Zero
			RealHWND = [IntPtr]::Zero
		}
	}

	if ($DebugSwitch) { Write-Host "Found $($matchingApps.Count) matching process(es)" -ForegroundColor Green }


	foreach ($app in $matchingApps) {
		if ($DebugSwitch) { Write-Host "Processing: $($app.ProcessName) (PID: $($app.ProcessId))" -ForegroundColor Gray }

		# Call Get-AppHwnd function for each matching process
		$AppResult = Get-AppHwnd -ProcessId $app.ProcessId

		# Only add to results if we got a valid HWND
		if ($AppResult.HWND -ne [IntPtr]::Zero) {
			$results += [PSCustomObject]@{
				ProcessName    = $app.ProcessName
				ProcessId      = $app.ProcessId
				AppUserModelId = $app.AppUserModelId
				WindowTitle    = $AppResult.Title
				HWND           = [IntPtr] $AppResult.HWND
				RealHWND       = [IntPtr] $AppResult.RealHWND
			}
			Write-Host "Found app: $($AppResult.Title) , App Model Id: $($app.AppUserModelId) "
		} else {
			if ($DebugSwitch) { Write-Host "  No window found for $($app.ProcessName) PID: $($app.ProcessId)" -ForegroundColor Yellow }
		}
	}

	return $results
}