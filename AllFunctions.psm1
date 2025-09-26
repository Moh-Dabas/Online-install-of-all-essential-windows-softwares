# All functions Module

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



function Repeatiwr {
	param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$uri
	)
	for ($i = 1; $i -le 20; $i++) {
		try {
			$Response = Invoke-WebRequest -UseBasicParsing -Uri $uri
			# This will only execute if the Invoke-WebRequest is successful.
			$StatusCode = $Response.StatusCode
		} catch {
			# Write-Host -f C "StatusCode:" $_.Exception.Response.StatusCode.value__
			# Write-Host -f C "StatusDescription:" $_.Exception.Response.StatusDescription
			$StatusCode = $_.Exception.Response.StatusCode.value__
		}
		if ($StatusCode -eq "200") { break }
	}
	return $Response
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

function Get-WiFiAdapters {
	<#
    .SYNOPSIS
    Retrieves active Wi-Fi adapters.

    .DESCRIPTION
    This function finds all active (Status = 'Up') Wi-Fi adapters based on common naming patterns.

    .EXAMPLE
    $wifiAdapters = Get-WiFiAdapters

    .EXAMPLE
    if (Get-WiFiAdapters) {
        Write-Host "Wi-Fi adapters found"
    }
    #>


	param()

	# Import the NetAdapter module
	Import-Module NetAdapter -EA SilentlyContinue

	# Get active Wi-Fi adapters
	$wifiAdapters = Get-NetAdapter | Where-Object {
		$_.Status -eq 'Up' -and (
			$_.InterfaceDescription -like "*Wi-Fi*" -or
			$_.Name -like "*Wi-Fi*" -or
			$_.InterfaceDescription -like "*Wireless*" -or
			$_.Name -like "*WLAN*"
		)
	}

	if (-not $wifiAdapters) {
		Write-Verbose "No active Wi-Fi adapter found."
		return $null
	}

	return $wifiAdapters
}

function Restart-WiFiAdapters {
	<#
    .SYNOPSIS
    Restarts Wi-Fi adapters and waits for them to fully restart.

    .DESCRIPTION
    This function finds all Wi-Fi adapters, restarts them, and waits for them to come back online.
    It provides detailed output about the status of each adapter restart operation.

    .PARAMETER Timeout
    Maximum time in seconds to wait for each adapter to restart (default: 30 seconds)

    .PARAMETER Parallel
    Switch to restart adapters in parallel instead of sequentially

    .EXAMPLE
    Restart-WiFiAdapters

    .EXAMPLE
    Restart-WiFiAdapters -Timeout 45 -Parallel
    #>


	param(
		[int]$Timeout = 60,
		[switch]$Parallel
	)

	# Get Wi-Fi adapters
	$wifiAdapters = Get-WiFiAdapters

	if (-not $wifiAdapters) {
		Write-Output "No active Wi-Fi adapter found."
		return
	}

	Write-Host "Found $($wifiAdapters.Count) Wi-Fi adapter(s)" -ForegroundColor Cyan

	if ($Parallel) {
		# Parallel execution using jobs
		$jobs = $wifiAdapters | ForEach-Object {
			$adapter = $_
			Start-Job -Name $adapter.Name {
				param($AdapterName, $Timeout)

				# Import the NetAdapter module
				Import-Module NetAdapter -EA SilentlyContinue

				try {
					# Restart the adapter
					Restart-NetAdapter -Name $AdapterName -Confirm:$false -EA SilentlyContinue

					# Wait for it to come back online
					$startTime = Get-Date
					$success = $false

					while (((Get-Date) - $startTime).TotalSeconds -lt $Timeout) {
						$adapter = Get-NetAdapter -Name $AdapterName -EA SilentlyContinue
						if ($adapter -and $adapter.Status -eq 'Up') {
							$success = $true
							break
						}
						Start-Sleep -Seconds 1
					}

					return @{
						Name    = $AdapterName
						Success = $success
						Error   = $null
					}
				} catch {
					return @{
						Name    = $AdapterName
						Success = $false
						Error   = $_.Exception.Message
					}
				}
			} -ArgumentList $adapter.Name, $Timeout
		}

		# Wait for all jobs with timeout
		$null = $jobs | Wait-Job -Timeout ($Timeout)  # Wait job timeout

		# Get results
		$results = $jobs | Receive-Job

		# Display results
		foreach ($result in $results) {
			if ($result.Success) {
				Write-Host "$($result.Name): Restarted successfully" -ForegroundColor Green
			} else {
				$errorMsg = if ($result.Error) { ": $($result.Error)" } else { " within timeout" }
				Write-Warning "$($result.Name): Failed to restart$errorMsg"
			}
		}

		# Cleanup
		$jobs | Remove-Job -Force
	} else {
		# Sequential execution (default)
		foreach ($adapter in $wifiAdapters) {
			Write-Host "Restarting adapter: $($adapter.Name)" -ForegroundColor Yellow

			try {
				# Restart the adapter
				Restart-NetAdapter -Name $adapter.Name -Confirm:$false -EA SilentlyContinue

				# Wait for the adapter to disappear (go down)
				$downStart = Get-Date
				while ((Get-NetAdapter -Name $adapter.Name -EA SilentlyContinue) -and
				(((Get-Date) - $downStart).TotalSeconds -lt 5)) {
					Start-Sleep -Milliseconds 100
				}

				# Wait for the adapter to reappear (come back up)
				$startTime = Get-Date
				$adapterRestarted = $false

				while (((Get-Date) - $startTime).TotalSeconds -lt $Timeout) {
					$currentAdapter = Get-NetAdapter -Name $adapter.Name -EA SilentlyContinue
					if ($currentAdapter -and $currentAdapter.Status -eq 'Up') {
						$adapterRestarted = $true
						Write-Host "Adapter $($adapter.Name) is back online" -ForegroundColor Green
						break
					}
					Start-Sleep -Seconds 1
				}

				if (-not $adapterRestarted) {
					Write-Warning "Timeout waiting for adapter $($adapter.Name) to restart"
				}
			} catch {
				Write-Error "Failed to restart adapter $($adapter.Name): $($_.Exception.Message)"
			}
		}
	}

	Write-Host "Wi-Fi adapter restart process completed" -ForegroundColor Cyan
}

function Fix-InternetConnection {
	Write-Host -f C "`r`n*** Trying to fix Internet connection ***`r`n"
	ipconfig /release
	ipconfig /flushdns
	Clear-DnsClientCache
	ipconfig /renew
	netsh int ip reset
	netsh winsock reset
	arp -d *
	netsh interface ip delete arpcache
	#Tls all
	Write-Host -f C "`r`n*** Fixing Tls ***`r`n"
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
	Write-Host -f C "`r`n*** Disabling proxies ***`r`n"
	set HTTP_PROXY=
	set HTTPS_PROXY=
}

function Invoke-WiFiScan {
	param([string]$InterfaceName)

	$wlanApi =
	@"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class WlanApi
{
    [DllImport("wlanapi.dll", SetLastError=true)]
    public static extern int WlanOpenHandle(
        uint dwClientVersion,
        IntPtr pReserved,
        out uint pdwNegotiatedVersion,
        out IntPtr phClientHandle);

    [DllImport("wlanapi.dll", SetLastError=true)]
    public static extern int WlanCloseHandle(
        IntPtr hClientHandle,
        IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError=true)]
    public static extern int WlanEnumInterfaces(
        IntPtr hClientHandle,
        IntPtr pReserved,
        out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll", SetLastError=true)]
    public static extern int WlanScan(
        IntPtr hClientHandle,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        IntPtr pIeData,
        IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError=true)]
    public static extern int WlanGetAvailableNetworkList(
        IntPtr hClientHandle,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pInterfaceGuid,
        uint dwFlags,
        IntPtr pReserved,
        out IntPtr ppAvailableNetworkList);

    [DllImport("wlanapi.dll", SetLastError=true)]
    public static extern void WlanFreeMemory(IntPtr pMemory);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)]
        public string strInterfaceDescription;
        public int isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_INTERFACE_INFO_LIST
    {
        public int dwNumberOfItems;
        public int dwIndex;
        // followed by WLAN_INTERFACE_INFO[dwNumberOfItems]
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DOT11_SSID
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=32)]
        public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct WLAN_AVAILABLE_NETWORK
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)]
        public string strProfileName;
        public DOT11_SSID dot11Ssid;
        public int dot11BssType;
        public uint uNumberOfBssids;
        public bool bNetworkConnectable;
        public uint wlanNotConnectableReason;
        public uint uNumberOfPhyTypes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)]
        public uint[] dot11PhyTypes;
        public bool bMorePhyTypes;
        public uint wlanSignalQuality; // 0â€“100
        public bool bSecurityEnabled;
        public uint dot11DefaultAuthAlgorithm;
        public uint dot11DefaultCipherAlgorithm;
        public uint dwFlags;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_AVAILABLE_NETWORK_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        // followed by WLAN_AVAILABLE_NETWORK[dwNumberOfItems]
    }
}
"@

	Add-Type -TypeDefinition $wlanApi -PassThru | Out-Null

	$client = [IntPtr]::Zero
	$ver = 0
	$result = [WlanApi]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$client)
	if ($result -ne 0) { throw "WlanOpenHandle failed: $result" }

	try {
		# Get interfaces
		$ifListPtr = [IntPtr]::Zero
		$result = [WlanApi]::WlanEnumInterfaces($client, [IntPtr]::Zero, [ref]$ifListPtr)
		if ($result -ne 0) { throw "WlanEnumInterfaces failed: $result" }

		$ifList = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ifListPtr, [type][WlanApi+WLAN_INTERFACE_INFO_LIST])
		$base = $ifListPtr.ToInt64() + 8

		$sizeInterface = [System.Runtime.InteropServices.Marshal]::SizeOf([type][WlanApi+WLAN_INTERFACE_INFO])
		$foundGuid = [guid]::Empty

		for ($i = 0; $i -lt $ifList.dwNumberOfItems; $i++) {
			$pItem = [IntPtr]($base + ($i * $sizeInterface))
			$info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pItem, [type][WlanApi+WLAN_INTERFACE_INFO])
			if (-not $InterfaceName -or $info.strInterfaceDescription -eq $InterfaceName) {
				$foundGuid = $info.InterfaceGuid
				break
			}
		}
		[WlanApi]::WlanFreeMemory($ifListPtr)

		if ($foundGuid -eq [guid]::Empty) { throw "Interface not found" }

		# Trigger scan
		[void][WlanApi]::WlanScan($client, $foundGuid, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
		Start-Sleep -Seconds 3

		# Get results
		$netPtr = [IntPtr]::Zero
		$result = [WlanApi]::WlanGetAvailableNetworkList($client, $foundGuid, 0, [IntPtr]::Zero, [ref]$netPtr)
		if ($result -ne 0) { throw "WlanGetAvailableNetworkList failed: $result" }

		$list = [System.Runtime.InteropServices.Marshal]::PtrToStructure($netPtr, [type][WlanApi+WLAN_AVAILABLE_NETWORK_LIST])
		$base = $netPtr.ToInt64() + 8
		$sizeAvail = [System.Runtime.InteropServices.Marshal]::SizeOf([type][WlanApi+WLAN_AVAILABLE_NETWORK])

		$out = @()
		for ($i = 0; $i -lt $list.dwNumberOfItems; $i++) {
			$ptr = [IntPtr]($base + $i * $sizeAvail)
			$n = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][WlanApi+WLAN_AVAILABLE_NETWORK])
			$ssid = ""
			if ($n.dot11Ssid.uSSIDLength -gt 0) {
				$ssid = [System.Text.Encoding]::ASCII.GetString($n.dot11Ssid.ucSSID, 0, [int]$n.dot11Ssid.uSSIDLength)
			}
			$out += [pscustomobject]@{
				SSID    = $ssid
				Signal  = $n.wlanSignalQuality
				Secure  = $n.bSecurityEnabled
				Profile = $n.strProfileName
			}
		}
		[WlanApi]::WlanFreeMemory($netPtr)

		return $out
	} finally { [WlanApi]::WlanCloseHandle($client, [IntPtr]::Zero) | Out-Null }
}

function Restart-WlanService {

	param(
		[int]$Timeout = 60,
		[int]$PostStartDelay = 5
	)

	try {
		# Restart the service
		Restart-Service -Name wlansvc -Force -EA SilentlyContinue

		# Wait for service to reach running state with timeout
		$service = Get-Service -Name wlansvc
		$startTime = Get-Date
		while ($service.Status -ne 'Running') {
			if (((Get-Date) - $startTime).TotalSeconds -gt $Timeout) { throw "Timed out waiting for wlansvc to start after $Timeout seconds" }

			Write-Host "Waiting for wlansvc to start... (Current: $($service.Status))"
			Start-Sleep -Seconds 1
			$service.Refresh()
		}

		# Additional grace period for service initialization
		Write-Host "Service started. Waiting additional $PostStartDelay seconds for initialization..."
		Start-Sleep -Seconds $PostStartDelay

		Write-Host "wlansvc is fully initialized. Proceeding with network scan..."
		return
	} catch {
		Write-Error "Failed to restart wlansvc: $_"
		return
	}
}

function Set-WiFiAutoConnect {
	<#
    .SYNOPSIS
    Sets all saved Wi-Fi profiles to auto-connect mode.

    .DESCRIPTION
    This function configures all saved Wi-Fi profiles to automatically connect
    when the network is available. Requires administrative privileges.

    .EXAMPLE
    Set-WiFiAutoConnect

    .NOTES
    Requires running PowerShell as Administrator
    #>

	try {
		# Get all Saved Wi-Fi profiles
		$WiFiprofiles = (netsh wlan show profiles) | Where-Object { $_ -match "All User Profile" } | ForEach-Object { $_.Split(":")[1].Trim() }
		if (-not $WiFiprofiles) { Write-Host "No Wi-Fi profiles found." -F Yellow; return }

		# Set each profile to auto-connect
		foreach ($WiFiprofile in $WiFiprofiles) {
			Write-Host -f DarkBlue "Set $WiFiprofile to auto-connect"
			netsh wlan set profileparameter name="$WiFiprofile" connectionmode=auto
		}
		Write-Host "All Wi-Fi profiles have been set to auto-connect." -ForegroundColor Green
	} catch { Write-Error "An error occurred: $_" }
}

function WifiPriority {

	# Get all Saved Wi-Fi profiles
	$WiFiprofiles = (netsh wlan show profiles) | Where-Object { $_ -match "All User Profile" } | ForEach-Object { $_.Split(":")[1].Trim() }
	if (-not $WiFiprofiles) { Write-Host "No Wi-Fi profiles found." -F Yellow; return }
	Set-WiFiAutoConnect

	# Get active Wi-Fi adapters
	$wifiAdapters = Get-WiFiAdapters
	if (-not $wifiAdapters) {
		Write-Output "No active Wi-Fi adapter found."
		return
	}

	# if not currently connected to WiFi network return
	$currentState = netsh wlan show interfaces | Select-String '^\s*State\s*:\s*(.+)$' | ForEach-Object { ($_ -split ":\s*", 2)[1].Trim() } | Select-Object -First 1
	if ($currentState -ne "connected") { Write-Output "Not connected to a WiFi network."; return }
	# Get current wifi Adapter
	$currentInterface = (Get-NetConnectionProfile).InterfaceAlias
	# Get current SSID
	$currentSSID = netsh wlan show interfaces | Select-String '^\s*SSID\s*:\s*(.+)$' | ForEach-Object { ($_ -split ":\s*", 2)[1].Trim() } | Select-Object -First 1
	# Check if currently connected SSID is already 5GHz
	$currentBand = netsh wlan show interfaces | Select-String '^\s*Band\s*:\s*(.+)$' | ForEach-Object { ($_ -split ":\s*", 2)[1].Trim() } | Select-Object -First 1
	if ($currentBand -match '5 GHz') {
		Write-Output "Already connected to 5GHz network: $currentSSID"
		$currentProfile = $WiFiprofiles | Where-Object { $_ -eq $currentSSID }
		if ($currentProfile) {
			Write-Host "Setting $currentProfile priority to 1"
			netsh wlan set profileorder name="$currentProfile" interface="$currentInterface" priority=1
			netsh wlan set profileparameter name="$currentProfile" connectionmode=auto
		} else { Write-Output "Failed to get the Current Network saved profile."; return }
	}

	Write-Host "Restarting WiFi interfaces & WLAN AutoConfig service (wlansvc)..."
	Restart-WiFiAdapters -Timeout 60 -Parallel:$true
	Restart-WlanService -Timeout 60 -PostStartDelay 5

	$SSIDs = Invoke-WiFiScan
	$SSIDs = $SSIDs | Sort-Object Signal -Descending | Format-Table -Property SSID, Signal, Profile -AutoSize -Wrap
	$SSIDs += ([Environment]::NewLine)
	$SSIDs

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

	$fiveGhzProfiles = $WiFiprofiles | Where-Object { $fiveGhzSSIDs -contains $_ }
	if (-not $fiveGhzProfiles) {
		Write-Output "No matching saved 5GHz profiles found."
		return
	} elseif ($currentProfile) {
		$fiveGhzProfiles = $fiveGhzProfiles | Where-Object { $_ -ne $currentProfile }
		$priority = 2
	} else { $priority = 1 }

	foreach ($fiveGhzProfile in $fiveGhzProfiles) {
		netsh wlan set profileorder name="$fiveGhzProfile" interface="$currentInterface" priority=$priority
		netsh wlan set profileparameter name="$fiveGhzProfile" connectionmode=auto
		$priority++
	}

	# Get all saved Wi-Fi profile names
	$profileNames = (netsh wlan show profiles) | Where-Object { $_ -match "All User Profile" } | ForEach-Object { $_.Split(":")[1].Trim() }
	# Get priority for each profile by checking the automatic connection order
	Write-Host "Wi-Fi Profiles and Their Connection Priority:" -ForegroundColor Green
	Write-Host "---------------------------------------------"
	$priority = 1
	foreach ($name in $profileNames) {
		Write-Host "$priority. $name" -ForegroundColor Cyan
		$priority++
	}
	Write-Host "---------------------------------------------"
	Write-Host "Wireless profiles are prioritized successfully `n" -ForegroundColor Green

	$TopProfile = $profileNames |  Select-Object -First 1
	netsh wlan connect name=$TopProfile
	Check-Internet
}

function Invoke-W32TimeResync {
	param(
		[int]$MaxRetries = 10,
		[int]$DelaySeconds = 1
	)

	# Ensure required registry settings
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type' 'NTP' 'String' # Autoupdate time
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'Allow' 'String' # Allow location
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' 'Start' '3' 'DWord' # Autoupdate timezone

	# Start services if not running
	Start-Service -Name "W32Time" -EA SilentlyContinue | Out-Null
	Start-Service -Name "tzautoupdate" -EA SilentlyContinue | Out-Null

	$success = $false

	for ($attempt = 1; $attempt -le $MaxRetries -and -not $success; $attempt++) {
		Write-Host "Attempt $attempt of ${MaxRetries}: Running w32tm /resync to sync time"

		# Run and capture both output & exit code
		$output = & w32tm /resync 2>&1
		$exitCode = $LASTEXITCODE

		if ($exitCode -eq 0 -and $output -match "completed successfully") {
			Write-Host "Sync time success on attempt $attempt."
			$success = $true
		} else {
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

function InitializeCommands {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Initializing *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	if (Check-Internet) {
		Write-Host "Removing old PSReadLine module"
		Get-Module PSReadLine -ListAvailable | ForEach-Object { Uninstall-Module -Name PSReadLine -RequiredVersion $_.Version -Force }
		Write-Host "Installing latest version of PSReadLine..."
		Install-Module -Name PSReadLine -Force -AllowClobber -Scope AllUsers
	}
	Import-Module PSReadLine
	Disable-DefenderRealtimeProtection
	#UAC
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' '1' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ValidateAdminCodeSignatures' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' '0' 'DWord'
	# IFEO Block Smart Screen
	Set-EmptyIFEO -TargetExe 'smartscreen.exe'
	Fix-InternetConnection
	WifiPriority
	Invoke-W32TimeResync
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\BITS' 'Start' '2' 'DWord'
	Start-Job -Name BITS { Start-Service -Name 'BITS' -EA SilentlyContinue | Out-Null } # Service needed for fast download
	New-Item -Path "$env:TEMP\IA" -ItemType Directory -EA SilentlyContinue | Out-Null
}

function Set-Hibernate {
	# Control Hibernate Default = 'Off' ,'Boot' ,'Full'
	param
	(
		[Parameter(Mandatory = $false, Position = 0)]
		[string]$Status = 'Off'
	)
	if ($Status -eq 'Full') {
		# Enable hibernate full
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '1' 'DWord'
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '1' 'DWord'
		powercfg hibernate size 0 | Out-Null
		powercfg /h /type full | Out-Null
		powercfg.exe /hibernate on | Out-Null
		# Enable hibernate button
		Add-RegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '1' 'DWord'
		# Enable HyperBoot
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
	} elseif ($Status -eq 'Boot') {
		# Enable hibernate Boot
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '1' 'DWord'
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '1' 'DWord'
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
		powercfg hibernate size 0 | Out-Null
		powercfg /h /type reduced | Out-Null
		powercfg.exe /hibernate on | Out-Null
		# Disable hibernate button
		Add-RegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '0' 'DWord'
		# Enable HyperBoot
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '1' 'DWord'
	} else {
		# Disable hibernate to avoid it's issues
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' '0' 'DWord'
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabledDefault' '0' 'DWord'
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '0' 'DWord'
		powercfg hibernate size 0 | Out-Null
		powercfg.exe /hibernate off | Out-Null
		# Disable hibernate button
		Add-RegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowHibernateOption' '0' 'DWord'
		# Disabling HyperBoot to avoid it's issues
		Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' '0' 'DWord'
	}
}

function MaxPowerPlan {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Activating Max Performance Power Plan *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	# scheme_GUID
	# High Performance Power Plan GUID '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' - Aliase: scheme_min
	$MaxPlanGUID = '11111111-1111-1111-1111-111111111111'
	# Activate High
	powercfg /SetActive 'scheme_min' | Out-Null
	# Deleting old plan
	powercfg /delete $MaxPlanGUID | Out-Null
	# Duplicate High performance power plan to new plan
	powercfg /duplicatescheme 'scheme_min' $MaxPlanGUID | Out-Null
	powercfg /changename $MaxPlanGUID "Max Performance" "Custom Plan for maximum performace" | Out-Null
	########################### Processor management sub_GUID '54533251-82be-4824-96c1-47b60b740d00' - Alias: SUB_PROCESSOR ####################################
	# ******************* Disable Core Parking ******************* Important
	# Specify the minimum number of unparked cores allowed (in percentage) # setting_GUID: '0cc5b647-c1df-4637-891a-dec35c318583' - Alias: CPMINCORES # Must be set to 100%
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'CPMINCORES' '0x00000064' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'CPMINCORES' '0x00000064' | Out-Null
	# Minimum percentage of processor capabilities to use (Minimum processor state)(in percentage) # setting_GUID: '893dee8e-2bef-41e0-89c6-b55d0929964c' - Alias: PROCTHROTTLEMIN # Must be set to 100%
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PROCTHROTTLEMIN' '0x00000064' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PROCTHROTTLEMIN' '0x00000064' | Out-Null
	# Specify the algorithm used to select a new performance state when the ideal performance state is higher than the current performace state (Processor performance increase policy) # setting_GUID: '465e1f50-b610-473a-ab58-00d1077dc418' - Alias: PERFINCPOL # 2 Rocket
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFINCPOL' '0x00000002' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFINCPOL' '0x00000002' | Out-Null
	# Specify how processors select a target frequency when allowed to select above maximum frequency by current operating conditions (Processor performance boost mode) # setting_GUID: 'be337238-0d82-4146-a960-4f3749d470c7' - Alias: PERFBOOSTMODE # 2 Aggressive
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFBOOSTMODE' '0x00000002' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'PERFBOOSTMODE' '0x00000002' | Out-Null
	# Specify the cooling mode for your system (System cooling policy) # setting_GUID: '94D3A615-A899-4AC5-AE2B-E4D8F634367F' - Alias: SYSCOOLPOL # 1 Active
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'SYSCOOLPOL' '0x00000001' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'SYSCOOLPOL' '0x00000001' | Out-Null
	# Allow processors to use throttle states # setting_GUID: '3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb' - Alias: THROTTLING # 0 Off
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'THROTTLING' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PROCESSOR' 'THROTTLING' '0x00000000' | Out-Null
	########################### No subgroup sub_GUID 'fea3413e-7e05-4911-9a71-700331f1c294' - Alias: SUB_NONE ####################################
	# Power Scheme Personality # setting_GUID:'245d8541-3943-4422-b025-13a784f679b7' - Alias: PERSONALITY # High Performance
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_NONE' 'PERSONALITY' '0x00000001' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_NONE' 'PERSONALITY' '0x00000001' | Out-Null
	# Specifies the policy for devices powering down while the system is running # setting_GUID: '4faab71a-92e5-4726-b531-224559672d19' - Alias: DEVICEIDLE #0 Performance ,1 Power savings
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_NONE' 'DEVICEIDLE' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_NONE' 'DEVICEIDLE' '0x00000000' | Out-Null
	# Require a password on wakeup # setting_GUID: '0e796bdb-100d-47d6-a2d5-f7d2daa51f51' - Alias: CONSOLELOCK #0 No ,1 Yes
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_NONE' 'CONSOLELOCK' '0x00000001' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_NONE' 'CONSOLELOCK' '0x00000001' | Out-Null
	########################### Hard disc management sub_GUID: '0012ee47-9041-4b5d-9b77-535fba8b1442' - Alias: SUB_DISK ####################################
	# The harddisk may power down after the specified time of inactivity is detected. (Turn off hard disc after) # setting_GUID: '6738e2c4-e8a5-4a42-b16a-e040e769756e' - Alias: DISKIDLE # Seconds - Never
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_DISK' 'DISKIDLE' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_DISK' 'DISKIDLE' '0x00000000' | Out-Null
	########################### Sleep management sub_GUID: '238c9fa8-0aad-41ed-83f4-97be242c8f20' - Alias: SUB_SLEEP ####################################
	# System idle timeout before the system enters a low power standby state. (sleep after) # setting_GUID: '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' - Alias: STANDBYIDLE # Seconds - Never
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_SLEEP' 'STANDBYIDLE' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_SLEEP' 'STANDBYIDLE' '0x00000000' | Out-Null
	# System idle timeout before the system enters a low power hibernation state (hibernate after) # setting_GUID: '9d7815a6-7ee4-497e-8888-515a05f02364' - Alias: HIBERNATEIDLE # Seconds - Never
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_SLEEP' 'HIBERNATEIDLE' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_SLEEP' 'HIBERNATEIDLE' '0x00000000' | Out-Null
	# Unattended Sleep Timeout # setting_GUID: '7bc4a2f9-d8fc-4469-b07b-33eb785aaca0' - Alias: UNATTENDSLEEP # Seconds - Never
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_SLEEP' 'UNATTENDSLEEP' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_SLEEP' 'UNATTENDSLEEP' '0x00000000' | Out-Null
	########################### Display management sub_GUID: '7516b95f-f776-4464-8c53-06167f40cc99' - Alias: SUB_VIDEO ####################################
	# Specifies Console lock display off timeout # setting_GUID: '8EC4B3A5-6868-48c2-BE75-4F3044BE88A7' - Alias: VIDEOCONLOCK # Seconds - Never
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOCONLOCK' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOCONLOCK' '0x00000000' | Out-Null
	# Specify how long your computer is inactive before your display turns off (Turn off display after) # setting_GUID: '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' - Alias: VIDEOIDLE # Seconds - Never
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOIDLE' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEOIDLE' '0x00000000' | Out-Null
	# Display brightness (in percentage) # setting_GUID: 'aded5e82-b909-4619-9949-f5d71dac0bcb' - Alias: VIDEONORMALLEVEL # 100%
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEONORMALLEVEL' '0x00000064' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_VIDEO' 'VIDEONORMALLEVEL' '0x00000064' | Out-Null
	########################### Power buttons and lid management sub_GUID: '4f971e89-eebd-4455-a8de-9e59040e7347' - Alias: SUB_BUTTONS ####################################
	# Enable forced shutdown for button and lid actions # setting_GUID: '833a6b62-dfa4-46d1-82f8-e09e34d029d6' - Alias: SHUTDOWN #0 off ,1 on
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'SHUTDOWN' '0x00000001' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'SHUTDOWN' '0x00000001' | Out-Null
	# Lid close action # setting_GUID: '5ca83367-6e45-459f-a27b-476b1d01c936' - Alias: LIDACTION # 0 Do nothing
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'LIDACTION' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'LIDACTION' '0x00000000' | Out-Null
	# Power button action # setting_GUID: '7648efa3-dd9c-4e3e-b566-50f929386280' - Alias: PBUTTONACTION # 3 Shutdown
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'PBUTTONACTION' '0x00000003' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'PBUTTONACTION' '0x00000003' | Out-Null
	# Start menu power button action # setting_GUID: 'a7066653-8d6c-40a8-910e-a1f54b84c7e5' - Alias: UIBUTTON_ACTION # 2 Shutdown
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'UIBUTTON_ACTION' '0x00000002' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BUTTONS' 'UIBUTTON_ACTION' '0x00000002' | Out-Null
	########################### PCI Express sub_GUID: '501a4d13-42af-4429-9fd1-a8218c268e20' - Alias: SUB_PCIEXPRESS ####################################
	# Link State Power Management # setting_GUID: 'ee12f906-d277-404b-b6da-e5fa1a576df5' - Alias: ASPM # 0 Off
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_PCIEXPRESS' 'ASPM' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_PCIEXPRESS' 'ASPM' '0x00000000' | Out-Null
	########################### Multimedia management sub_GUID: '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' ####################################
	# Specify the policy to bias video playback quality & performance # setting_GUID: '10778347-1370-4ee0-8bbd-33bdacaade49' # 1 Video playback performance and quality bias
	powercfg /setacvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '10778347-1370-4ee0-8bbd-33bdacaade49' '0x00000001' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '10778347-1370-4ee0-8bbd-33bdacaade49' '0x00000001' | Out-Null
	# When playing video # setting_GUID: '10778347-1370-4ee0-8bbd-33bdacaade49' # 0 Optimize video quality
	powercfg /setacvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' '34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4' '0x00000000' | Out-Null
	########################### Battery management sub_GUID: 'e73a048d-bf27-4f12-9731-8b2076e8891f' - Alias: SUB_BATTERY ####################################
	# Critical battery action # setting_GUID: '637ea02f-bbcb-4015-8e2c-a1c7b9c0b546' - Alias: BATACTIONCRIT # 2 Hibernate
	powercfg /setacvalueindex $MaxPlanGUID 'SUB_BATTERY' 'BATACTIONCRIT' '0x00000002' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID 'SUB_BATTERY' 'BATACTIONCRIT' '0x00000002' | Out-Null
	################################################################### Other ####################################################################
	# Desktop background slide show # sub_GUID: '0d7dbae2-4294-402a-ba8e-26777e8488cd' # setting_GUID: '309dce9b-bef4-4119-9921-a851fb12f0f4' # 1 Paused
	powercfg /setacvalueindex $MaxPlanGUID '0d7dbae2-4294-402a-ba8e-26777e8488cd' '309dce9b-bef4-4119-9921-a851fb12f0f4' '0x00000001' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID '0d7dbae2-4294-402a-ba8e-26777e8488cd' '309dce9b-bef4-4119-9921-a851fb12f0f4' '0x00000001' | Out-Null
	# Wireless adapter power saving mode # sub_GUID: '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' # setting_GUID: '12bbebe6-58d6-4636-95bb-3217ef867c1a' # 0 Maximum performance
	powercfg /setacvalueindex $MaxPlanGUID '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' '12bbebe6-58d6-4636-95bb-3217ef867c1a' '0x00000000' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' '12bbebe6-58d6-4636-95bb-3217ef867c1a' '0x00000000' | Out-Null
	# intel(r) graphics power plan # sub_GUID: '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' # setting_GUID: '3619c3f2-afb2-4afc-b0e9-e7fef372de36' # 2 Maximum performance
	powercfg /setacvalueindex $MaxPlanGUID '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' '3619c3f2-afb2-4afc-b0e9-e7fef372de36' '0x00000002' | Out-Null
	powercfg /setdcvalueindex $MaxPlanGUID '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' '3619c3f2-afb2-4afc-b0e9-e7fef372de36' '0x00000002' | Out-Null
	# AMD power slider overlay # sub_GUID: 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' # setting_GUID: '7ec1751b-60ed-4588-afb5-9819d3d77d90' # 3 Best performance
	if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\c763b4ec-0e50-4b6b-9bed-2b92a6ee884e\7ec1751b-60ed-4588-afb5-9819d3d77d90' -EA SilentlyContinue) {
		powercfg /setacvalueindex $MaxPlanGUID 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' '7ec1751b-60ed-4588-afb5-9819d3d77d90' '0x00000003' | Out-Null
		powercfg /setdcvalueindex $MaxPlanGUID 'c763b4ec-0e50-4b6b-9bed-2b92a6ee884e' '7ec1751b-60ed-4588-afb5-9819d3d77d90' '0x00000003' | Out-Null
	}
	# ATI graphics powerplay settings # sub_GUID: 'f693fb01-e858-4f00-b20f-f30e12ac06d6' # setting_GUID: '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' # 1 Best performance
	if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\f693fb01-e858-4f00-b20f-f30e12ac06d6\191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' -EA SilentlyContinue) {
		powercfg /setacvalueindex $MaxPlanGUID 'f693fb01-e858-4f00-b20f-f30e12ac06d6' '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' '0x00000001' | Out-Null
		powercfg /setdcvalueindex $MaxPlanGUID 'f693fb01-e858-4f00-b20f-f30e12ac06d6' '191f65b5-d45c-4a4f-8aae-1ab8bfd980e6' '0x00000001' | Out-Null
	}
	# Switchable dynamic graphics global settings # sub_GUID: 'e276e160-7cb0-43c6-b20b-73f5dce39954' # setting_GUID: 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' # 3 Maximize performance
	if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\11111111-1111-1111-1111-111111111111\e276e160-7cb0-43c6-b20b-73f5dce39954\a1662ab2-9d34-4e53-ba8b-2639b9e20857' -EA SilentlyContinue) {
		powercfg /setacvalueindex $MaxPlanGUID 'e276e160-7cb0-43c6-b20b-73f5dce39954' 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' '0x00000003' | Out-Null
		powercfg /setdcvalueindex $MaxPlanGUID 'e276e160-7cb0-43c6-b20b-73f5dce39954' 'a1662ab2-9d34-4e53-ba8b-2639b9e20857' '0x00000003' | Out-Null
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
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff' '1' 'DWord'
	# System responsiveness
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'SystemResponsiveness' '0' 'DWord'
	# Enable lock button
	Add-RegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowLockOption' '1' 'DWord'
	# Enable Sleep button
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' 'ShowSleepOption' '1' 'DWord'
	powercfg /SetActive $MaxPlanGUID | Out-Null
	powercfg /SetActive $MaxPlanGUID | Out-Null
	# Set Hibernate Off
	Set-Hibernate 'Off'
}

function Ins-WindowsFeatures {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** 📥 Installing Windows Features using DISM *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	Write-Host -f C "`r`n*** 📥 Installing .NetFX3 ***`r`n"
	$St1 = dism /online /get-featureinfo /featurename:NetFx3 | Select-String State | ForEach-Object { $_.ToString().split(':')[1] -replace '\s', '' }
	if ($St1 -ne "Enabled" ) { DISM /Online /Enable-Feature /FeatureName:NetFx3 /NoRestart } else { Write-Host -f C "Already Installed" }
	Write-Host -f C "`r`n*** 📥 Installing DirectPlay ***`r`n"
	$St2 = dism /online /get-featureinfo /featurename:DirectPlay | Select-String State | ForEach-Object { $_.ToString().split(':')[1] -replace '\s', '' }
	if ($St2 -ne "Enabled" ) { DISM /Online /Enable-Feature /FeatureName:DirectPlay /All /NoRestart } else { Write-Host -f C "Already Installed" }
}

function Ins-Nuget {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** 📥 Installing Nuget provider *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	# Nuget PackageProvider
	if ((Get-PackageProvider -Name NuGet -ListAvailable -EA SilentlyContinue | select -ExpandProperty Name -First 1) -eq "NuGet") {
		Write-Host -f C "Nuget PackageProvider already exists"
	} else { Start-Job -Name PackageProviderNuGet { Install-PackageProvider -Name NuGet -Confirm:$False -Scope AllUsers -Force -EA SilentlyContinue | Out-Null } | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name, State; if (Get-PackageProvider -Name NuGet -EA SilentlyContinue) { Write-Host -f C "Successfully Installed" } }
	Import-PackageProvider -Name NuGet -Force -EA SilentlyContinue | Out-Null
	# NuGet Module
	if ((Get-Module -Name NuGet -ListAvailable -EA SilentlyContinue | select -ExpandProperty Name -First 1) -eq "NuGet") {
		Write-Host -f C "Nuget Module already exists"
	} else { Start-Job -Name ModuleNuGet { Install-Module -Name NuGet -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -EA SilentlyContinue | Out-Null } | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name, State }
	Import-Module NuGet -Force -EA SilentlyContinue | Out-Null
}

function Ins-Choco {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** 📥 Installing Chocolatey *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	# Ensure Chocolatey is installed
	if (-not (Get-Command choco -EA SilentlyContinue)) {
		Write-Host "Chocolatey not found. 📥 Installing..." -ForegroundColor Yellow
		Set-ExecutionPolicy Bypass -Scope Process -Force;
		iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
	}
	try { $ChocoInstalled = Get-Command -Name choco -EA SilentlyContinue } catch {}
	if ($ChocoInstalled) {
		Write-Host "Choco is already installed"
	} else {
		iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
		Start-Sleep -Seconds 1
		Relaunch
	}
	# Set choco features
	Choco feature enable -n allowGlobalConfirmation
	Choco feature enable -n ignoreInvalidOptionsSwitches
	Choco feature enable -n allowEmptyChecksums
	Choco feature disable -n exitOnRebootDetected
	Choco feature disable -n logValidationResultsOnWarnings

	Get-PackageProvider -Name "Chocolatey" -ForceBootstrap | Out-Null
	if (choco list -l -e -r Chocolatey-core.extension) { Choco upgrade Chocolatey-core.extension -y } else { Choco install Chocolatey-core.extension -y }
	Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1 -Force -EA SilentlyContinue | Out-Null
	Choco upgrade Chocolatey -y
	refreshenv
}

function Ins-Scoop-git {
	try { $scoopInstalled = Get-Command -Name scoop -EA SilentlyContinue } catch {}
	if ($scoopInstalled) { Write-Host "scoop is already installed" } else { Write-Host "`n *** 📥 Installing scoop *** `n"; iex "& {$(irm get.scoop.sh)} -RunAsAdmin" }
	try { $gitInstalled = Get-Command -Name git -EA SilentlyContinue } catch {}
	if ($gitInstalled) { Write-Host "git is already installed `n Trying to update git"; scoop update git } else { Write-Host "📥 Installing git"; scoop install git }
	if (Get-Command -Name scoop) { Write-Host "Trying to update scoop"; scoop update }
}

function Test-MicrosoftFileUrl {
	param(
		[string]$Url
	)

	try {
		$request = [System.Net.HttpWebRequest]::Create($Url)
		$request.Method = "HEAD"
		$request.AllowAutoRedirect = $true   # follow all redirects
		$response = $request.GetResponse()

		$status = $response.StatusCode
		$finalUrl = $response.ResponseUri.AbsoluteUri
		$response.Close()

		if ($status -eq 200 -and $finalUrl.StartsWith("https://download.microsoft.com")) {
			return $true
		} else {
			return $false
		}
	} catch {
		return $false
	}
}

function Install-UpdateVCLibs {
	<#
    .SYNOPSIS
    Installs or updates Microsoft.VCLibs package from the internet if needed.
    #>

	# Try Choco
	if (choco list -l -e -r microsoft-vclibs) { Choco upgrade microsoft-vclibs -y } else { choco install microsoft-vclibs -y }

	# Determine system architecture
	$architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
		'AMD64' { 'x64' }
		'x86' { 'x86' }
		'ARM64' { 'arm64' }
		default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
	}

	Write-Host "Detected architecture: $architecture"

	# Check if any VCLibs package is already installed (using wildcard)
	$installedPackage = Get-AppxPackage -Name Microsoft.VCLibs* |
	Where-Object { $_.Architecture -eq $architecture } |
	Sort-Object Version -Descending |
	Select-Object -First 1

	# Try versions from 20 to 10
	$validDownloadUrl = $null
	$onlineVersion = $null

	# Try from highest to lowest version
	for ($version = 20; $version -ge 10; $version--) {
		$testUrl = "https://aka.ms/Microsoft.VCLibs.$architecture.$version.00.Desktop.appx"
		# Write-Host "Testing URL: $testUrl"

		try {
			# Test if URL exists without downloading the full file
			$ValidFile = Test-MicrosoftFileUrl $testUrl
			if ($ValidFile) {
				$validDownloadUrl = $testUrl
				$onlineVersion = "$version.00"
				Write-Host "Found valid URL for version $onlineVersion"
				break
			}
		} catch {
			Write-Host "URL not valid for version $version.00"
			continue
		}
	}

	if (-not $validDownloadUrl) {
		throw "Could not find a valid download URL for Microsoft.VCLibs on architecture $architecture"
	}

	try {
		$tempFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.appx'

		if (-not $installedPackage) {
			Write-Host "Microsoft.VCLibs not found. 📥 Installing version $onlineVersion..."
			Invoke-WebRequest -Uri $validDownloadUrl -OutFile $tempFile
			Add-AppxPackage -Path $tempFile -EA SilentlyContinue
			Write-Host "Microsoft.VCLibs version $onlineVersion installed successfully."
		} else {
			Write-Host "Microsoft.VCLibs found (Version $($installedPackage.Version))."
			Write-Host "Latest available version is $onlineVersion."

			# Parse versions for comparison
			$installedVer = [version]$installedPackage.Version
			$onlineVer = [version]$onlineVersion

			if ($onlineVer -gt $installedVer) {
				Write-Host "Updating to version $onlineVersion..."
				Invoke-WebRequest -Uri $validDownloadUrl -OutFile $tempFile
				Add-AppxPackage -Path $tempFile -ForceApplicationShutdown -ForceUpdateFromAnyVersion
				Write-Host "Microsoft.VCLibs updated successfully to version $onlineVersion."
			} else {
				Write-Host "Already on the latest version ($onlineVersion)."
			}
		}
	} catch { throw "Failed to install/update Microsoft.VCLibs: $_" }
	finally { if (Test-Path $tempFile) { Remove-Item $tempFile -EA SilentlyContinue } }
}

function Install-UpdateMicrosoftUIXaml {

	param(
		[Parameter(Mandatory = $false)]
		[switch]$Force
	)

	# Get the latest version of Microsoft.UI.Xaml using REST API
	Write-Host "Checking for latest version of Microsoft.UI.Xaml..." -ForegroundColor Yellow
	try {
		$uiXamlVersionsNugetUrl = 'https://packages.nuget.org/api/v2/package-versions/Microsoft.UI.Xaml'
		$latestVersionString = @(Invoke-RestMethod -Uri $uiXamlVersionsNugetUrl -UseBasicParsing)[0] | Select-Object -Last 1
		if (-not $latestVersionString) {
			# Use NuGet API to get package info
			$packageUrl = "https://api.nuget.org/v3-flatcontainer/microsoft.ui.xaml/index.json"
			$versions = Invoke-RestMethod -Uri $packageUrl -UseBasicParsing
			# Filter out pre-release versions and convert to proper version objects
			$stableVersions = $versions.versions | Where-Object { $_ -notmatch '-' } | ForEach-Object {
				try { [System.Version]$_ } catch {} # Skip versions that can't be converted
			}
			if (-not $stableVersions) { Write-Error "Failed to retrieve stable version information"; return }
			$latestVersion = $stableVersions | Sort-Object -Descending | Select-Object -First 1
			$latestVersionString = $latestVersion.ToString()
		}

		Write-Host "Latest NuGet version available: $latestVersionString" -ForegroundColor Green
		# Extract major.minor from latest version
		$latestMajorMinor = [System.Version]::new($latestVersion.Major, $latestVersion.Minor)
	} catch {
		Write-Error "Failed to get package information: $($_.Exception.Message)"
		return
	}

	# Check if already installed (using wildcard to match all Microsoft.UI.Xaml packages)
	$installedPackages = Get-AppxPackage -Name "Microsoft.UI.Xaml*" -EA SilentlyContinue

	if ($installedPackages) {
		# Extract version from Name property (e.g., "Microsoft.UI.Xaml.2.3" -> "2.3")
		$installedVersions = $installedPackages | ForEach-Object {
			if ($_.Name -match 'Microsoft\.UI\.Xaml\.(\d+\.\d+)') {
				[System.Version]$matches[1]
			}
		} | Sort-Object -Descending

		if ($installedVersions) {
			$latestInstalledVersion = $installedVersions | Select-Object -First 1
			Write-Host "Latest installed UI version: $latestInstalledVersion" -ForegroundColor Cyan

			# Compare versions (only major.minor)
			if ($latestInstalledVersion -ge $latestMajorMinor -and -not $Force) {
				Write-Host "You already have the latest version ($latestInstalledVersion) installed." -ForegroundColor Green
				Write-Host "Use -Force to reinstall anyway." -ForegroundColor Yellow
				return
			} elseif ($latestInstalledVersion -lt $latestMajorMinor) {
				Write-Host "Newer version available: $latestMajorMinor (currently installed: $latestInstalledVersion)" -ForegroundColor Yellow
				# Continue with installation
			}
		}
	}

	# Download the package using direct download URL
	Write-Host "Downloading Microsoft.UI.Xaml version $latestVersionString..." -ForegroundColor Yellow
	$downloadPath = "$env:TEMP\Microsoft.UI.Xaml.$latestVersionString.nupkg"
	try {
		$downloadUrl = "https://api.nuget.org/v3-flatcontainer/microsoft.ui.xaml/$latestVersionString/microsoft.ui.xaml.$latestVersionString.nupkg"
		Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -UseBasicParsing
	} catch {
		Write-Error "Failed to download package: $($_.Exception.Message)"
		return
	}

	# Extract the package
	Write-Host "Extracting package..." -ForegroundColor Yellow
	$extractPath = "$env:TEMP\Microsoft.UI.Xaml.Extracted"
	if (Test-Path $extractPath) {
		Remove-Item $extractPath -Recurse -Force
	}

	New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

	try {
		# Rename .nupkg to .zip and extract
		$zipPath = "$env:TEMP\Microsoft.UI.Xaml.$latestVersionString.zip"
		Copy-Item $downloadPath $zipPath
		Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
		Remove-Item $zipPath -Force
	} catch {
		Write-Error "Failed to extract package: $($_.Exception.Message)"
		return
	}

	# Install the package
	Write-Host "📥 Installing Microsoft.UI.Xaml..." -ForegroundColor Yellow

	# Look for AppX packages in the extracted content
	$appxFiles = Get-ChildItem -Path $extractPath -Recurse -Filter "*.appx" -File
	if (-not $appxFiles) {
		$appxFiles = Get-ChildItem -Path $extractPath -Recurse -Filter "*.msix" -File
	}

	if (-not $appxFiles) {
		Write-Error "No AppX/MSIX package found in the downloaded content"
		return
	}

	# Determine system architecture and select the correct package
	$systemArchitecture = $env:PROCESSOR_ARCHITECTURE
	Write-Host "System architecture: $systemArchitecture" -ForegroundColor Cyan

	# Map architecture to package path
	$architectureMap = @{
		"AMD64" = "x64"
		"x86"   = "x86"
		"ARM64" = "arm64"
	}

	$targetArchitecture = $architectureMap[$systemArchitecture]
	if (-not $targetArchitecture) {
		Write-Warning "Unknown system architecture: $systemArchitecture. Defaulting to x64."
		$targetArchitecture = "x64"
	}

	Write-Host "Looking for package for architecture: $targetArchitecture" -ForegroundColor Cyan

	# Find the package for the correct architecture
	$targetAppxFile = $appxFiles | Where-Object { $_.FullName -match "\\$targetArchitecture\\" } | Select-Object -First 1

	if (-not $targetAppxFile) {
		Write-Warning "No package found for architecture $targetArchitecture. Available packages:"
		$appxFiles | ForEach-Object { Write-Host "  - $($_.FullName)" -ForegroundColor Yellow }
		return
	}

	Write-Host "Installing from: $($targetAppxFile.FullName)" -ForegroundColor Cyan

	try {
		# Install the .appx file directly
		Add-AppxPackage -Path $targetAppxFile.FullName -ForceApplicationShutdown -ForceUpdateFromAnyVersion
		Write-Host "Package installed successfully." -ForegroundColor Green
	} catch {
		Write-Error "Failed to install package: $($_.Exception.Message)"
		return
	}

	# Cleanup
	Write-Host "Cleaning up temporary files..." -ForegroundColor Yellow
	Remove-Item $extractPath -Recurse -Force -EA SilentlyContinue
	Remove-Item $downloadPath -Force -EA SilentlyContinue

	Write-Host "Microsoft.UI.Xaml installation/update process completed." -ForegroundColor Green
}

function Ins-WingetDirect {
	Write-Host "Falling back to direct installation method..." -ForegroundColor Yellow
	# Install VCLibs
	Install-UpdateVCLibs
	# Install UIXaml
	Install-UpdateMicrosoftUIXaml
	# Install Winget
	Install-UsingBITS
}

function Ins-wingetClientModule {
	Write-Host "📥 Installing Microsoft.WinGet.Client Module..." -ForegroundColor Cyan
	# install WinGet PowerShell Module (Microsoft.WinGet.Client) using chocolatey
	if (choco list -l -e -r winget.powershell) { Choco upgrade winget.powershell -y } else { Choco install winget.powershell /core /desktop -y }
	try { $WinGetClientInstalled = Get-Command -Name Find-WinGetPackage -EA SilentlyContinue } catch { Write-Host "Failed to Install Microsoft.WinGet.Client using chocolatey" -ForegroundColor Yellow }
	if (-not $WinGetClientInstalled) {
		# install Module Microsoft.WinGet.Client
		Install-Module Microsoft.WinGet.Client -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -EA SilentlyContinue
		Import-Module Microsoft.WinGet.Client -Force -EA SilentlyContinue
	}
	try { $WinGetClientInstalled = Get-Command -Name Get-WinGetVersion -ea silentlycontinue } catch { Write-Host "Failed to Install Module Microsoft.WinGet.Client" -ForegroundColor Yellow }
	if ($WinGetClientInstalled) { return $true } else { return $false }
}

function Install-Winget-FirstMethod {
	if (Ins-wingetClientModule) {
		Write-Output "📥 Installing Winget..."
		Repair-WinGetPackageManager -AllUsers -Force -Latest
	} else { return $false }
}

function Install-OrUpdateWinget {
	<#
    .SYNOPSIS
    Installs or updates the Microsoft Desktop App Installer (winget).

    .DESCRIPTION
    This function checks if both the DesktopAppInstaller package and winget command are available.
    If both are available, try to update.
    Otherwise, it performs a fresh installation trying 2 methods

    .EXAMPLE
    Install-OrUpdateWinget
    #>

	param()

	# Check if DesktopAppInstaller package is installed
	$desktopAppInstaller = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller'

	# Check if winget command is available
	$wingetAvailable = Get-Command -Name winget -EA SilentlyContinue

	if ($desktopAppInstaller -and $wingetAvailable) {
		Write-Host "Attempting to upgrade Winget..." -ForegroundColor Green
		# Try to update winget if Needed

		# Get the current version
		try {
			$currentVersion = (winget --version) -replace 'v'  # Remove 'v' prefix if present
			Write-Host "Current Winget version: $currentVersion"
		} catch {
			Write-Host "Winget is not installed or not found in PATH."
			# Try to install first method if fail use direct
			if (-not (Install-Winget-FirstMethod)) { Ins-WingetDirect }
			return
		}

		# Fetch the latest release information from GitHub API
		$url = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
		try {
			$response = Invoke-RestMethod -Uri $url -Method Get
			$onlineVersion = $response.tag_name -replace 'v'  # Remove 'v' prefix from the tag
			Write-Host "Latest online version: $onlineVersion"
		} catch {
			Write-Host "Failed to retrieve the latest version online. Check your internet connection."
			return
		}

		# Compare versions
		if ($currentVersion -eq $onlineVersion) {
			Write-Host "Your Winget is up to date." -ForegroundColor Green
		} else {
			Write-Host "A newer version of Winget is available." -ForegroundColor Yellow
			# Try to install first method if fail use direct
			if (-not (Install-Winget-FirstMethod)) { Ins-WingetDirect }
		}
	} else {
		# Try to install first method if fail use direct
		if (-not (Install-Winget-FirstMethod)) { Ins-WingetDirect }
	}
	return
}

function Install-UsingBITS {
	<#
    .SYNOPSIS
    Helper function to install Microsoft.DesktopAppInstaller using BITS transfer.
    #>
	try {
		$installerPath = Join-Path -Path $env:TEMP -ChildPath "Microsoft.DesktopAppInstaller.msixbundle"

		# Remove existing file if it exists
		if (Test-Path $installerPath) {
			Remove-Item $installerPath -Force
		}

		Write-Host "Downloading Microsoft.DesktopAppInstaller..." -ForegroundColor Yellow

		# Create a job to download using BITS transfer with timeout
		$job = Start-Job -Name "DownloadWinget" -ScriptBlock {
			param($url, $path)
			Start-BitsTransfer -Source $url -Destination $path
		} -ArgumentList "https://aka.ms/getwinget", $installerPath
		# Another link "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

		# Wait for the download to complete with timeout
		$jobResult = $job | Wait-Job -Timeout 400

		if ($jobResult.State -eq 'Completed') {
			Receive-Job -Job $job | Out-Null
			Write-Host "Download completed. 📥 Installing package..." -ForegroundColor Yellow

			# Install the package
			$installResult = Add-AppxPackage -Path $installerPath -ForceApplicationShutdown -ForceUpdateFromAnyVersion
			Write-Host "Microsoft.DesktopAppInstaller installed successfully." -ForegroundColor Green
			Start-Sleep -Seconds 1
			Relaunch
			return $true
		} else {
			# Handle timeout or failure
			if ($job.State -eq 'Running') {
				$job | Stop-Job
				Write-Error "Download timed out after 400 seconds"
				return $false
			} else {
				$errorMsg = Receive-Job -Job $job 2>&1
				Write-Error "Download failed: $errorMsg"
				return $false
			}
		}
	} catch {
		Write-Error "Failed to install using BITS transfer: $($_.Exception.Message)"
		return $false
	} finally {
		# Clean up
		if ($job) {
			Remove-Job -Job $job -Force
		}
		if (Test-Path $installerPath) {
			Remove-Item $installerPath -Force -EA SilentlyContinue
		}
	}
}

function Install-Winget {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** 📥 Installing Winget & scoop & git *****************************"
	Write-Host -f C "======================================================================================================================`r`n"

	# Install or Update Winget & Dependencies using Chocolatey
	if (choco list -l -e -r winget) { Choco upgrade winget -y } else { Choco install winget -y }

	# Install or Update Winget
	Install-OrUpdateWinget

	Start-Job -Name ConfigWinget1 { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe } | Wait-Job -Timeout 100 | Format-Table -Wrap -AutoSize -Property Name, State
	Start-Job -Name ConfigWinget2 { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.Winget.Source_8wekyb3d8bbwe } | Wait-Job -Timeout 100 | Format-Table -Wrap -AutoSize -Property Name, State

	# Install Scoop & git
	Ins-Scoop-git

	winget source reset --force
}

function Ins-arSALang {
	Write-Host -f C "`r`n *** 📥 Installing Arabic-SA language *** `r`n"
	Write-Host "📥 Installing Arabic (Saudi Arabia) language pack..." -ForegroundColor Cyan
	$Lang = "ar-SA"
	$LCID = 1025    # Arabic (Saudi Arabia)

	function WCap {
		param(
			[Parameter(Mandatory = $true, Position = 1)]
			[string]$Cap,
			[Parameter(Mandatory = $true, Position = 2)]
			[string]$Lang
		)
		$Installed = (Get-WindowsCapability -Online -Name Language.$Cap~~~$Lang~0.0.1.0 -EA SilentlyContinue).State
		if ($Installed -ne "Installed") {
			Write-Host -f C "Installing $Lang $Cap Windows Capability `n"; Add-WindowsCapability -Online -Name Language.$Cap~~~$Lang~0.0.1.0 -EA SilentlyContinue
		} else { Write-Host -f C "$Lang $Cap Windows Capability already installed `n" }
		return
	}

	WCap Basic $Lang
	WCap Handwriting $Lang
	WCap OCR $Lang
	WCap Speech $Lang
	WCap TextToSpeech $Lang
	WCap Handwriting $Lang
	WCap Handwriting ar-EG # Unified
	Add-WindowsCapability -Online -Name Language.Fonts.Arab~~~und-ARAB~0.0.1.0 -EA SilentlyContinue

	if (Get-Command -Name Install-Language -EA SilentlyContinue) { Start-Job -Name InsAr { Install-Language -Language ar-SA -EA SilentlyContinue } | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name, State }
	Set-WinHomeLocation 0xcd
	Set-WinDefaultInputMethodOverride -InputTip "0401:00000401" #Default input language Arabic
	Set-WinSystemLocale -SystemLocale ar-SA
	Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True
	Write-Host -f C "Adding $Lang to user's language list (will NOT remove existing languages)..."
	try {
		$current = Get-WinUserLanguageList
		if ($current.LanguageTag -notcontains $Lang) {
			$new = New-WinUserLanguageList -Language $Lang
			$current.Add($new[0])
			Set-WinUserLanguageList -LanguageList $current -Force
			Write-Host -f Green "Added $Lang to WinUserLanguageList."
		} else { Write-Host -f C "$Lang already present in WinUserLanguageList." }
	} catch { Write-Host -f Red "Could not modify WinUserLanguageList: $_" }
	# Strict rules for Arabic spelling
	Write-Host -f C "Configuring strict Arabic proofing rules in Windows..."
	Add-RegEntry 'HKCU:\Software\Microsoft\Spelling\Options' "$($Lang):StrictInitialAlefHamza" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Spelling\Options' "$($Lang):StrictFinalYaa" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Spelling\Options' "$($Lang):StrictTaaMarboota" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Microsoft\Spelling\ar-SA" "StrictInitialAlefHamza" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Microsoft\Spelling\ar-SA" "StrictFinalYaa" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Microsoft\Spelling\ar-SA" "StrictTaaMarboota" '1' 'DWord'

	Write-Host -f C "Applying Arabic strict proofing rules in Office..."
	Add-RegEntry 'HKCU:\Software\Microsoft\Shared Tools\Proofing Tools\1.0\office' "ArabicStrictAlefHamza" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Shared Tools\Proofing Tools\1.0\office' "ArabicStrictFinalYaa" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Shared Tools\Proofing Tools\1.0\office' "ArabicStrictTaaMarboota" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Shared Tools\Proofing Tools\1.0\Override\ar-SA' "ArabicStrictAlefHamza" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Shared Tools\Proofing Tools\1.0\Override\ar-SA' "ArabicStrictFinalYaa" '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Shared Tools\Proofing Tools\1.0\Override\ar-SA' "ArabicStrictTaaMarboota" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Microsoft\Office\16.0\Common\ProofingTools\ar-SA" "ArabicStrictAlefHamza" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Microsoft\Office\16.0\Common\ProofingTools\ar-SA" "ArabicStrictFinalYaa" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Microsoft\Office\16.0\Common\ProofingTools\ar-SA" "ArabicStrictTaaMarboota" '1' 'DWord'
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
}

function Set-en-US-Culture {
	Write-Host -ForegroundColor Cyan "`r`n *** Setting en-US Culture (Regional format) *** `r`n"

	# Import the module (if available)
	Import-Module International -Force -EA SilentlyContinue | Out-Null

	# Set culture for future sessions using registry
	Set-Culture -CultureInfo en-US

	# Customize the date/time formats
	$intlPath = 'HKCU:\Control Panel\International'

	# Calendar type (1 = Gregorian)
	Add-RegEntry -Path $IntlPath -Name iCalendarType -Value '1' -Type 'String'
	# Set registry values directly
	Add-RegEntry -Path $intlPath -Name 'sLongDate' -Value 'dd MMMM yyyy' -Type 'String'
	Add-RegEntry -Path $intlPath -Name 'sShortDate' -Value 'dd/MM/yyyy' -Type 'String'
	Add-RegEntry -Path $intlPath -Name 'sTimeFormat' -Value 'hh:mm:ss tt' -Type 'String'
	Add-RegEntry -Path $intlPath -Name 'sShortTime' -Value 'hh:mm tt' -Type 'String'
	Add-RegEntry -Path $intlPath -Name 'iFirstDayOfWeek' -Value "5" -Type 'String' # Saturday
	Add-RegEntry -Path $intlPath -Name 'iFirstWeekOfYear' -Value "0" -Type 'String'
	Add-RegEntry -Path $intlPath -Name 'iPaperSize' -Value "9" -Type 'String'
	Add-RegEntry -Path $intlPath -Name 'NumShape' -Value "0"  -Type 'String' # 0=Context, 1=Native, 2=Traditional

	# Set additional settings
	Add-RegEntry -Path "$intlPath\User Profile" -Name 'ShowTextPrediction' -Value '1' -Type 'DWord'

	Restart-ExplorerSilently

	Write-Host "Culture settings updated."
}

function Ins-enUSLang {
	Write-Host -f C "`r`n *** 📥 Installing English-US language *** `r`n"
	Start-Job -Name InsEng { Install-Language -Language en-US -CopyToSettings } | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name, State
	Set-WinSystemLocale en-US
	Set-WinUILanguageOverride en-US
	Set-WinDefaultInputMethodOverride "0409:00000409"
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguage' '0409' 'String'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguageFallback' '@ "en-US"' 'MultiString'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' 'Default' '0409' 'String'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale' 'default' '00000409' 'String'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Locale' 'Default' '00000409' 'String'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'Languages' '@ "en-US"' 'MultiString'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile System Backup\en-US' '0409:00000409' '1' 'DWord'
}

function Unins-enGBLang {
	Write-Host -f C "`r`n *** Removing English-GB language *** `r`n"
	Uninstall-Language -Language en-GB; lpksetup.exe /u en-GB /s
	Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language\English_UK"  -Recurse -Force -EA SilentlyContinue | Out-Null
	Remove-Item -LiteralPath "HKCU:\Control Panel\International\User Profile\en-GB"  -Recurse -Force -EA SilentlyContinue | Out-Null
	Remove-Item -LiteralPath "HKCU:\Control Panel\International\User Profile System Backup\en-GB"  -Recurse -Force -EA SilentlyContinue | Out-Null
}

function Tweak-Language {
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowAutoCorrection' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowCasing' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowShiftLock' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile' 'ShowTextPrediction' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowAutoCorrection' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowCasing' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowShiftLock' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\International\User Profile System Backup' 'ShowTextPrediction' '1' 'DWord'
	Add-RegEntry 'HKCU:\Control Panel\Input Method' 'EnableHexNumpad' '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Input\Settings' 'EnableHwkbTextPrediction' '1' 'DWord'
}

function Ins-LatestPowershell {
	Write-Host -f C "`r`n *** Installing Latest Stable Powershell *** `r`n"
	winget install --id 'Microsoft.Powershell' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-Terminal {
	Write-Host -f C "`r`n *** Installing Windows Terminal *** `r`n"
	winget install -e --id 'Microsoft.WindowsTerminal' --silent --accept-source-agreements --accept-package-agreements
	Add-RegEntry 'HKCU:Console\%%Startup' "DelegationConsole" "{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}" 'String'
	Add-RegEntry 'HKCU:Console\%%Startup' "DelegationTerminal" "{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}" 'String'
}

function Ins-DotNetRuntime {
	Write-Host -f C "`r`n *** Installing .Net Runtime All versions *** `r`n"
	if (choco list -l -e -r dotnet-all) { Choco upgrade dotnet-all -y } else { Choco install dotnet-all -y }
	(Find-WinGetPackage "Microsoft.DotNet.DesktopRuntime").Id | ForEach-Object { winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous }
	(Find-WinGetPackage "Microsoft.DotNet.Runtime").Id | ForEach-Object { winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous }
	(Find-WinGetPackage "Microsoft.DotNet.AspNetCore").Id | ForEach-Object { winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous }
}

function Ins-VCPPRuntime {
	Write-Host -f C "`r`n *** Installing Visual C++ Runtime All versions *** `r`n"
	if (choco list -l -e -r vcredist-all) { Choco upgrade vcredist-all -y } else { Choco install vcredist-all -y }
	(Find-WinGetPackage "Microsoft.VCRedist").Id | Where-Object { -not $_.EndsWith("arm64") } | ForEach-Object { winget install -e --id $_ --silent --accept-source-agreements --accept-package-agreements --uninstall-previous }
}

function Ins-JavaRuntime {
	Write-Host -f C "`r`n *** Installing Java Runtime Environment *** `r`n"
	winget install -e --id Oracle.JavaRuntimeEnvironment --silent --accept-source-agreements --accept-package-agreements
	if (choco list -l -e -r javaruntime) { Choco upgrade javaruntime -y } else { Choco install javaruntime -y }
}

function Ins-XNA {
	Write-Host -f C "`r`n *** Installing Microsoft XNA Framework Redistributable *** `r`n"
	if (choco list -l -e -r xna) { Choco upgrade xna -y } else { Choco install xna -y }
	winget install -e --id Microsoft.XNARedist --silent --accept-source-agreements --accept-package-agreements
}

function Ins-AdobeAIRRuntime {
	Write-Host -f C "`r`n *** Installing Adobe AIR Runtime *** `r`n"
	if (choco list -l -e -r adobeair) { Choco upgrade adobeair -y } else { Choco install adobeair -y }
	winget install -e --id HARMAN.AdobeAIR --silent --accept-source-agreements --accept-package-agreements
}

function Ins-WScan {
	Write-Host -f C "`r`n *** Installing Windows Scan *** `r`n"
	winget install -e --name 'Windows Scan' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-HpSmart {
	Write-Host -f C "`r`n *** Installing Hp Smart App *** `r`n"
	winget install -e --name 'HP Smart' --silent --accept-source-agreements --accept-package-agreements
}


function Ins-NotepadPP {
	Write-Host -f C "`r`n *** Installing Notepad++ *** `r`n"
	winget install -e --name 'Notepad++' --silent --accept-source-agreements --accept-package-agreements
	if (choco list -l -e -r notepadplusplus.install) { Choco upgrade notepadplusplus.install -y } else { Choco install notepadplusplus.install -y }
}

function Ins-Chrome {
	Write-Host -f C "`r`n *** Installing Chrome *** `r`n"
	if (choco list -l -e -r googlechrome) { Choco upgrade googlechrome --ignore-checksums -y } else { Choco install googlechrome --ignore-checksums -y }
	winget install -e --id 'Google.Chrome' --silent --accept-source-agreements --accept-package-agreements
	# remove logon chrome
	Remove-Item -LiteralPath "HKLM:\Software\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# disable chrome services
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService' '4' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\gupdate' 'Start' '4' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\gupdatem' 'Start' '4' 'DWord'
	# remove chrome tasks
	Get-ScheduledTask | Where-Object { $_.Taskname -match 'GoogleUpdateTaskMachineCore' } | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | Out-Null
	Get-ScheduledTask | Where-Object { $_.Taskname -match 'GoogleUpdateTaskMachineUA' } | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | Out-Null
	Get-ScheduledTask | Where-Object { $_.Taskname -match 'GoogleUpdaterTaskSystem' } | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | Out-Null
	# Allow popups on all chrome profiles (will prompt to close Chrome if running)
	Set-ChromePopupSettings -Action Allow
}

function Set-ChromePopupSettings {
	param(
		[Parameter(Mandatory = $false)]
		[ValidateSet("Allow", "Block", "Default", "ShowGUI")]
		[string]$Action = "ShowGUI",

		[Parameter(Mandatory = $false)]
		[switch]$Force
	)

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
			$chromeProcesses = Get-Process -Name "chrome" -EA SilentlyContinue
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
			Stop-Process -Name "chrome" -EA SilentlyContinue
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
								origin  = "https://*"
								setting = $settingValue
							},
							@{
								origin  = "http://*"
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
		Add-Type -AssemblyName System.Windows.Forms -EA SilentlyContinue
		Add-Type -AssemblyName System.Drawing -EA SilentlyContinue
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
		$form.Add_Shown({ $form.Activate() })
		[void] $form.ShowDialog()
	}

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
}

function Tweak-Edge {
	Write-Host -f C "`r`n *** Tweaking Edge *** `r`n"
	# edge
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'AutofillCreditCardEnabled' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser' 'AllowAddressBarDropdown' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' 'AllowPrelaunch' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
	# remove logon edge
	Remove-Item -LiteralPath "HKLM:\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}"  -Recurse -Force -EA SilentlyContinue | Out-Null
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' 'AllowTabPreloading' '0' 'DWord'
	# disable edge services
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService' 'Start' '4' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate' 'Start' '4' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem' 'Start' '4' 'DWord'
	# remove edge tasks
	Get-ScheduledTask | Where-Object { $_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore' } | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | Out-Null
	Get-ScheduledTask | Where-Object { $_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA' } | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | Out-Null
	Get-ScheduledTask | Where-Object { $_.Taskname -match 'MicrosoftEdgeUpdateBrowserReplacementTask' } | Unregister-ScheduledTask -Confirm:$false -EA SilentlyContinue | Out-Null
}

function Ins-AcrobatRdr {
	Write-Host -f C "`r`n *** Installing Adobe Acrobat Reader DC *** `r`n"
	try { $Acrobat = Get-Package -Name 'Adobe Acrobat (64-bit)' -EA SilentlyContinue } catch {}
	if ($Acrobat) {
		Write-Host -f C "Adobe Acrobat (64-bit) found installed"
	} elseif (choco list -l -e -r adobereader) { Choco upgrade adobereader -y } else { Choco install adobereader -y }
	winget install -e --id 'Adobe.Acrobat.Reader.64-bit' --silent --accept-source-agreements --accept-package-agreements
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

function Unins-Acrobat {
	Write-Host -f C "`r`n *** Killing Acrobat processes *** `r`n"
	kill -Name acro* -Force;
	kill -Name adobe* -Force;
	try { Choco uninstall adobereader | Out-Null } catch {}
	# Get installed programs for both 32-bit and 64-bit architectures
	$paths = @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\')
	$installedPrograms = foreach ($registryPath in $paths) {
		try {
			Get-ChildItem -LiteralPath $registryPath -EA SilentlyContinue | Get-ItemProperty | Where-Object { $_.PSChildName -ne $null }
		} catch { Write-Warning "Error reaging registry" }
	}
	# Filter programs with Adobe Acrobat in their display name
	$adobeacrobatEntries = $installedPrograms | Where-Object { $_.DisplayName -like '*Adobe Acrobat*' }
	# Try to uninstall Adobe Acrobat for each matching entry
	foreach ($entry in $adobeacrobatEntries) {
		$ProductCode = $entry.PSChildName
		$DisplayName = $entry.DisplayName
		try {
			# Use the MSIExec command to uninstall the product
			Write-Host -f C "`r`n *** Uninstalling $DisplayName *** `r`n"
			Start-Process -Verb RunAs -FilePath "msiexec.exe" -ArgumentList "/x $ProductCode /qb-! /norestart" -Wait -PassThru
		} catch { Write-Warning "Failed to uninstall $DisplayName with product code $ProductCode. Error: $_" }
	}
	# Uninstall Using winget
	winget uninstall -e --id "Adobe.Acrobat.Reader.32-bit"
	winget uninstall -e --id "Adobe.Acrobat.Reader.64-bit"
	winget uninstall -e --id "Adobe.Acrobat.Pro"
	Write-Host -f C "`r`n *** Removing All Acrobat left overs *** `r`n"
	$DDURL = Convert-GoogleDriveUrl -URL "https://drive.google.com/file/d/16etkp4rCcon2NyGGh0oYSocHhB_054cm" -Key "AIzaSyBjpiLnU2lhQG4uBq0jJDogcj0pOIR9TQ8"
	if ($DDURL) { Start-BitsTransfer -Source $DDURL -Destination "$env:TEMP\AdobeAcroCleaner.exe"  -EA SilentlyContinue | Out-Null }
	if (Test-Path -Path "$env:TEMP\AdobeAcroCleaner.exe" -EA SilentlyContinue) { Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcroCleaner.exe" -ArgumentList "/silent", "/product=0", "/cleanlevel=1" -EA SilentlyContinue | Out-Null }
	if (Test-Path -Path "$env:TEMP\AdobeAcroCleaner.exe" -EA SilentlyContinue) { Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcroCleaner.exe" -ArgumentList "/silent", "/product=1", "/cleanlevel=1" -EA SilentlyContinue | Out-Null }
	return
}

function Fix-AdobeAcrobatProPdfThumbnails {

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
			Get-ChildItem -Path $thumbCachePath -Include "*thumbcache*.db" -File -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
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
				Add-RegEntry -Path $cleanupKeyPath -Name "StateFlags$SageSetNumber" -Value 2 -PropertyType DWord -Force | Out-Null
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
	Stop-Service -Name "AppReadiness" -Force -EA SilentlyContinue
	# Stop Explorer temporarily
	Stop-Process -Name "explorer" -EA SilentlyContinue

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
		Get-ChildItem $path -EA SilentlyContinue | Remove-Item -Force
	}

	# Reset thumbnail related registry settings
	$regPaths = @(
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ThumbnailCache"
	)

	foreach ($regPath in $regPaths) {
		if (Test-Path $regPath) {
			Remove-Item $regPath -Recurse -Force -EA SilentlyContinue
		}
	}

	Write-Host "Icon cache rebuilt. Icons may take a moment to reappear." -ForegroundColor Green

	# 2. Enable thumbnails in Folder Options via registry
	Write-Host "Enabling thumbnails in Folder Options via registry..." -ForegroundColor Yellow
	$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	Add-RegEntry -Path $regPath -Name "IconsOnly" -Value 0
	Write-Host "Thumbnails enabled in Folder Options."

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
				$path = (Get-ItemProperty -Path $p -EA SilentlyContinue).'(Default)'
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
			$xmlContent =
			@"
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
	Restart-ExplorerSilently

	Write-Host "Adobe Acrobat Pro PDF thumbnail fix completed." -ForegroundColor Green
}

function Refresh-Desktop {
	Add-Type -TypeDefinition
	@"
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

function Invoke-AcrobatFix {
	<#
    .SYNOPSIS
    Applies comprehensive registry tweaks and fixes for Adobe Acrobat DC

    .DESCRIPTION
    This function performs a complete cleanup and optimization of Adobe Acrobat DC by:
    - Modifying registry settings to disable activation, notifications, and telemetry
    - Blocking unwanted Adobe processes from running
    - Applying UI/UX improvements and Arabic language support
    - Removing scheduled tasks and startup entries
    - Deleting unnecessary files and folders

    .NOTES
    - This function should be called from a script that already handles admin elevation
    - All operations are designed to be idempotent (safe to run multiple times)

    .EXAMPLE
    Invoke-AcrobatFix
    #>

	#region Registry Modifications
	Write-Host "🔧 Applying registry modifications..."

	# Define all registry changes needed for Acrobat optimization
	# These settings disable activation checks, improve UI, and configure preferences
	# Activation and licensing enforcement settings
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation" -Name "IsAMTEnforced" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Activation" -Name "IsAMTEnforced" -Type "DWord" -Value 1

	# User interface and notification preferences
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bappFirstLaunchForNotifications" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\FTEDialog" -Name "iFTEVersion" -Type "DWord" -Value 10
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\FTEDialog" -Name "iLastCardShown" -Type "DWord" -Value 0

	# ARM (Adobe Application Manager) settings
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\ARMUser" -Name "bDeclined" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVAlert\cCheckbox" -Name "iAVARMNoAutoUpdateWarning" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVAlert\cCheckbox" -Name "iAutoAcceptEDCPrivacyNotification" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVAlert\cCheckbox" -Name "iDisableCEFRepairDialog" -Type "DWord" -Value 1

	# Entitlement and activation status
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name "bActivated" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name "bIsAcroTrayEnabledAsService" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bActivated" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bSCAAcrCrashReporterEnabled" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bNewUserForModernization" -Type "DWord" -Value 0

	# First-time experience (FTE) settings
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\FTEDialog" -Name "bFTEHomeOrViewerTourDialogueLaunched" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\HomeWelcome" -Name "bIsAcrobatUpdated" -Type "DWord" -Value 1

	# Additional activation disable settings
	Add-RegEntry -Path "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Activation" -Name "Disabled" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Activation" -Name "DisabledActivation" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe ARM\1.0\ARM" -Name "DisablePromptForUpgrade" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation" -Name "Disabled" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Activation" -Name "DisabledActivation" -Type "DWord" -Value 1

	# Group Policy-like settings for enterprise control
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bAcroSuppressUpsell" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bPurchaseAcro" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bSuppressSignOut" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bToggleBillingIssue" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bToggleFTE" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bToggleShareFeedback" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Name "bUpdater" -Type "DWord" -Value 0

	# In-product messaging settings
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cIPM" -Name "bDontShowMsgWhenViewingDoc" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cIPM" -Name "bShowMsgAtLaunch" -Type "DWord" -Value 0

	# Services and notification settings
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices" -Name "bEnableBellButton" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices" -Name "bToggleNotificationToasts" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices" -Name "bToggleNotifications" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices" -Name "bTogglePrefsSync" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices" -Name "bUpdater" -Type "DWord" -Value 0

	# Process blocking via Image File Execution Options X64 (redirects to ctfmon)
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ADNotificationManager.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AGCInvokerUtility.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AGMService.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AGSService.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcroServicesUpdater.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Adobe Crash Processor.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Adobe Genuine Launcher.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AdobeCollabSync.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AdobeGCClient.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SingleClientServicesUpdater.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\agshelper.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\armsvc.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	# Process blocking via Image File Execution Options X32 (redirects to ctfmon)
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ADNotificationManager.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AGCInvokerUtility.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AGMService.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AGSService.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcroServicesUpdater.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Adobe Crash Processor.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Adobe Genuine Launcher.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AdobeCollabSync.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AdobeGCClient.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SingleClientServicesUpdater.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\agshelper.exe" -Name "Debugger" -Type "String" -Value "ctfmon"
	Add-RegEntry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\armsvc.exe" -Name "Debugger" -Type "String" -Value "ctfmon"

	# Arabic language and RTL support
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "bComplexScript" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "bHindiDigit" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "bLigature" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "iIntlSelectFont" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "iParaDir" -Type "DWord" -Value 2
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "bDigitsUI" -Type "DWord" -Value 1
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\Intl" -Name "bRTLUI" -Type "DWord" -Value 1

	# UI optimization and customization
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bEnableAV2" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bOpenCommentAppAutomatically" -Type "DWord" -Value 0
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bCommentAppLaunchNotSetByIPM" -Type "DWord" -Value 1

	# Toolbar favorites customization
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a0" -Type "String" -Value "PagesApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a1" -Type "String" -Value "EditPDFApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a2" -Type "String" -Value "ExportPDFApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a3" -Type "String" -Value "OptimizePDFApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a4" -Type "String" -Value "CombineApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a5" -Type "String" -Value "PaperToPDFApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a6" -Type "String" -Value "CreatePDFApp"
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AcroApp\cFavorites" -Name "a7" -Type "String" -Value "PrintProductionApp"

	# View and display preferences
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\RememberedViews" -Name "iRememberView" -Type "DWord" -Value 2
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\FullScreen" -Name "bForceSinglePageFitPage" -Type "DWord" -Value 1

	# Print settings
	Add-RegEntry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bPrintSaveToner" -Type "DWord" -Value 0

	# Service startup configuration (4 Disabled)
	Add-RegEntry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AGMService" -Name "Start" -Type "DWord" -Value 4
	Add-RegEntry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AGSService" -Name "Start" -Type "DWord" -Value 4
	Add-RegEntry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AdobeARMservice" -Name "Start" -Type "DWord" -Value 4

	# Delete registry values related to trial mode and licensing
	addregentry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bInTrialMode"
	addregentry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name "bInTrialMode"
	addregentry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name "iDayPassUserState"
	addregentry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name "iLicenseDaysRemaining"
	addregentry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVEntitlement" -Name "uDayPassExpiryTime"
	addregentry -Path "HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral" -Name "bShowTrialNag"

	# Delete entire registry keys
	$registryKeyDeletes = @(
		"HKLM:\SOFTWARE\Adobe\Adobe Genuine Service"
	)

	foreach ($key in $registryKeyDeletes) {
		try {
			Remove-Item -Path $key -Recurse -Force -EA SilentlyContinue
		} catch {} # Silently continue if key doesn't exist
	}
	#endregion

	#region Process Termination
	Write-Host "Stopping Adobe processes..."

	# List of Adobe processes to terminate
	$processes = @("AGMService", "AGSService", "AdobeIPCBroker", "acrotray")

	foreach ($process in $processes) {
		try {
			Get-Process -Name $process -EA SilentlyContinue | Stop-Process -Force
		} catch {} # Silently continue if process isn't running
	}
	#endregion

	#region Service Management
	Write-Host "Disabling some Adobe services..."

	# List of Adobe services to disable
	$services = @("AGMService", "AGSService", "AdobeARMservice")

	foreach ($service in $services) {
		try {
			# Stop the service if it's running
			Stop-Service -Name $service -Force -EA SilentlyContinue

			# Disable the service from starting automatically
			Set-Service -Name $service -StartupType Disabled -EA SilentlyContinue
		} catch {} # Silently continue if service doesn't exist or can't be modified
	}
	#endregion

	#region Scheduled Tasks Management
	Write-Host "Removing scheduled tasks..."

	# Get all Adobe/Acrobat related tasks
	$adobeTasks = Get-ScheduledTask | Where-Object { $_.TaskName -match 'Adobe' -or $_.TaskName -match 'Acrobat' }

	# Disable and remove all found tasks
	foreach ($task in $adobeTasks) {
		try {
			# Disable the task first
			Disable-ScheduledTask -TaskName $task.TaskName -EA SilentlyContinue
			# Then completely remove it
			Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -EA SilentlyContinue
		} catch {} # Silently continue if task cannot be modified or removed
	}
	#endregion

	# region File Cleanup
	Write-Host "Cleaning up files and directories..."

	# List of Adobe directories to remove
	$paths = @(
		"${env:COMMONPROGRAMFILES(X86)}\Adobe\OOBE\PDApp\IPC",
		"${env:COMMONPROGRAMFILES}\Adobe\OOBE\PDApp\IPC",
		"${env:COMMONPROGRAMFILES(X86)}\Adobe\AdobeGCClient",
		"${env:SYSTEMDRIVE}\Users\Public\Documents\AdobeGCData"
	)

	foreach ($path in $paths) {
		try {
			if (Test-Path $path) {
				Remove-Item -Path $path -Recurse -Force -EA SilentlyContinue
			}
		} catch {}
	}
	#endregion

	#region Additional Fixing Operations
	Write-Host "Performing additional Fixes..."

	# Remove task files from the system tasks directory
	try {
		Get-ChildItem -Path "$env:SystemRoot\SYSTEM32\TASKS" | Where-Object { ($_.Name -match 'Adobe') -or ($_.Name -match 'Acrobat') } | Remove-Item -Recurse -Force -EA SilentlyContinue
	} catch { Write-Warning "Error!" } # Silently continue on errors

	# Clean Adobe entries from Run registry keys (both HKLM and HKCU)
	$runPaths = @(
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
	)

	foreach ($runPath in $runPaths) {
		try {
			# Check if the path exists before trying to access it
			if (Test-Path $runPath) {
				$properties = Get-ItemProperty -Path $runPath -EA SilentlyContinue
				if ($properties) { $properties.PSObject.Properties | Where-Object { $_.Name -match 'Adobe' -or $_.Name -match 'Acrobat' } | ForEach-Object { Remove-RegEntry -Path $runPath -Name $_.Name -Force -EA SilentlyContinue } }
			}
		} catch { Write-Warning "Error!" } # Silently continue if registry operations fail
	}
	#endregion

	Write-Host "Acrobat fix completed successfully!"
}

function Invoke-ShellAssocChanged {
	<#
    .SYNOPSIS
        Notifies Explorer that file associations or shell handlers have changed.

    .DESCRIPTION
        Calls SHChangeNotify with SHCNE_ASSOCCHANGED to refresh the system’s
        awareness of file type/handler changes without requiring logout/reboot.
    #>

	Add-Type 
@"
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

function Ins-AcrobatPro {
	Unins-Acrobat
	#Set-MpPreference -DisableRealtimeMonitoring $false
	Write-Host -f C "`r`n *** Installing Adobe Acrobat Pro DC *** `r`n"
	Disable-DefenderRealtimeProtection
	# Acrobat 2024 https://drive.google.com/file/d/10R43n4peqwLJJBIoR8PxMOIcRbrlvDNb/view
	# Acrobat 2025 https://drive.google.com/file/d/1dvAq0k6JRtSOOXiR4hhkfva_OuxSzYbf/view
	$DDURL = Convert-GoogleDriveUrl -URL "https://drive.google.com/file/d/1dvAq0k6JRtSOOXiR4hhkfva_OuxSzYbf/view" -Key "AIzaSyBjpiLnU2lhQG4uBq0jJDogcj0pOIR9TQ8"
	if ($DDURL) { Start-BitsTransfer -Source $DDURL -Destination "$env:TEMP\AdobeAcrobatProDCx64.exe"  -EA SilentlyContinue | Out-Null }
	Start-Job -Name AcrobatPro { if (Test-Path -Path "$env:TEMP\AdobeAcrobatProDCx64.exe" -EA SilentlyContinue) { Start-Process -Wait -Verb RunAs -FilePath "$env:TEMP\AdobeAcrobatProDCx64.exe" -EA SilentlyContinue | Out-Null } } | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name, State
	# Thumbnail image handler (IThumbnailProvider)
	Add-RegEntry 'HKCR:\.pdf\ShellEx\{e357fccd-a995-4576-b01f-234630154e96}' "(default)" "{F9DB5320-233E-11D1-9F84-707F02C10627}" 'String'
	# Image handler (IExtractImage)
	Add-RegEntry 'HKCR:\.pdf\ShellEx\{BB2E617C-0920-11d1-9A0B-00C04FC2D6C1}' "(default)" "{F9DB5320-233E-11D1-9F84-707F02C10627}" 'String'
	# Preview handler (IPreviewHandler)
	Add-RegEntry 'HKCR:\.pdf\ShellEx\{8895b1c6-b41f-4c1c-a562-0d564250836f}' "(default)" "{DC6EFB56-9CFA-464D-8880-44885D7DC193}" 'String'
	Ins-Foxit
	Invoke-ShellAssocChanged
	$printer = Get-CimInstance -Class Win32_Printer -Filter "Name='Adobe PDF'"
	Invoke-CimMethod -InputObject $printer -MethodName SetDefaultPrinter
	(New-Object -ComObject WScript.Network).SetDefaultPrinter('Adobe PDF')
	Invoke-AcrobatFix
	Fix-AdobeAcrobatProPdfThumbnails
	Start-Sleep -Seconds 5
	Refresh-Desktop
}

function Ins-WinRAR {
	Write-Host -f C "`r`n *** Installing WinRAR *** `r`n"
	if (choco list -l -e -r winrar) { Choco upgrade winrar --ignore-checksums -y } else { Choco install winrar --ignore-checksums -y }
	winget install -e --id 'RARLab.WinRAR' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-KLiteMega {
	Write-Host -f C "`r`n *** Installing K-Lite Codec Pack Mega *** `r`n"
	if (choco list -l -e -r k-litecodecpackmega) { Choco upgrade k-litecodecpackmega -y } else { Choco install k-litecodecpackmega -y }
	winget install -e --id 'CodecGuide.K-LiteCodecPack.Mega' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-VLC {
	Write-Host -f C "`r`n *** Installing VLC *** `r`n"
	winget install -e --id 'VideoLAN.VLC' --silent --accept-source-agreements --accept-package-agreements
	winget install -e --id 'XPDM1ZW6815MQM' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-PaintDotNet {
	Write-Host -f C "`r`n *** Installing Paint.net *** `r`n"
	winget install -e --id 'dotPDN.PaintDotNet' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-GIMP {
	Write-Host -f C "`r`n *** Installing GIMP *** `r`n"
	winget install -e --id 'GIMP.GIMP' --silent --accept-source-agreements --accept-package-agreements
}

function Ins-OpenAl {
	Write-Host -f C "`r`n *** Installing OpenAl *** `r`n"
	if (choco list -l -e -r openal) { Choco upgrade openal -y } else { Choco install openal -y }
}

function Ins-Foxit {
	# Step 1: Install Foxit PDF Reader via winget
	Write-Host "📥 Installing Foxit PDF Reader..."

	# Define download folder
	$DownloadFolder = "$env:TEMP\FoxitDownload"

	# 1. Delete old folder if it exists
	if (Test-Path $DownloadFolder) {
		Remove-Item -Path $DownloadFolder -Recurse -Force
	}
	# Recreate folder
	New-Item -Path $DownloadFolder -ItemType Directory | Out-Null

	# 2. Download latest Foxit Reader EXE using winget
	winget download -e --id "Foxit.FoxitReader" --accept-source-agreements --accept-package-agreements -d $DownloadFolder

	# 3. Find the downloaded EXE
	$InstallerExe = Get-ChildItem -Path $DownloadFolder -Filter *.exe -File -Recurse | Select-Object -First 1
	if (-not $InstallerExe) {
		Write-Error "Foxit installer EXE not found in $DownloadFolder"
		exit 1
	}

	# 4. Extract EXE contents
	Start-Process -FilePath $InstallerExe.FullName -ArgumentList "/extract `"$DownloadFolder`"" -Wait

	# 5. Get MSI + MSP files
	$MsiFile = Get-ChildItem -Path $DownloadFolder -Filter *.msi -File -Recurse | Select-Object -First 1
	$MspFile = Get-ChildItem -Path $DownloadFolder -Filter *.msp -File -Recurse | Select-Object -First 1

	if (-not $MsiFile) {
		Write-Error "No MSI file found in $DownloadFolder"
		exit 1
	}

	# 6. Define custom install arguments (updated)
	$InstallArgs = @(
		"/i `"$($MsiFile.FullName)`"",
		"/quiet", "/norestart",
		"ADDLOCAL=All",
		"MAKEDEFAULT=0",
		"VIEW_IN_BROWSER=0",
		"DESKTOP_SHORTCUT=0",
		"STARTMENU_SHORTCUT=0",
		"LAUNCHCHECKDEFAULT=0",
		"EMBEDDED_PDF_INOFFICE=0",
		"REMOVENEWVERSION=1",
		"INTERNET_DISABLE=1",
		"AUTO_UPDATE=0",
		"NOTINSTALLUPDATE=1"
	)

	# 7. Install MSI
	Write-Host "Installing Foxit Reader MSI..."
	Start-Process -FilePath "msiexec.exe" -ArgumentList ($InstallArgs -join ' ') -Wait -NoNewWindow

	# 8. Apply MSP patch if available
	if ($MspFile) {
		Write-Host "Applying MSP patch..."
		Start-Process -FilePath "msiexec.exe" -ArgumentList "/p `"$($MspFile.FullName)`" /quiet /norestart" -Wait -NoNewWindow
	}

	Write-Host "Foxit Reader setup completed successfully."

	Write-Host "🔧 Configuring Foxit as default PDF thumbnail provider..."

	# Apply thumbnail handler
	Add-RegEntry 'HKCR:\.pdf\ShellEx\{e357fccd-a995-4576-b01f-234630154e96}' "(default)" "{21F5E992-636E-48DC-9C47-5B05DEF82372}" 'String'
	# Apply preview handler
	Add-RegEntry 'HKCR:\.pdf\ShellEx\{8895b1c6-b41f-4c1c-a562-0d564250836f}' "(default)" "{1B0F3B9D-3A01-453F-BD45-0A9438F97BDA}" 'String'
	# Image extract handler acrobat
	Add-RegEntry 'HKCR:\.pdf\ShellEx\{BB2E617C-0920-11d1-9A0B-00C04FC2D6C1}' "(default)" "{F9DB5320-233E-11D1-9F84-707F02C10627}" 'String'

	Write-Host "✅ Foxit PDF Reader installed and set as default thumbnail preview handler."
}

function Ins-WhatsApp {
	Write-Host -f C "`r`n *** 📥 Installing MS store WhatsApp *** `r`n"
	winget install -e --name 'WhatsApp' --id '9NKSQGP7F2NH' --source 'msstore' --silent --accept-source-agreements --accept-package-agreements
	# Pin MS store Whatsapp to taskbar
	Pin-to-taskbar -IDorPath "WhatsAppDesktop" -PinType "AppUserModelID" -SearchID
}

function Unins-Devhome {
	Write-Host -f C "`r`n *** Uninstalling Dev Home *** `r`n"
	Remove-AppxApp -AppName "DevHome"
	winget uninstall --id 'Microsoft.DevHome'
}

function Unins-DropboxPromotion {
	Write-Host -f C "`r`n *** Uninstalling Dropbox promotion *** `r`n"
	Remove-AppxApp -AppName "DropboxOEM"
}

function Unins-Cortana {
	Write-Host -f C "`r`n *** Uninstalling & disabling Cortana & tweaking search *** `r`n"
	Remove-AppxApp -AppName "Microsoft.549981C3F5F10"
	winget uninstall cortana
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortanaAboveLock' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search' 'CortanaConsent' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowSearchToUseLocation' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' '1' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCloudSearch' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'EnableDynamicContentInWSB' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings' 'IsDynamicSearchBoxEnabled' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' '0' 'DWord'
}

function Unins-Copilot {
	Write-Host -f C "`r`n *** Uninstalling & disabling Copilot *** `r`n"
	Remove-AppxApp -AppName "Copilot"
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
	Add-RegEntry 'HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' '1' 'DWord'
	# remove copilot from taskbar
	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowCopilotButton' '0' 'DWord'
	Add-RegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'AutoRestartShell' '1' 'DWord'
	Restart-ExplorerSilently
}

function Unins-Xbox {
	Write-Host -f C "`r`n *** Uninstalling Xbox & Game Bar *** `r`n"
	Remove-AppxApp -AppName "Xbox"
	Add-RegEntry "HKLM:\System\CurrentControlSet\Services\xbgm" "Start" '4' 'DWORD'
	Set-Service -Name XblAuthManager -StartupType Disabled -EA SilentlyContinue | Out-Null
	Set-Service -Name XblGameSave -StartupType Disabled -EA SilentlyContinue | Out-Null
	Set-Service -Name XboxGipSvc -StartupType Disabled -EA SilentlyContinue | Out-Null
	Set-Service -Name XboxNetApiSvc -StartupType Disabled -EA SilentlyContinue | Out-Null
	# Disabling scheduled tasks
	Get-ScheduledTask -TaskName 'XblGameSaveTask' | Disable-ScheduledTask -EA SilentlyContinue | Out-Null
	#  Disable Game DVR
	Add-RegEntry 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR' 'value' '0' 'DWord'
	Add-RegEntry 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR' 'AllowgameDVR' '0' 'DWORD'
	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' '0' 'DWord'
	#  Disable Game Bar
	Add-RegEntry 'HKCU:\Software\Microsoft\GameBar' 'AllowAutoGameMode' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled' '0' 'DWord'
}

function Unins-MSTeams {
	Write-Host -f C "`r`n *** Uninstalling Microsoft Teams *** `r`n"
	if (Get-Module -Name UninstallTeams -ListAvailable -EA SilentlyContinue) { Write-Host -f C "UninstallTeams Module already exists" }
	else { Start-Job -Name UninstallTeams { Install-Module -Name UninstallTeams -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -EA SilentlyContinue | Out-Null } | Wait-Job -Timeout 400 | Format-List -Property Name, State }
	Import-Module UninstallTeams -Force -EA SilentlyContinue | Out-Null
	Install-Script UninstallTeams -Confirm:$False -Force -EA SilentlyContinue | Out-Null
	UninstallTeams -DisableChatWidget -AllUsers
	UninstallTeams -DisableOfficeTeamsInstall
	UninstallTeams
}

function Update-WinGetPackages {
	[CmdletBinding()]
	param(
		[string[]]$NamePatterns = @(),
		[string[]]$IdPatterns = @()
	)

	Ins-wingetClientModule

	# Import the module
	Import-Module Microsoft.WinGet.Client -Force

	Write-Host -f C "Checking for available upgrades..."

	# Get all packages and filter for those with available updates
	$upgrades = Get-WinGetPackage | Where-Object { $_.IsUpdateAvailable }

	if (-not $upgrades -or $upgrades.Count -eq 0) {
		Write-Host -f C "No upgrades available."
		return
	}

	# Format the output
	$upgradeTable = $upgrades | Select-Object Name, Id, InstalledVersion, @{
		Name       = 'AvailableVersion'
		Expression = { if ($_.AvailableVersions.Count -gt 0) { $_.AvailableVersions[0] } else { "Unknown" } }
	}

	Write-Host -f C "Found $($upgrades.Count) upgrade(s) available:"
	$upgradeTable | Format-Table -AutoSize

	# Filter out excluded packages
	$upgradesToInstall = $upgrades | Where-Object {
		$package = $_
		$exclude = $false

		foreach ($pattern in $NamePatterns) {
			if ($package.Name -like "*$pattern*") {
				$exclude = $true
				break
			}
		}

		if (-not $exclude) {
			foreach ($pattern in $IdPatterns) {
				if ($package.Id -like "*$pattern*") {
					$exclude = $true
					break
				}
			}
		}

		-not $exclude
	}

	# Show excluded packages
	$excluded = $upgrades | Where-Object { $_.Id -notin $upgradesToInstall.Id }
	if ($excluded.Count -gt 0) {
		Write-Host -f Yellow "Excluded $($excluded.Count) package(s):"
		$excluded | ForEach-Object { Write-Host "  - $($_.Name) ($($_.Id))" }
	}

	if ($upgradesToInstall.Count -eq 0) {
		Write-Host -f Yellow "All upgrades excluded based on filters."
		return
	}

	Write-Host -f C "Upgrading $($upgradesToInstall.Count) package(s)..."

	foreach ($package in $upgradesToInstall) {
		Write-Host "Upgrading: $($package.Name) ($($package.Id))"
		winget upgrade --id $package.Id --silent --accept-package-agreements --force
	}
}

function UpdateAll {
	Write-Host -f C "`r`n *** Updating all installed applications *** `r`n"
	Update-WinGetPackages -NamePatterns "Acrobat" -IdPatterns "Acrobat"
	# winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --force
	choco upgrade all -y
	refreshenv
}

function Ins-DirectX {
	Write-Host -f C "`r`n *** Installing DirectX Extra Files *** `r`n"
	if (choco list -l -e -r directx) { Choco upgrade directx -y } else { Choco install directx -y }
	scoop bucket add games
	scoop install games/dxwrapper
	scoop update dxwrapper
	Start-Job -Name DX-Extra { winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements }
	# Run on Windows Terminal
	#wt winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements
	#Start-Process 'wt.exe' -Verb RunAs -WindowStyle Minimized -ArgumentList '-p "Windows PowerShell"','winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements'
	# Run on Latest PowerShell
	#try {$PSLatestInstalled = Get-Command -Name pwsh -EA SilentlyContinue} catch {}
	#if ($PSLatestInstalled) {pwsh -NoProfile -InputFormat None -ExecutionPolicy Bypass -nologo -Command "winget install -e --id Microsoft.DirectX --silent --accept-source-agreements --accept-package-agreements"}
}

function Windows-Update {
	Write-Host -f C "`r`n *** Starting Windows Updates *** `r`n"
	# Update reg entries
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpgrade' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpgradePeriod' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DeferUpdatePeriod' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate' 'AutoDownload' '4' 'DWord' #Store auto download updates
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload' '4' 'DWord' #Store auto download updates all users policy
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DoNotConnectToWindowsUpdateInternetLocations' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971F918-A847-4430-9279-4A52D1EFE18D' 'RegisteredWithAU' '1' 'DWord' #Microsoft Update
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\855E8A7C-ECB4-4CA3-B045-1DFA50104289' 'RegisteredWithAU' '1' 'DWord' #Windows Store (DCat Prod)
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' 'Start' '3' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc' 'Start' '3' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' 'Start' '3' 'DWord'
	# Start Services
	Start-Service -Name "wuauserv" -EA SilentlyContinue | Out-Null
	Start-Service -Name "UsoSvc" -EA SilentlyContinue | Out-Null
	# Use PSWindowsUpdate Module
	if (-not (Get-Module -ListAvailable -Name PSWindowsUpdateModule)) { Start-Job -Name PSWindowsUpdateModule { Install-Module -Name PSWindowsUpdate -Repository PSGallery -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -EA SilentlyContinue | Out-Null } | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name, State }
	Import-Module PSWindowsUpdate -Force -EA SilentlyContinue | Out-Null
	Get-WUServiceManager | ForEach-Object { Add-WUServiceManager -ServiceID $_.ServiceID -Confirm:$false -EA SilentlyContinue | Out-Null }
	Start-Job -Name WindowsUpdate { Get-WindowsUpdate -Install -ForceInstall -AcceptAll -IgnoreReboot -Silent -EA SilentlyContinue }
	(New-Object -ComObject Microsoft.Update.ServiceManager).Services | select Name, ServiceID | foreach { if ($_.Name -match "Store") { $StoreServiceID = $_.ServiceID } } #Get Store Service ID
	Start-Job -Name WindowsStoreAppsUpdate { Get-WindowsUpdate -ServiceID $StoreServiceID -Install -ForceInstall -AcceptAll -IgnoreReboot -Silent -EA SilentlyContinue }
	# Use kbupdate Module
	try {
		if (-not (Get-Module -ListAvailable -Name kbupdate)) { Install-Module kbupdate -Confirm:$False -SkipPublisherCheck -AllowClobber -Force -EA SilentlyContinue }
		Import-Module kbupdate -Force -EA SilentlyContinue | Out-Null
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

function DeepTweaks {
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

function Dis-BitLocker {
	Write-Host -f C "`r`n *** Disabling BitLocker *** `r`n"
	Get-BitLockerVolume | foreach { manage-bde -unlock $_.MountPoint -recoverypassword (Get-BitLockerVolume -MountPoint $_.MountPoint).KeyProtector.RecoveryPassword -EA SilentlyContinue } | Out-Null
	Get-BitLockerVolume | foreach { manage-bde -off $_.MountPoint } | Out-Null
	#Clear-BitLockerAutoUnlock -EA SilentlyContinue | out-null
	#Get-BitLockerVolume | foreach {Disable-BitLocker -MountPoint $_.MountPoint -EA SilentlyContinue} | out-null
}

function EnableSMB1Protocol-Client {
	#Insecure (only old devices use it).
	Add-RegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'SMB1' '1' 'DWORD'
	if ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).state -ne "Enabled") { Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol }
	if ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client).state -ne "Enabled") { Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client }
	if ((Get-SmbServerConfiguration).EnableSMB1Protocol -ne $true) { Set-SmbServerConfiguration -EnableSMB1Protocol $true }
	if ((Get-SmbServerConfiguration).AuditSmb1Access -ne $true) { Set-SmbServerConfiguration -AuditSmb1Access $true }
	Set-SmbServerConfiguration  -EnableSMB1Protocol -Force -Confirm:$false
}

function CLUA {
	Write-Host -f C "`r`n *** Activating Classic local users authenticate *** `r`n"
	net user guest /active:yes
	Write-Host -f C "`r`n" | net user guest *
	net user guest /passwordreq:no
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'forceguest' '0' 'DWord' #Use local users authenticate not guest
	net user guest /active:no
}

function Del-WinDomainCred {
	Write-Host -f C "`r`n *** Deleting windows Domain credintials (sometimes it's stuck) *** `r`n"
	Write-Host -f C "`r`n Maped drives and saved shared folders credintials will be affected `r`n"
	cmdkey /list | ForEach-Object {
		if ($_ -like "*Target: Domain:target=*") {
			$c = ($_ -replace (' ')).split(":", 2)[1]
			cmdkey.exe /delete $c | Out-Null
		}
	}
}

function Fix-Share {
	Write-Host -f C "`r`n *** Fixining Windows file sharing *** `r`n"
	CLUA #Classic local users authenticate (Disable the ForceGuest feature)
	Del-WinDomainCred #Delete windows Domain credintials (sometimes it's stuck). Maped drives and saved shared folders credintials will be affected
	if ((Get-SmbServerConfiguration).EnableSMB2Protocol -ne $true) { Set-SmbServerConfiguration -EnableSMB2Protocol $true }
	(Get-NetConnectionProfile).Name | foreach { Set-NetConnectionProfile -Name $_ -NetworkCategory private } #Make currently connected networks private
	#(New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults(); netsh advfirewall reset #Reset firewall settings (Needed sometimes).
	netsh advfirewall set currentprofile state on
	netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
	netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
	Start-Job -Name NFR1 { Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Enable-NetFirewallRule }
	Start-Job -Name NFR2 { Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule }
	Start-Job -Name NFR3 { Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Private }
	Start-Job -Name NFR4 { Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Private }
	Start-Job -Name NFR5 { Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Domain }
	Start-Job -Name NFR6 { Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Domain }
	Start-Job -Name NFR7 { Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Public }
	Start-Job -Name NFR8 { Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Public }
	Start-Job -Name NFR9 { Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Any }
	Start-Job -Name NFR10 { Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -Profile Any }
	# Make sure required protocols are enabled in the adapter (they should be by default)
	Start-Job -Name NetAdapter1 { Get-NetAdapter | foreach { Enable-NetAdapterBinding -Name $_.Name -DisplayName "File and Printer Sharing for Microsoft Networks" -EA SilentlyContinue | Out-Null } }
	Start-Job -Name NetAdapter2 { Get-NetAdapter | foreach { Enable-NetAdapterBinding -Name $_.Name -DisplayName "Client for Microsoft Networks" -EA SilentlyContinue | Out-Null } }
	Remove-Item "$env:SystemRoot\System32\GroupPolicyUsers" -Recurse -Force -EA SilentlyContinue | Out-Null
	Remove-Item "$env:SystemRoot\System32\GroupPolicy" -Recurse -Force -EA SilentlyContinue | Out-Null
	gpupdate /force
	# Get-ComputerInfo -Property CsWorkgroup | Select-Object -ExpandProperty CsWorkgroup
	Add-Computer -WorkgroupName "WORKGROUP" -EA SilentlyContinue | Out-Null
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
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private' 'AutoSetup' '1' 'DWord' #Setup network connected devices automatically
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinClientSec' '0x20000000' 'DWord' #128
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinServerSec' '0x20000000' 'DWord' #128
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableAuthenticateUserSharing' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' '1' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RejectUnencryptedAccess' '0' 'DWord'
	Add-RegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'AutoShareWks' '1' 'DWORD'
	Add-RegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" 'AutoShareServer' '1' 'DWORD'
	Add-RegEntry 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' 'EnableSecuritySignature' '1' 'DWord'
	Add-RegEntry 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' 'RequireSecuritySignature' '0' 'DWord'
	Add-RegEntry 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' 'AllowInsecureGuestAuth' '1' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' '1' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'disabledomaincreds' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'everyoneincludesanonymous' '1' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymous' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'restrictanonymoussam' '0' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SamConnectedAccountsExist' '1' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' '1' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\fdPHost' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\upnphost' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\lmhosts' 'Start' '2' 'DWord'
	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\FDResPub' 'Start' '3' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'scforceoption' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' 'DevicePasswordLessBuildVersion' '0' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' 'DevicePasswordLessUpdateType' '1' 'DWord'
	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions' 'value' '1' 'DWord'
}

function Tweak-schtasks {
	Write-Host -f C "`r`n *** Disabling scheduled tasks that are considered unnecessary *** `r`n"
	Get-ScheduledTask -TaskName 'Consolidator' | Disable-ScheduledTask -EA SilentlyContinue | Out-Null
	Get-ScheduledTask -TaskName 'UsbCeip' | Disable-ScheduledTask -EA SilentlyContinue | Out-Null
	Get-ScheduledTask -TaskName 'DmClient' | Disable-ScheduledTask -EA SilentlyContinue | Out-Null
	Get-ScheduledTask -TaskName 'DmClientOnScenarioDownload' | Disable-ScheduledTask -EA SilentlyContinue | Out-Null
}

function Registry-Tweaks {
	Write-Host -f C "`r`n *** Applying Registry Tweaks *** `r`n"

	# ===============================
	# DESKTOP ICONS & LAYOUT
	# ===============================

	Add-RegEntry "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" "Sort" "0x40000002" 'DWord'
	# Desktop icon sort order. 0x40000002 = sort by Name (ascending).

	$sortBinary = [byte[]] (0x02, 0x00, 0x00, 0x40)
	Add-RegEntry -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Name "Sort" -Value $sortBinary -Type Binary
	# Same as above in binary form (02 00 00 40 = Name ascending).

	Add-RegEntry "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" "FFlags" "0x40200225" 'DWord'
	# Desktop view flags (auto-arrange/align/show icons etc.). Composite flag value.

	Add-RegEntry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" '1' 'DWord'
	# Hide Microsoft Edge desktop icon (CLSID).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" '1' 'DWord'
	# Hide OneDrive icon on desktop (CLSID). 0=show, 1=hide.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" '0' 'DWord'
	# Show "User Files" (profile) icon on desktop.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" '0' 'DWord'
	# Show "This PC" icon on desktop.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" '0' 'DWord'
	# Show "Network" icon on desktop.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" '0' 'DWord'
	# Show "Control Panel" icon on desktop.

	# ===============================
	# SMARTSCREEN & REPUTATION-BASED PROTECTION
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' 'String'
	# Explorer SmartScreen (file reputation) policy. "Off" = disabled.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' '0' 'DWord'
	# System policy to disable SmartScreen for apps (0=disabled).

	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
	# Microsoft Edge SmartScreen off for current user.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' '0' 'DWord'
	# Microsoft Edge SmartScreen off (machine-wide).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell' 'value' '0' 'DWord'
	# PolicyManager: disable SmartScreen in Shell/Explorer.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl' 'value' '0' 'DWord'
	# PolicyManager: disable app install control (reputation checks).

	Add-RegEntry 'HKCU:\Software\Microsoft\Edge\SmartScreenEnabled' 'Default' '0' 'String'
	# Legacy Edge setting: SmartScreen disabled (per-user).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
	# Legacy Edge (Spartan) phishing filter disabled.

	Add-RegEntry 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' 'EnabledV9' '0' 'DWord'
	# Legacy Edge per-AppContainer phishing filter disabled.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter' 'EnabledV9' '0' 'DWord'
	# Internet Explorer phishing filter disabled.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' '0' 'DWord'
	# Disable SmartScreen for Win32 web content evaluation.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' 'PreventOverride' '0' 'DWord'
	# Allow user to bypass SmartScreen warnings (0=allow override).

	# Replaced by the function Set-EmptyIFEO
	# Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe' 'Debugger' 'ctfmon' 'String'
	# Add-RegEntry 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe' 'Debugger' 'ctfmon' 'String'
	# IFEO "Debugger" redirection effectively disables smartscreen.exe (advanced/forceful).

	# ===============================
	# LOCK SCREEN & LOGON EXPERIENCE
	# ===============================

	Add-RegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10" 'String'
	# Number of cached domain logons allowed.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData' 'AllowLockScreen' '0' 'DWord'
	# Disable lock screen (when possible).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreen' '1' 'DWord'
	# Policy: disable lock screen (1=enabled policy).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableAcrylicBackgroundOnLogon' '1' 'DWord'
	# Disable acrylic blur on Logon screen background.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableLogonBackgroundImage' '0' 'DWord'
	# Keep logon background image (0=use image, 1=solid color).

	Remove-RegEntry -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Force -EA SilentlyContinue | Out-Null
	# Remove legal notice caption (if exists).

	Remove-RegEntry -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -Force -EA SilentlyContinue | Out-Null
	# Remove legal notice text (if exists).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'dontdisplaylastusername' '0' 'DWord'
	# Show last signed-in user on logon (0=show).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'shutdownwithoutlogon' '1' 'DWord'
	# Allow shutdown from logon screen.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'undockwithoutlogon' '1' 'DWord'
	# Allow undock from logon screen (laptops/docks).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableFirstLogonAnimation' '0' 'DWord'
	# Disable first sign-in animation.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLockedUserId' '3' 'DWord'
	# Show account details on lock screen: 3 = do not display name/email.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableForcedLogoff' '1' 'DWord'
	# Force logoff of users when logon hours expire.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' '0' 'DWord'
	# Disable Start/Lock screen suggestions/ads.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenEnabled' '0' 'DWord'
	# Disable Windows Spotlight on lock screen.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'RotatingLockScreenOverlayEnabled' '0' 'DWord'
	# Disable lock screen tips on Spotlight.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' '1' 'DWord'
	# Disable camera on lock screen.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen' 'SlideshowDuration' '0' 'DWord'
	# Lock screen slideshow duration (0 = default/disabled slideshow).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\AccessPage\Camera' 'CameraEnabled' '0' 'DWord'
	# Disable camera access on sign-in UI.

	# ===============================
	# DOWNLOADED FILES / ATTACHMENTS
	# ===============================

	Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# Clear existing machine Attachment policies (reset).

	Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# Clear existing user Attachment policies (reset).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' '1' 'DWord'
	# Preserve Zone.Identifier (Mark-of-the-Web) on downloads (1=save). NOTE: enables MOTW.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation' '1' 'DWord'
	# Same at user level.

	Add-RegEntry 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations' 'DefaultFileTypeRisk' '24914' 'DWord'
	# File association security risk level (affects warning prompts).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations' 'DefaultFileTypeRisk' '24914' 'DWord'
	# Same at user level.

	# ===============================
	# HARDWARE ACCELERATED GPU SCHEDULING (HAGS)
	# ===============================

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' '2' 'DWord'
	# Enable HAGS (2=enable, 1=default/driver, 0=disable).

	# ===============================
	# BACKGROUND APPS
	# ===============================

	Add-RegEntry 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled' '0' 'DWord'
	# Allow background apps (0=enabled). Set to 1 to block; kept 0 to avoid issues.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'BackgroundAppGlobalToggle' '1' 'DWord'
	# Enable background search components.

	# ===============================
	# FAST STARTUP / BOOT ANIMATION
	# ===============================

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HybridBootAnimationTime' '0' 'DWord'
	# Set Fast Startup animation duration (0 = minimal/none).

	# ===============================
	# SPECTRE/MELTDOWN (KERNEL MITIGATIONS)
	# ===============================

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride' '3' 'DWord'
	# Disable certain CPU vulnerability mitigations (bitmask). 3 commonly disables Spectre/Meltdown mitigations.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverrideMask' '3' 'DWord'
	# Mask for above override (which bits are considered).

	# ===============================
	# OFFLINE MAPS
	# ===============================

	Add-RegEntry 'HKLM:\SYSTEM\Maps' 'AutoUpdateEnabled' '0' 'DWord'
	# Disable automatic offline maps updates.

	# ===============================
	# TELEMETRY / DIAGNOSTICS / FEEDBACK / Privacy
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' '0' 'DWord'
	# Telemetry level (0=Security/Minimum; Home/Pro may map to Basic).

	Add-RegEntry 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' '0' 'DWord'
	# Feedback frequency count (0 = never prompt).

	Remove-RegEntry -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'PeriodInNanoSeconds' -Force -EA SilentlyContinue | Out-Null
	# Remove feedback timing window (reset).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'AllowCommercialDataPipeline' '0' 'DWord'
	# Disable commercial data pipeline (diagnostics sharing).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'FeedbackHubAlwaysSaveDiagnosticsLocally' '0' 'DWord'
	# Do not force Feedback Hub to save diagnostics locally.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System' 'LimitEnhancedDiagnosticDataWindowsAnalytics' '1' 'DWord'
	# Limit diagnostic data used by Windows Analytics.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' 'PreventHandwritingDataSharing' '1' 'DWord'
	# Prevent sharing handwriting data.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' 'PreventHandwritingErrorReports' '1' 'DWord'
	# Block handwriting error reports.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' '0' 'DWord'
	# Disable Timeline/Activity feed (global).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' '0' 'DWord'
	# Block publishing user activities.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' '0' 'DWord'
	# Block uploading user activities.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' 'Start' '0' 'DWord'
	# Disable Diagnostics Tracking autologger.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'UserFeedbackAllowed' '0' 'DWord'
	# Disable user feedback in Edge.

	Add-RegEntry 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' '1' 'DWord'
	# Block implicit inking data collection.

	Add-RegEntry 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' '1' 'DWord'
	# Block implicit text input data collection.

	Add-RegEntry 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' '0' 'DWord'
	# Do not harvest contacts for personalization.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' '0' 'DWord'
	# Disable input personalization.

	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' '1' 'DWord'
	# Disable local AI features analyzing user data (current user).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' '1' 'DWord'
	# Disable local AI data analysis (machine-wide).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' '1' 'DWord'
	# Limit diagnostic log collection.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' '1' 'DWord'
	# Disable OneSettings (content/experiment) downloads.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' '1' 'DWord'
	# Do not show feedback notifications.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry' '0' 'DWord'
	# Redundant telemetry minimum (backup location).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' '0' 'DWord'
	# Disable tailored experiences based on diagnostics (system).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' '0' 'DWord'
	# Disable tailored experiences (user).

	Add-RegEntry 'HKCU:\Software\Microsoft\Siuf\Rules' 'PeriodInNanoSeconds' '0' 'DWord'
	# Set feedback period to 0 (never prompt).

	Add-RegEntry 'HKCU:\Software\Microsoft\MediaPlayer\Preferences' 'UsageTracking' '0' 'DWord'
	# Disable Windows Media Player usage tracking.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_TrackDocs' '0' 'DWord'
	# Do not track recently opened items for Start.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack' 'Start' '4' 'DWord'
	# Disable Connected User Experiences and Telemetry service (DiagTrack). 4=Disabled.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'HideRecentlyAddedApps' '0' 'DWord'
	# Show recently added apps (0=show). (Note: later you also disable some Start suggestions.)

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpyNetReporting' '0' 'DWord'
	# Disable Microsoft MAPS cloud reporting.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' '2' 'DWord'
	# Prompt before sending samples (2=never send automatically).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' 'DontReportInfectionInformation' '1' 'DWord'
	# Malicious Software Removal Tool: don't report infection info.

	# ===============================
	# PRINTING
	# ===============================

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'SpoolerPriority' '128' 'DWord'
	# Raise print spooler priority (higher value = more priority).

	Add-RegEntry 'HKCU:\Control Panel\International' 'iPaperSize' '9' 'String'
	# Default paper size (9 = A4).

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International' 'iPaperSize' '9' 'String'
	# Machine default paper size A4.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'KMPrintersAreBlocked' '0' 'DWord'
	# Do not block KM (Konica Minolta) printers.

	# ===============================
	# STARTUP / PERFORMANCE CLEANUP
	# ===============================

	Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# Clear per-user startup entries.

	Remove-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# Clear per-user startup notifications list.

	Remove-Item -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# Clear 32-bit machine-wide startup entries.

	Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  -Recurse -Force -EA SilentlyContinue | Out-Null
	# Clear machine-wide startup entries.

	# ===============================
	# SERVICES START TYPE / DISABLES
	# ===============================

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\LicenseManager' 'Start' '3' 'DWord'
	# License Manager service: Manual (3).

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent' 'Start' '3' 'DWord'
	# OpenSSH Authentication Agent: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPAppHelperCap' 'Start' '3' 'DWord'
	# HP Telemetry/Helper services: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPCustomCapDriver' 'Start' '3' 'DWord'
	# HP custom capture driver: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPDiagsCap' 'Start' '3' 'DWord'
	# HP diagnostics capture: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPNetworkCap' 'Start' '3' 'DWord'
	# HP network capture: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPPrintScanDoctorService' 'Start' '3' 'DWord'
	# HP Print and Scan Doctor service: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\hpqcaslwmiex' 'Start' '3' 'DWord'
	# HP CASL WMI Ex: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSmartDeviceAgentBase' 'Start' '3' 'DWord'
	# HP Smart Device Agent: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSupportSolutionsFrameworkService' 'Start' '3' 'DWord'
	# HP Support Solutions Framework: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HPSysInfoCap' 'Start' '3' 'DWord'
	# HP System Info capture: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\HpTouchpointAnalyticsService' 'Start' '3' 'DWord'
	# HP Touchpoint Analytics: Manual (instead of auto).

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\RstMwService' 'Start' '3' 'DWord'
	# Intel RST (Management/WMI) service: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Intel R Capability Licensing Service TCP IP Interface' 'Start' '3' 'DWord'
	# Intel Capability Licensing Service: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SECOMNService' 'Start' '3' 'DWord'
	# Intel/Third-party service (common): Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\USER_ESRV_SVC_QUEENCREEK' 'Start' '3' 'DWord'
	# Intel Energy Server Service (power telemetry): Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Intel R SUR QC SAM' 'Start' '3' 'DWord'
	# Intel System Usage Report (SUR) service: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\jhi_service' 'Start' '3' 'DWord'
	# Intel Dynamic Application Loader Host Interface: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SystemUsageReportSvc_QUEENCREEK' 'Start' '3' 'DWord'
	# Intel System Usage Report Svc: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service' 'Start' '3' 'DWord'
	# Apple Mobile Device service: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\MozillaMaintenance' 'Start' '3' 'DWord'
	# Mozilla Maintenance service: Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WsAppService3' 'Start' '3' 'DWord'
	# Wacom/Workspace App service (common name): Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ESRV_SVC_QUEENCREEK' 'run' '0' 'DWord'
	# Intel ESRV flag 'run' off.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ESRV_SVC_QUEENCREEK' 'Start' '3' 'DWord'
	# Intel ESRV start type Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch' 'Start' '3' 'DWord'
	# Windows Search start type Manual.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\SysMain' 'Start' '4' 'DWord'
	# SysMain (Superfetch) disabled.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice' 'Start' '4' 'DWord'
	# WAP Push Message Routing service disabled.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVPN App Service' 'Start' '4' 'DWord'
	# ExpressVPN App Service disabled.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVPN System Service' 'Start' '4' 'DWord'
	# ExpressVPN System Service disabled.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVPN VPN Service' 'Start' '4' 'DWord'
	# ExpressVPN VPN Service disabled.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc' 'Start' '4' 'DWord'
	# Windows Error Reporting service disabled.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' '1' 'DWord'
	# Disable Windows Error Reporting (policy).

	# ===============================
	# Improve shutdown & responsiveness
	# ===============================

	Add-RegEntry 'HKCU:\Control Panel\Desktop' 'AutoEndTasks' '1' 'String'
	# Automatically end tasks at logoff/shutdown.

	Add-RegEntry 'HKCU:\Control Panel\Desktop' 'SmoothScroll' '0' 'DWord'
	# Disable smooth scrolling in UI.

	Add-RegEntry 'HKCU:\Control Panel\Desktop' 'WaitToKillAppTimeout' '1500' 'String'
	# App kill timeout (ms) when logging off/shutdown.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control' 'WaitToKillServiceTimeout' '1500' 'String'
	# Service kill timeout (ms) on shutdown.

	Add-RegEntry 'HKCU:\Control Panel\Desktop' 'HungAppTimeout' '1500' 'String'
	# Hung app timeout (ms) before "Not responding".

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'IRQ8Priority' '1' 'DWord'
	# Give system clock (IRQ8) priority boost (legacy tweak).

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher' '0' 'DWord'
	# Disable Prefetcher (0=disable).

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnableSuperfetch' '0' 'DWord'
	# Disable Superfetch (SysMain) (legacy; service also disabled above).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter' 'NoMobilityCenter' '1' 'DWord'
	# Disable Windows Mobility Center UI.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoInstrumentation' '1' 'DWord'
	# Disable shell instrumentation (reduces certain data collection).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' 'AllowWindowsInkWorkspace' '0' 'DWord'
	# Disable Windows Ink Workspace.

	Add-RegEntry 'HKCU:\Software\Microsoft\input\TIPC' 'Enabled' '0' 'DWord'
	# Disable Text Input Processor features (TIPC).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' 'CEIPEnable' '0' 'DWord'
	# Disable Customer Experience Improvement Program.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' '1' 'DWord'
	# Disable application inventory.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableUAR' '1' 'DWord'
	# Disable Program Compatibility Assistant (User Account Reporting).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' '0' 'DWord'
	# Disable Application Impact Telemetry.

	# ===============================
	# TASKBAR / SEARCH
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoChangeStartMenu' '0' 'DWord'
	# Allow Start menu changes (0=allow).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAl' '0' 'DWord'
	# Taskbar alignment: 0=Left, 1=Center.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowTaskViewButton' '0' 'DWord'
	# Hide Task View button on taskbar.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' '0' 'DWord'
	# Hide Chat (Meet/Teams) button.

	Add-RegEntry 'HKLM:\Software\Policies\Microsoft\Windows\Windows Feeds' 'EnableFeeds' '0' 'DWord'
	# Hide News and Interests/Feeds.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' '1' 'DWord'
	# Hide Meet Now (user policy).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAMeetNow' '1' 'DWord'
	# Hide Meet Now (machine policy).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' 'PeopleBand' '0' 'DWord'
	# Hide People band on taskbar (0=hide).

	Add-RegEntry 'HKLM:\Software\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' '0' 'DWord'
	# Disable Widgets/Feeds (policy).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'SearchboxTaskbarMode' '1' 'DWord'
	# Taskbar search: 0=hide, 1=icon only, 2=search box, 3=icon+label.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarDa' '0' 'DWord'
	# Disable Widgets button on taskbar.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds' 'ShellFeedsTaskbarViewMode' '2' 'DWord'
	# Feeds taskbar view mode (2=off/hidden).

	# ===============================
	# BIOMETRICS
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' 'Enabled' '1' 'DWord'
	# Allow biometric features (Windows Hello).

	# ===============================
	# CLIPBOARD
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowClipboardHistory' '1' 'DWord'
	# Enable clipboard history.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard' '0' 'DWord'
	# Disable clipboard sync across devices.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ClipboardHistory' 'SyncPolicy' '5' 'DWord'
	# Clipboard sync policy: 5 = disabled/not allowed.

	# ===============================
	# SETTING SYNC (MICROSOFT ACCOUNT)
	# ===============================

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization' 'Enabled' '0' 'DWord'
	# Disable sync for Personalization.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings' 'Enabled' '0' 'DWord'
	# Disable sync for Browser settings.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials' 'Enabled' '0' 'DWord'
	# Disable sync for passwords/credentials.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language' 'Enabled' '0' 'DWord'
	# Disable sync for Language.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility' 'Enabled' '0' 'DWord'
	# Disable sync for Accessibility.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows' 'Enabled' '0' 'DWord'
	# Disable sync for Windows settings group.

	# ===============================
	# GENERAL TWEAKS
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AutoDownloadAndUpdateMapData' '0' 'DWord'
	# Disable automatic map data download/update.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableUwpStartupTasks' '1' 'DWord'
	# Enable UWP apps registering startup tasks. (to avoid issues)

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'SupportUwpStartupTasks' '1' 'DWord'
	# support UWP startup tasks. (to avoid issues)

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableVirtualization' '1' 'DWord'
	# Enable UAC virtualization for legacy apps.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' '0' 'DWord'
	# Prevent silent installation of suggested apps.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' '0' 'DWord'
	# Disable soft landing tips/first-run suggestions.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' '0' 'DWord'
	# Disable post-OOBE "Get even more out of Windows" (SCOOBE).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' '0' 'DWord'
	# Disable Remote Assistance invitations.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' '1' 'DWord'
	# Deny Remote Desktop (RDP) connections.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' 'NoGenTicket' '0' 'DWord'
	# Allow generation of Windows Store licensing tickets (UWP license gen). (to Avoid issues).

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' 'AllowUntriggeredNetworkTrafficOnSettingsPage' '0' 'DWord'
	# Block background network traffic on Maps settings page.

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' 'EnableActiveProbing' '0' 'DWord'
	# Disable active Internet connectivity probing (NCSI). May affect captive portal detection.

	Add-RegEntry 'HKCU:\Control Panel\Keyboard' 'InitialKeyboardIndicators' '2' 'String'
	Add-RegEntry 'HKU:\.DEFAULT\Control Panel\Keyboard' 'InitialKeyboardIndicators' '2' 'String'
	# NumLock state at logon for default profile (2147483650 = NumLock ON for all users).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput' 'EnableTouchKeyboardAutoInvokeInDesktopMode' '0' 'DWord'
	# Prevent touch keyboard from auto-appearing in desktop mode.

	Add-RegEntry 'HKLM:\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' '0' 'DWord'
	# Unpin OneDrive from File Explorer navigation pane.

	Add-RegEntry 'HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}' 'SortOrderIndex' '84' 'DWord'
	# Libraries display order index in navigation pane.

	Add-RegEntry 'HKLM:\SOFTWARE\Classes\AllFilesystemObjects' 'DefaultDropEffect' '0' 'DWord'
	# Default drag & drop effect (0=ask/none, 1=copy, 2=move, 4=link). Here 0 leaves default behavior.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'ShowDriveLettersFirst' '0' 'DWord'
	# Show drive letters: 0=after label (default), 1=before, 2=hide network, 4=hide local.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'Link' 'hex 3:00,00,00,00' 'String'
	# Remove " - Shortcut" suffix on new shortcuts (per-user).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'Link' 'hex 3:00,00,00,00' 'String'
	# Remove " - Shortcut" suffix (machine-wide).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'DisablePreviewDesktop' '0' 'DWord'
	# Peek at desktop when hovering taskbar (0=allow).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoPreviewPane' '0' 'DWord'
	# Allow Preview Pane in Explorer (0=allow).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoLowDiskSpaceChecks' '1' 'DWord'
	# Disable low disk space warnings.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' 'ModelDownloadAllowed' '0' 'DWord'
	# Block speech model downloads (OneCore).

	Add-RegEntry 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'fullprivilegeauditing' '0' 'DWord'
	# LSA privilege use auditing disabled (0). (1 enables detailed audits).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowAllTrustedApps' '1' 'DWord'
	# Allow sideloading of trusted apps.

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' 'AllowDevelopmentWithoutDevLicense' '1' 'DWord'
	# Allow developer mode for sideloading without Dev license.

	# ===============================
	# NOTIFICATIONS
	# ===============================

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'NOC_GLOBAL_SETTING_TOASTS_ENABLED' '0' 'DWord'
	# Turn off all toast notifications (user).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' 'ToastEnabled' '0' 'DWord'
	# Disable toast notifications globally (note: many specific toasts are disabled).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK' '0' 'DWord'
	# Block notifications above lock screen.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSyncProviderNotifications' '0' 'DWord'
	# Disable OneDrive/Sync provider marketing notifications.

	# ===============================
	# ADVERTISING / SUGGESTIONS
	# ===============================

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' '0' 'DWord'
	# Disable advertising ID (system).

	Add-RegEntry 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' 'AllowAdvertising' '0' 'DWord'
	# Block Bluetooth advertising features.

	Add-RegEntry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging' 'AllowMessageSync' '0' 'DWord'
	# Disable message sync (SMS) to cloud.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353698Enabled' '0' 'DWord'
	# Disable suggested content tile (various IDs below are different slots).

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' '0' 'DWord'
	# Disable suggested content tile.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' '0' 'DWord'
	# Disable suggested content tile.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' '0' 'DWord'
	# Disable suggested content tile.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' '0' 'DWord'
	# Disable suggested content tile.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' '0' 'DWord'
	# Disable suggested content tile.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' '0' 'DWord'
	# Disable suggested content tile.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338387Enabled' '0' 'DWord'
	# Disable suggested content tile.

	# ===============================
	# FOCUS ASSIST
	# ===============================

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\QuietHours' 'QuietHoursEnabled' '1' 'DWord'
	# Enable Focus Assist.

	Add-RegEntry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\QuietHours' 'QuietHoursActive' '1' 'DWord'
	# Focus Assist active (Priority only by default).
}


function ShrinkC-MakeNew {
	param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$DriveLetter
	)
	if (Get-Volume -DriveLetter $DriveLetter -EA SilentlyContinue) { Write-Warning "Partition $DriveLetter already exist"; return }
	$CSizeMax = (Get-PartitionSupportedSize -DriveLetter C).SizeMax
	$CSizeMin = (Get-PartitionSupportedSize -DriveLetter C).SizeMin
	$CShrink = ($CSizeMax - $CSizeMin) / 1000000000 #Shrinkable amount in GB
	if ($CShrink -gt 70) {
		Resize-Partition -DriveLetter C -Size ($CSizeMax - 50GB) -EA SilentlyContinue | Out-Null
		$CDiskNumber = (Get-Volume | where DriveLetter -EQ "C" | Get-Partition | Get-Disk).Number
		New-Partition -DiskNumber $CDiskNumber -UseMaximumSize -DriveLetter $DriveLetter -EA SilentlyContinue | Out-Null
		Format-Volume -DriveLetter $DriveLetter -FileSystem NTFS -Force -EA SilentlyContinue | Out-Null
	} else { Write-Host -f C "`r`n Not Enough shrinkable Space on Partition C" }
}

function D-ScanFolder {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "************************* Creating Drive D (If not found) & Creating shared Scan folder in it **************************"
	Write-Host -f C "======================================================================================================================`r`n"
	if (!(Get-Volume -DriveLetter D -EA SilentlyContinue)) { ShrinkC-MakeNew "D" }
	elseif ((Get-Volume -DriveLetter D -EA SilentlyContinue).DriveType -ne "Fixed") {
		try { $successful = $true; Set-WmiInstance -InputObject (Get-WmiObject -Class Win32_volume -Filter "DriveLetter = 'd:'" ) -Arguments @{DriveLetter = 'Z:' } }
		catch { $successful = $false; Write-Host -f C "Busy Removable Partition D" }
		if ($successful) { ShrinkC-MakeNew "D" }
	}
	if ((Get-Volume -DriveLetter D -EA SilentlyContinue).DriveType -eq "Fixed") {
		if (!(Test-Path -Path "D:\Scans" -EA SilentlyContinue)) { New-Item -Path "D:\" -Name "Scans" -ItemType Directory -EA SilentlyContinue | Out-Null }
		Remove-SmbShare -Name "Scans" -Confirm:$False -Force -EA SilentlyContinue | Out-Null
		if (!([System.IO.Directory]::Exists("\\localhost\Scans"))) { New-SmbShare -Name "Scans" -Path "D:\Scans" -FullAccess "Everyone" -EA SilentlyContinue | Out-Null }
		else { Grant-SmbShareAccess -Name "Scans" -AccountName "Everyone" -AccessRight Full -Force -EA SilentlyContinue | Out-Null }
		$s = (New-Object -COM WScript.Shell).CreateShortcut("$env:PUBLIC\Desktop\Scans.lnk"); $s.TargetPath = "D:\Scans\"; $s.Save()
	}
	Remove-SmbShare -Name "Users" -Confirm:$False -Force -EA SilentlyContinue | Out-Null
}

function Set-EmptyIFEO {
	param(
		[Parameter(Mandatory = $true)][string]$TargetExe,
		[string]$DebuggerName = "EmptyIFEO.exe"
	)

	$sys32 = "$env:SystemRoot\System32"
	$exePath = Join-Path $sys32 $DebuggerName

	# --- Minimal Win32 GUI EXE bytes (~1.5 KB) ---
	$exeBytes = [byte[]](
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
		0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xE0, 0x00, 0x00, 0x00, 0x0F, 0x01, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00
		# Total: ~1.5 KB minimal GUI stub
	)

	# --- Write EXE to System32 ---
	try {
		[IO.File]::WriteAllBytes($exePath, $exeBytes)
		Write-Host "[OK] Wrote minimal empty EXE to $exePath"
	} catch {
		Write-Error "Failed to write EXE: $_"
		return
	}

	# --- IFEO registry paths (64-bit and 32-bit) ---
	$keys = @(
		"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$TargetExe",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$TargetExe"
	)

	foreach ($key in $keys) {
		if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
		Add-RegEntry -Path $key -Name 'Debugger' -Value $exePath -PropertyType String -Force | Out-Null
		Write-Host "[OK] Set Debugger for $key -> $exePath"
	}

	Write-Host "`nDone! IFEO Debugger is set for $TargetExe (32-bit and 64-bit)."
}

function Adj-Hosts {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Adjusting Hosts file *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	Write-Host -f C "`r`n Taking ownership of hosts file"
	AdminTakeownership -Path "$env:SystemRoot\System32\drivers\etc\hosts"
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
	Set-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value $HostsFile -Force -EA SilentlyContinue | Out-Null
}

function uninsSara-Office {
	Write-Host -f C "`r`n *** Removing currently installed MS office products using SaraCmd *** `r`n"
	# Run SaraCMD non-interactive Script
	New-Item -Path "$env:TEMP\IA\office" -ItemType Directory -EA SilentlyContinue | Out-Null
	Invoke-WebRequest -Uri "https://aka.ms/SaRAEnterpriseHelper" -OutFile "$env:TEMP\IA\office\ExecuteSaraCmd.zip"
	Expand-Archive -LiteralPath "$env:TEMP\IA\office\ExecuteSaraCmd.zip" -DestinationPath "$env:TEMP\IA\office" -Force -EA SilentlyContinue | Out-Null
	$SNIfile = "$env:TEMP\IA\office\ExecuteSaraCmd.ps1"
	$find = '$SaraScenarioArgument = ""'; $replace = '$SaraScenarioArgument = "-S OfficeScrubScenario -Script -AcceptEula -OfficeVersion All"'
	(Get-Content $SNIfile).replace($find, $replace) | Set-Content -Path $SNIfile -Force -EA SilentlyContinue | Out-Null
	& "$SNIfile"
}

function Stop-OfficeProcess {
	Write-Host "Stopping running Office applications ..."
	$OfficeProcessesArray = "lync", "winword", "excel", "msaccess", "mstore", "infopath", "setlang", "msouc", "ois", "onenote", "outlook", "powerpnt", "mspub", "groove", "visio", "winproj", "graph", "teams"
	foreach ($ProcessName in $OfficeProcessesArray) {
		if (Get-Process -Name $ProcessName -EA SilentlyContinue) {
			if (Stop-Process -Name $ProcessName -Force -EA SilentlyContinue) {
				Write-Output "Process $ProcessName was stopped."
			} else {
				Write-Warning "Process $ProcessName could not be stopped."
			}
		}
	}
	Stop-Service -Name ClickToRunSvc
	taskkill /f /im OfficeClickToRun.exe
	taskkill /f /im AppVShNotify.exe
}

function Uninstall-MicrosoftOffice {

	Write-Host -f C "`r`n *** Uninstalling Microsoft Office *** `r`n"
	Stop-OfficeProcess

	# Define registry paths to search for Office installations
	$uninstallPaths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
		"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	)

	# Find all Microsoft Office installations
	$officePrograms = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Microsoft Office*" }
	if (-not $officePrograms) {
		Write-Host "No Microsoft Office installations found."
		return
	}

	foreach ($program in $officePrograms) {
		Write-Host -f C "Uninstalling: $($program.DisplayName)"

		# Check if this is a ClickToRun Office installation
		if ($program.UninstallString -like "*OfficeClickToRun*") {
			try {
				# Extract the executable path and parameters
				$executablePath = $program.UninstallString.Split('"')[1]
				$parameters = $program.UninstallString.Substring($executablePath.Length + 2) | Select-Object -First 1

				# Add parameters for silent uninstallation
				$parameters += " updatepromptuser=False displaylevel=false forceappshutdown=True"

				Write-Host "Running: $executablePath $parameters"
				Start-Process -FilePath $executablePath -ArgumentList $parameters -Wait -NoNewWindow
				Write-Host -f Green "Successfully uninstalled: $($program.DisplayName)"
			} catch {
				Write-Host -f Red "Failed to uninstall: $($program.DisplayName) - $($_.Exception.Message)"
			}
		} else {
			Write-Host -f Yellow "Skipping non-ClickToRun Office installation: $($program.DisplayName)"
			Write-Host "This function only supports ClickToRun Office installations."
		}
	}
	# Remove MS Store Office 365
	Remove-AppxApp -AppName "Microsoft.Office.Desktop"
	# Clean any remaining package
	Get-Package -Name "*Microsoft Office*" -EA SilentlyContinue | Uninstall-Package
}

function ActOffice {
	Write-Host "Activating MS Office..." -ForegroundColor Cyan
	$Url = "https://git.activated.win/massgrave/Microsoft-Activation-Scripts/raw/branch/master/MAS/All-In-One-Version-KL/MAS_AIO.cmd"
	$Path = "$env:ALLUSERSPROFILE\ACT.cmd"
	Start-BitsTransfer -Source $Url -Destination $Path
	Start-Sleep -Seconds 1
	Start-Process -FilePath $Path -ArgumentList '/K-Office', '/K-NoRenewalTask' -Verb RunAs -Wait
	Start-Sleep -Seconds 1
	Start-Process -FilePath $Path -ArgumentList '/Z-Office' -Verb RunAs -Wait
	Remove-Item $Path -Force
	$Officeospp64 = "$Env:Programfiles\Microsoft Office\Office16\ospp.vbs"; $Officeospp32 = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\ospp.vbs"
	if (Test-Path -Path $Officeospp64 -EA SilentlyContinue) { $officeospp = $Officeospp64 } elseif (Test-Path -Path $Officeospp32 -EA SilentlyContinue) { $officeospp = $Officeospp32 } else { Write-Host -f C "Office16 ospp.vbs not found"; return }
	$LicenseStatus = cscript $officeospp /dstatus | Where-Object { ($_ -like "*LICENSE STATUS:*") -and ($_ -like "*LICENSED*") }
	if ($LicenseStatus) { Write-Host -f Green "Successfully activated Office.`r`nFull activation details below`r`n" } else { Write-Host -f Green "Office Activation Failed" }
	cscript $officeospp /dstatus
	return
}

function Config-Office {
	# -----------------------------
	# Office Application Settings
	# -----------------------------
	# Disable automatic updates (user wonâ€™t get updates)
	Add-RegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'EnableAutomaticUpdates' '0' 'DWord'
	# Hide update-related options in the UI (user cannot enable updates manually)
	Add-RegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'HideEnableDisableUpdates' '1' 'DWord'

	# Prevent Microsoft Teams from auto-installing when Office is installed or updated
	Add-RegEntry 'HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' 'PreventTeamsInstall' '1' 'DWord'

	# Enable inline text prediction in Outlook/Word mail editor (AI predictive text)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings' 'InlineTextPrediction' '1' 'DWord'


	# -----------------------------
	# Common Office Policies
	# -----------------------------
	# Default dictation language = English (US)
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'ActiveDictationLanguage' 'en-US' 'String'
	# Set UI theme = Dark Gray (3)
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'UI Theme' '3' 'DWord'


	# -----------------------------
	# Telemetry & Privacy
	# -----------------------------
	# Disable Office telemetry (client-side)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\Common\ClientTelemetry' 'DisableTelemetry' '1' 'DWord'
	# Disable sending telemetry (policy)
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry' 'SendTelemetry' '3' 'DWord'
	# Block sending customer info
	Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\common\privacy" "SendCustomerInfo" '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerData' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerDataOptIn' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'SendCustomerDataOptInReason' '0' 'DWord'
	# Disable feedback collection
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'Enabled' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'IncludeEmail' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback' 'SurveyEnabled' '0' 'DWord'
	# Disable quality metrics collection
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'QMEnable' '0' 'DWord'
	# Disable update reliability data collection
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common' 'UpdateReliabilityData' '0' 'DWord'
	# Disable connected services and online content
	#Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'ControllerConnectedServicesEnabled' '2' 'DWord'
	#Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'DisconnectedState' '2' 'DWord'
	#Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'DownloadContentDisabled' '2' 'DWord'
	#Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy' 'UserContentDisabled' '2' 'DWord'
	#Disable Cloud Login prompts
	# Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\common\signin" "SignInOptions" '3' 'DWord'
	# Disable online content for all apps
	Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\common\internet" "UseOnlineContent" '1' 'DWord'
	# Per-application online content disabling
	Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\word\options" "UseOnlineContent" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\excel\options" "UseOnlineContent" '1' 'DWord'
	Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\powerpoint\options" "UseOnlineContent" '1' 'DWord'
	# Disable connected experiences
	Add-RegEntry "HKCU:\Software\Policies\Microsoft\office\16.0\common\officecloud" "UseOnlineContent" '1' 'DWord'

	# -----------------------------
	# Office Service Manager (OSM)
	# -----------------------------
	# Enable file obfuscation (for telemetry data)
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'EnableFileObfuscation' '1' 'DWord'
	# Block OSM uploads
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'EnableUpload' '0' 'DWord'
	# Disable logging in OSM
	Add-RegEntry 'HKCU:\Software\Policies\Microsoft\Office\16.0\osm' 'Enablelogging' '0' 'DWord'


	# -----------------------------
	# Word Configuration
	# -----------------------------
	# Enable Arabic date formatting
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'AraDate' '1' 'DWord'
	# Prevent Word from opening files in the background
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'BackgroundOpen' '0' 'DWord'
	# Enable background pagination for long docs
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'BkgrndPag' '1' 'DWord'
	# Show Developer tab in the ribbon
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DeveloperTools' '1' 'DWord'
	# Skip Start screen when opening Word
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DisableBootToOfficeStart' '1' 'DWord'
	# Force Word to use light mode (disable dark mode)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'DisableDarkMode' '1' 'DWord'
	# Default number formatting = context (2 = Hindi/Arabic context)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'NumForm' '2' 'DWord'
	# Default to Print Layout view when opening documents
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'PreferredView' '0' 'DWord'
	# Hide ruler by default
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'Ruler' '0' 'DWord'
	# Show background graphics in documents
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' 'ShowBkg' '1' 'DWord'
	# Set default paper size to A4 in Word Wizards
	Add-RegEntry 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Wizards' 'PageSize' 'A4' 'String'


	# -----------------------------
	# Excel Configuration
	# -----------------------------
	# Default to A4 paper size instead of Letter
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'A4Letter' '1' 'DWord'
	# Show Developer tab in the ribbon
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'DeveloperTools' '1' 'DWord'
	# Skip the Start screen when opening Excel
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'DisableBootToOfficeStart' '1' 'DWord'
	# Disable Accessibility Checker from running automatically
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'EnableAccChecker' '0' 'DWord'
	# Open Excel maximized by default (3 = maximized)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'Maximized' '3' 'DWord'
	# Force Gregorian calendar instead of Hijri
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'Xl9_hijri' '0' 'DWord'
	# Recognize smart tags = limited (2)
	Add-RegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'recognizesmarttags' '2' 'DWord'
	# VBA force Loading
	Add-RegEntry 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\options' 'ForceVBALoadFromSource' '1' 'DWord'


	# -----------------------------
	# Excel Security Settings
	# -----------------------------
	# Disable warning prompts for external data connections
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'DataConnectionWarnings' '0' 'DWord'
	# Disable rich data type connection warnings
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'RichDataConnectionWarnings' '0' 'DWord'
	# Disable workbook link warnings (linked files wonâ€™t trigger alerts)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'WorkbookLinkWarnings' '0' 'DWord'
	# Show macro warnings, but do not disable them (1 = enable warnings)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'VBAWarnings' '1' 'DWord'
	# Allow access to VBA project model (needed for macros)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security' 'AccessVBOM' '1' 'DWord'


	# -----------------------------
	# Excel AutoRecover & Backup
	# -----------------------------
	# AutoRecover every 1 minute (default is 10)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options' 'AutoRecoverTime' '1' 'DWord'
	# AutoSave every 1 minute
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel' 'AutoSaveInterval' '1' 'DWord'
	# Try to recover corrupted workbooks
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel' 'ExcelWorkbookAutoRecoverDirty' '1' 'DWord'
	# Policy-based AutoRecover delay = 1 min
	Add-RegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'autorecoverdelay' '1' 'DWord'
	# Policy-based AutoRecover enabled
	Add-RegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'autorecoverenabled' '1' 'DWord'
	# Policy-based AutoRecover time = 1 min
	Add-RegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'autorecovertime' '1' 'DWord'
	# Policy: skip Start screen
	Add-RegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'disableboottoofficestart' '1' 'DWord'
	# Always recover unsaved changes (policy enforced)
	Add-RegEntry 'HKCU:\software\policies\microsoft\office\16.0\excel\options' 'keepunsavedchanges' '1' 'DWord'


	# -----------------------------
	# Excel File Block & Protected View
	# -----------------------------
	# Disable opening blocked file types in Protected View (0 = allow opening normally)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'OpenInProtectedView' '0' 'DWord'
	# Allow older Excel formats (disable blocking)
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL4Workbooks' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL4Worksheets' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL4Macros' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL3Workbooks' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL3Worksheets' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL3Macros' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL2Workbooks' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL2Worksheets' '0' 'DWord'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\FileBlock' 'XL2Macros' '0' 'DWord'

	# Protected View (PV) settings
	# 0 = Enabled (use PV), 1 = Disabled (do not use PV)
	# Allow files from the internet to open normally
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView' 'DisableInternetFilesInPV' '1' 'DWord'
	# Allow email attachments to open normally
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView' 'DisableAttachmentsInPV' '1' 'DWord'
	# Allow files from unsafe locations to open normally
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView' 'DisableUnsafeLocationsInPV' '1' 'DWord'


	# -----------------------------
	# Excel Trusted Locations
	# -----------------------------
	# Allow network locations to be trusted
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations' 'AllowNetworkLocations' '1' 'DWord'
	# Trust entire C:\ drive
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location90' 'Path' 'C:\' 'String'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location90' 'AllowSubfolders' '1' 'DWord'
	# Trust entire D:\ drive
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location91' 'Path' 'D:\' 'String'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location91' 'AllowSubfolders' '1' 'DWord'
	# Trust all mapped network drives
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location92' 'Path' '\\' 'String'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location92' 'AllowSubfolders' '1' 'DWord'
	# Trust all UNC paths
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location93' 'Path' '//' 'String'
	Add-RegEntry 'HKCU:\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location93' 'AllowSubfolders' '1' 'DWord'


	# -----------------------------
	# Printer Configuration
	# -----------------------------
	# Loop through all installed printers and force A4 + single-sided printing
	$Printers = Get-Printer
	foreach ($Printer in $Printers) { Set-PrintConfiguration -PrinterName $Printer.Name -PaperSize A4 -DuplexingMode OneSided }
}

function Deploy-Office {
	Write-Host -f C "`r`n *** Downloading & extracting Office Deployment Tool *** `r`n"
	for ($i = 1; $i -le 50; $i++) {
		$webpage2 = Repeatiwr -uri "https://www.microsoft.com/en-us/download/details.aspx?id=49117"
		$FileLink = $webpage2.Links | Where-Object href -Like '*officedeploymenttool*exe' | select -Last 1 -expand href
		if ($Filelink -ne $null) { break }
	}
	if ($Filelink -ne $null) { Invoke-WebRequest -Uri $FileLink -OutFile "$env:TEMP\IA\office\officedeploymenttool.exe" }
	if (Test-Path -Path "$env:TEMP\IA\office\officedeploymenttool.exe" -EA SilentlyContinue) { Start-Process -Wait -FilePath "$env:TEMP\IA\office\officedeploymenttool.exe" -ArgumentList "/extract:$env:TEMP\IA\office", "/quiet", "/passive", "/norestart" -EA SilentlyContinue | Out-Null }
	Write-Host -f C "`r`n *** Installing Office ... *** `r`n"
	if (Test-Path -Path "$env:TEMP\IA\office\setup.exe" -EA SilentlyContinue) {
		Start-Process -WindowStyle Minimized -Wait -FilePath "$env:TEMP\IA\office\setup.exe" -ArgumentList "/configure", "$env:TEMP\IA\office\configuration.xml" -EA SilentlyContinue | Out-Null
		Start-Sleep -Seconds 2
	} else { Write-Host -f C "`r`n Failed to download & extract Office Deployment Tool" }
}

function configurationFile21PP {
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
	Set-Content -Path "$env:TEMP\IA\office\Configuration.xml" -Value $ConfigurationFile -Force -EA SilentlyContinue | Out-Null
}

function configurationFile24PP {
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
	Set-Content -Path "$env:TEMP\IA\office\Configuration.xml" -Value $ConfigurationFile -Force -EA SilentlyContinue | Out-Null
}

function New-OfficeShortcuts {
	# Function to read install path from registry for a given app
	function Get-OfficeAppPath($appName) {
		$regPaths = @(
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$appName.exe",
			"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$appName.exe"
		)
		foreach ($reg in $regPaths) {
			try {
				$path = (Get-ItemProperty -Path $reg -EA SilentlyContinue).'(default)'
				if (Test-Path $path) { return $path }
			} catch { }
		}
		return $null
	}

	# Try registry first
	$wordPath = Get-OfficeAppPath "WINWORD"
	$excelPath = Get-OfficeAppPath "EXCEL"
	if ($wordPath) { Write-Host -f C "Registry Word Path:$wordPath" }
	if ($excelPath) { Write-Host -f C "Registry Excel Path:$excelPath" }

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

function Ins-Office21PP {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Start Installing Office 2021 Pro Plus *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	Uninstall-MicrosoftOffice
	uninsSara-Office
	configurationFile21PP
	Deploy-Office
	# ActivateOfficeKMS
	Config-Office
	New-OfficeShortcuts
	ActOffice
}

function Ins-Office24PP {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Start Installing Office 2024 Pro Plus *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	Uninstall-MicrosoftOffice
	uninsSara-Office
	configurationFile24PP
	Deploy-Office
	# ActivateOfficeKMS
	Config-Office
	New-OfficeShortcuts
	ActOffice
}

function Create-RLMCopyShortcut {
	# 1. Paths
	$vbsPath = Join-Path $env:SystemRoot "System32\CopyRLM.vbs"
	$desktop = [Environment]::GetFolderPath("Desktop")
	$shortcutPath = Join-Path $desktop "Copy RLM.lnk"
	$iconPath = Join-Path $env:SystemRoot "System32\imageres.dll"

	# 2. Create the VBScript
	$vbsContent =
	@"
Set objShell = CreateObject("Wscript.Shell")
' Run PowerShell silently to copy RLM to clipboard
objShell.Run "powershell.exe -NoProfile -Command Set-Clipboard ([char]0x200F);exit", 0, False
"@
	# 3. Save VBS (requires admin if writing to System32)
	try {
		Set-Content -Path $vbsPath -Value $vbsContent -Force -Encoding ASCII
		Write-Host "✅ VBScript created at $vbsPath"
	} catch {
		Write-Warning "Cannot write to System32. Run PowerShell as Admin."
		return
	}

	# 4. Create Desktop Shortcut
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut($shortcutPath)
	$Shortcut.TargetPath = "wscript.exe"
	$Shortcut.Arguments = "`"$vbsPath`""
	$Shortcut.IconLocation = "$iconPath,242"  # clipboard icon index in imageres.dll
	$Shortcut.Save()

	Write-Host "✅ Shortcut created on Desktop: $shortcutPath"
	Write-Host "Double-click the shortcut or assign a hotkey to copy RLM to clipboard silently."
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
	if ($Replace -or $ClearAll) { $Placement = '<CustomTaskbarLayoutCollection PinListPlacement="Replace">' } else { $Placement = '<CustomTaskbarLayoutCollection>' }
	$taskbar_layout2 =
	@"

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

function Ins-ExtraFonts {
	Write-Host -f C "`r`n *** Installing Extra Fonts *** `r`n"
	if (choco list -l -e -r dejavufonts) { Write-Host -f C "dejavufonts already installed" } else { Choco install dejavufonts -y }
	if (choco list -l -e -r victormononf) { Choco upgrade victormononf -y } else { Choco install victormononf -y }
	if (choco list -l -e -r montserrat.font) { Choco upgrade montserrat.font -y } else { Choco install montserrat.font -y }
	if (choco list -l -e -r opensans) { Choco upgrade opensans -y } else { Choco install opensans -y }
	if (choco list -l -e -r cascadiafonts) { Choco upgrade cascadiafonts -y } else { Choco install cascadiafonts -y }
}

function Pin-WhatsappWebChrome {
	Write-Host -f C "`r`n *** Pining Chrome whatsapp web to taskbar *** `r`n"
	$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'
	$Chrome = (Get-ItemProperty -Path $key -Name '(Default)').'(default)'
	if ($chrome -eq $null) {
		if (Test-Path '${env:ProgramFiles(x86)}\Google\Chrome' -EA SilentlyContinue) {
			$chrome = '${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe'
		} elseif (Test-Path '$Env:Programfiles\Google\Chrome' -EA SilentlyContinue) {
			$chrome = '$Env:Programfiles\Google\Chrome\Application\chrome.exe'
		} else { Write-Host "Not Found" }
	}
	Invoke-WebRequest -Uri "https://web.whatsapp.com/favicon-64x64.ico" -OutFile "$Env:Programfiles\Google\Chrome\WhatsApp.ico"
	$Arguments1 = " --new-window --force-app-mode --app=https://web.whatsapp.com/"
	$s = (New-Object -COM WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\WhatsAppWeb.lnk")
	$s.TargetPath = "$chrome"; $s.Arguments = $Arguments1; $s.IconLocation = "$Env:Programfiles\Google\Chrome\WhatsApp.ico"; $s.Save()
	Pin-to-taskbar -IDorPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\WhatsAppWeb.lnk" -PinType "DesktopApplicationLinkPath"
}

function Fix-MSWindows {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Fixing Windows *****************************"
	Write-Host -f C "======================================================================================================================`r`n"
	sfc /scannow
	# DISM /Online /Cleanup-Image /RestoreHealth
	# Start-Job -Name ReApps {Get-AppXPackage | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}} | Wait-Job -Timeout 400 | Format-Table -Wrap -AutoSize -Property Name,State
}

function Clean-up {
	Write-Host -f C "`r`n======================================================================================================================"
	Write-Host -f C "***************************** Cleaning up *****************************"
	Write-Host -f C "======================================================================================================================`r`n"

	# Wait for all background jobs to finish
	Wait-Job -State Running
	# Optionally receive and display the results of all jobs
	Get-Job | ForEach-Object {
		Write-Output "Result from job $($_.Id):"
		Receive-Job -Job $_
		Remove-Job -Job $_
	}
	Clear-PrintQueue
	Restart-ExplorerSilently
	Start-Sleep 1
	Refresh-Desktop
	Change_computer_name
	Remove-Item -LiteralPath "$env:TEMP\IA" -Force -Recurse -EA SilentlyContinue | Out-Null
	Remove-Item -LiteralPath "$env:TEMP" -Force -Recurse -EA SilentlyContinue | Out-Null
}

function Change_computer_name {

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
	$label.Location = New-Object System.Drawing.Point(10, 20)
	$label.Size = New-Object System.Drawing.Size(150, 20)
	$form.Controls.Add($label)

	# TextBox - New Computer Name
	$textBox = New-Object System.Windows.Forms.TextBox
	$textBox.Text = $env:COMPUTERNAME
	$textBox.Location = New-Object System.Drawing.Point(160, 18)
	$textBox.Size = New-Object System.Drawing.Size(200, 20)
	$form.Controls.Add($textBox)

	# Button - Change Computer Name
	$buttonChange = New-Object System.Windows.Forms.Button
	$buttonChange.Text = "Change Computer Name"
	$buttonChange.Location = New-Object System.Drawing.Point(110, 60)
	$buttonChange.Size = New-Object System.Drawing.Size(160, 30)
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
	$buttonRestart.Location = New-Object System.Drawing.Point(110, 110)
	$buttonRestart.Size = New-Object System.Drawing.Size(160, 30)
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

function Clear-PrintQueue {
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
	Stop-Service -Name Spooler -Force -EA SilentlyContinue

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
		Get-Process -Name $p -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
	}

	Start-Sleep -Seconds 2

	Write-Output "Clearing stuck print jobs..."

	# First try normal PowerShell print job cleanup
	Get-Printer | ForEach-Object {
		Get-PrintJob -PrinterName $_.Name -EA SilentlyContinue |
		Remove-PrintJob -Confirm:$false -EA SilentlyContinue
	}

	# Then do the hard clear in case jobs are still locked
	$spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"
	if (Test-Path $spoolPath) {
		Remove-Item "$spoolPath\*" -Force -EA SilentlyContinue -Confirm:$false
	}

	Write-Output "Starting Print Spooler service..."
	Start-Service -Name Spooler

	Restart-ExplorerSilently
	Write-Output "Done. Print queue has been fully cleared."
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

function Set-Personalization {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $false)]
		[string]$AccentColor = "126 115 95",   # "R G B" or "#RRGGBB" or "RRGGBB"

		[switch]$LightMode,                    # optional: enable light mode if set
		[switch]$NoRestart                     # optional: don't restart Explorer/ShellExperienceHost
	)

	# --- parse input ---
	if ($AccentColor -match '^#?[0-9A-Fa-f]{6}$') {
		$hex = $AccentColor.TrimStart('#')
		$r = [int][Convert]::ToInt32($hex.Substring(0, 2), 16)
		$g = [int][Convert]::ToInt32($hex.Substring(2, 2), 16)
		$b = [int][Convert]::ToInt32($hex.Substring(4, 2), 16)
	} elseif ($AccentColor -match '^\s*\d{1,3}\s+\d{1,3}\s+\d{1,3}\s*$') {
		$parts = ($AccentColor -split '\s+')
		$r = [int]$parts[0]; $g = [int]$parts[1]; $b = [int]$parts[2]
	} else {
		throw "AccentColor must be 'R G B' or '#RRGGBB' / 'RRGGBB'"
	}

	foreach ($v in @($r, $g, $b)) { if ($v -lt 0 -or $v -gt 255) { throw "RGB values must be 0..255" } }

	# --- Build DWORDs ---
	# DWM expects ABGR → swap R <-> B
	$dword_DWM = [BitConverter]::ToUInt32(@([byte]$b, [byte]$g, [byte]$r, 0xFF), 0)
	# Explorer expects ARGB → normal RGB
	$dword_Explorer = [BitConverter]::ToUInt32(@([byte]$r, [byte]$g, [byte]$b, 0xFF), 0)

	# --- Personalization: dark/light mode ---
	$personalizePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
	$lightValue = if ($LightMode) { 1 } else { 0 }
	Add-RegEntry -Path $personalizePath -Name "AppsUseLightTheme" -Value $lightValue -Type DWord -Force
	Add-RegEntry -Path $personalizePath -Name "SystemUsesLightTheme" -Value $lightValue -Type DWord -Force
	Add-RegEntry -Path $personalizePath -Name "ColorPrevalence" -Value 1 -Type DWord -Force

	# --- DWM keys (ABGR) ---
	$dwmPath = "HKCU:\SOFTWARE\Microsoft\Windows\DWM"
	New-Item -Path $dwmPath -Force | Out-Null
	Add-RegEntry -Path $dwmPath -Name "AccentColor" -Value $dword_DWM -Type DWord -Force
	Add-RegEntry -Path $dwmPath -Name "ColorizationColor" -Value $dword_DWM -Type DWord -Force
	Add-RegEntry -Path $dwmPath -Name "ColorizationAfterglow" -Value $dword_DWM -Type DWord -Force
	Add-RegEntry -Path $dwmPath -Name "AccentColorInactive" -Value $dword_DWM -Type DWord -Force
	Add-RegEntry -Path $dwmPath -Name "EnableWindowColorization" -Value 1 -Type DWord -Force
	Add-RegEntry -Path $dwmPath -Name "ColorizationColorBalance" -Value 60 -Type DWord -Force

	# --- Explorer keys (ARGB) ---
	$accentPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent"
	New-Item -Path $accentPath -Force | Out-Null
	Add-RegEntry -Path $accentPath -Name "AccentColor" -Value $dword_Explorer -Type DWord -Force
	Add-RegEntry -Path $accentPath -Name "AccentColorMenu" -Value $dword_Explorer -Type DWord -Force
	Add-RegEntry -Path $accentPath -Name "StartColorMenu" -Value $dword_Explorer -Type DWord -Force
	Add-RegEntry -Path $accentPath -Name "AccentColorInactive" -Value $dword_Explorer -Type DWord -Force

	# --- AccentPalette (8 ARGB DWORDs) ---
	$paletteList = New-Object System.Collections.Generic.List[byte]
	for ($i = 0; $i -lt 8; $i++) {
		$bytes = [BitConverter]::GetBytes([UInt32]$dword_Explorer)
		$paletteList.AddRange($bytes)
	}
	$paletteBytes = $paletteList.ToArray()
	Add-RegEntry -Path $accentPath -Name "AccentPalette" -Value ([byte[]]$paletteBytes) -PropertyType Binary -Force | Out-Null

	# --- Control Panel legacy string ---
	$cpPath = "HKCU:\Control Panel\Desktop\Colors"
	New-Item -Path $cpPath -Force | Out-Null
	$cpColors = "{0} {1} {2} 0 0 0 0 0 0" -f $r, $g, $b
	Add-RegEntry -Path $cpPath -Name "AccentColorMenu" -Value $cpColors -Type String -Force

	# --- Broadcast ImmersiveColorSet ---
	Add-Type 
@"
using System;
using System.Runtime.InteropServices;
public class User32 {
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
"@

	$HWND_BROADCAST = [intptr]0xffff
	$WM_SETTINGCHANGE = 0x1A
	[UIntPtr]$result = [UIntPtr]::Zero
	try {
		[void][User32]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "ImmersiveColorSet", 2, 5000, [ref]$result)
	} catch { Write-Warning "Error! $_" }

	# --- Restart Explorer / Shell hosts unless NoRestart ---
	if (-not $NoRestart) {
		Restart-ExplorerSilently
	}

	Write-Host "✓ Personalization applied" -ForegroundColor Green
	Write-Host ("RGB (as seen in Settings): {0} {1} {2}" -f $r, $g, $b) -ForegroundColor Cyan
	Write-Host ("DWM ABGR DWORD: 0x{0:X8}" -f $dword_DWM) -ForegroundColor Cyan
	Write-Host ("Explorer ARGB DWORD: 0x{0:X8}" -f $dword_Explorer) -ForegroundColor Cyan
	if ($NoRestart) { Write-Host "Note: Explorer/Shell restart skipped" -ForegroundColor Yellow }
}

# ==================================================================================
# Function: Get-ForegroundWindow
# - Return an object with [UIA WindowElement, handle, title, Class Name, Control Type & Automation Id] of the current Foreground Window
# ==================================================================================
function Get-ForegroundWindow {
	Add-Type -TypeDefinition
		@"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

        [DllImport("user32.dll")]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder lpClassName, int nMaxCount);
    }
"@

	# Load UI Automation assemblies
	Add-Type -AssemblyName UIAutomationClient
	Add-Type -AssemblyName UIAutomationTypes

	# Get the foreground window handle
	$hWnd = [Win32]::GetForegroundWindow()

	if ($hWnd -eq [IntPtr]::Zero) {
		Write-Warning "⚠️ No foreground window found"
		return $null
	}

	# Get the window title
	$titleLength = [Win32]::GetWindowTextLength($hWnd)
	$titleBuilder = New-Object System.Text.StringBuilder($titleLength + 1)
	[Win32]::GetWindowText($hWnd, $titleBuilder, $titleBuilder.Capacity) | Out-Null
	$title = $titleBuilder.ToString()

	# Get the window class name
	$classBuilder = New-Object System.Text.StringBuilder(256)
	[Win32]::GetClassName($hWnd, $classBuilder, $classBuilder.Capacity) | Out-Null
	$className = $classBuilder.ToString()

	# Get UI Automation element and ControlType
	try {
		$WindowElement = [System.Windows.Automation.AutomationElement]::FromHandle($hWnd)
		$ctrlControlType = $WindowElement.Current.ControlType.ProgrammaticName.Replace("ControlType.", "")
		$AutomationId = $WindowElement.Current.AutomationId
	} catch { Write-Warning "⚠️ Failed to get all the window properties" }

	# Return an object with the properties
	return [PSCustomObject] @{
		WindowElement = $WindowElement
		Handle        = $hWnd
		Title         = $title
		ClassName     = $className
		ControlType   = $ctrlControlType
		AutomationId  = $AutomationId
	}
}

# ==================================================================================
# Function: Invoke-UIControl
# - Can Automate a wide range of UI tasks in windows
# - Return full list of controls with extended properties if needed
# ==================================================================================
function Invoke-UIControl {
	param(
		[string]$uri,                					# Opens the App. Optional, e.g. ms-settings:printers OR ms-windows-store://downloadsandupdates OR windowsdefender://threatsettings

		# Window properties
		[string]$winName,                 				# Window Name
		[string]$winClass,           					# Window Class
		[string]$winControlType,  						# Window ControlType
		[string]$winAutomationId,    					# Window AutomationId

		# Control properties
		[string]$controlAutomationId,					# Control AutomationId
		[string]$controlClass,							# Control Class
		[string]$ctrlControlType,						# Control ControlType
		[string]$controlName,							# Control Name
		[string]$controlFrameworkId,					# Control Framework Id
		[string]$extraControlProperty,					# Property name for the an extra control property to use
		[string]$extraControlValue,						# Property value for the extra control property provided in extraControlProperty
		[switch]$noWindow,								# Search for the control in all windows

		# Dynamic wait
		[int]$Delay = 2000,				  				# Delay after finding the window for initialization (Milliseconds)
		[int]$Timeout = 10000,			  				# How long to keep searching for the window (Milliseconds)

		# Decide the job you want to do (Default single Ctrl Click)
		[switch]$ListWindows,							# Returns a list of all Open windows found and thier properties
		[switch]$ListControls,			  				# Returns a list of all controls found on the target window and thier properties
		[switch]$CheckWindow,			  				# Returns $true/$false if Window exists
		[switch]$CheckControl,            				# Returns $true/$false if control exists
		[switch]$MultiCtrl,								# Press all Buttons that match
		[switch]$NoWarn,								# Supress warning if the control to be clicked isn't found
		[ValidateSet("On", "Off", "Toggle")]
		[string]$SwitchToggle							# For Toggle Switchs change state to On, Off or Toggle it
	)

	Add-Type -AssemblyName UIAutomationClient
	Add-Type -AssemblyName UIAutomationTypes

	# ----------------------------------------------------------------
	# Section 1: Start the UI APP: Start the target process
	# ----------------------------------------------------------------
	if ($uri) {
		(New-Object -ComObject "Shell.Application").MinimizeAll()
		Start-Process $uri
	}

	# ----------------------------------------------------------------
	# Section 2: List Windows: Shows a list of all Open windows found and thier properties
	# ----------------------------------------------------------------
	# root: Windows Desktop
	$root = [System.Windows.Automation.AutomationElement]::RootElement
	if ($ListWindows) {
		$out = @()
		$allWindows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
		foreach ($win in $allWindows) {
			$out += [pscustomobject] @{
				Name         = $win.Current.Name
				ClassName    = $win.Current.ClassName
				ControlType  = $win.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
				AutomationId	= $win.Current.AutomationId
			}
		}
		$out = $out | Sort-Object Signal -Descending | Format-Table -Property Name, ClassName, ControlType, AutomationId -AutoSize -Wrap
		return $out
	}

	# ----------------------------------------------------------------
	# Section 3: Window Search:  Search for the target window until Timeout using Foreground Window or conditions
	# ----------------------------------------------------------------
	$elapsed = 0
	$appWin = $null

	# Use Foreground Window If no conditions sent
	if (-not $winName -and -not $winClass -and -not $winControlType -and -not $winAutomationId) { $UseForegroundWindow = $true }

	if ($UseForegroundWindow -and -not $noWindow) {
		while ($elapsed -lt $Timeout -and $null -eq $appWin) {
			$appWin = (Get-ForegroundWindow).WindowElement
			if (-not $appWin) { Start-Sleep -Milliseconds 200; $elapsed += 200 } else { break }
		}
	}

	# Window find by conditions If requested
	if (-not $UseForegroundWindow -and -not $noWindow) {
		$WinConditions = @()
		if ($winName) { $WinConditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty, $winName) }
		if ($winClass) { $WinConditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ClassNameProperty, $winClass) }
		if ($winControlType) { $WinConditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::$winControlType) }
		if ($winAutomationId) { $WinConditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $winAutomationId) }

		if ($WinConditions.Count -gt 1) {
			$WinCondition = New-Object System.Windows.Automation.AndCondition($WinConditions)
		} else { $WinCondition = $WinConditions[0] }

		while ($elapsed -lt $Timeout -and $null -eq $appWin) {
			$appWin = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $WinCondition)
			if (-not $appWin) { Start-Sleep -Milliseconds 200; $elapsed += 200 } else { break }
		}
	}

	if ($noWindow) { $appWin = $root }

	if (-not $appWin) {
		Write-Warning "⚠️ Window not found: Name='$winName' Class='$winClass' Id='$winAutomationId' Type='$winControlType'"
		return $false
	} elseif ($CheckWindow) { return $true }

	if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }

	# ----------------------------------------------------------------
	# Section 4: List controls: Show a list of all controls found on the target window and thier properties if requested
	# ----------------------------------------------------------------
	if ($ListControls) {
		$out = @()
		$allctrls = $appWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
		foreach ($ctrl in $allctrls) {
			$out += [pscustomobject] @{
				AutomationId	= $ctrl.Current.AutomationId
				ClassName    = $ctrl.Current.ClassName
				ControlType  = $ctrl.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
				Name         = $ctrl.Current.Name
			}
		}
		# $out = $out | Sort-Object Signal -Descending | Format-Table -Property AutomationId, ClassName, ControlType, Name -AutoSize -Wrap
		return $out
	}

	# ----------------------------------------------------------------
	# Section 5: Control Search: Search for Control with matching properties if requested
	# ----------------------------------------------------------------
	# Control find by conditions
	$ctrlconditions = @()
	if ($controlName) { $ctrlconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty, $controlName) }
	if ($controlAutomationId) { $ctrlconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $controlAutomationId) }
	if ($controlClass) { $ctrlconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ClassNameProperty, $controlClass) }
	if ($ctrlControlType) { $ctrlconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::$ctrlControlType) }
	if ($controlFrameworkId) { $ctrlconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::FrameworkIdProperty, $controlFrameworkId) }
	if ($extraControlProperty) { $ctrlconditions += New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::$extraControlProperty, $extraControlValue) }

	if ($ctrlconditions.Count -gt 1) {
		$ctrlCondition = New-Object System.Windows.Automation.AndCondition($ctrlconditions)
	} else {
		$ctrlCondition = $ctrlconditions[0]
	}

	if ($MultiCtrl) {
		$controls = $appWin.FindAll([System.Windows.Automation.TreeScope]::Descendants, $ctrlCondition)
	} else { $control = $appWin.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $ctrlCondition) }

	if (-not $control -and -not $controls) {
		if ($CheckControl) { return $false } # Make sure warning are displayed for Invoke not for Check
		if (-not $NoWarn) { Write-Warning "⚠️ Control not found: Name= $controlName  AutomationId= $controlAutomationId  Class= $controlClass  Type= $ctrlControlType " }
		return $false
	} elseif ($CheckControl) { return $true }

	# ----------------------------------------------------------------
	# Section 6: Click on Control :  Invoke the searched control if requested and if it can be clicked
	# ----------------------------------------------------------------
	try {
		if ($SwitchToggle) {
			# Handle ToggleSwitches
			$togglePattern = $control.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
			$state = $togglePattern.Current.ToggleState
			if ($state -eq [System.Windows.Automation.ToggleState]::On) { $onState = $true }
			switch ($SwitchToggle) {
				"On" { if ($onState) { Write-Host "✅ Already On" } else { $togglePattern.Toggle() } }
				"Off" { if ($onState) { $togglePattern.Toggle() } else { Write-Host "✅ Already OFF" } }
				"Toggle" { $togglePattern.Toggle() }
			}
			Write-Host "✅ Toggled Switch $SwitchToggle : AutomationId= $controlAutomationId  Name= $controlName  Class= $controlClass  Type= $ctrlControlType "
			return $true
		} elseif ($MultiCtrl) {
			# Multi Ctrls
			foreach ($control in $controls) {
				$invokePattern = $control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
				$invokePattern.Invoke()
				Write-Host "✅ Invoked control: AutomationId= $controlAutomationId  Name= $controlName  Class= $controlClass  Type= $ctrlControlType "
			}
			return $true
		} else {
			# Single Ctrl
			$invokePattern = $control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
			$invokePattern.Invoke()
			Write-Host "✅ Invoked control: AutomationId= $controlAutomationId  Name= $controlName  Class= $controlClass  Type= $ctrlControlType "
			return $true
		}
	} catch {
		Write-Warning "⚠️ Control found but does not support Invoke or Toggle"
		return $false
	}
}

function Test-WindowsDefenderStatus {
	param(
		[switch]$DebugView
	)

	$avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue

	$isDefenderEnabled = $false
	$otherAVEnabled = $false
	$defenderFound = $false
	$debugOutput = @()

	foreach ($product in $avProducts) {
		$state = $product.productState

		# Decode productState
		$byte1 = ($state -band 0xFF0000) -shr 16
		$byte2 = ($state -band 0x00FF00) -shr 8   # Product status
		$byte3 = ($state -band 0x0000FF)          # Signature status

		# Product enabled if byte2 = 0x10, 0x11, 0x12 (On states)
		$isEnabled = ($byte2 -in 0x10, 0x11, 0x12)

		# Identify Defender strictly
		$isDefender = ($product.displayName -match "^(Windows Defender|Microsoft Defender)")

		if ($isDefender) {
			$defenderFound = $true
			$isDefenderEnabled = $isEnabled
		} elseif ($isEnabled) {
			$otherAVEnabled = $true
		}

		if ($DebugView) {
			$debugOutput += [PSCustomObject]@{
				DisplayName  = $product.displayName
				ProductState = $state
				Byte1        = ('0x{0:X2}' -f $byte1)
				Byte2        = ('0x{0:X2}' -f $byte2)
				Byte3        = ('0x{0:X2}' -f $byte3)
				IsEnabled    = $isEnabled
				IsDefender   = $isDefender
			}
		}
	}

	# Defender is primary if found and no other AV is enabled
	$isDefenderPrimary = ($defenderFound -and -not $otherAVEnabled)

	# Service check (safety net)
	$defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
	$isRunning = ($defenderService -and $defenderService.Status -eq 'Running')
	if ($isRunning) { $isDefenderEnabled = $true }

	$result = [PSCustomObject]@{
		IsEnabled     = $isDefenderEnabled
		IsPrimary     = $isDefenderPrimary
		OtherAVActive = $otherAVEnabled
	}

	if ($DebugView) {
		Write-Output "=== Antivirus Debug Info ==="
		$debugOutput | Format-Table -AutoSize
		Write-Output "`n=== Result ==="
	}

	return $result
}

# ==================================================================================
# Function: Disable-DefenderRealtimeProtection
# - Trunoff Windows Desfender Realtime Protection using UI Automation
# ==================================================================================
function Disable-DefenderRealtimeProtection {
	# ----------------------------------------------------------------
	# Step 1: Try to Switch off Real-time protection toggle
	# ----------------------------------------------------------------

	$defenderStatus = Test-WindowsDefenderStatus
	if ($defenderStatus.IsEnabled -or $defenderStatus.IsPrimary) {
		Write-Host "`r`n *** 🔴 Turning Off Windows Defender Real-Time Protection *** `r`n" -ForegroundColor Cyan
	} elseif ($defenderStatus.OtherAVActive) {
		Write-Warning "`r`n *** Kindly turn off your antivirus to avoid false positives *** `r`n"
		return
	} else { return }

	$uri = "windowsdefender://threatsettings"
	$winName = "Windows Security"
	$winClass = "ApplicationFrameWindow"
	$winControlType = "Window"

	$toggle = Invoke-UIControl `
	-uri $uri `
	-winName $winName `
	-winClass $winClass `
	-winControlType $winControlType `
	-controlName "Real-time protection" `
	-controlAutomationId "settingToggle" `
	-controlClass "ToggleSwitch" `
	-SwitchToggle "Off"

	if (-not $toggle) {
		Write-Warning "Trying to use Foreground Window"
		$toggle = Invoke-UIControl `
		-uri $uri `
		-controlName "Real-time protection" `
		-controlAutomationId "settingToggle" `
		-controlClass "ToggleSwitch" `
		-SwitchToggle "Off"
	}

	if (-not $toggle) {
		Write-Warning "⚠️ Could not find Real-time protection toggle"
		return $false
	}

	# ----------------------------------------------------------------
	# Step 2: Close Window
	# ----------------------------------------------------------------

	$CloseWindow = Invoke-UIControl `
	-winName $winName `
	-winClass $winClass `
	-winControlType $winControlType `
	-controlAutomationId "Close" `
	-ctrlControlType "Button"
	return
}

# ==================================================================================
# Function: Update-MSStoreApps
# - Update Stroe Apps using UI Automation
# ==================================================================================
function Update-MSStoreApps {
	Write-Host "`r`n*** MS Store Apps Updates ***`r`n" -ForegroundColor Cyan

	$uri = "ms-windows-store://downloadsandupdates"
	$winName = "Microsoft Store"
	$winClass = "ApplicationFrameWindow"
	$winControlType = "Window"
	$updatesHappened = $false

	# ----------------------------------------------------------------
	# Step 1: Click "Check for Updates"
	# ----------------------------------------------------------------
	$checkBtnClicked = Invoke-UIControl `
	-uri $uri `
	-winName $winName `
	-winClass $winClass `
	-winControlType $winControlType `
	-controlAutomationId "CheckForUpdatesButton" `
	-ctrlControlType "Button" `
	-controlClass "Button" `
	-controlFrameworkId "XAML"


	if (-not $checkBtnClicked) {
		Write-Warning "Trying to use Foreground Window"
		$checkBtnClicked = Invoke-UIControl `
		-uri $uri `
		-controlAutomationId "CheckForUpdatesButton" `
		-ctrlControlType "Button" `
		-controlClass "Button" `
		-controlFrameworkId "XAML"
	}

	if (-not $checkBtnClicked) {
		Write-Warning "⚠️ Could not click 'Check for updates'."
		return
	}

	# ----------------------------------------------------------------
	# Step 2: checking for updates ("Ring" is found)
	# ----------------------------------------------------------------

	# Check for control Ring quickly
	$ringFound = Invoke-UIControl `
	-winName $winName `
	-winClass $winClass `
	-winControlType $winControlType `
	-controlAutomationId "Ring" `
	-controlClass "Microsoft.UI.Xaml.Controls.ProgressRing" `
	-ctrlControlType "ProgressBar" `
	-controlName "Busy" `
	-CheckControl `
	-Delay 0
	if ($ringFound) { Write-Output "Checking for Updates..." }

	# ----------------------------------------------------------------
	# Step 3: try to click "Update all" if it exists & Try Click all individual ActionButtons if any
	# ----------------------------------------------------------------

	for ($i = 1; $i -le 100; $i++) {
		# Check progress
		$progress = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-controlAutomationId "ProgressRing" `
		-controlClass "Microsoft.UI.Xaml.Controls.ProgressRing" `
		-ctrlControlType "ProgressBar" `
		-controlName "Busy" `
		-CheckControl `
		-Delay 0
		$progressBackground = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-controlAutomationId "BackgroundProgressRing" `
		-controlClass "Microsoft.UI.Xaml.Controls.ProgressRing" `
		-ctrlControlType "ProgressBar" `
		-CheckControl `
		-Delay 0
		if ($progress -or $progressBackground) { $updatesHappened = $true }
		# Try Update All button if it exists
		$updateAll = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-controlName "Update all" `
		-ctrlControlType "Hyperlink" `
		-controlClass "Hyperlink" `
		-NoWarn `
		-Delay 0
		# Try individual update ActionButtons
		$actionButtons = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-controlName "Update" `
		-controlAutomationId "ActionButton" `
		-ctrlControlType "Button" `
		-NoWarn `
		-Delay 0
		if ($updateAll) { break }
		Start-Sleep -Milliseconds 100
	}
	# ----------------------------------------------------------------
	# Step 4: Wait until all ProgressRing & BackgroundProgressRing controls disappear
	# ----------------------------------------------------------------
	if ($updatesHappened) { Write-Host "Waiting for the MS Store apps updates to finish..." }
	while ($true) {
		$progress = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-controlAutomationId "ProgressRing" `
		-controlClass "Microsoft.UI.Xaml.Controls.ProgressRing" `
		-ctrlControlType "ProgressBar" `
		-controlName "Busy" `
		-CheckControl `
		-Delay 0
		$progressBackground = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-controlAutomationId "BackgroundProgressRing" `
		-controlClass "Microsoft.UI.Xaml.Controls.ProgressRing" `
		-ctrlControlType "ProgressBar" `
		-CheckControl `
		-Delay 0
		if ($progress -or $progressBackground) { $updatesHappened = $true }
		if ((-not $progress) -and (-not $progressBackground)) { break }
		Start-Sleep -Milliseconds 100
	}

	# ----------------------------------------------------------------
	# Step 5: Generate updated apps report safely
	# ----------------------------------------------------------------
	if ($updatesHappened) {
		Write-Host "`r`n--- Updated Apps Report ---`r`n" -ForegroundColor Cyan

		$ControlElements = Invoke-UIControl `
		-winName $winName `
		-winClass $winClass `
		-winControlType $winControlType `
		-ListControls

		$updatedElements = $ControlElements | Where-Object { ($_.Name -match "Modified (minutes|moments) ago") -and ($_.ControlType -eq "Custom") -and ($_.ClassName -eq "Button") } | select -ExpandProperty Name
		$updatedApps = $updatedElements -replace ', Modified (minutes|moments) ago\.?', ''

		if ($updatedApps.Count -gt 0) {
			Write-Host "Updated Apps:" -ForegroundColor Cyan
			$updatedApps
			Write-Host "`r`nAll updates completed and reported!`r`n" -ForegroundColor Green
		} else {
			Write-Host "ℹ️ No apps reported as updated." -ForegroundColor Yellow
		}
	} else { Write-Host "ℹ️ No updates found." -ForegroundColor Yellow }

	# ----------------------------------------------------------------
	# Step 6: Close Window
	# ----------------------------------------------------------------
	# -controlName "Close Microsoft Store" affected by Language
	Write-Host "Closing MS Store window."
	$CloseWindow = Invoke-UIControl `
	-winName $winName `
	-winClass $winClass `
	-winControlType $winControlType `
	-controlAutomationId "Close" `
	-ctrlControlType "Button"
	return
}

