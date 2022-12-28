#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
#########################################
#         ClientSide Script             #
#########################################
# See README.md for all setting values  #
#########################################

# TODO: 
# 	Fetch Persmission and Accounts
#  		FromAPI direct; filter: safe Regex, favorites etc.), 
# 		From SafeAccountList.json; Map with AD Groups, JSON User/Groups (LDAP DIFF), FromAPI Safes, ALL oder filter safe Regex
#
#   Folder structure:
# 		From Safes, Description, Platform or specified Account Attribute
#
# leave empty if none or enter URL to the json settings like "https://WebHost/ScriptData/cyberRoyalSettings.json"
$webSettingsUrl = ""

# enable or disable SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
$psCertValidation = $false

# switch debug mode on (only directly in powershell, cannot be used in RoyalTS)
$debugOn = $true

# settings localy, webSettingsUrl will replace this entries!
$settings = @"
{
    "cyberRoyalMode": "list",
    "listMode": "listRBAC",
    "listUrl": "https://pam.kubi.gg/ScriptData/cyberRoyalSafeAccountList.json",
	"listPermissionUrl": "https://pam.kubi.gg/ScriptData/cyberRoyalPermissionList.json",
    "pvwaUrl": "https://pam.kubi.gg/PasswordVault",
    "pvwaAuthMethod": "Cyberark",
    "pvwaAuthPrompt": 1,
	"usernameFromEnv": 0,
    "psmRdpAddress": "pam-pm1.kubi.gg",
    "psmSshAddress": "pam-psmp1.kubi.gg",
    "platformMappings": {
        "UnixSSH": {
            "connections": [
                {
                    "type": "SSH",
                    "components": [
                        "PSMP-SSH"
                    ]
                },
                {
                    "type": "SFTP",
                    "components": [
                        "PSMP-SFTP"
                    ]
                },
                {
                    "type": "RDP",
                    "components": [
                        "PSM-WinSCP"
                    ]
                }
            ]
        },
        "WinDomain": {
            "psmRemoteMachine": 1,
            "connections": [
                {
                    "type": "RDP",
                    "components": [
                        "PSM-RDP"
                    ]
                }
            ]
        },
        "WinServerLocal": {
            "namePrefix": "Local - ",
            "namePostfix": "",
            "psmRemoteMachine": 0,
            "entryName": "full",
            "connections": [
                {
                    "type": "RDP",
                    "components": [
                        "PSM-RDP"
                    ]
                }
            ]
        }
    }
}
"@


#########################################
#           Powershell Settings         #
#########################################
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
if ($psCertValidation) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }

if ($debugOn) { 
	$stopWatch = [system.diagnostics.stopwatch]::StartNew() 
	$debugNrAccounts = 0
	$debugNrServerConnections = 0
}
else {
	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"
}

#########################################
#               Variables               #
#########################################
# get settings from web if available
if (![string]::isNullOrEmpty($webSettingsUrl)) {
	$settings = Invoke-WebRequest -Uri $webSettingsUrl -Method Get -UseBasicParsing -ContentType "application/json; charset=utf-8"
}

# get settings and form a platformMapping hashtable with key = platformname
$settings = $settings | ConvertFrom-Json
$platformMapping = @{ }
foreach ( $prop in $settings.platformMappings.psobject.properties ) { $platformMapping[ $prop.Name ] = $prop.Value }

# multiple used variables
$cyberRoyalMode = $settings.cyberRoyalMode
$pvwaUrl = $settings.pvwaUrl
$listUrl = $settings.listUrl
$listMode = $settings.listMode

$pvwaAuthMethod = $settings.pvwaAuthMethod
$pvwaAuthPrompt = $settings.pvwaAuthPrompt

$psmRdpAddress = $settings.psmRdpAddress
$psmSshAddress = $settings.psmSshAddress

# when are PVWA credentials required
if ($cyberRoyalMode -eq "pvwa" -or $listMode -eq "pvwaRBAC") { $pvwaLoginRequired = $true } else { $pvwaAuthRequired = $false }

# RoyalTs user context or credential will fill the following $variables$ if defined during script execution
$caUser = @'
$EffectiveUsername$
'@

$caPass = @'
$EffectivePassword$
'@

if ($settings.usernameFromEnv) { $caUser = $env:username }

if ($pvwaLoginRequired) {
	if ($pvwaAuthPrompt) { 
		if ($settings.usernameFromEnv) {
			$caCredentials = Get-Credential -UserName $caUser -Message "Please enter your CyberArk Password" 
		}
		else {
			$caCredentials = Get-Credential -Message "Please enter your CyberArk Username and Password"
			$caUser = $caCredentials.UserName
		}
	} 
	elseif ([string]::isNullOrEmpty( $caPass )) {
		Write-Error "No PVWA Credentials provided" 
	} 
}

# prepare RoyalJSON response
$response = @{
	Objects = [System.Collections.Generic.List[object]]::new();
}

#########################################
#              Functions                #
#########################################

function Write-Debug($message) {
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " - $message" }
}
function Invoke-Logon() {
	$global:header = @{ }
	$header.Add("Content-type", "application/json") 
	$logonURL = $pvwaUrl + "/api/auth/" + $pvwaAuthMethod + "/Logon"
	if ($pvwaAuthPrompt) { $logonData = @{ username = $caCredentials.GetNetworkCredential().UserName; password = $caCredentials.GetNetworkCredential().Password; concurrentSession = $true; } | ConvertTo-Json }
	else { $logonData = @{ username = $caUser; password = $caPass; concurrentSession = $true; } | ConvertTo-Json }
	try {
		$logonDataEnc = [System.Text.Encoding]::UTF8.GetBytes($logonData)
		$logonResult = $( Invoke-WebRequest -Uri $logonURL -Headers $header -Method Post -UseBasicParsing -Body $logonDataEnc ).content | ConvertFrom-Json 
	} 
	catch { 
		Write-Error "Did you define the right credentials to login?"
	}
	$header.Add("Authorization" , $logonResult) 
}
function Invoke-Logoff() {
	try { Invoke-WebRequest -Uri $( $pvwaUrl + "/api/auth/Logoff") -Headers $header -UseBasicParsing -Method Post | Out-Null } catch { }
}
function Get-PvwaSafes() {
	if ([string]::IsNullOrEmpty($settings.pvwaSafeSearch)) { $safeURL = $pvwaUrl + "/api/Safes?limit=10000" } else { $safeURL = $pvwaUrl + "/api/Safes?limit=10000&search=$($settings.pvwaSafeSearch)" }
	$safesList = $( Invoke-WebRequest -Uri $safeURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json
	$safes = [System.Collections.Generic.List[string]]::new();
	foreach ($safe in $safesList.value) {
		$safes.Add($safe.SafeName)
	}
	Write-Debug "fetched safes from PVWA" 
	[System.Collections.Generic.List[string]]$safes = $safes | Sort-Object
	return $safes
}

function Get-PermissionListSafes($listUrl) {
	$jsonFileData = Invoke-WebRequest -Uri $listUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
	$safePermissionList = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
	$safes = [System.Collections.Generic.List[string]]::new();
	foreach ($safePermission in $safePermissionList) {
		if ($safePermission.user -eq $caUser) {
			$safes = $safePermission.permissions
		}
	}
	Write-Debug "fetched $($safes.Count) safe permissions from PermissionList"
	if ($safes.Count -lt 1) { Write-Error "No safe permissions for user $caUser in PermissionList found" }
	[System.Collections.Generic.List[string]]$safes = $safes | Sort-Object
	return $safes
}

function Get-adGroupSafes() {
	$userGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$( $caUser )))")).FindOne().GetDirectoryEntry()
	$groups = $userGroups.memberOf
	Write-Debug "fetched $caUser member groups $groups"
	$safes = [System.Collections.Generic.List[string]]::new();
	foreach ($group in $groups) {
		$match = [regex]::Match($group, $settings.groupSafeRegex)
		if ($match.Success) {
			$safeName = $match.Groups[1].ToString()
			$safes.Add($safeName)
		}
	}
	Write-Debug "fetched safes from groups" 
	[System.Collections.Generic.List[string]]$safes = $safes | Sort-Object
	return $safes
}

function Get-PvwaAccountsFromList($listUrl) {
	# get the prepared data file and remove BOM (thanks to .NET, IIS) if necessary
	$jsonFileData = Invoke-WebRequest -Uri $listUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
	Write-Debug "fetched json file length: $( $jsonFileData.RawContentLength)"
	
	# ConvertFrom-Json -AsHashtable only available in PWSH 7
	# PSCustomObject with objects (key=value objects, where key=SafeName)
	[PSCustomObject]$safesAndAccounts = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
	# [System.Collections.SortedList]
	return $safesAndAccounts
}

function Get-PvwaAccountsFromSafes($safes) {
	$safesAndAccounts = [PSCustomObject]@{}
	foreach ($safe in $safes) {
		$accountURL = $pvwaUrl + "/api/Accounts?limit=1000&filter=safeName eq $($safe.SafeName)"
		$accountsResult = $(Invoke-Request -Uri $accountURL -Headers $header -Method Get).content | ConvertFrom-Json
		if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
			$safeEntry = @{ "SafeName" = $safe.SafeName; "Description" = $safe.Description; "Accounts" = [System.Collections.Generic.List[object]]::new(); }
			foreach ($account in $accountsResult.value) {
				$accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
				foreach ($property in $additionalPlatformAccountProperties) {
					$accountEntry += @{$property = $account.platformAccountProperties.$property }
				}
				$safeEntry.Accounts.Add($accountEntry)
				$accountEntriesCount++
			}
			$safesAndAccounts.Add($safe.SafeName, $safeEntry)
		}
	}
	return $safesAndAccounts
}

function Get-PvwaAccountsFromSavedFilter($savedFilter) {
	$safesAndAccounts = [PSCustomObject]@{}
	$accountURL = $pvwaUrl + "/api/Accounts?savedFilter=$savedFilter"
	$accountsResult = $(Invoke-Request -Uri $accountURL -Headers $header -Method Get).content | ConvertFrom-Json
	if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
		$safes = $accountsResult.value.safeName
		foreach ($safe in $safes) {
			$safeEntry = @{ "SafeName" = $safe; "Description" = ""; "Accounts" = [System.Collections.Generic.List[object]]::new(); }
			foreach ($account in $accountsResult.value) {
				if ($account.safeName -eq $safe) {
					$accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
					foreach ($property in $additionalPlatformAccountProperties) {
						$accountEntry += @{$property = $account.platformAccountProperties.$property }
					}
					$safeEntry.Accounts.Add($accountEntry)
					$accountEntriesCount++
				}
			}
			$safesAndAccounts.Add($safe.SafeName, $safeEntry)
		}
	}
	return $safesAndAccounts
}

function Get-ConnectionRDP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = "RemoteDesktopConnection"

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmRdpAddress } else { $entry.ComputerName = $plat.replacePsm }
	if ([string]::isNullOrEmpty( $settings.rdpResizeMode )) { $entry.ResizeMode = "SmartSizing" } else { $entry.ResizeMode = $settings.rdpResizeMode }
    
	$entry.Username = $caUser
	if ($plat.drivesRedirection) { $entry.Properties.RedirectDrives = "true" }    
	if ($settings.enableNLA) { $entry.NLA = "true" } else { $entry.NLA = "false" }
	if ($plat.psmRemoteMachine) {
		if ($comp -ne "PSM-RDP") { $componentAddition = ' - ' + $comp }
		# Entry Name
		if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
		else {
			if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
			switch ($entryName) {
				"full" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.address + " - " + $acc.target + $componentAddition + $plat.namePostfix } 
				"named" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + $componentAddition + $plat.namePostfix }
				Default { $entry.Name = $plat.namePrefix + $acc.target + $componentAddition + $plat.namePostfix }
			}
			if (![string]::isNullOrEmpty( $plat.replaceRegex )) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
		}
		$entry.Properties.StartProgram = "psm /u " + $acc.userName + "@" + $acc.address + " /a " + $acc.target + " /c " + $comp
	}
	else {
		if ($comp -ne "PSM-RDP") { $componentAddition = " - " + $comp }

		# Entry Name
		if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
		else {
			if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
			switch ($entryName) {
				"full" { $entry.Name = $plat.namePrefix + $acc.userName + " - " + $acc.target + $componentAddition + $plat.namePostfix } 
				"named" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + $componentAddition + $plat.namePostfix }
				Default { $entry.Name = $plat.namePrefix + $acc.target + $componentAddition + $plat.namePostfix }
			}
			if (![string]::isNullOrEmpty( $plat.replaceRegex )) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
		}
		$entry.Properties.StartProgram = "psm /u " + $acc.userName + " /a " + $acc.target + " /c " + $comp
	}
	return $entry
}

function Get-ConnectionSSH($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = "TerminalConnection"
	$entry.TerminalConnectionType = "SSH"

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmSshAddress } else { $entry.ComputerName = $plat.replacePsm }

	# Entry Name
	if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
	else {
		if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
		switch ($entryName) {
			"full" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + " - " + $comp + $plat.namePostfix }  
			"named" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + $plat.namePostfix } 
			Default { $entry.Name = $plat.namePrefix + $acc.target + $plat.namePostfix }
		}
		if (![string]::isNullOrEmpty($plat.replaceRegex)) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
	}
	$entry.UserName = $caUser + "@" + $acc.userName + "@" + $acc.target
	return $entry
}

function Get-ConnectionSFTP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = "FileTransferConnection"
	$entry.FileTransferConnectionType = "SFTP"

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmSshAddress } else { $entry.ComputerName = $plat.replacePsm }

	# Entry Name
	if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
	else {
		if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
		switch ($entryName) {
			"full" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + " - " + $comp + $plat.namePostfix }  
			"named" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + $plat.namePostfix } 
			Default { $entry.Name = $plat.namePrefix + $acc.target + $plat.namePostfix }
		}
		if (![string]::isNullOrEmpty($plat.replaceRegex)) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
	}
	$entry.CredentialMode = 4
	$entry.CredentialName = $caUser + "@" + $acc.userName + "@" + $acc.target
	return $entry
}


function Get-ConnectionWEB($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = "WebConnection"

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if (![string]::isNullOrEmpty( $plat.webProtocol )) { $webProtocol = $plat.webProtocol } else { $webProtocol = "https" }
	if (![string]::isNullOrEmpty( $plat.webOverwriteUri )) {  
		$entry.URL = "$( $webProtocol )://" + $plat.webOverwriteUri
	} 
	else {     
		$entry.URL = "$( $webProtocol )://" + $acc.target
	}
	# Entry Properties
	$entry.Properties.ShowToolbar = $true
	$entry.Properties.IgnoreCertificateErrors = $true
	$entry.Properties.UseDedicatedEngine = $true
	# AutoFill Implementations
	if (![string]::isNullOrEmpty($plat.webInputObject)) { 
		$fillUser = $acc.userName
		$fillMappings = @( @{ Element = $plat.webInputObject; Action = "Fill"; Value = $fillUser } )
		$entry.AutoFillElements = $fillMappings
		$entry.AutoFillDelay = 1000
	}
	# Entry Name
	if (![string]::isNullOrEmpty( $plat.replaceName )) {
		$entry.Name = $plat.replaceName
	}
	else {
		if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
		switch ($entryName) {
			"full" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + " - " + $comp + $plat.namePostfix }
			"named" { $entry.Name = $plat.namePrefix + $acc.userName + "@" + $acc.target + $plat.namePostfix }
			Default { $entry.Name = $plat.namePrefix + $acc.target + $plat.namePostfix }
		}
		if (![string]::isNullOrEmpty( $plat.replaceRegex )) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
	}
	# Use Win WebPlugin ID instead of global config
	if (![string]::isNullOrEmpty( $settings.useWebPluginWin )) {
		$entry.Properties.UseGlobalPlugInWin = $false
		$entry.Properties.PlugInWin = $settings.useWebPluginWin
	}
	return $entry
}

function Get-ConnectionEntry($accountDetail, $platformSetting, $connectionType, $component) {
	switch ($connectionType) {
		"SSH" { return Get-ConnectionSSH $accountDetail $platformSetting $component }
		"SFTP" { return Get-ConnectionSFTP $accountDetail $platformSetting $component }
		"RDP" { return Get-ConnectionRDP $accountDetail $platformSetting $component }
		"WEB" { return Get-ConnectionWEB $accountDetail $platformSetting $component }
	}
}

#########################################
#                MAIN                   #
#########################################

# Switch cyberRoyal mode - set the users "permissive" safes to apply account connections
switch ($cyberRoyalMode) {
	"list" {
		switch ($listMode) {
			"adGroupRBAC" { 
				$safes = Get-adGroupSafes
				Write-Debug "fetched adGroup safes: $( $safes.Count )" 
			}
			"pvwaRBAC" { 
				Invoke-Logon
				$safes = Get-PvwaSafes 
				Write-Debug "fetched PVWA safes: $( $safes.Count )" 
			}
			"listRBAC" { 
				$safes = Get-PermissionListSafes($settings.listPermissionUrl)
				Write-Debug "fetched PermissionList safes: $( $safes.Count )" 
			}
			"listALL" { 
				$skipSafesMatching = $true
				Write-Debug "applying all accounts from list" 
			}
		}
		$safesAndAccounts = Get-PvwaAccountsFromList($listUrl)
	}
	"pvwa" {
		Invoke-Logon
		$safes = Get-PvwaSafes
		$safesAndAccounts = Get-PvwaAccountsFromSafes($safes)
		#TODO: from saved filters
	}
}

# safes as List
# safesAndAccounts as SortedList
# loop through all safes and accounts and create connection entries
foreach ($safe in $safesAndAccounts.PsObject.Properties) {
	# match safe or continue
	if ( !$skipSafesMatching -and !($safes.Contains( $safe.Name )) ) { continue }

	# match safeFilter or continue
	if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe.Name, $settings.safeFilter ).Success )) { continue } 

	if ($settings.folderCreation -eq "none") {
		$objects = [System.Collections.Generic.List[object]]::new();
	}
	else {
		$folder = @{
			Objects         = [System.Collections.Generic.List[object]]::new();
			Type            = "Folder"
			ColorFromParent = $true
		}

		switch ($settings.folderCreation) {
			"safe.name" { $folder.Name = $safe.Name }
			"safe.name-description" { $folder.Name = $safe.Name + ' - ' + $safe.Value.Description }
			"safe.description" { $folder.Name = $safe.Value.Description }
			"safe.description-name" { $folder.Name = $safe.Value.Description + ' - ' + $safe.Name }
		}
	}

	foreach ($account in $safe.Value.Accounts) {

		$accountPlatform = $account.platformId

		if (!$platformMapping.ContainsKey( $accountPlatform )) { continue }
		if (![string]::IsNullOrEmpty($settings.excludeAccounts) -and $settings.excludeAccounts.Contains( $account.userName)) { continue }
		if ($debugOn) { $debugNrAccounts++ }
		# create connections for every configured connection component
		if ($null -eq $account.remoteMachines) {
			Add-Member -InputObject $account -NotePropertyName 'target' -NotePropertyValue $account.address
			$royalPlatform = $platformMapping[ $accountPlatform ]
			foreach ($connection in $royalPlatform.connections) {
				foreach ($component in $connection.components) { 
					$connectionEntry = Get-ConnectionEntry $account $royalPlatform $connection.Type $component
					if ($settings.folderCreation -eq "none") { $objects.Add( $connectionEntry ) }
					else { $folder.Objects.Add( $connectionEntry ) }
					if ($debugOn) { $debugNrServerConnections++ }
				}
			}
		}
		# create connections for each remoteMachine and every configured connection component
		else {
			$remoteMachines = $account.remoteMachines.split(';', [System.StringSplitOptions]::RemoveEmptyEntries) | Sort-Object
			foreach ($remoteMachine in $remoteMachines) {
				Add-Member -InputObject $account -NotePropertyName 'target' -NotePropertyValue $remoteMachine -Force
				$royalPlatform = $platformMapping[ $accountPlatform]
				foreach ($connection in $royalPlatform.connections) {
					foreach ($component in $connection.components) { 
						$connectionEntry = Get-ConnectionEntry $account $royalPlatform $connection.Type $component
						if ($settings.folderCreation -eq "none") { $objects.Add($connectionEntry) }
						else { $folder.Objects.Add($connectionEntry) }
						if ($debugOn) { $debugNrServerConnections++ }
					}
				}
			}
		}
	}
	if ($settings.folderCreation -eq "none" -and $objects.Length -gt 0) {
		$response.Objects.Add($objects)
	}
	elseif ($folder.Objects.Length -gt 0) {
		$response.Objects.Add($folder)
	}
}

# send RoyalJSON response
$jsonResponse = $response | ConvertTo-Json -Depth 100

if ($debugOn) { 
	Write-Host $stopWatch.Elapsed + " got $debugNrServerConnections server connections" 
	Out-File -FilePath "data.json" -Encoding UTF8 -InputObject $jsonResponse
}
else {
	Write-Host $jsonResponse
}

# logoff if required
if ($pvwaLoginRequired) { Invoke-Logoff }
Write-Debug "finished" 