﻿#########################################
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
$debugOn = $false

# settings localy, webSettingsUrl will replace this entries!
$settings = @"
{
    "pvwaUrl": "https://YOUR-PVWA/PasswordVault",
    "dataUrl": "https://YOUR-WEBHOST/ScriptData/cyberRoyalSafeAccountList.json",
    "authMethod": "LDAP",
    "authPrompt": 1,
    "psmRdpAddress": "YOUR-PSM-RDP",
    "psmSshAddress": "YOUR-PSM-SSH",
    "allAccountsMode": 0,
    "safeFilter": 0,
    "safeFilterRegex": ".*_OnylThisSafes.*",
    "groupBasedMode": 0,
    "groupBasedSafeRegex": "CN=.*?(SafeName),OU=.*",
    "folderCreation": "safe.name",
    "entryName": "named",
    "enableNLA": 0,
    "rdpResizeMode": "",
    "excludeAccounts": ["guest"],
    "useWebPluginWin": "f008c2f0-5fb3-4c5e-a8eb-8072c1183088",
    "platformMappings": {
        "UnixSSH": {
            "connections": [{ "type": "SSH", "components": ["PSMP-SSH"] }]
        },
        "LinuxLinux": {
            "replacePsm": "another-ssh-proxy",
            "connections": [
                { "type": "SSH", "components": ["PSMP-SSH"] },
                { "type": "SFTP", "components": ["PSMP-SFTP"] }
            ]
        },
        "WindowsDomain": {
            "psmRemoteMachine": 1,
            "connections": [{
                    "type": "RDP",
                    "components": ["PSM-RDP", "PSM-RDP-Console", "PSM-DSA"]
                },
                { "type": "SSH", "components": ["PSMP-BadExample"] }
            ]
        },
        "ExchangeDomainUser": {
            "replacePsm": "ANOTHER-PSM-ADDRESS",
            "connections": [
                { "type": "RDP", "components": ["PSM-RDP", "PSM-WebECP"] }
            ]
        },
        "Fortigate": {
            "color": "#FF0000",
            "connections": [
                { "type": "RDP", "components": ["PSM-FortiWeb"] },
                { "type": "SSH", "components": ["PSMP-SSH"] }
            ]
        },
        "WindowsServerLocal": {
            "replaceName": "",
            "replaceRegex": "@domain.acme.com",
            "namePrefix": "Local - ",
            "namePostfix": "",
            "psmRemoteMachine": 0,
            "entryName": "full",
            "connections": [{ "type": "RDP", "components": ["PSM-RDP"] }]
        },
        "AzureWebAccount": {
            "namePrefix": "Azure - ",
            "webProtocol": "https",
            "webOverwriteUri": "",
            "webInputObject": "input#i0116",
            "connections": [{ "type": "WEB", "components": ["AzureWebsite"] }]
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
	$settings = Invoke-WebRequest -Uri $webSettingsUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
}

# get settings and form a platformMapping hashtable with key = platformname
$settings = $settings | ConvertFrom-Json
$platformMapping = @{ }
foreach ( $prop in $settings.platformMappings.psobject.properties ) { $platformMapping[ $prop.Name ] = $prop.Value }

$baseURL = $settings.pvwaUrl
$dataUrl = $settings.dataUrl
$authMethod = $settings.authMethod
$authPrompt = $settings.authPrompt
$groupBasedMode = $settings.groupBasedMode

$psmRdpAddress = $settings.psmRdpAddress
$psmSshAddress = $settings.psmSshAddress

# get user from RoyalTs User context or defined credentials
$caUser = @'
$EffectiveUsername$
'@

$caPass = @'
$EffectivePassword$
'@

if ([string]::isNullOrEmpty( $caUser )) { $caUser = $env:username }
if ((!$groupBasedMode) -and $authPrompt) {	$caCredentials = Get-Credential -UserName $caUser -Message "Please enter your CyberArk Username and Password" }


# prepare RoyalJSON response
$response = @{
	Objects = [System.Collections.Generic.List[object]]::new();
}

#########################################
#              Functions                #
#########################################
function Invoke-Logon() {
	$global:header = @{ }
	$header.Add('Content-type', 'application/json') 
	$logonURL = $baseURL + '/api/auth/' + $authMethod + '/Logon'
	if ($authPrompt) { $logonData = @{ username = $caCredentials.GetNetworkCredential().UserName; password = $caCredentials.GetNetworkCredential().Password; concurrentSession = $true; } | ConvertTo-Json }
	else { $logonData = @{ username = $caUser; password = $caPass; concurrentSession = $true; } | ConvertTo-Json }
	try {
		$logonDataEnc = [System.Text.Encoding]::UTF8.GetBytes($logonData)
		$logonResult = $( Invoke-WebRequest -Uri $logonURL -Headers $header -Method Post -UseBasicParsing -Body $logonDataEnc ).content | ConvertFrom-Json 
	} 
	catch { 
		Write-Error "Did you define the right credentials to login? "
	}
	$header.Add('Authorization' , $logonResult) 
}
function Invoke-Logoff() {
	try { Invoke-WebRequest -Uri $( $baseURL + '/api/auth/Logoff') -Headers $header -UseBasicParsing -Method Post | Out-Null } catch { }
}
function Get-Safes() {
	$safeURL = $baseURL + '/api/Safes?limit=10000'
	$safesList = $( Invoke-WebRequest -Uri $safeURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json
	$safes = [System.Collections.Generic.List[string]]::new();
	foreach ($safe in $safesList.value) {
		$safes.Add($safe.SafeName)
	}
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched safes from API" }
	$safes = $safes | Sort-Object
	return $safes
}

function Get-SafeGroups() {
	$userGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$( $caUser )))")).FindOne().GetDirectoryEntry()
	$groups = $userGroups.memberOf

	if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched $caUser member groups $groups" }

	$safes = [System.Collections.Generic.List[string]]::new();
	foreach ($group in $groups) {
		$match = [regex]::Match($group, $settings.groupBasedSafeRegex)
		if ($match.Success) {
			$safeName = $match.Groups[1].ToString()
			$safes.Add($safeName)
		}
	}
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched safes from groups" }

	$safes = $safes | Sort-Object
	return $safes
}

function Get-AccountsFromSafesPVWA($safes) {
	$safesAndAccounts = [System.Collections.Generic.Dictionary[string, object]]::new();
	foreach ($safe in $safes) {
		$accountURL = $pvwaUrl + '/api/Accounts?limit=1000&filter=safeName eq ' + $safe.SafeName
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
	$safesAndAccounts = $safesAndAccounts.GetEnumerator() | Sort-Object
	return $safesAndAccounts
}

function Get-ConnectionRDP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = 'RemoteDesktopConnection'

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmRdpAddress } else { $entry.ComputerName = $plat.replacePsm }
	if ([string]::isNullOrEmpty( $settings.rdpResizeMode )) { $entry.ResizeMode = 'SmartSizing' } else { $entry.ResizeMode = $settings.rdpResizeMode }
    
	$entry.Username = $caUser
	if ($plat.drivesRedirection) { $entry.Properties.RedirectDrives = 'true' }    
	if ($settings.enableNLA) { $entry.NLA = 'true' } else { $entry.NLA = 'false' }
	if ($plat.psmRemoteMachine) {
		if ($comp -ne "PSM-RDP") { $componentAddition = ' - ' + $comp }
		# Entry Name
		if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
		else {
			if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
			switch ($entryName) {
				"full" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.address + ' - ' + $acc.target + $componentAddition + $plat.namePostfix } 
				"named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $componentAddition + $plat.namePostfix }
				Default { $entry.Name = $plat.namePrefix + $acc.target + $componentAddition + $plat.namePostfix }
			}
			if (![string]::isNullOrEmpty( $plat.replaceRegex )) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
		}
		$entry.Properties.StartProgram = 'psm /u ' + $acc.userName + '@' + $acc.address + ' /a ' + $acc.target + ' /c ' + $comp
	}
	else {
		if ($comp -ne "PSM-RDP") { $componentAddition = ' - ' + $comp }

		# Entry Name
		if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
		else {
			if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
			switch ($entryName) {
				"full" { $entry.Name = $plat.namePrefix + $acc.userName + ' - ' + $acc.target + $componentAddition + $plat.namePostfix } 
				"named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $componentAddition + $plat.namePostfix }
				Default { $entry.Name = $plat.namePrefix + $acc.target + $componentAddition + $plat.namePostfix }
			}
			if (![string]::isNullOrEmpty( $plat.replaceRegex )) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
		}
		$entry.Properties.StartProgram = 'psm /u ' + $acc.userName + ' /a ' + $acc.target + ' /c ' + $comp
	}
	return $entry
}

function Get-ConnectionSSH($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = 'TerminalConnection'
	$entry.TerminalConnectionType = 'SSH'

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmSshAddress } else { $entry.ComputerName = $plat.replacePsm }

	# Entry Name
	if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
	else {
		if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
		switch ($entryName) {
			"full" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + ' - ' + $comp + $plat.namePostfix }  
			"named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $plat.namePostfix } 
			Default { $entry.Name = $plat.namePrefix + $acc.target + $plat.namePostfix }
		}
		if (![string]::isNullOrEmpty($plat.replaceRegex)) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
	}
	$entry.UserName = $caUser + '@' + $acc.userName + '@' + $acc.target
	return $entry
}

function Get-ConnectionSFTP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = 'FileTransferConnection'
	$entry.FileTransferConnectionType = 'SFTP'

	if ([string]::isNullOrEmpty( $plat.color )) { $entry.ColorFromParent = $true } else { $entry.color = $plat.color }
	if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmSshAddress } else { $entry.ComputerName = $plat.replacePsm }

	# Entry Name
	if (![string]::isNullOrEmpty( $plat.replaceName )) { $entry.Name = $plat.replaceName }
	else {
		if (![string]::isNullOrEmpty( $plat.entryName )) { $entryName = $plat.entryName } else { $entryName = $settings.entryName }
		switch ($entryName) {
			"full" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + ' - ' + $comp + $plat.namePostfix }  
			"named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $plat.namePostfix } 
			Default { $entry.Name = $plat.namePrefix + $acc.target + $plat.namePostfix }
		}
		if (![string]::isNullOrEmpty($plat.replaceRegex)) { $entry.Name = $entry.Name -replace $plat.replaceRegex }
	}
	$entry.CredentialMode = 4
	$entry.CredentialName = $caUser + '@' + $acc.userName + '@' + $acc.target
	return $entry
}


function Get-ConnectionWEB($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = 'WebConnection'

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
			"full" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + ' - ' + $comp + $plat.namePostfix }
			"named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $plat.namePostfix }
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

# TODO Switch cyberRoyal mode
if ($settings.allAccountsMode) { 
	$safes = [System.Collections.Generic.List[string]]::new();
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " applying all accounts" }
}
elseif ($settings.groupBasedMode) {
	$safes = Get-SafeGroups
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched group based safes: $( $safes.Count )" }
}
else {
	Invoke-Logon
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " login done" }

	$safes = Get-Safes 
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched safes: $( $safes.Count )" }
}

# Get safes and accounts list either from prefetched data or via PVWA
if ([string]::isNullOrEmpty($dataUrl)) { 
	$safesAndAccounts = Get-AccountsFromSafesPVWA($safes)
}
else {
	# get the prepared data file and remove BOM (thanks to .NET, IIS) if necessary
	$jsonFileData = Invoke-WebRequest -Uri $dataUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
	if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched json file length: $( $jsonFileData.RawContentLength)" }
	
	# Array with objects (key=value objects, where key=SafeName)
	$safesAndAccounts = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
}


foreach ($safe in $safesAndAccounts) {
   
	# match safe or continue
	if ( !$settings.allAccountsMode -and !($safes.Contains( $safe.Key )) ) { continue }

	# apply safeFilter
	if ($settings.safeFilter -and !([regex]::Match( $safe.Key, $settings.safeFilterRegex ).Success )) { continue } 

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
			"safe.name" { $folder.Name = $safe.Key }
			"safe.name-description" { $folder.Name = $safe.Key + ' - ' + $safe.Value.Description }
			"safe.description" { $folder.Name = $safe.Value.Description }
			"safe.description-name" { $folder.Name = $safe.Value.Description + ' - ' + $safe.Key }
		}
	}

	foreach ($account in $safe.Value.Accounts) {

		$accountPlatform = $account.platformId

		if (!$platformMapping.ContainsKey( $accountPlatform )) { continue }
		if ($settings.excludeAccounts.Contains( $account.userName)) { continue }
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
			$rmMachines = $account.remoteMachines.split(';', [System.StringSplitOptions]::RemoveEmptyEntries) | Sort-Object
			foreach ($rmAddress in $rmMachines) {
				Add-Member -InputObject $account -NotePropertyName 'target' -NotePropertyValue $rmAddress -Force
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
if (!$settings.groupBasedMode -and !$settings.allAccountsMode) { Invoke-Logoff }
if ($debugOn) { Write-Host $stopWatch.Elapsed + " finished" }