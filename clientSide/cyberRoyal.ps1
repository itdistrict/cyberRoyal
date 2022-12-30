#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
#########################################
#         ClientSide Script             #
#########################################

# to start and debug directly from PowerShell the following params can be used
param([String]$username, [String]$settingsFile, [Boolean]$debugAuthPrompt, [Boolean]$debugOn)

# leave empty if none or enter URL to the json settings like "https://WebHost/ScriptData/cyberRoyalSettings.json"
$webSettingsUrl = ""

# enable or disable (not recommended) SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
$psCertValidation = $false

# settings localy, webSettingsUrl will replace this entries!
$settings = @{
	cyberRoyalMode           = "list" #list | pvwa

	listMode                 = "listALL" #adGroupRBAC | pvwaRBAC | listRBAC | listALL
	listUrl                  = "https://YOUR-WEBHOST/ScriptData/cyberRoyalSafeAccountList.json" # required for "list" mode - json that includes safes and accounts
	listPermissionUrl        = "https://YOUR-WEBHOST/ScriptData/cyberRoyalPermissionList.json" # required fore "listRBAC" listMode - json that includes user and its safe use permissions
	listAdGroupSafeRegex     = "CN=.*?(SafeName),OU=.*" # required for listMode "adGroupRBAC" - regex for mapping AD Groups where match group 1 matches safenames

	pvwaUrl                  = "https://YOUR-PVWA/PasswordVault" # required for "pvwa" mode and "pvwaRBAC" listMode
	pvwaAuthMethod           = "LDAP" # CyberArk | LDAP | RADIUS
	pvwaAuthPrompt           = $true # prompt mask for username and password (PWSH7 not supported)
	usernameFromEnv          = $false # takes cyberark username from $env:username

	pvwaSafeSearch           = "" # get only safes from PVWA according search
	pvwaSavedFilter          = "Favorites" # Favorites | Recently |... "pvwa" mode - get acounts only from PVWA Saved Filters
	pvwaAdditionalProperties = @("location", "FQDN") # "pvwa" mode - get additional account properties when query PVWA for all accounts

	psmRdpAddress            = "YOUR-PSM" # required
	psmSshAddress            = "YOUR-PSMP" # required

	safeFilter               = ".*" # handle only safes that match this regex
	excludeAccounts          = @("guest", "player") # exclude accounts with this username 

	connectionDescription    = "location" # property to set in connection description - default is safe description

	folderCreation           = "safeName" # safeName | safeDescription | safeName-Description | safeDescription-Name | platform | accountParameter - create folders according different properties
	folderAccountParameter   = "Location" # use a specific account property to create folders when using folderCreation = "accountParameter"

	enableNLA                = $false # enable NLA/CredSSP in RoyalTS RDP connections which can take the saved credentials
	rdpResizeMode            = "SmartSizing"
	useWebPluginWin          = "f008c2f0-5fb3-4c5e-a8eb-8072c1183088" # use specifid browser plugin when creating web connections (chrome engine)

	platformMappings         = @{
		UnixSSH        = @{
			connections = @(
				@{type = "SSH"; components = @("PSMP-SSH") },
				@{type = "SFTP"; components = @("PSMP-SFTP") },
				@{type = "RDP"; components = @("PSM-WinSCP") }
			)
		}
		WinDomain      = @{
			psmRemoteMachine = 1
			connections      = @(
				@{type = "RDP"; components = @("PSM-RDP") }
			)
		}
		WinServerLocal = @{
			namePrefix       = "Local - "
			namePostfix      = ""
			color            = "#FF0000"
			replaceRegex     = "@domain.acme.com"
			psmRemoteMachine = 0
			connections      = @(
				@{type = "RDP"; components = @("PSM-RDP") }
			)
		}
	}
}



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
# RoyalTS user context or credential will fill the following $variables$ if defined during script execution
$caUser = @'
$EffectiveUsername$
'@

$caPass = @'
$EffectivePassword$
'@

# get settings from web if available
if (![string]::isNullOrEmpty($webSettingsUrl)) {
	try {
		$settings = Invoke-WebRequest -Uri $webSettingsUrl -Method Get -UseBasicParsing -ContentType "application/json; charset=utf-8"
		$settings = $settings | ConvertFrom-Json
	}
	catch {
		Write-Error "Could not get settings from provided URL"
	}
}
elseif (![string]::IsNullOrEmpty($settingsFile)) {
	if (Test-Path $settingsFile) {
		Write-Host -ForegroundColor Cyan "apply settings from file $settingsFile"
		$settings = Get-Content $settingsFile | ConvertFrom-Json
	}
	else {
		Write-Error "settings file not found" -ErrorAction Stop
	}
}

# get settings and form a platformMapping hashtable with key = platformname
$platformMapping = @{ }
foreach ( $prop in $settings.platformMappings.psobject.properties ) { $platformMapping[ $prop.Name ] = $prop.Value }

# multiple used variables
$pvwaUrl = $settings.pvwaUrl

# when are PVWA credentials required
if ($settings.cyberRoyalMode -eq "pvwa" -or $settings.listMode -eq "pvwaRBAC") { $pvwaLoginRequired = $true } else { $pvwaAuthRequired = $false }

if (![string]::IsNullOrEmpty($username)) { $caUser = $username }
if ($settings.usernameFromEnv) { $caUser = $env:username }

if ($pvwaLoginRequired -or $debugAuthPrompt) {
	if ($settings.pvwaAuthPrompt -or $debugAuthPrompt) { 
		if (![string]::IsNullOrEmpty($username) -or $settings.usernameFromEnv) {
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
	if ($debugOn) { Write-Host $stopWatch.Elapsed + $message }
}
function Invoke-Logon() {
	Write-Debug "invoke PVWA logon"
	$global:header = @{ }
	$header.Add("Content-type", "application/json") 
	$logonURL = $pvwaUrl + "/api/auth/" + $settings.pvwaAuthMethod + "/Logon"
	if ($settings.pvwaAuthPrompt -or $debugAuthPrompt) { $logonData = @{ username = $caCredentials.GetNetworkCredential().UserName; password = $caCredentials.GetNetworkCredential().Password; concurrentSession = $true; } | ConvertTo-Json }
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
function Get-PvwaSafeDetails() {
	if ([string]::IsNullOrEmpty($settings.pvwaSafeSearch)) { 
		Write-Debug "get all accessable PVWA safes"
		$safeURL = $pvwaUrl + "/api/Safes?limit=10000" 
	}
 else { 
		Write-Debug "get PVWA safes with safe search $($settings.pvwaSafeSearch)"
		$safeURL = $pvwaUrl + "/api/Safes?limit=10000&search=$($settings.pvwaSafeSearch)" 
	}
	$safesList = $( Invoke-WebRequest -Uri $safeURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json
	$safes = [System.Collections.Generic.List[object]]::new();
	foreach ($safe in $safesList.value) {
		$safes.Add($safe)
	}
	Write-Debug "fetched $($safes.Count) safes from PVWA" 
	[System.Collections.Generic.List[object]]$safes = $safes | Sort-Object
	return $safes
}

function Get-PermissionListSafeNames($listUrl) {
	Write-Debug "get permissionsList from $listUrl"
	$jsonFileData = Invoke-WebRequest -Uri $listUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
	$safePermissionList = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
	$safeNames = [System.Collections.Generic.List[string]]::new();
	foreach ($safePermission in $safePermissionList.users) {
		if ($safePermission.username -eq $caUser) {
			$safeNames = $safePermission.permissions
		}
	}
	Write-Debug "fetched $($safeNames.Count) safeNames from PermissionList"
	if ($safeNames.Count -lt 1) { Write-Error "No safe permissions for user $caUser in PermissionList found" -ErrorAction Stop }
	[System.Collections.Generic.List[string]]$safeNames = $safeNames | Sort-Object
	return $safeNames
}

function Get-adGroupSafeNames() {
	Write-Debug "get adGroups from user $caUser"
	$userGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$( $caUser )))")).FindOne().GetDirectoryEntry()
	$groups = $userGroups.memberOf
	Write-Debug "fetched $caUser member groups $groups"
	$safeNames = [System.Collections.Generic.List[string]]::new();
	foreach ($group in $groups) {
		$match = [regex]::Match($group, $settings.listAdGroupSafeRegex)
		if ($match.Success) {
			$safeName = $match.Groups[1].ToString()
			$safeNames.Add($safeName)
		}
	}
	Write-Debug "fetched $($safeNames.Count) safeNames from adGroups" 
	[System.Collections.Generic.List[string]]$safeNames = $safeNames | Sort-Object
	return $safeNames
}

function Get-PvwaAccountsFromList($listUrl) {
	Write-Debug "get accountsList from $listUrl"
	# get the prepared data file and remove BOM (thanks to .NET, IIS) if necessary
	$jsonFileData = Invoke-WebRequest -Uri $listUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
	Write-Debug "fetched json file length: $( $jsonFileData.RawContentLength)"
	
	# ConvertFrom-Json -AsHashtable only available in PWSH 7
	# PSCustomObject with objects (key=value objects, where key=SafeName)
	[PSCustomObject]$safesAndAccounts = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json
	# [System.Collections.SortedList]
	return $safesAndAccounts
}

#c: check safeFilter
function Get-PvwaAccountsFromSafes($safeDetails) {
	Write-Debug "get accounts from PVWA safes"
	$safesAndAccounts = [System.Collections.SortedList]::new()
	foreach ($safe in $safeDetails) {
		if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe.SafeName, $settings.safeFilter ).Success )) { continue } 
		$accountURL = $pvwaUrl + "/api/Accounts?limit=1000&filter=safeName eq $($safe.SafeName)"
		$accountsResult = $( Invoke-WebRequest -Uri $accountURL -Headers $header -Method Get).content | ConvertFrom-Json
		if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
			$safeEntry = @{ "SafeName" = $safe.SafeName; "Description" = $safe.Description; "Accounts" = [System.Collections.Generic.List[object]]::new(); }
			foreach ($account in $accountsResult.value) {
				$accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
				foreach ($property in $settings.pvwaAdditionalProperties) {
					$accountEntry += @{$property = $account.platformAccountProperties.$property }
				}
				$safeEntry.Accounts.Add($accountEntry)
				$accountEntriesCount++
			}
			$safesAndAccounts.Add($safe.SafeName, $safeEntry)
		}
	}
	Write-Debug "retrieved $accountEntriesCount accounts from PVWA"
	return $safesAndAccounts
}

function Get-PvwaAccountsFromSavedFilter($savedFilter) {
	Write-Debug "get accounts from PVWA saved Filter $savedFilter"
	$safesAndAccounts = [System.Collections.SortedList]::new()
	$accountURL = $pvwaUrl + "/api/Accounts?savedFilter=$savedFilter"
	$accountsResult = $(Invoke-WebRequest -Uri $accountURL -Headers $header -Method Get).content | ConvertFrom-Json
	if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
		$safes = $accountsResult.value.safeName | Select-Object -Unique
		foreach ($safe in $safes) {
			if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe, $settings.safeFilter ).Success )) { continue } 
			$safeURL = $pvwaUrl + "/api/Safes/$safe"
			$safeResult = $(Invoke-WebRequest -Uri $safeURL -Headers $header -Method Get).content | ConvertFrom-Json
			$safeEntry = @{ "SafeName" = $safe; "Description" = $($safeResult.description); "Accounts" = [System.Collections.Generic.List[object]]::new(); }
			foreach ($account in $accountsResult.value) {
				if ($account.safeName -eq $safe) {
					$accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
					foreach ($property in $settings.pvwaAdditionalProperties) {
						$accountEntry += @{$property = $account.platformAccountProperties.$property }
					}
					$safeEntry.Accounts.Add($accountEntry)
					$accountEntriesCount++
				}
			}
			$safesAndAccounts.Add($safe, $safeEntry)
		}
	}
	return $safesAndAccounts
}

function Get-ConnectionRDP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = "RemoteDesktopConnection"
	$entry.Username = $caUser
	if ($plat.psmRemoteMachine) {
		$entry.Name = $acc.userName + "@" + $acc.address 
		$entry.Properties.StartProgram = "psm /u " + $acc.userName + "@" + $acc.address + " /a " + $acc.target + " /c " + $comp
	}
	else {
		$entry.Name = $acc.userName + "@" + $acc.target
		$entry.Properties.StartProgram = "psm /u " + $acc.userName + " /a " + $acc.target + " /c " + $comp
	}
	return $entry
}

function Get-ConnectionSSH($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = "TerminalConnection"
	$entry.TerminalConnectionType = "SSH"
	$entry.Name = $acc.userName + "@" + $acc.target
	$entry.UserName = $caUser + "@" + $acc.userName + "@" + $acc.target
	return $entry
}

function Get-ConnectionSFTP($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Type = "FileTransferConnection"
	$entry.FileTransferConnectionType = "SFTP"
	$entry.Name = $acc.userName + "@" + $acc.target
	$entry.CredentialMode = 4
	$entry.CredentialName = $caUser + "@" + $acc.userName + "@" + $acc.target
	return $entry
}


function Get-ConnectionWEB($acc, $plat, $comp) {
	$entry = @{ }
	$entry.Properties = @{ }
	$entry.Type = "WebConnection"
	$entry.Name = $acc.userName + "@" + $acc.target
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
	# Use Win WebPlugin ID instead of global config
	if (![string]::isNullOrEmpty( $settings.useWebPluginWin )) {
		$entry.Properties.UseGlobalPlugInWin = $false
		$entry.Properties.PlugInWin = $settings.useWebPluginWin
	}
	return $entry
}

function Get-ConnectionEntry($accountDetail, $safeDetails, $platformSetting, $connectionType, $component) {
	# create connection entry for different connection types
	switch ($connectionType) {
		"SSH" {
			$entry = Get-ConnectionSSH $accountDetail $platformSetting $component 
			if ([string]::isNullOrEmpty( $platformSetting.replacePsm )) { $entry.ComputerName = $settings.psmSshAddress } else { $entry.ComputerName = $platformSetting.replacePsm }
		}
		"SFTP" {
			$entry = Get-ConnectionSFTP $accountDetail $platformSetting $component
			if ([string]::isNullOrEmpty( $platformSetting.replacePsm )) { $entry.ComputerName = $settings.psmSshAddress } else { $entry.ComputerName = $platformSetting.replacePsm }
		}
		"RDP" {
			$entry = Get-ConnectionRDP $accountDetail $platformSetting $component
			if ([string]::isNullOrEmpty( $platformSetting.replacePsm )) { $entry.ComputerName = $settings.psmRdpAddress } else { $entry.ComputerName = $platformSetting.replacePsm }
			if ([string]::isNullOrEmpty( $settings.rdpResizeMode )) { $entry.ResizeMode = "SmartSizing" } else { $entry.ResizeMode = $settings.rdpResizeMode }
			if (![string]::isNullOrEmpty($platformSetting.drivesRedirection )) { $entry.Properties.RedirectDrives = "true" }    
			if (![string]::isNullOrEmpty($settings.enableNLA )) { $entry.NLA = "true" } else { $entry.NLA = "false" }
		}
		"WEB" { $entry = Get-ConnectionWEB $accountDetail $platformSetting $component }
	}

	# add standard connection entry values and naming
	$componentName = $component.Replace("PSM-RDP", "").Replace("PSMP-SSH", "").Replace("PSMP-SFTP", "").Replace("PSM-", "").Replace("PSMP-", "")
	if (![string]::isNullOrEmpty( $componentName)) { $componentName = " - " + $componentName }
	$entry.Name = $plat.namePrefix + $entry.Name + $componentName + $plat.namePostfix

	# account description
	$connectionDescriptionProperty = $settings.connectionDescription
	if ([string]::isNullOrEmpty( $connectionDescriptionProperty )) {
		$entry.Description = $safeDetails.Value.Description
	}
	else {
		$entry.Description = $accountDetail.$connectionDescriptionProperty
	}

	# add standard connection entry values and naming
	if ([string]::isNullOrEmpty( $platformSetting.color )) { $entry.ColorFromParent = $true } else { $entry.color = $platformSetting.color }
	if (![string]::isNullOrEmpty( $platformSetting.replaceName )) { $entry.Name = $platformSetting.replaceName }
	if (![string]::isNullOrEmpty($platformSetting.replaceRegex )) { $entry.Name = $entry.Name -replace $platformSetting.replaceRegex }

	return $entry
}

#########################################
#                MAIN                   #
#########################################

# Switch cyberRoyal mode - set the users "permissive" safes to apply account connections
switch ($settings.cyberRoyalMode) {
	"list" {
		switch ($settings.listMode) {
			"adGroupRBAC" { 
				$safes = Get-adGroupSafeNames
				Write-Debug "fetched adGroup safes: $( $safes.Count )" 
			}
			"pvwaRBAC" { 
				Invoke-Logon
				$safesDetails = Get-PvwaSafeDetails
				$safes = $safesDetails.SafeName
				Write-Debug "fetched PVWA safes: $( $safes.Count )" 
			}
			"listRBAC" { 
				$safes = Get-PermissionListSafeNames($settings.listPermissionUrl)
				Write-Debug "fetched PermissionList safes: $( $safes.Count )" 
			}
			"listALL" { 
				$skipSafesMatching = $true
				Write-Debug "applying all accounts from list" 
			}
		}
		$safesAndAccounts = Get-PvwaAccountsFromList($settings.listUrl)
	}
	"pvwa" {
		Invoke-Logon
		# Get PVWA safes details and accounts
		if ([string]::IsNullOrEmpty($settings.pvwaSavedFilter)) {
			$safesDetails = Get-PvwaSafeDetails
			$safes = $safesDetails.SafeName
			$safesAndAccountsSortedList = Get-PvwaAccountsFromSafes($safesDetails)
		}
		else {
			$safesAndAccountsSortedList = Get-PvwaAccountsFromSavedFilter($settings.pvwaSavedFilter)
			$safes = $safesAndAccountsSortedList.Keys
		}
		# Convert SortedList to PSCustomObject List
		[PSCustomObject]$safesAndAccounts = $safesAndAccountsSortedList | ConvertTo-Json -Depth 100 | ConvertFrom-Json
	}
}

if ([string]::IsNullOrEmpty($settings.folderCreation)) {
	$objects = [System.Collections.Generic.List[object]]::new();
}
# safes as List
# safesAndAccounts as PSCustomObject List
# loop through all safes and accounts and create connection entries
foreach ($safe in $safesAndAccounts.PsObject.Properties) {
	# match safe or continue
	if ( !$skipSafesMatching -and !($safes.Contains( $safe.Name )) ) { continue }

	# match safeFilter or continue
	if (![string]::IsNullOrEmpty($settings.safeFilter) -and !([regex]::Match( $safe.Name, $settings.safeFilter ).Success )) { continue } 
	if (![string]::IsNullOrEmpty($settings.folderCreation)) {
		$folder = @{
			Objects         = [System.Collections.Generic.List[object]]::new();
			Type            = "Folder"
			ColorFromParent = $true
		}

		switch ($settings.folderCreation) {
			"safeName" { $folder.Name = $safe.Name; $folder.Description = $safe.Value.Description }
			"safeName-Description" { $folder.Name = $safe.Name + ' - ' + $safe.Value.Description; $folder.Description = $safe.Value.Description }
			"safeDescription" { $folder.Name = $safe.Value.Description; $folder.Description = "Safe:" + $safe.Name }
			"safeDescription-Name" { $folder.Name = $safe.Value.Description + ' - ' + $safe.Name; $folder.Description = $safe.Value.Description }
			Default { $folder.Name = $safe.Name }
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
					$connectionEntry = Get-ConnectionEntry $account $safe $royalPlatform $connection.Type $component
					if ([string]::IsNullOrEmpty($settings.folderCreation)) { $objects.Add( $connectionEntry ) }
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
						$connectionEntry = Get-ConnectionEntry $account $safe $royalPlatform $connection.Type $component
						if ([string]::IsNullOrEmpty($settings.folderCreation)) { $objects.Add($connectionEntry) }
						else { $folder.Objects.Add($connectionEntry) }
						if ($debugOn) { $debugNrServerConnections++ }
					}
				}
			}
		}
	}
	if (![string]::IsNullOrEmpty($settings.folderCreation) -and $folder.Objects.Length -gt 0) {
		$response.Objects.Add($folder)
	}
}

if ([string]::IsNullOrEmpty($settings.folderCreation) -and $objects.Length -gt 0) {
	$response.Objects = $objects
}

# send RoyalJSON response
$jsonResponse = $response | ConvertTo-Json -Depth 100

if ($debugOn) { 
	Write-Debug "created $debugNrServerConnections server connections" 
	Out-File -FilePath "dataRoyalJson.json" -Encoding UTF8 -InputObject $jsonResponse
	$safesAndAccounts | ConvertTo-Json -Depth 100 | Out-File -FilePath "dataSafeAndAccounts.json" -Encoding UTF8
}
else {
	Write-Host $jsonResponse
}

# logoff if required
if ($pvwaLoginRequired) { Invoke-Logoff }
Write-Debug "finished" 