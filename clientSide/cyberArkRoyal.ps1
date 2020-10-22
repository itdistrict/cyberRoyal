#########################################
##       Royal TS meets CyberArk       ##
##          www.itdistrict.ch          ##
#########################################
#         ClientSide Script             #
#########################################
# See README.md for all setting values  #
#########################################

# leave empty if none or enter URL to the json settings like "https://WebHost/ScriptData/cyberArkRoyalSettings.json"
$webSettingsUrl = ""

# enable or disable SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
$psCertValidation = $false

# switch debug mode on (only directly in powershell, cannot be used in RoyalTS)
$debugOn = $false

# settings localy, webSettingsUrl will replace this entries!
$settings = @"
{
    "pvwaUrl": "https://YOUR-PVWA/PasswordVault",
    "dataUrl": "https://YOUR-WEBHOST/ScriptData/cyberArkSafeAccountList.json",
    "authMethod": "LDAP",
    "psmRdpAddress": "YOUR-PSM-RDP",
    "psmSshAddress": "YOUR-PSM-SSH",
    "psmWebAddress": "YOUR-PSM-WEB",
    "psmWebPort": 8080,
    "allAccountsMode": 0,
    "safeFilter": 0,
    "safeFilterRegex": ".*_OnylThisSafes.*",
    "groupBasedMode": 0,
    "groupBasedSafeRegex": "CN=.*?(SafeName),OU=.*",
    "folderCreation": "safe.name",
    "entryName": "named",
    "credentialsFromParent": 1,
    "enableNLA": 0,
    "excludeAccounts": [ "guest" ],
    "useWebPluginWin": "f008c2f0-5fb3-4c5e-a8eb-8072c1183088",
    "platformMappings": {
        "UnixSSH": {
            "royalTsConnection": "SSH",
            "accountType": "local"
        },
        "WindowsDomain": {
            "royalTsConnection": "RDP",
            "accountType": "domain",
            "connectionComponent": "PSM-RDP"
        },
        "ExchangeDomainUser": {
            "replacePsm": "ANOTHER-PSM-ADDRESS",
            "royalTsConnection": "RDP",
            "accountType": "domain",
            "connectionComponent": "PSM-WebApp-Exchange-EPC"
        },
        "WindowsServerLocal": {
            "royalTsConnection": "RDP",
            "accountType": "local",
            "connectionComponent": "PSM-RDP"
        },
        "AzureWebAccount":{
            "replaceName": "",
            "namePrefix": "Azure - ",
            "namePostfix": "",
            "royalTsConnection": "WEB",
            "accountType": "local",
            "webProtocol": "https",
            "webOverwriteUri": "",
            "webInputObject": "input#i0116"
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

$psmRdpAddress = $settings.psmRdpAddress
$psmSshAddress = $settings.psmSshAddress
$psmWebAddress = $settings.psmWebAddress
$psmWebPort = $settings.psmWebPort

# get user from RoyalTs User context or defined from Credentials variable
if ($settings.groupBasedMode) {
    $caUser = $env:username
}
else {
    $caUser = '$EffectiveUsername$'
    $caPass = @'
$EffectivePassword$
'@
}

# prepare RoyalJSON response
$json_response = @{ }
$json_response.Objects = @()

#########################################
#              Functions                #
#########################################
function Invoke-Logon() {
    $global:header = @{ }
    $header.Add('Content-type', 'application/json') 
    $logonURL = $baseURL + '/api/auth/' + $authMethod + '/Logon'
    $logonData = @{ username = $caUser; password = $caPass; concurrentSession = $true; } | ConvertTo-Json
    try {
        $logonResult = $( Invoke-WebRequest -Uri $logonURL -Headers $header -Method Post -UseBasicParsing -Body $logonData ).content | ConvertFrom-Json 
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
    $safeURL = $baseURL + '/WebServices/PIMServices.svc/Safes'
    $safesList = $( Invoke-WebRequest -Uri $safeURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json

    $safes = @{ }
    foreach ($safe in $safesList.GetSafesResult) {
        $safeName = $safe.SafeName
        $safes[ $safeName ] = $safe
    }
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " wrote safes to HashTable" }

    return $safes
}

function Get-SafeGroups() {
    $userGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$( $caUser )))")).FindOne().GetDirectoryEntry()
    $groups = $userGroups.memberOf

    $safes = @{ }
    foreach ($group in $groups) {
        $match = [regex]::Match($group, $settings.groupBasedSafeRegex)
        if ($match.Success) {
            $safeName = $match.Groups[1].ToString()
            $safes[ $safeName ] = $group
        }
    }
    return $safes
}

function Get-AccountsFromSafes($safes) {
    $accountsList = @{ }
    foreach ($safe in $safes) {
        $accountURL = $baseURL + '/api/Accounts?search=' + $safe.SafeName
        $accounts = $( Invoke-WebRequest -Uri $accountURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json
        if ($null -ne $accounts.value -and $accounts.value.Length -gt 0) {
            $accountsList[ $safe.SafeName ] = @{ }
            $accountsList[ $safe.SafeName ][ "safe" ] = $safe
            foreach ($account in $accounts.value) {
                $accountsList[ $safe.SafeName ][ $account.id ] = $account
            }
        }
    }
    return $accountsList        
}

function Get-ConnectionRDP($acc, $plat) {
    $entry = @{ }
    $entry.Properties = @{ }
    $entry.ColorFromParent = $true
    
    $entry.Type = 'RemoteDesktopConnection'
    if ([string]::isNullOrEmpty( $plat.replacePsm )) { $entry.ComputerName = $psmRdpAddress } else { $entry.ComputerName = $plat.replacePsm }

    if ($settings.credentialsFromParent) { $entry.CredentialsFromParent = $true } else { $entry.Username = $caUser }
    if ($settings.enableNLA) { $entry.NLA = 'true' } else { $entry.NLA = 'false' }
    if ($plat.accountType -eq "domain") {
        if ($plat.connectionComponent -ne "PSM-RDP") { $componentAddition = ' - ' + $plat.connectionComponent }

        # Entry Name
        if (![string]::isNullOrEmpty($plat.replaceName)) {
            $entry.Name = $plat.replaceName
        }
        else {
            switch ($settings.entryName) {
                "full" { $entry.Name = $plat.namePrefix + $acc.target + ' - ' + $acc.userName + '@' + $acc.address + $componentAddition + $plat.namePostfix } 
                "named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $componentAddition + $plat.namePostfix }
                Default { $entry.Name = $plat.namePrefix + $acc.target + $componentAddition + $plat.namePostfix }
            }
        }
        $entry.Properties.StartProgram = 'psm /u ' + $acc.userName + '@' + $acc.address + ' /a ' + $acc.target + ' /c ' + $plat.connectionComponent

    }
    else {
        if ($plat.connectionComponent -ne "PSM-RDP") { $componentAddition = ' - ' + $plat.connectionComponent }

        # Entry Name
        if (![string]::isNullOrEmpty($plat.replaceName)) {
            $entry.Name = $plat.replaceName
        }
        else {
            switch ($settings.entryName) {
                "full" { $entry.Name = $plat.namePrefix + $acc.target + ' - ' + $acc.userName + $componentAddition + $plat.namePostfix } 
                "named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $componentAddition + $plat.namePostfix }
                Default { $entry.Name = $plat.namePrefix + $acc.target + $componentAddition + $plat.namePostfix }
            }
        }
        $entry.Properties.StartProgram = 'psm /u ' + $acc.userName + ' /a ' + $acc.target + ' /c ' + $plat.connectionComponent
    }
    return $entry
}

function Get-ConnectionSSH($acc, $plat) {
    $entry = @{ }
    $entry.Type = 'TerminalConnection'
    $entry.TerminalConnectionType = 'SSH'
    $entry.ColorFromParent = $true
    
    # Entry Name
    if (![string]::isNullOrEmpty($plat.replaceName)) {
        $entry.Name = $plat.replaceName
    }
    else {
        switch ($settings.entryName) {
            "full" { $entry.Name = $plat.namePrefix + $acc.target + ' - ' + $acc.userName + $plat.namePostfix }  
            "named" { $entry.Name = $plat.namePrefix + $acc.userName + '@' + $acc.target + $plat.namePostfix } 
            Default { $entry.Name = $plat.namePrefix + $acc.target + $plat.namePostfix }
        }
    }
    if ([string]::isNullOrEmpty($plat.replacePsm)) { $entry.ComputerName = $caUser + '@' + $acc.userName + '@' + $acc.target + '@' + $psmSshAddress } 
    else { $entry.ComputerName = $caUser + '@' + $acc.userName + '@' + $acc.target + '@' + $plat.replacePsm }
    
    if ($settings.credentialsFromParent) { $entry.CredentialsFromParent = $true } else { $entry.Username = $caUser }
    return $entry
}

function Get-ConnectionWEB($acc, $plat) {
    $entry = @{ }
    $entry.Properties = @{ }

    $entry.Type = 'WebConnection'
    $entry.Username = $caUser
    $entry.ColorFromParent = $true
    
    # Web URI overwrite if defined
    if (![string]::isNullOrEmpty($plat.webOverwriteUri)) {  
        $entry.URL = "$( $plat.webProtocol )://" + $plat.webOverwriteUri
    } 
    else {     
        $entry.URL = "$( $plat.webProtocol )://" + $acc.target
    }

    # Entry Properties
    $entry.Properties.ShowToolbar = $true
    $entry.Properties.IgnoreCertificateErrors = $true
    $entry.Properties.UseDedicatedEngine = $true
    if ([string]::isNullOrEmpty($plat.replacePsm)) { $entry.Properties.ProxyHostname = $psmWebAddress }
    else { $entry.Properties.ProxyHostname = $plat.replacePsm }
    $entry.Properties.ProxyPort = $psmWebPort
    $entry.Properties.ProxyMode = 1

    # AutoFill Implementations
    $webApp = "default"
    if (![string]::isNullOrEmpty( $acc.platformAccountProperties.WebApplicationID )) {
        $webApp = $acc.platformAccountProperties.WebApplicationID 
    }

    switch ($webApp) {
        "ADDITIONAL-IMPLEMENTATION" {
            $fillUser = $caUser + ":" + $acc.userName
            $fillMappings = @( @{ Element = "input#i0116"; Action = "Fill"; Value = $fillUser } )
            $entry.AutoFillElements = $fillMappings
            $entry.AutoFillDelay = 3000
        }
        Default { 
            $fillUser = $caUser + ":" + $acc.userName
            $fillMappings = @( @{ Element = $plat.webInputObject; Action = "Fill"; Value = $fillUser } )
            $entry.AutoFillElements = $fillMappings
            $entry.AutoFillDelay = 1000
        }
    }

    # Entry Name
    if (![string]::isNullOrEmpty($plat.replaceName)) {
        $entry.Name = $plat.replaceName
    }
    else {
        switch ($settings.entryName) {
            "full" { $entry.Name = $plat.namePrefix + $acc.userName + ' - ' + $acc.target + ' - ' + $webApp + $plat.namePostfix }
            "named" { $entry.Name = $plat.namePrefix + $acc.userName + ' - ' + $acc.target + $plat.namePostfix }
            Default { $entry.Name = $plat.namePrefix + $acc.userName + $plat.namePostfix }
        }
    }

    # Use Win WebPlugin ID instead of global config
    if (![string]::isNullOrEmpty($settings.useWebPluginWin)) {
        $entry.Properties.UseGlobalPlugInWin = $false
        $entry.Properties.PlugInWin = $settings.useWebPluginWin
    }

    return $entry
}

function Get-ConnectionEntry($accountDetail, $platformSetting) {
    switch ($platformSetting.royalTsConnection) {
        "SSH" { return Get-ConnectionSSH $accountDetail $platformSetting }
        "RDP" { return Get-ConnectionRDP $accountDetail $platformSetting }
        "WEB" { return Get-ConnectionWEB $accountDetail $platformSetting }
    }
}

#########################################
#                MAIN                   #
#########################################
if ($settings.allAccountsMode) { 
    $safes = @{ } 
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " applying all accounts" }
}
elseif ($settings.groupBasedMode) {
    $safes = Get-SafeGroups
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched group based safes: $( $safes.Count )" }
}
else {
    Invoke-Logon
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " login done" }

    $safes = Get-Safes 
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched safes: $( $safes.Count )" }
}

# get the prepared data file and remove BOM (thanks to .NET, IIS) if necessary
$jsonFileData = Invoke-WebRequest -Uri $dataUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched json file length: $( $jsonFileData.RawContentLength)" }
$safesAndAccountsList = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json

# sort list
switch ($settings.folderCreation) {
    "safe.name" { $sortedSafesAndAccountsList = $safesAndAccountsList.psobject.properties | Sort-Object { $_.Value.safe.safename } }
    "safe.name-description" { $sortedSafesAndAccountsList = $safesAndAccountsList.psobject.properties | Sort-Object { $_.Value.safe.safename } }
    "safe.description" { $sortedSafesAndAccountsList = $safesAndAccountsList.psobject.properties | Sort-Object { $_.Value.safe.description } }
    "safe.description-name" { $sortedSafesAndAccountsList = $safesAndAccountsList.psobject.properties | Sort-Object { $_.Value.safe.description } }
    Default { $sortedSafesAndAccountsList = $safesAndAccountsList.psobject.properties | Sort-Object { $_.Value.safe.safename } }
}

# SafesAndAccountsList into a hashtable with key = order
$safesAndAccountsTable = @{ }
foreach ($entry in $sortedSafesAndAccountsList) { 
    $safesAndAccountsTable[ $safesAndAccountsTable.Count ] = @($entry.Name, $entry.Value)
}
if ($debugOn) { Write-Host $stopWatch.Elapsed + " wrote and sorted safesAndAccounts to HashTable" }

foreach ($safeKey in $safesAndAccountsTable.getEnumerator() | Sort-Object Key) {
    $safeAndAccounts = $safeKey.Value
    
    # match safe or continue
    if ( !$settings.allAccountsMode -and !$safes.ContainsKey( $safeAndAccounts.safe.SafeName ) ) { continue }

    # apply safeFilter
    if ($settings.safeFilter -and !([regex]::Match( $safeAndAccounts.safe.SafeName, $settings.safeFilterRegex ).Success )) { continue } 

    if ($settings.folderCreation -eq "none") {
        $objects = @()
    }
    else {
        $folder = @{ }
        $folder.Objects = @()
        $folder.Type = 'Folder'
        $folder.ColorFromParent = $true

        if ($settings.credentialsFromParent) { $folder.CredentialsFromParent = $true }

        switch ($settings.folderCreation) {
            "safe.name" { $folder.Name = $safeAndAccounts.safe.SafeName }
            "safe.name-description" { $folder.Name = $safeAndAccounts.safe.SafeName + ' - ' + $safeAndAccounts.safe.Description }
            "safe.description" { $folder.Name = $safeAndAccounts.safe.Description }
            "safe.description-name" { $folder.Name = $safeAndAccounts.safe.Description + ' - ' + $safeAndAccounts.safe.SafeName }
        }
    }

    # get accounts hashtable with key = ID
    $accounts = @{ }
    $safeAndAccounts.accounts.psobject.properties | ForEach-Object { $accounts[ $_.Name] = $_.Value }
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " wrote accounts from $( $safeAndAccounts.safe.SafeName) to HashTable" }
    foreach ($accountKey in $accounts.Keys) {
        $accountDetails = $accounts[ $accountKey]
        $accountPlatform = $accountDetails.platformId
        if (!$platformMapping.ContainsKey( $accountPlatform)) { continue }
        if ($settings.excludeAccounts.Contains( $accountDetails.userName)) { continue }
        if ($debugOn) { $debugNrAccounts++ }
        if ($null -eq $accountDetails.remoteMachinesAccess.remoteMachines) {
            Add-Member -InputObject $accountDetails -NotePropertyName 'target' -NotePropertyValue $accountDetails.address
            $connection = Get-ConnectionEntry $accountDetails $platformMapping[ $accountPlatform]
            if ($settings.folderCreation -eq "none") {
                $objects += $connection
            }
            else {
                $folder.Objects += $connection
            }
            if ($debugOn) { $debugNrServerConnections++ }
        }
        else {
            $remoteMachines = $accountDetails.remoteMachinesAccess.remoteMachines.split(';', [System.StringSplitOptions]::RemoveEmptyEntries) | Sort-Object
            foreach ($rmAddress in $remoteMachines) {
                Add-Member -InputObject $accountDetails -NotePropertyName 'target' -NotePropertyValue $rmAddress -Force
                $connection = Get-ConnectionEntry $accountDetails $platformMapping[ $accountPlatform]
                if ($settings.folderCreation -eq "none") {
                    $objects += $connection
                }
                else {
                    $folder.Objects += $connection
                }
                if ($debugOn) { $debugNrServerConnections++ }
            }
        }
    }
    if ($settings.folderCreation -eq "none" -and $objects.Length -gt 0) {
        $json_response.objects += $objects
    }
    elseif ($folder.Objects.Length -gt 0) {
        $json_response.objects += $folder
    }

}

# send RoyalJSON response
$response = $json_response | ConvertTo-Json -Depth 100

if ($debugOn) { 
    Write-Host $stopWatch.Elapsed + " got $( $json_response.objects.Count) folders with $debugNrAccounts accounts and $debugNrServerConnections server connections" 
    Out-File -FilePath "data.json" -Encoding UTF8 -InputObject $response
}
else {
    Write-Host $response
}

# logoff if required
if (!$settings.groupBasedMode -and !$settings.allAccountsMode) { Invoke-Logoff }
if ($debugOn) { Write-Host $stopWatch.Elapsed + " finished" }