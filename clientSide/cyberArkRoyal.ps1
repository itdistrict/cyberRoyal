#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
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
$response = @{ }
$response.Objects = @()

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
    $safeURL = $baseURL + '/WebServices/PIMServices.svc/Safes'
    $safesList = $( Invoke-WebRequest -Uri $safeURL -Headers $header -Method Get -UseBasicParsing).content | ConvertFrom-Json

    $safes = @{ }
    foreach ($safe in $safesList.GetSafesResult) {
        $safeName = $safe.SafeName
        $safes[ $safeName ] = $safe
    }
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched safes from API" }

    return $safes
}

function Get-SafeGroups() {
    $userGroups = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$( $caUser )))")).FindOne().GetDirectoryEntry()
    $groups = $userGroups.memberOf

    if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched $caUser member groups $groups" }

    $safes = @{ }
    foreach ($group in $groups) {
        $match = [regex]::Match($group, $settings.groupBasedSafeRegex)
        if ($match.Success) {
            $safeName = $match.Groups[1].ToString()
            $safes[ $safeName ] = $group
        }
    }
    if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched safes from groups" }

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
if ($settings.allAccountsMode) { 
    $safes = @{ } 
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

# get the prepared data file and remove BOM (thanks to .NET, IIS) if necessary
$jsonFileData = Invoke-WebRequest -Uri $dataUrl -Method GET -UseBasicParsing -ContentType 'application/json; charset=utf-8'
if ($debugOn) { Write-Host $stopWatch.Elapsed + " fetched json file length: $( $jsonFileData.RawContentLength)" }

$safesAndAccounts = $jsonFileData.Content | Foreach-Object { $_ -replace "\xEF\xBB\xBF", "" } | ConvertFrom-Json

foreach ($safeAccount in $safesAndAccounts) {
   
    # match safe or continue
    if ( !$settings.allAccountsMode -and !$safes.ContainsKey( $safeAccount.SafeName ) ) { continue }

    # apply safeFilter
    if ($settings.safeFilter -and !([regex]::Match( $safeAccount.SafeName, $settings.safeFilterRegex ).Success )) { continue } 

    if ($settings.folderCreation -eq "none") {
        $objects = @()
    }
    else {
        $folder = @{ }
        $folder.Objects = @()
        $folder.Type = 'Folder'
        $folder.ColorFromParent = $true

        switch ($settings.folderCreation) {
            "safe.name" { $folder.Name = $safeAccount.SafeName }
            "safe.name-description" { $folder.Name = $safeAccount.SafeName + ' - ' + $safeAccount.Description }
            "safe.description" { $folder.Name = $safeAccount.Description }
            "safe.description-name" { $folder.Name = $safeAccount.Description + ' - ' + $safeAccount.SafeName }
        }
    }

    foreach ($account in $safeAccount.Accounts) {

        $accountPlatform = $account.platformId

        if (!$platformMapping.ContainsKey( $accountPlatform)) { continue }
        if ($settings.excludeAccounts.Contains( $account.userName)) { continue }
        if ($debugOn) { $debugNrAccounts++ }
        # create connections for every configured connection component
        if ($null -eq $account.remoteMachines) {
            Add-Member -InputObject $account -NotePropertyName 'target' -NotePropertyValue $account.address
            $royalPlatform = $platformMapping[ $accountPlatform]
            foreach ($connection in $royalPlatform.connections) {
                foreach ($component in $connection.components) { 
                    $connectionEntry = Get-ConnectionEntry $account $royalPlatform $connection.Type $component
                    if ($settings.folderCreation -eq "none") { $objects += $connectionEntry }
                    else { $folder.Objects += $connectionEntry }
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
                        if ($settings.folderCreation -eq "none") { $objects += $connectionEntry }
                        else { $folder.Objects += $connectionEntry }
                        if ($debugOn) { $debugNrServerConnections++ }
                    }
                }
            }
        }
    }
    if ($settings.folderCreation -eq "none" -and $objects.Length -gt 0) {
        $response.objects += $objects
    }
    elseif ($folder.Objects.Length -gt 0) {
        $response.objects += $folder
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