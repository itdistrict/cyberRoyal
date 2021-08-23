#########################################
##       Royal TS meets CyberArk       ##
##          www.itdistrict.ch          ##
#########################################
#         ServerSide Script             #
#########################################
# See README.md for all setting values  #
#########################################

#########################################
#          Customisations               #
#########################################

#########################################
# URL to PVWA PasswordVault Site
$pvwaUrl = "https://127.0.0.1/PasswordVault"

# Filename Path to safe .json safes and accounts file to
$filePath = "C:\Cyberark\ScriptData\cyberArkSafeAccountList.json"

# Secrets for CyberArk Auditor user or an user in Auditors group to read all safes and accounts
$apiUsername = "Auditor"
$apiPasswordFile = "C:\scripts\secret.ini"
$apiPasswordKey = "C:\scripts\keys\secret.key"

# enable or disable SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
$psCertValidation = $false

# Turn debug on to see more console output and get more details in log
$debugOn = $false

if ($debugOn) { $stopWatch = [system.diagnostics.stopwatch]::StartNew() }

#########################################
#           Powershell Settings         #
#########################################
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
if ($psCertValidation) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }

#########################################
#               Variables               #
#########################################
$logonUrl = $pvwaUrl + "/api/auth/Cyberark/Logon"
$logoffUrl = $pvwaUrl + "/api/auth/Logoff"
$safesUrl = $pvwaUrl + "/WebServices/PIMServices.svc/Safes"

#########################################
#              Functions                #
#########################################

# Get API Secrets
$ApiPassword = Get-Content $apiPasswordFile | ConvertTo-SecureString -Key (Get-Content $apiPasswordKey)
$ApiPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiPassword))

# Load log module
Import-Module "$PSScriptRoot\log\Write-LogEntry.psm1" -Force

# Logging
$logFile = $MyInvocation.MyCommand.Path.ToString() 
$scriptName = $MyInvocation.MyCommand.Name.ToString()

function Write-Log {
    param ([string]$LogString, [switch]$AsError, [switch]$AsWarning, $ErrorAction = "Continue")
    if ($AsError) {
        Write-LogEntry -LogFile $logFile -ScriptName $scriptName -Message $LogString -AsError
        if ($debugOn) { Write-Error $LogString -ErrorAction $ErrorAction }
    }
    elseif ($AsWarning) {
        Write-LogEntry -LogFile $logFile -ScriptName $scriptName -Message $LogString -AsWarning
        if ($debugOn) { Write-Warning $LogString -ErrorAction $ErrorAction }
    }
    else {
        Write-LogEntry -LogFile $logFile -ScriptName $scriptName -Message $LogString
        if ($debugOn) { Write-Host $LogString }
    }
}

function Invoke-Request {
    param ($Uri, $Method, $Headers, $Body, $ErrorAction = "Continue")
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType 'application/json; charset=utf-8' -UseBasicParsing
    }
    catch {
        if ($null -ne $_.Exception.Response.StatusDescription) {
            if ($debugOn) { Write-Log -LogString "$($_.Exception.Response.StatusDescription) StatusCode: $($_.Exception.Response.StatusCode.value__) on $Method $Uri" -AsError -ErrorAction $ErrorAction }
        }
        else {
            if ($debugOn) { Write-Log -LogString "StatusCode: $($_.Exception.Response.StatusCode.value__) on $Method $Uri" -AsError -ErrorAction $ErrorAction }
        }
        $response = $null
    }
    if ($response) {
        if ($debugOn) { Write-Log -LogString "WebRequest $uri Status: $($response.StatusCode)" }
    }
    return $response
}

#########################################
#                MAIN                   #
#########################################

# logon
$header = @{ } 
$header.Add("content-type", "application/json") 
$logonBody = @{ username = $apiUsername; password = $ApiPasswordPlain; concurrentSession = $true } | ConvertTo-Json

$response = Invoke-Request -Uri $logonUrl -Method POST -Headers $header -Body $logonBody -ErrorAction Stop
if ([string]::IsNullOrEmpty($response.Content)) {
    Write-Log -LogString "Logon Token is Empty - Cannot login" -AsError -ErrorAction Stop
}
else {
    if ($debugOn) { Write-Log -LogString "Logon to CyberArk successfully" }
    $logonToken = $response.Content | ConvertFrom-Json
}
$header.Add("authorization", $logonToken)
if ($debugOn) { Write-Host $stopWatch.Elapsed + " login done" }

# get safes
$safesResult = $(Invoke-Request -Uri $safesURL -Headers $header -Method Get).content | ConvertFrom-Json
$safes = $safesResult.GetSafesResult
Write-Log -LogString "Retrieved $($safes.Count) CyberArk safes"
if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched safes: $($safes.Count)" }

# get accounts from safe list
$safesAndAccounts = @()
$accountEntriesCount = 0

foreach ($safe in $safes) {
    $accountURL = $pvwaUrl + '/api/Accounts?limit=1000&filter=safeName eq ' + $safe.SafeName
    $accountsResult = $(Invoke-Request -Uri $accountURL -Headers $header -Method Get).content | ConvertFrom-Json
    if ($null -ne $accountsResult.value -and $accountsResult.value.Length -gt 0) {
        $safeEntry = @{ "SafeName" = $safe.SafeName; "Description" = $safe.Description; "Accounts" = @() }

        foreach ($account in $accountsResult.value) {
            $accountEntry = @{ "userName" = $account.userName; "address" = $account.address ; "platformId" = $account.platformId; "remoteMachines" = $account.remoteMachinesAccess.remoteMachines }
            $safeEntry.Accounts += $accountEntry
            $accountEntriesCount++
        }

        $safesAndAccounts += $safeEntry
    }
}
Write-Log -LogString "Retrieved $accountEntriesCount CyberArk accounts"
if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched safes accounts: $accountEntriesCount" }

# check accounts list
if ($safesAndAccounts.Count -gt 1) {
    $results = $safesAndAccounts | ConvertTo-Json -Depth 100

    
    $filePathBak = $filePath + '.bak'
    Write-Log -LogString "Write backup file $filePathBak"
    
    if (Test-Path $filePath) {
        if (Test-Path $filePathBak) {
            Remove-Item $filePathBak
        }
        Move-Item $filePath $filePathBak
    }

    Write-Log -LogString "Write new list file $filePath"
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($filePath, $results, $Utf8NoBomEncoding)
}
else {
    Write-Log -LogString "Retrieved none CyberArk accounts, will not replace existing list" -AsError
}

#logoff
Invoke-Request -Uri $logoffUrl -Headers $header -Method Post | Out-Null
if ($debugOn) { Write-Host $stopWatch.Elapsed + " finished" }