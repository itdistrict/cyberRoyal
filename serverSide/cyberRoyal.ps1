#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
#########################################
#         ServerSide Script             #
#########################################
# See README.md for all setting values  #
#########################################

# Read settings
$configPath = Join-Path $PSScriptRoot "config.json"
if (!(Test-Path -Path $configPath)) { Write-Error "No config.json file was found in $configPath"; exit }
$cyberRoyalConfig = Get-Content -Path $configPath -Encoding utf8 | ConvertFrom-Json

# Settings
$pvwaUrl = $cyberRoyalConfig.pvwaUrl
$listPath = $cyberRoyalConfig.listPath
$apiUsername = $cyberRoyalConfig.apiUsername
$apiPasswordFile = $cyberRoyalConfig.apiPasswordFile
$apiPasswordKey = $cyberRoyalConfig.apiPasswordKey
$additionalPlatformAccountProperties = $cyberRoyalConfig.additionalPlatformAccountProperties
$psCertValidation = $cyberRoyalConfig.psCertValidation # enable or disable SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
$debugOn = $cyberRoyalConfig.debugOn # Turn debug on to see more console output and get more details in log

#########################################
#           Powershell Settings         #
#########################################
if ($debugOn) { $stopWatch = [system.diagnostics.stopwatch]::StartNew() }
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
if ($psCertValidation) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }

# ssl/tls workaround for selfsigned
# Add-Type @"
#     using System;
#     using System.Net;
#     using System.Net.Security;
#     using System.Security.Cryptography.X509Certificates;
#     public class ServerCertificateValidationCallback
#     {
#         public static void Ignore()
#         {
#             ServicePointManager.ServerCertificateValidationCallback += 
#                 delegate
#                 (
#                     Object obj, 
#                     X509Certificate certificate, 
#                     X509Chain chain, 
#                     SslPolicyErrors errors
#                 )
#                 {
#                     return true;
#                 };
#         }
#     }
# "@
# [ServerCertificateValidationCallback]::Ignore();


#########################################
#               Variables               #
#########################################
$logonUrl = $pvwaUrl + "/api/auth/Cyberark/Logon"
$logoffUrl = $pvwaUrl + "/api/auth/Logoff"
$safesUrl = $pvwaUrl + "/api/Safes?limit=10000"

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
$safes = $safesResult.value
Write-Log -LogString "Retrieved $($safes.Count) CyberArk safes"
if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched safes: $($safes.Count)" }

# get accounts from safe list and collect as sorted list, sorted by safename
$safesAndAccounts = [System.Collections.SortedList]::new()
$accountEntriesCount = 0
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
Write-Log -LogString "Retrieved $accountEntriesCount CyberArk accounts"
if ($debugOn) { Write-Host $stopWatch.Elapsed + " catched safes accounts: $accountEntriesCount" }

# check accounts list
if ($safesAndAccounts.Count -gt 1) {
	$results = $safesAndAccounts | ConvertTo-Json -Depth 100
	
	$listPathBak = $listPath + '.bak'
	Write-Log -LogString "Write backup file $listPathBak"
    
	if (Test-Path $listPath) {
		if (Test-Path $listPathBak) {
			Remove-Item $listPathBak
		}
		Move-Item $listPath $listPathBak
	}

	Write-Log -LogString "Write new list file $listPath"
	$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
	[System.IO.File]::WriteAllLines($listPath, $results, $Utf8NoBomEncoding)
}
else {
	Write-Log -LogString "Retrieved none CyberArk accounts, will not replace existing list" -AsError
}

#logoff
Invoke-Request -Uri $logoffUrl -Headers $header -Method Post | Out-Null
if ($debugOn) { Write-Host $stopWatch.Elapsed + " finished" }