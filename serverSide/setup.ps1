# Define your settings
$cyberRoyalSettings = @{
	# Script data
	scriptPath                          = "C:\Scripts\"
	listPath                            = "C:\Cyberark\ScriptData\cyberRoyalSafeAccountList.json"
	
	# PVWA url and login data
	pvwaUrl                             = "https://127.0.0.1/PasswordVault";
	apiUsername                         = "Auditor"
	apiPasswordFile                     = "C:\Scripts\secret.ini"
	apiPasswordKey                      = "C:\Scripts\keys\secret.key"

	# Addition account attributes to fetch (coma separated)
	additionalPlatformAccountProperties = @("Location", "Port")

	# Enable or disable SSL/TLS certificate validation callback in PowerShell (.NET) for the web calls
	psCertValidation                    = $false
	
	# Turn debug on to see more console output and get more details in log
	debugOn                             = $false
}

# Export settings
$cyberRoyalSettings | ConvertTo-Json | Set-Content -Path "$($cyberRoyalSettings.scriptPath)\settings.json" -Force

# Export Credentials
$password = Read-Host -AsSecureString "Please enter the $($cyberRoyalSettings.apiUsername) password"

$key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
$key | Out-File "$($cyberRoyalSettings.apiPasswordKey)" -Force

$password | ConvertFrom-SecureString -Key (Get-Content "$($cyberRoyalSettings.apiPasswordKey)") | Set-Content -Path "$($cyberRoyalSettings.apiPasswordFile)" -Force

# Add Scheduled Task
$taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -like "CyberRoyal" }
if ($taskExists) {
	Write-Host -ForegroundColor Green "Task CyberRoyal exists already"
}
else {
	Write-Host -ForegroundColor Cyan "Register new Scheduled Task CyberRoyal hourly from now"
	$taskActions = (New-ScheduledTaskAction -Execute "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($cyberRoyalSettings.scriptPath)\cyberRoyal.ps1`"" -WorkingDirectory "$($cyberRoyalSettings.scriptPath)")
	$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 60)
	$taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)
	Register-ScheduledTask -TaskName "CyberRoyal" -TaskPath "\CyberArk\" -Settings $taskSettings -Trigger $taskTrigger -User SYSTEM -Action $taskActions -Force
}

