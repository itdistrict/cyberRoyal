# Define your settings
$ldapConfig = @{
	# Script data
	scriptPath         = "C:\Scripts\plugins\ldap"
	scriptName         = "ldapPermissionList.ps1"
	listPath           = "C:\Cyberark\ScriptData\ldapPermissionList.json"

	# LDAP Connection Details
	name               = "LDAP-Host"
	server             = "ldap.acme.com"
	port               = 636
	ssl                = $true
	sslVerify          = $true
	bindUser           = "CN=pam-ldap-bind,CN=Users,DC=acme,DC=com"
	passwordKey        = "bind.key"
	passwordFile       = "bind.ini"

	# LDAP Group Member search
	searchBase         = "DC=acme,DC=com"
	searchFilter       = "(objectClass=group)"
	groupNameAttribute = "cn"
	userNameAttribute  = "cn"

	# LDAP Group match to CyberArk SafeNames where first match group equals the safename
	safeRegex          = "^PAM-(.+)-.+$"
}

# Export settings
$ldapConfig | ConvertTo-Json | Set-Content -Path "$($ldapConfig.scriptPath)\config.json" -Force

# Export Credentials
$password = Read-Host -AsSecureString "Please enter the $($ldapConfig.bindUser) password"

$key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
$key | Out-File "$($ldapConfig.scriptPath)\$($ldapConfig.passwordKey)" -Force

$password | ConvertFrom-SecureString -Key (Get-Content "$($ldapConfig.scriptPath)\$($ldapConfig.passwordKey)") | Set-Content -Path "$($ldapConfig.scriptPath)\$($ldapConfig.passwordFile)" -Force

# Add Scheduled Task
$taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -like "CyberRoyal-ldapPermissionList" }
if ($taskExists) {
	Write-Host -ForegroundColor Green "Task CyberRoyal-ldapPermissionList exists already"
}
else {
	Write-Host -ForegroundColor Cyan "Register new Scheduled Task CyberRoyal hourly from now"
	$taskActions = (New-ScheduledTaskAction -Execute "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($ldapConfig.scriptPath)\$($ldapConfig.scriptName)`"" -WorkingDirectory "$($ldapConfig.scriptPath)")
	$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
	$taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)
	Register-ScheduledTask -TaskName "CyberRoyal-ldapPermissionList" -TaskPath "\CyberArk\" -Settings $taskSettings -Trigger $taskTrigger -User SYSTEM -Action $taskActions -Force
}