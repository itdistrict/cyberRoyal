#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
#########################################
#         ServerSide LDAP List          #
#########################################
# See README.md for all setting values  #
#########################################

# Read settings
$configPath = Join-Path $PSScriptRoot "config.json"
if (!(Test-Path -Path $configPath)) { Write-Error "No config.json file was found in $configPath"; exit }
$ldapConfig = Get-Content -Path $configPath -Encoding utf8 | ConvertFrom-Json

# Variables
$listPath = $ldapConfig.listPath

# Get credentials
$ldapPassword = Get-Content $ldapConfig.passwordFile | ConvertTo-SecureString -Key (Get-Content $ldapConfig.passwordKey)
$ldapCredentials = New-Object System.Management.Automation.PSCredential ($ldapConfig.bindUser, $ldapPassword)
# $ldapPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ldapPassword))

# Add assemblies
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
Add-Type -AssemblyName System.Net -ErrorAction Stop

# LDAP Connection
$ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection((New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($ldapConfig.server, $ldapConfig.port)), $ldapCredentials)
$ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic

if ($ldapConfig.ssl) {
	$ldapConnection.SessionOptions.ProtocolVersion = 3
	$ldapConnection.SessionOptions.VerifyServerCertificate = { $ldapConfig.sslVerify }
	$ldapConnection.SessionOptions.StartTransportLayerSecurity($null)
}

$ldapConnection.Bind($ldapCredentials)

# prepare group search
$groupNameAttribute = $($ldapConfig.groupNameAttribute)
$searchBase = $($ldapConfig.searchBase)
$filter = $($ldapConfig.searchFilter)
$scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
$searchRequest = New-object System.DirectoryServices.Protocols.SearchRequest -ArgumentList  $searchBase, $filter, $scope
$searchRequest.Attributes.Add($groupNameAttribute)

# search groups
$searchResponse = $ldapConnection.SendRequest($searchRequest)
$groups = $searchResponse.Entries
Write-Host "Fetched $($groups.Count) groups from LDAP $($ldapConfig.name)"

# prepare users search
$userNameAttribute = $($ldapConfig.userNameAttribute)

$userAndGroups = [hashtable]@{}
foreach ($group in $groups) {
	$groupname = $group.Attributes.$groupNameAttribute.GetValues([string])
	Write-Host "Get users for $groupname"

	$filter = "(&(objectCategory=user)(memberOf=$($group.DistinguishedName)))"
	# TODO: AD or LDAP separation
	# $filter = "(&(objectCategory=user)(memberOf=$($group.DistinguishedName)))"

	$scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
	$searchRequest = New-object System.DirectoryServices.Protocols.SearchRequest -ArgumentList  $searchBase, $filter, $scope
	$searchRequest.Attributes.Add($userNameAttribute)
	$searchResponse = $ldapConnection.SendRequest($searchRequest)
	$users = $searchResponse.Entries

	foreach ($user in $users) {
		$username = $($user.Attributes.$userNameAttribute.GetValues([string]))
		Write-Host "User in $($group.DistinguishedName): $username"
		if ($null -eq $userAndGroups[$username]) { $userAndGroups[$username] = [System.Collections.Generic.List[string]]::new() }
		
		$match = [regex]::Match($groupname, $ldapConfig.safeRegex)
		if ($match.Success) {
			$safeName = $match.Groups[1].ToString()
			$userAndGroups[$username].Add($safeName)
		}
	} 
}

$permissionList = [PSCustomObject]@{ users = @() }
foreach ($userPermission in $userAndGroups.GetEnumerator() ) {
	$permissions = $userPermission.Value | Sort-Object -Unique
	$permissionList.users += New-Object -TypeName psobject -Property @{username = $userPermission.Key; permissions = $permissions }
}

if ($permissionList.users.count -gt 1) {
	$results = $permissionList | ConvertTo-Json -Depth 100
	
	$listPathBak = $listPath + '.bak'
	Write-Host "Write backup file $listPathBak"
    
	if (Test-Path $listPath) {
		if (Test-Path $listPathBak) {
			Remove-Item $listPathBak
		}
		Move-Item $listPath $listPathBak
	}

	Write-Host "Write new list file $listPath"
	$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
	[System.IO.File]::WriteAllLines($listPath, $results, $Utf8NoBomEncoding)
}
else {
	Write-Error "Retrieved none LDAP permissions, will not replace existing list"
}
