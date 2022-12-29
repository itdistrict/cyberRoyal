#########################################
##       Royal TS meets CyberArk       ##
##          www.gravitir.ch            ##
#########################################
#         ServerSide LDAP List          #
#########################################
# See README.md for all setting values  #
#########################################

# Read settings
$settingsPath = Join-Path $PSScriptRoot "ldapConfig.json"
if (!(Test-Path -Path $settingsPath)) { Write-Error "No settings.json file was found in $settingsPath"; exit }
$ldapConfig = Get-Content -Path $settingsPath -Encoding utf8 | ConvertFrom-Json

$ldapPassword = Get-Content $ldapConfig.passwordFile | ConvertTo-SecureString -Key (Get-Content $ldapConfig.passwordKey)
$ldapPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ldapPassword))


# add assemblies
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
Add-Type -AssemblyName System.Net -ErrorAction Stop

# constants
$ADS_GROUP_TYPE_GLOBAL_GROUP = 0x00000002
$ADS_GROUP_TYPE_LOCAL_GROUP = 0x00000004
$ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008
$ADS_PROPERTY_APPEND = 3
$ADS_GROUP_TYPE_SECURITY_ENABLED = "&H80000000"

# clear connection
$_ldapConnection = $null

# Functions
function Get-LDAPConnection() {
	param(
		[string] $Server,
		[int] $Port,
		[string] $User,
		[string] $Password,
		[boolean] $Ssl
	)
	if ($_ldapConnection) {
		return $_ldapConnection
	}
       
	$ldapCred = New-Object System.Net.NetworkCredential -ArgumentList $User, $Password
	$ldapIdentifier = New-object System.DirectoryServices.Protocols.ldapDirectoryIdentifier -ArgumentList $Server, $Port 
	$_ldapConnection = New-object System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ldapIdentifier, $ldapCred
	$_ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic

	if ($Ssl) {
		$_ldapConnection.SessionOptions.SecureSocketLayer = $true
		$_ldapConnection.SessionOptions.ProtocolVersion = 3
		$_ldapConnection.SessionOptions.VerifyServerCertificate = { $true }
	}
	$_ldapConnection.Bind($ldapCred)
	return $_ldapConnection
}

function Clear-LDAPConnection() {
	$_ldapConnection = $null
}

function Search-LDAPEnties() {
	param(
		[System.DirectoryServices.Protocols.LdapConnection] $LdapConnection,
		[string] $Name,
		[string] $Class,
		[string] $Searchbase
	)
	$filter = "(CN=$Name)"

	$attrlist = , '*'
	$scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
	$searchRequest = New-object System.DirectoryServices.Protocols.SearchRequest -ArgumentList  $Searchbase, $filter, $scope, $attrlist
	$searchResponse = $LdapConnection.SendRequest($searchRequest)
	return $searchResponse.Entries
}

# MAIN
$connection = Get-LDAPConnection -Server $ldapConfig.host -Port $ldapConfig.port -User $ldapConfig.bindUser -Password $ldapPasswordPlain -Ssl $true
