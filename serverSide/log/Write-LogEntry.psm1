#########################################
##            Gravitir AG	           ##
##          www.gravitir.ch		       ##
#########################################
# Write Log file and WinEventLog entries
$maxSize = "100MB"

function Write-LogEntry {
	param(
		[string] $LogFile,
		[string] $ScriptName,
		[string] $Message,
		[switch] $AsWarning,
		[switch] $AsError
	)
    
	$timeStamp = (Get-Date).toString("yyyy-MM-dd-HH-mm-ss")

	if ($LogFile -notlike "*.log") { $LogFile = $LogFile + ".log" }
	if (!(Test-Path -Path $LogFile)) { New-Item -Path $LogFile -Type File -Force }
	if ((Get-Item $LogFile).length -gt $maxSize) { 
		$archiveLogFile = "$LogFile.1" 
		if (Test-Path -Path $archiveLogFile) { Remove-Item -Path $archiveLogFile }
		Rename-Item -Path $LogFile -NewName $archiveLogFile
	}

	if ($AsError) {
		$entryType = 'Error'
		$eventId = '500'
		$logLine = "[$timeStamp]:[$ScriptName]:ERROR: " + $Message
	}
	elseif ($AsWarning) {
		$entryType = 'Warning'
		$eventId = '300'
		$logLine = "[$timeStamp]:[$ScriptName]:WARNING: " + $Message
	}
	else {
		$entryType = 'Information'
		$eventId = '200'
		$logLine = "[$timeStamp]:[$ScriptName]:INFO: " + $Message
	}

	$Source = "PowerShell"

	try {
		if (![System.Diagnostics.EventLog]::SourceExists($ScriptName)) {
			New-EventLog -LogName "Windows PowerShell" -Source $ScriptName 
		} 
		$Source = $ScriptName 
	}
	catch {
		$Source = "PowerShell"
	}

	Write-EventLog -LogName "Windows PowerShell" -Source $Source -Message $logLine -EventId $eventId -EntryType $entryType
	Add-Content $LogFile -value $logLine
}
