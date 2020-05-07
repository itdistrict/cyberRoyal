#########################################
##          IT DISTRICT GmbH           ##
##          www.itdistrict.ch          ##
#########################################
# Write Log file and WinEventLog entries
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
