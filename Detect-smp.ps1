$eventLog = Get-WinEvent -FilterHashtable @{LogName='Security'; ID='4624'; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue

foreach ($event in $eventLog) {
    $ipAddress = $event.Properties[18]
    $logonType = $event.Properties[8]
    $logonProcess = $event.Properties[11]
    if ($logonType -eq 3 -and $logonProcess -eq "NtLmSsp ") {
        $smbLog = Get-WinEvent -FilterHashtable @{LogName='System'; ID='5140'; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue
        foreach ($smbEvent in $smbLog) {
            $smbIpAddress = $smbEvent.Properties[17]
            $smbShareName = $smbEvent.Properties[8]
            if ($ipAddress -eq $smbIpAddress) {
                Write-Alert "SMB relay attack detected on $smbShareName from $ipAddress"
                
            }
        }
    }
}
