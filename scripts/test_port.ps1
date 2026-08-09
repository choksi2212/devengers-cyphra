$t = New-Object System.Net.Sockets.TcpClient
try {
    $t.Connect('127.0.0.1', 3001)
    Write-Host 'TCP OK - port 3001 is open and server is running'
    $t.Close()
} catch {
    Write-Host 'TCP FAILED:' $_.Exception.Message
}

$t2 = New-Object System.Net.Sockets.TcpClient
try {
    $t2.Connect('192.168.1.18', 3001)
    Write-Host 'LAN TCP OK - phone can reach 192.168.1.18:3001'
    $t2.Close()
} catch {
    Write-Host 'LAN TCP FAILED:' $_.Exception.Message
}
