$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.State -eq 'Alive' } | ForEach-Object {
    $iface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex
    if ($iface.ConnectionState -eq 'Connected') {
        [PSCustomObject]@{ Index = $_.InterfaceIndex; Metric = $_.RouteMetric + $iface.InterfaceMetric }
    }
} | Sort-Object Metric,Index)
if ($routes.Count -eq 0) { throw 'No connected IPv4 default route was found.' }
$index = $routes[0].Index
$adapter = Get-NetAdapter -InterfaceIndex $index
$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index
$nrpt = @(Get-DnsClientNrptPolicy -Effective)
if ($nrpt.Count -ne 0) { throw 'An active DNS namespace policy (NRPT) overrides system DNS. Auto Browse cannot isolate the candidate on this connection.' }
$ipv6 = @(Get-DnsClientServerAddress -AddressFamily IPv6 -InterfaceIndex $index | Select-Object -ExpandProperty ServerAddresses | Where-Object { $_ -notlike 'fec0:*' })
if ($ipv6.Count -ne 0) { throw 'The selected adapter has IPv6 DNS servers. Remove them manually before IPv4-only Auto Browse.' }
$policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
if ($policy -and $policy.DoHPolicy -eq 1) { throw 'Windows policy prohibits DNS over HTTPS.' }
[PSCustomObject]@{
    interfaceIndex = [int]$index
    interfaceGuid = $adapter.InterfaceGuid.ToString()
    interfaceName = $adapter.Name
    servers = @($dns.ServerAddresses)
} | ConvertTo-Json -Compress -Depth 5
