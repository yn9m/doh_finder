$adapter = Get-ActiveDNSAdapter
$index = $adapter.ifIndex
$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index
$ipv6 = @(Get-DnsClientServerAddress -AddressFamily IPv6 -InterfaceIndex $index | Select-Object -ExpandProperty ServerAddresses | Where-Object { $_ -notlike 'fec0:*' })
if ($ipv6.Count -ne 0) { throw 'The selected adapter has IPv6 DNS servers. Remove them manually before IPv4-only Auto Browse.' }
$policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
if ($policy -and $policy.DoHPolicy -eq 1) { throw 'Windows policy prohibits DNS over HTTPS.' }
[PSCustomObject]@{
    interfaceIndex = [int]$index
    interfaceGuid = $adapter.InterfaceGuid.ToString()
    interfaceName = $adapter.Name
    servers = @($dns.ServerAddresses)
    nrpt = @(Get-EffectiveDNSPolicies)
} | ConvertTo-Json -Compress -Depth 5
