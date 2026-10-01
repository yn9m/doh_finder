$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-EffectiveDNSPolicies {
    Get-DnsClientNrptPolicy -Effective | ForEach-Object {
        $rule = $_
        foreach ($namespace in @($rule.Namespace)) {
            if (-not [string]::IsNullOrWhiteSpace($namespace)) {
                [PSCustomObject]@{
                    namespace = [string]$namespace
                    nameServers = @($rule.NameServers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    directAccessEnabled = [bool]$rule.DirectAccessEnabled
                    directAccessDnsServers = @($rule.DirectAccessDnsServers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    dnssecValidationRequired = [bool]$rule.DnsSecValidationRequired
                }
            }
        }
    }
}

function Get-ActiveDNSAdapter {
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Status -eq 'Up' })
    $interfaces = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.ConnectionState -eq 'Connected' })
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore | Where-Object { $_.State -eq 'Alive' } | ForEach-Object {
        $route = $_
        $iface = @($interfaces | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex })
        $adapter = @($adapters | Where-Object { $_.ifIndex -eq $route.InterfaceIndex })
        if ($iface.Count -eq 1 -and $adapter.Count -eq 1) {
            [PSCustomObject]@{ Index = $route.InterfaceIndex; Metric = [long]$route.RouteMetric + [long]$iface[0].InterfaceMetric }
        }
    } | Sort-Object Metric,Index)
    if ($routes.Count -eq 0) { throw 'No connected IPv4 default route was found.' }
    $best = @($routes | Where-Object { $_.Metric -eq $routes[0].Metric } | Select-Object -ExpandProperty Index -Unique)
    if ($best.Count -ne 1) { throw 'Several adapters have equally preferred IPv4 default routes. Set a preferred route before Auto Browse.' }
    $adapters | Where-Object { $_.ifIndex -eq $best[0] }
}
