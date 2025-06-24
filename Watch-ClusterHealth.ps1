Install-Module -Name SqlServer -Verbose:$false

$DbName = "northwind"
$DbNodes = @(1..3 | ForEach-Object { "win25-db0$_" })
$ClusterName = "cluster01"
$ListenerName = "dblistener01"

[array]$Nodes = (@($DbNodes + $ClusterName + $ListenerName) | Sort-Object)
$filter = 'Address="' + ($Nodes -join '" or Address="') + '"'

$randomUpdate="UPDATE
Products
    SET UnitsInStock = FLOOR(RAND() * (100 - 1 + 1)) + 1 
WHERE
ProductId = (SELECT TOP 1 ProductId FROM Products ORDER BY NEWID())"

$clusterHealthQuery =
"SELECT
    @@SERVERNAME AS host,
    synchronization_health_desc AS sync_health,  
    synchronization_state_desc as sync_state,  
    database_state_desc as db_state,
    (SELECT TOP 1 role_desc FROM sys.dm_hadr_availability_replica_states ars WHERE replica_id = rs.replica_id) AS replica_role
FROM
    sys.dm_hadr_database_replica_states rs
WHERE
    rs.is_local = 1"

$PSStyle.Formatting.TableHeader = "`e[97;1m"
while ($true)
{
    try {
        $Servers = Get-WmiObject -Class Win32_PingStatus -Filter $filter | Select-Object `
            @{Name="Time";Expression={Get-Date -Format "HH:mm:ss.fff"}},`
            @{Name="Host";Expression={$_.Address}},
            @{Name="IP";Expression={$_.IPV4Address}},    
            @{Name="Link";Expression={if ($_.StatusCode -eq 0){"$($PSStyle.Foreground.Green)OK$($PSStyle.Reset)"} else {"$($PSStyle.Foreground.Red)DOWN$($PSStyle.Reset)"}}}`
            | Sort-Object -Property Host

        $Servers | Add-Member -MemberType NoteProperty -Name Role -Value ""
        $Servers | Add-Member -MemberType NoteProperty -Name SyncHealth -Value ""
        $Servers | Add-Member -MemberType NoteProperty -Name SyncState -Value ""
        $Servers | Add-Member -MemberType NoteProperty -Name DbState -Value ""

        if(($Servers| Where-Object Host -eq $ListenerName).Link -match "OK") {
            try
            {
                $listenerOk = $false
                try { 
                    Invoke-Sqlcmd -ServerInstance $ListenerName -TrustServerCertificate -Database $DbName -Query $randomUpdate -ErrorAction Stop
                    $listenerOk = $true
                } 
                catch { 
                    Write-Verbose ($_.Exception.Message | Out-String)
                }
                ($Servers| Where-Object Host -eq $ListenerName).Role = "LISTENER"
                ($Servers| Where-Object Host -eq $ListenerName).SyncHealth = ("⁉️", "OK")[$listenerOk]
            }
            catch {
                Write-Verbose ($_.Exception.Message | Out-String)
            }
        }

        $DbNodes | ForEach-Object {
            $clusterStatus = $null
            if(($Servers | Where-Object Host -eq $_).Link -match "OK") {
                try {
                    $clusterStatus = Invoke-Sqlcmd -ServerInstance $_ -TrustServerCertificate -Query $clusterHealthQuery -ErrorAction Stop
                }
                catch {
                    Write-Verbose ($_.Exception.Message | Out-String)
                }

                if ($clusterStatus)
                {
                    ($Servers| Where-Object Host -eq $_).Role = $clusterStatus.replica_role
                    ($Servers| Where-Object Host -eq $_).SyncHealth = $clusterStatus.sync_health
                    ($Servers| Where-Object Host -eq $_).SyncState = $clusterStatus.sync_state
                    ($Servers| Where-Object Host -eq $_).DbState = $clusterStatus.db_state
                }
                else {
                    ($Servers| Where-Object Host -eq $_).Role = "⁉️"
                    ($Servers| Where-Object Host -eq $_).SyncHealth = "⁉️"
                    ($Servers| Where-Object Host -eq $_).SyncState = "⁉️"
                    ($Servers| Where-Object Host -eq $_).DbState = "⁉️"
                }
            }
        }
    }
    catch
    {
        Write-Verbose ($_.Exception.Message | Out-String)
    }
    finally {
        $Servers | Format-Table -Property Time,Host,IP,Link,Role,SyncHealth,SyncState,DbState -Wrap
    }
    Start-Sleep -Seconds 3
}
