function New-Win25Router {
    [CmdletBinding()]
    param ()

    $vmRouterName = "win25-router"
    $win25RouterPath = "$($HddPath)\$($vmRouterName).vhdx"

    if(-not (Get-VM -Name $vmRouterName -ErrorAction SilentlyContinue)) {
        Deploy-UnattendedXml -VMName $vmRouterName -EditionIndex 1

        if(-not (Get-VM -Name $vmRouterName -ErrorAction SilentlyContinue)) {
            Write-Verbose "Creating new VM: $vmRouterName"
            $win25Router = New-VM -Name $vmRouterName -Generation 2 -MemoryStartupBytes 1GB -VHDPath $win25RouterPath -SwitchName $Script:ExternalSwitch
            $win25Router | Set-VMProps -Processors 2 -MaxMemory 4GB
        }
        Start-VM $win25Router -WarningAction SilentlyContinue | Write-Verbose "Starting $win25Router"

        $remoteSession = Wait-WinRMSession -VMName $vmRouterName -MaxTimeout 60 -SleepTime 2
        # rename the external network interface
        Invoke-Command -Session $remoteSession { Get-NetAdapter | Rename-NetAdapter -NewName "External" -Verbose }
        # adding private LAN network interfaces
        Write-Verbose "Adding private LAN interfaces"
        10,20 | ForEach-Object {
            Add-VMNetworkAdapter $win25Router -SwitchName "Private-Lan$($_)" -Verbose:$VerbosePreference
            Start-Sleep -Seconds 2
            Invoke-Command -Session $remoteSession -ArgumentList $_ -ScriptBlock {
                param($lanIndex)
                Get-NetAdapter | Where-Object { $_.Name -ne "External" -and $_.Name -notlike "Private-Lan*" } | Rename-NetAdapter -NewName "Private-Lan$($lanIndex)"
            } -Verbose:$VerbosePreference
        }
        # renaming and updating private LAN networks
        Write-Verbose "Assigning IP addresses for private LAN interfaces"
        Invoke-Command -Session $remoteSession -ScriptBlock {
            10,20 | ForEach-Object {
                New-NetIPAddress -InterfaceAlias "Private-Lan$($_)" -IPAddress "10.$($_).$($_).1" -AddressFamily IPv4 -PrefixLength 24 | Out-Null
                do {
                    Start-Sleep -Seconds 1
                } while ((Get-NetAdapter -Name "Private-Lan$($_)").State -eq "Up")
                Set-NetConnectionProfile -InterfaceAlias "Private-Lan$($_)" -NetworkCategory Private
            }
            Start-Sleep -Seconds 1
            Write-Verbose (ipconfig | Out-String)
            # test connectivity
            ping www.google.com -n 2
            # install RRAS
            Install-WindowsFeature -Name Routing -IncludeManagementTools
            Get-Service RemoteAccess | Set-Service -StartupType Automatic -Verbose
            # disable ics service and install 
            Get-NetFirewallRule | Where-Object { $_.DisplayGroup -eq "Routing and Remote Access" } | Set-NetFirewallRule -Enabled True -Verbose
            Get-Service "Internet Connection Sharing (ICS)" | Set-Service -StartupType Disabled | Stop-Service
            Restart-Computer -Force
        }
        Wait-ServerEvent -VMName $vmRouterName -WaitWhile {
            (Get-PSSession -Name $vmRouterName).State -eq "Opened" -and (Get-PSSession -Name $vmRouterName).Availability -eq "Available"
        } -TextMsg "$vmRouterName is restarting" -ErrorMsg "max. wait time reached but $vmRouterName has not been restarted yet." -MaxTimeout 40 -SleepTime 2
        Remove-PSSession $remoteSession
        $remoteSession = Wait-WinRMSession -VMName $vmRouterName -MaxTimeout 60 -SleepTime 2
        Invoke-Command -Session $remoteSession {
            Stop-Service RemoteAccess
            Install-RemoteAccess -VpnType RoutingOnly
            Restart-Computer -Force
        }
        Wait-ServerEvent -VMName $vmRouterName -WaitWhile {
            (Get-PSSession -Name $vmRouterName).State -eq "Opened" -and (Get-PSSession -Name $vmRouterName).Availability -eq "Available"
        } -TextMsg "$vmRouterName is restarting" -ErrorMsg "max. wait time reached but $vmRouterName has not been restarted yet." -MaxTimeout 40 -SleepTime 2
        Remove-PSSession $remoteSession
        $remoteSession = Wait-WinRMSession -VMName $vmRouterName -MaxTimeout 60 -SleepTime 2
        Write-Verbose "running netsh commands to setup NAT/LAN routing"
        Invoke-Command -Session $remoteSession {
            Get-Service RemoteAccess
            # use legacy netsh to add full NAT on IPv4 interfaces
            netsh.exe routing ip nat install | Out-Null
            Get-Service RemoteAccess | Restart-Service -Verbose
            netsh.exe routing ip nat set global tcptimeoutmins=1440 udptimeoutmins=1 loglevel=ERROR
            netsh.exe routing ip nat add interface name="External" mode=FULL
            netsh.exe routing ip nat show interface
        }
        Remove-PSSession $remoteSession
        Write-Host  "Router$_`🚥"
    }
}