# MAYBE: try windows RRAS router once again for fully automated setup
# You need to find a way to create IPv4 routes automatically

function New-Win25Router {
    [CmdletBinding()]
    param ()

    $vmRouterName = "win25-router"
    $win25RouterPath = "$($HddPath)\$($vmRouterName).vhdx"

    New-Win25VHD -VMName $vmRouterName -EditionIndex 2 -Verbose:$VerbosePreference

    if(-not (Get-VM -Name $vmRouterName -ErrorAction SilentlyContinue)) {
        Write-Verbose "Creating new VM: $vmRouterName"
        $win25Router = New-VM -Name $vmRouterName -Generation 2 -MemoryStartupBytes 1GB -VHDPath $win25RouterPath -SwitchName $global:ExternalSwitchName
        $win25Router | Set-VMProps -Processors 2 -MaxMemory 4GB
    }

    if((Get-VM -Name $vmRouterName).State -eq "Off") {
        Write-Verbose "Starting $vmRouterName"
        Start-VM $vmRouterName
    }
    $maxWaitCycle = 20
    Write-Host "Waiting for $vmRouterName to accept WinRM session" -NoNewline
    while (-not (Test-WSMan -ComputerName $vmRouterName -ErrorAction SilentlyContinue)) {
        Write-Host "." -ForegroundColor DarkGray -NoNewline
        if(--$maxWaitCycle -eq 0) {
            Write-Host
            Write-Error "max. wait time reached but $vmRouterName has not been initialized yet." -ErrorAction Stop
            break
        }
        Start-Sleep -Seconds 5
    }

    Write-Host
    Write-Verbose "Creating remote session to $vmRouterName"
    $remoteSession = New-PSSession -VMName $vmRouterName -Credential $Credential
    # rename the external network interface
    Invoke-Command -Session $remoteSession { Get-NetAdapter | Rename-NetAdapter -NewName "External" }
    # adding and renaming, updating LAN network interfaces
    Write-Verbose "Adding and renaming private LAN interfaces"
    10,20 | ForEach-Object {
        Add-VMNetworkAdapter $win25Router -SwitchName "Private-Lan$($_)" -Verbose:$VerbosePreference
        Invoke-Command -Session $remoteSession -ArgumentList $_ -ScriptBlock {
            param([int]$lanIndex)
            Get-NetAdapter | Where-Object { $_.Name -ne "External" -and $_.Name -notlike "Private-Lan*" } | Rename-NetAdapter -NewName "Private-Lan$($lanIndex)"
        }
    }
    Write-Verbose "Assigning IP addresses for private LAN interfaces"
    Invoke-Command -Session $remoteSession {
        10,20 | ForEach-Object {
            New-NetIPAddress -InterfaceAlias "Private-Lan$($_)" -IPAddress "10.$($_).$($_).1" -PrefixLength 24 | Out-Null
            Start-Sleep -Seconds 1
            Set-NetConnectionProfile -InterfaceAlias "Private-Lan$($_)" -NetworkCategory Private
        }
    }
    Start-Sleep -Seconds 2
    Write-Verbose (Invoke-Command -Session $remoteSession { ipconfig } | Out-String)
    Write-Verbose "Installing Routing feature"
    # needed to wait for the session to be established also features to be installed
    Start-Sleep -Seconds 2
    Invoke-Command -Session $remoteSession { Install-WindowsFeature -Name Routing -IncludeManagementTools }
    # test connectivity
    Invoke-Command -Session $remoteSession { ping 10.10.10.1 -n 2 }
    Invoke-Command -Session $remoteSession { ping 10.20.20.1 -n 2 }
    Invoke-Command -Session $remoteSession { ping www.google.com -n 2 }
    # Set RemoteAccess service to auto-start
    Invoke-Command -Session $remoteSession { Get-Service RemoteAccess | Set-Service -StartupType Automatic -Verbose }
    Remove-PSSession -Session $remoteSession
    # TODO: automate the config via powershell
    # manually configure the routing
    Write-Host "You are not going to be connected to: $vmRouterName`. Please configure the routing manually." -ForegroundColor Magenta
    vmconnect localhost $vmRouterName
}