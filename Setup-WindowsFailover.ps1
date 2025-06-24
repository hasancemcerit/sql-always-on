#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$VerbosePreference = "SilentlyContinue"

# some sensible defaults in case the script is run without parameters
$Script:DownloadPath = "$($env:USERPROFILE)\Downloads"
$Script:HddPath = "C:\hdd"
$Script:ExternalSwitch = "HyperV-External"
$Script:InternalSwitch = "HyperV-Internal"
[Int64]$Script:DiskSize = 32GB
$Script:Win25WimFile = Join-Path -Path $Script:DownloadPath -ChildPath "install.wim"
$Script:Win25ParentVhdx = $null
# cloudflare DNS servers
$Script:DnsServers = @("1.1.1.1", "1.0.0.1")

function Enable-HyperV {
    [CmdletBinding()]
    param()

    begin {
        $verbose = $VerbosePreference
        $VerbosePreference = "SilentlyContinue"
        $hyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -Verbose:$false
        $VerbosePreference = $verbose
    }

    process {
        Write-Verbose ($hyperV | Out-String) -Verbose:$VerbosePreference
        $hyperVOk = $hyperV.State -eq "Enabled"
        Write-Host "HyperV`t$(("❌","🚀")[$hyperVOk])"
        if(-not $hyperVOk) {
            if ($PSCmdlet.ShouldContinue("Now the installation of Hyper-V will begin. Are you sure you want to continue?", "Confirm?", [ref]$true, [ref]$false, [ref]$false)) {
                Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -Verbose:$VerbosePreference
            }
            else {
                Write-Error "Operation aborted." -ErrorAction Stop
            }
        }
        if(-not (Get-Process | Where-Object { $_.MainWindowTitle -eq 'Hyper-V Manager' })) { virtmgmt.msc }
    }

    end  {
        $VerbosePreference = $verbose
    }
}

function Assert-VMSwitches {
    [CmdletBinding()]
    param()

    begin {
        $verbose = $VerbosePreference
        $VerbosePreference = "SilentlyContinue"
    }

    process {
        $physicalNet = Get-NetAdapter -Physical | Where-Object Status -eq Up | Sort-Object LinkSpeed, ifIndex | Select-Object -First 1
        $externalSwitch = Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue
        $VerbosePreference = $verbose

        if(-not $externalSwitch) {
            Write-Warning "You will temporarily loose internet connection here!"
            New-VMSwitch -Name "$Script:ExternalSwitch" -NetAdapterName $physicalNet.Name -Verbose:$VerbosePreference -Confirm
        }
        elseif ([guid]::Parse($externalSwitch.NetAdapterInterfaceGuid) -ne [guid]::Parse($physicalNet.InterfaceGuid)) {
            Write-Warning "You will temporarily loose internet connection here!"
            Set-VMSwitch "$Script:ExternalSwitch" -NetAdapterName $physicalNet.Name -Verbose:$VerbosePreference -Confirm
        }
        Write-Host "External`t🌎"

        $internalSwitch = Get-VMSwitch -SwitchType Internal -Name $InternalSwitch -ErrorAction SilentlyContinue
        if(-not $internalSwitch) {
            New-VMSwitch -SwitchType Internal -Name "$Script:InternalSwitch" -Verbose:$VerbosePreference
            Get-NetAdapter | Where-Object Name -Like "*$($InternalSwitch)*" | Rename-NetAdapter -NewName $InternalSwitch -Verbose:$VerbosePreference
            New-NetIPAddress -InterfaceAlias "$InternalSwitch" -IPAddress "192.168.200.1" -AddressFamily IPv4 -PrefixLength 24
            do {
                Start-Sleep -Seconds 1
            } while ((Get-NetAdapter -Name "$InternalSwitch").State -eq "Up")
            Set-NetConnectionProfile -InterfaceAlias "$InternalSwitch" -NetworkCategory Private
        }
        Write-Host "Internal`t🛜"

        10,20 | ForEach-Object {
            if(-not (Get-VMSwitch -Name "Private-Lan$($_)" -ErrorAction SilentlyContinue)) {
                Write-Host "Creating new private VMSwitch: Private-Lan$($_)"
                New-VMSwitch -Name "Private-Lan$($_)" -SwitchType Private -Notes "10.$($_).$($_).0/24 private network" -Verbose:$VerbosePreference | Out-Null
            }
            Write-Host "Lan$($_)`t🔒"
        }
    }

    end {
        $VerbosePreference = $verbose
    }
}

function Get-WindowsEvalImage {

    $win25IsoFile = Join-Path -Path $DownloadPath -ChildPath "windows-server-2025-evaluation.iso"
    if(-not (Test-Path $win25IsoFile)) {
        Write-Verbose "Downloading Windows Server 2025 evaluation ISO: $win25IsoFile"
        Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?linkid=2293312&clcid=0x409&culture=en-us&country=us" -Destination $win25IsoPath -Verbose:$VerbosePreference
    }
    Write-Host "Iso`t💿"

    if(-not (Test-Path $Win25WimFile)) {
        Write-Verbose "Extracting Windows Imaging Format from ISO: $Win25WimFile"
        $mountIso = Mount-DiskImage -ImagePath $win25IsoFile -PassThru -Verbose:$VerbosePreference
        $isoDrive = $mountIso | Get-Volume | Select-Object -ExpandProperty DriveLetter
        Copy-Item -Path "$($isoDrive):\sources\install.wim" -Destination $Win25WimFile -Force -Verbose:$VerbosePreference
        Dismount-DiskImage -ImagePath $win25IsoFile -Verbose:$VerbosePreference
    }
    Write-Host "Wim`t💽"
    Write-Verbose (Get-WindowsImage -ImagePath $Win25WimFile | Format-Table ImageIndex, ImageName | Out-String)
}

# create a function that can be called by this script and ps remoting
$EnableEchoRequest = {
4,6 | ForEach-Object {
    $ruleName = "File and Printer Sharing (Echo Request - ICMPv$($_)-In)"
    Get-NetFirewallRule -DisplayName $ruleName | Where-Object { $_.Profile -like "*Private*" -or $_.Profile -like "*Domain*" } | ForEach-Object {
        if(-not $_.Enabled) {
            Set-NetFirewallRule $_ -Enabled True -Verbose:$VerbosePreference
        }
    }
}
Write-Host "Echo`t🏓"
}
if(-not (Test-Path -Path "Function:Enable-EchoRequest")) {
    New-Item -Path "Function:Enable-EchoRequest" -ItemType "Function" -Value $EnableEchoRequest | Out-Null
}

function Wait-WinRMSession {
    [CmdletBinding()]
    param(
        [parameter(Position=0,Mandatory=$true, HelpMessage="Enter virtual machine name", ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$VMName,
        [ValidateRange(10, 300)]
        [int]$MaxTimeout = 60, # total number of seconds to wait
        [ValidateRange(1, 10)]
        [int]$SleepTime = 5, # seconds to wait between each check
        [switch]$AsDomainAdmin
    )
    Get-PSSession | Remove-PSSession
    Write-Host "Waiting for $VMName to accept WinRM session" -NoNewline
    [string]$userName = "Administrator"
    if($AsDomainAdmin.IsPresent) {
        Write-Host " using domain admin" -NoNewline
        $userName = "sqldemo\" + $userName
    }
    $credential = New-Object -TypeName System.Management.Automation.PSCredential($userName, $SecurePass)
    $maxWaitCycle = [int]($MaxTimeout / $SleepTime)
    do {
        $remoteSession = New-PSSession -VMName $VMName -Credential $credential -Name $VMName -ErrorAction SilentlyContinue
        Write-Host "." -ForegroundColor DarkGray -NoNewline
        Start-Sleep -Seconds $SleepTime
        if($remoteSession) {
            Write-Host "`t🔗"
            break
        }
        if(--$maxWaitCycle -eq 0) {
            Write-Host
            Write-Error "max. wait time reached but $vmBaseName is not accepting connection." -ErrorAction Stop
        }
    } while ($true)
    return $remoteSession
}

function Wait-ServerEvent {
    [CmdletBinding()]
    param(
        [parameter(Position=0,Mandatory=$true, HelpMessage="Enter virtual machine name", ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$VMName,
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$WaitWhile,
        [ValidateRange(10, 300)]
        [int]$MaxTimeout = 60, # total number of seconds to wait
        [ValidateRange(1, 10)]
        [int]$SleepTime = 5, # seconds to wait between each check,
        [string]$TextMsg = "Please wait...",
        [string]$ErrorMsg = "max. wait time reached."
    )
    $maxWaitCycle = [int]($MaxTimeout / $SleepTime)
    Write-Host $TextMsg -ForegroundColor Cyan -NoNewline
    do {
        Write-Host "." -ForegroundColor Cyan -NoNewline
        Start-Sleep -Seconds $SleepTime
        if(--$maxWaitCycle -eq 0) {
            Write-Host
            Write-Error $ErrorMsg -ErrorAction Stop
        }
    } while (& $WaitWhile)
    Get-PSSession | Remove-PSSession
    Write-Host
}

function Get-AdminCredential {
    if(-not $Script:SecurePass) {
        Write-Host "Please enter the password for the Domain & Local Administrator account." -ForegroundColor Yellow
        $Script:SecurePass = Read-Host "Password" -AsSecureString
    }
    Write-Host "Pwd`t🔐"
}

function Set-VMProps {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [Microsoft.HyperV.PowerShell.VirtualMachineBase]$VM,
        [ValidateRange(1, 8)]
        [Int32]$Processors = 2,
        [ValidateRange(512MB, 16GB)]
        [Int64]$MaxMemory = 4GB
    )
    Set-VMProcessor $VM -Count $Processors
    Set-VMMemory $VM -DynamicMemoryEnabled $true -MinimumBytes 512MB -StartupBytes 1GB -MaximumBytes $MaxMemory -Priority 20 -Buffer 20
    Set-VM $VM -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -AutomaticCheckpointsEnabled $false
    Enable-VMIntegrationService $VM -Name "Guest Service Interface"
}

function New-Win25VHD {
    [CmdletBinding()]
    param (
        [parameter(Position=0,Mandatory=$true, HelpMessage="Enter virtual machine name", ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$VMName,
        [parameter(Position=1,Mandatory=$true, HelpMessage="Enter the edition index for Windows Server 2025")]
        [int]$EditionIndex
    )

    $win25Vhdx = "$($HddPath)\$($VMName).vhdx"

    if(-not (Test-Path $win25Vhdx)) {
        Write-Verbose "Creating new windows server VHDX: $win25Vhdx"
        New-VHD -Path $win25Vhdx -SizeBytes $DiskSize -Dynamic -Verbose:$VerbosePreference | Out-Null
        $disk = Mount-VHD -Path $win25Vhdx -PassThru -Verbose:$VerbosePreference
        # get the disk number
        $diskNum = ($disk | Get-Disk).Number
        # initialize as GPT
        Write-Verbose "Initializing disk# $diskNum as GPT"
        Initialize-Disk -Number $diskNum -PartitionStyle GPT -Verbose:$VerbosePreference | Out-Null
        # create required partitions
        Write-Verbose "Creating and formating sys partition"
        New-Partition -DiskNumber $diskNum -AssignDriveLetter -Size 500MB -GptType "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}" -Verbose:$VerbosePreference `
            | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false -Verbose:$VerbosePreference
        Write-Verbose "Creating and formating windows partition"
        New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter -Verbose:$VerbosePreference `
            | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -Verbose:$VerbosePreference

        Write-Verbose "Applying windows image to primary partition"
        $winDrive = (Get-Partition -DiskNumber $diskNum | Where-Object Size -GT 500MB).DriveLetter
        dism.exe /Apply-Image /ImageFile:$Win25WimFile /Index:$EditionIndex /ApplyDir:${winDrive}":\"

        Write-Verbose "Making the disk bootable"
        $efiDrive = (Get-Partition -DiskNumber $diskNum | Where-Object Type -EQ "System").DriveLetter
        bcdboot.exe "${winDrive}:\Windows" /s ${efiDrive}: /f UEFI

        Write-Verbose "Copying unattend.xml"
        $unattendFile = "unattend.xml"
        $pantherDir = "${winDrive}:\Windows\Panther"
        New-Item -ItemType Directory -Path $pantherDir -Force -Verbose:$VerbosePreference | Out-Null
        (Get-Content $unattendFile) -replace "{PASSWORD}", ($SecurePass | ConvertFrom-SecureString -AsPlainText) -replace "{COMPUTERNAME}", $VMName `
            | Out-File "$($pantherDir)\unattend.xml" -Encoding utf8 -Verbose:$verbosePreference

        Write-Verbose "Removing sys partition access"
        Get-Volume -DriveLetter $efiDrive | Get-Partition | Remove-PartitionAccessPath -AccessPath "$($efiDrive):\"
        Write-Verbose "Dismounting VHDX"
        Dismount-VHD -Path $win25Vhdx -Verbose:$VerbosePreference
    }
    Write-Host "VHDX`t✅"
}

function New-Win25BaseVM {
    [CmdletBinding()]
    param (
        [parameter(Position=0,Mandatory=$true)]
        [int]$EditionIndex
    )
    #1=2025 Standard Evaluation
    #2=2025 Standard Evaluation (Desktop Experience)
    $vmBaseName = switch ($EditionIndex) {
        1 { "win25-core" }
        2 { "win25-std" }
        default { throw "Windows Server 2025 Datacenter is not supported yet." }
    }
    $Script:Win25ParentVhdx = "$($HddPath)\$($vmBaseName).vhdx"
    # create vm and sysprep only once
    if(-not (Test-Path $Win25ParentVhdx)) {
        New-Win25VHD -VMName $vmBaseName -EditionIndex $EditionIndex

        if(-not (Get-VM -Name $vmBaseName -ErrorAction SilentlyContinue)) {
            Write-Verbose "Creating new VM: $vmBasename"
            $win25Base = New-VM -Name $vmBaseName -VHDPath $Win25ParentVhdx -Generation 2 -MemoryStartupBytes 1GB
            $win25Base | Set-VMProps -Processors 2 -MaxMemory 4GB
        }

        Start-VM $vmBaseName -WarningAction SilentlyContinue | Write-Verbose "Starting $vmBaseName"
        $remoteSession = Wait-WinRMSession -VMName $vmBaseName -MaxTimeout 120 -SleepTime 5
        # enable PS remoting and CredSSP (this will allow passing credentials to remote sessions)
        Invoke-Command -Session $remoteSession {
            Enable-PSRemoting -Force
            Disable-WSManCredSSP -Role Server
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Concatenate -Confirm:$false -Force
            $EnableEchoRequest
        }
        Write-Verbose "running System Preparation Tool (Sysprep) to generalize the base image"
        Invoke-Command -Session $remoteSession { C:\Windows\System32\Sysprep\sysprep.exe /generalize /shutdown /oobe }
        Remove-PSSession -Session $remoteSession
        Wait-ServerEvent -VMName $vmBaseName -WaitWhile {
            (Get-VM -VMName $vmBaseName).State -ne "Off"
        } -TextMsg "$vmBaseName is shutting down" -ErrorMsg "max. wait time reached but $vmBaseName has not been shutdown yet." -MaxTimeout 100 -SleepTime 5
        Remove-VM -Name $vmBaseName -Confirm:$false -Force -Verbose:$VerbosePreference
    }
    Write-Host "Base`t📦"
}

function Deploy-UnattendedXml {
    [CmdletBinding()]
    param (
        [parameter(Position=0,Mandatory=$true, HelpMessage="Enter virtual machine name", ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$VMName,
        [parameter(Position=1,Mandatory=$true, HelpMessage="Enter the edition index for Windows Server 2025")]
        [int]$EditionIndex
    )

    $win25Vhdx = "$($HddPath)\$($VMName).vhdx"
    New-Win25BaseVM -EditionIndex $EditionIndex

    if(-not (Test-Path -Path $Win25ParentVhdx)) {
        Write-Error "There is a problem with parent VHDX. Please check that if exists: $Win25ParentVhdx" -ErrorAction Stop
    }

    if(-not (Test-Path $win25Vhdx)) {
        New-VHD -Path $win25Vhdx -ParentPath $Win25ParentVhdx -SizeBytes $DiskSize -Verbose:$VerbosePreference | Out-Null
        $disk = Mount-VHD -Path $win25Vhdx -PassThru -Verbose:$VerbosePreference
        $diskNum = ($disk | Get-Disk).Number
        $primaryDrive = (Get-Partition -DiskNumber $diskNum | Where-Object Size -GT 500MB).DriveLetter
        Write-Verbose "Copying unattend.xml"
        $unattendFile = "unattend.xml"
        $pantherDir = "${primaryDrive}:\Windows\Panther"
        (Get-Content $unattendFile) -replace "{PASSWORD}", ($SecurePass | ConvertFrom-SecureString -AsPlainText) -replace "{COMPUTERNAME}", $VMName `
            | Out-File "$($pantherDir)\unattend.xml" -Force -Encoding utf8 -Verbose:$verbosePreference
        Dismount-VHD -Path $win25Vhdx -Verbose:$VerbosePreference
    }
}

function New-Win25DC {
    [CmdletBinding()]
    param (
        # edition index for Windows Server Editions
        [parameter(Position=0, Mandatory=$true, HelpMessage="Enter the edition index for the Windows Server 2025")]
        [int]$EditionIndex
    )
    $vmDcName="win25-dc"
    $win25DcPath = "$($HddPath)\$($vmDcName).vhdx"

    if(-not (Get-VM -Name $vmDcName -ErrorAction SilentlyContinue)) {
        Deploy-UnattendedXml -VMName $vmDcName -EditionIndex $EditionIndex

        if(-not (Get-VM -Name $vmDcName -ErrorAction SilentlyContinue)) {
            Write-Verbose "Creating new VM: $vmDcName"
            $win25Dc = New-VM -Name $vmDcName -Generation 2 -MemoryStartupBytes 1GB -VHDPath $win25DcPath -SwitchName "Private-Lan10"
            $win25Dc | Set-VMProps -Processors 2 -MaxMemory 4GB
        }
        # start vm
        Start-VM $vmDcName -WarningAction SilentlyContinue | Write-Verbose "Starting $vmDcName"
        $remoteSession = Wait-WinRMSession -VMName $vmDcName -MaxTimeout 60 -SleepTime 5
        # rename the external network interface
        Invoke-Command -Session $remoteSession { Get-NetAdapter | Rename-NetAdapter -NewName "Private-Lan10" }
        Write-Verbose "Updating IP addresses for LAN interfaces"
        Invoke-Command -Session $remoteSession -ArgumentList $DnsServers {
            param($dnsServers)
            New-NetIPAddress -InterfaceAlias "Private-Lan10" -IPAddress "10.10.10.53" -PrefixLength 24 -DefaultGateway "10.10.10.1" | Out-Null
            Set-DnsClientServerAddress -InterfaceAlias "Private-Lan10" -ServerAddresses $dnsServers
        }
        Start-Sleep -Seconds 5
        Write-Verbose (Invoke-Command -Session $remoteSession { ipconfig } | Out-String)
        Invoke-Command -Session $remoteSession { Set-NetConnectionProfile -InterfaceAlias "Private-Lan10" -NetworkCategory Private }
        Write-Verbose "Installing Active Directory"
        # needed to wait for the session to be established also features to be installed
        Start-Sleep -Seconds 5
        Invoke-Command -Session $remoteSession { Install-WindowsFeature AD-Domain-Services -IncludeManagementTools }
        Write-Verbose "Installing DNS"
        Invoke-Command -Session $remoteSession { Install-WindowsFeature -Name DNS -IncludeManagementTools }
        # Install the new Forest
        Write-Verbose "Installing Active Directory Forest"
        Invoke-Command -Session $remoteSession -ArgumentList ($SecurePass | ConvertFrom-SecureString -AsPlainText) -ScriptBlock {
            param($secretText)
            # install AD Forest
            Install-ADDSForest -DomainName "sqldemo.local" -SafeModeAdministratorPassword ($secretText | ConvertTo-SecureString -AsPlainText -Force) -InstallDNS -Force
            Set-NetFirewallProfile -Profile Domain -Enabled False -Verbose
            # reset IP configuration
            ipconfig /flushdns
            ipconfig /registerdns
            gpupdate /force
        }
        <#
        # MAYBE: Install DHCP Server
        #Add-DnsServerForwarder -IPAddress $DnsServers
        #Invoke-Command -Session $remoteSession { Install-WindowsFeature -Name DHCP -IncludeManagementTools }
        #>
        Wait-ServerEvent -VMName $vmDcName -WaitWhile {
            (Get-PSSession -Name $vmDcName).State -eq "Opened" -and (Get-PSSession -Name $vmDcName).Availability -eq "Available"
        } -TextMsg "$vmDcName is restarting" -ErrorMsg "max. wait time reached but $vmDcName has not been restarted yet." -MaxTimeout 60 -SleepTime 2
        $remoteSession = Wait-WinRMSession -VMName $vmDcName -MaxTimeout 120 -SleepTime 5 -AsDomainAdmin
        # test connectivity
        Write-Verbose "Testing network connections"
        $networkOk = Invoke-Command -Session $remoteSession -ScriptBlock {
            $testLan10 = Test-NetConnection -ComputerName "10.10.10.1" -ErrorAction SilentlyContinue
            $testLan20 = Test-NetConnection -ComputerName "10.20.20.1" -ErrorAction SilentlyContinue
            $testNet = Test-NetConnection -ComputerName "www.google.com" -ErrorAction SilentlyContinue
            $testLan10.PingSucceeded -and $testLan20.PingSucceeded -and $testNet.PingSucceeded
        }
        Remove-PSSession -Session $remoteSession
        if(-not $networkOk) {
            Write-Warning "There might be a problem with DC connectivity. You must fix this network issue before proceeding."
            Write-Warning "If login screen shows 'Please wait for the gpvc or Group Policy Client' it is normal. Just be patient."
            Write-Host "AD`t🩺"
        }
    }
    Write-Host "AD`t🌳"
}

function New-Win25DbServers {
    [CmdletBinding()]
    param (
        # edition index for Windows Server Editions
        [parameter(Position=0, Mandatory=$true, HelpMessage="Enter the edition index for the Windows Server 2025")]
        [int]$EditionIndex,
        [ValidateRange(1, 5)]
        [uint]$DBServers = 3
    )

    $sql2022IsoFile = Join-Path -Path $DownloadPath -ChildPath "SQLServer2022-x64-ENU-Dev.iso"
    if(-not (Test-Path $sql2022IsoFile)) {
        Write-Host "SQL installation media will be downloaded using installer. Make sure select 'Download Media' and 'ISO' option."
        Write-Host "to download here, with the same file name: $sql2022IsoFile"
        $sql2022Downloader = Join-Path -Path $DownloadPath -ChildPath "sql2022-dev.exe"
        if(-not (Test-Path $sql2022Downloader)) {
            Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?linkid=2215158&clcid=0x1009&culture=en-ca&country=ca" -OutFile $sql2022Downloader
        }
        Start-Process -FilePath $sql2022Downloader -Wait
    }

    1..$DBServers | ForEach-Object {
        $vmDbName= "win25-db0$_"
        if(-not (Get-VM -Name $vmDbName -ErrorAction SilentlyContinue)) {
            $win25DbPath = "$($HddPath)\$($vmDbName).vhdx"

            Deploy-UnattendedXml -VMName $vmDbName -EditionIndex $EditionIndex

            $switchSuffix = (10,20)[$_ % 3 -eq 0]
            if(-not (Get-VM -Name $vmDbName -ErrorAction SilentlyContinue)) {
                Write-Verbose "Creating new VM: $vmDbName"
                $win25Db = New-VM -Name $vmDbName -Generation 2 -MemoryStartupBytes 2GB -VHDPath $win25DbPath -SwitchName "Private-Lan$($switchSuffix)"
                $win25Db | Set-VMProps -Processors 1 -MaxMemory 4GB
                Add-VMDvdDrive $win25Db -Path $sql2022IsoFile
            }
            Start-VM $vmDbName -WarningAction SilentlyContinue | Write-Verbose "Starting $vmDbName"
            $remoteSession = Wait-WinRMSession -VMName $vmDbName -MaxTimeout 60 -SleepTime 5
            Write-Verbose "Renaming LAN interface"
            Invoke-Command -Session $remoteSession -ArgumentList $switchSuffix -ScriptBlock {
                param([int]$lanIndex)
                Get-NetAdapter | Where-Object { $_.Name -ne "External" -and $_.Name -notlike "Private-Lan*" } | Rename-NetAdapter -NewName "Private-Lan$($lanIndex)" -Verbose
            }
            Write-Verbose "Updating IP address for LAN interface"
            Invoke-Command -Session $remoteSession -ArgumentList $_, $switchSuffix {
                param([int]$index, [int]$lanIndex)
                New-NetIPAddress -InterfaceAlias "Private-Lan$($lanIndex)" `
                    -IPAddress "10.$($lanIndex).$($lanIndex).$($index * 10 + $index)" -PrefixLength 24 `
                    -DefaultGateway "10.$($lanIndex).$($lanIndex).1" | Out-Null
                Set-DnsClientServerAddress -InterfaceAlias "Private-Lan$($lanIndex)" -ServerAddresses "10.10.10.53"
                Set-NetConnectionProfile -InterfaceAlias "Private-Lan$($lanIndex)" -NetworkCategory Private
            }
            Start-Sleep -Seconds 10
            Write-Verbose (Invoke-Command -Session $remoteSession { ipconfig } | Out-String)
            # install WSFC Role w/o Management Tools
            Invoke-Command -Session $remoteSession { Add-WindowsFeature -Name Failover-Clustering }
            # join the domain
            Invoke-Command -Session $remoteSession -ArgumentList ($SecurePass | ConvertFrom-SecureString -AsPlainText) {
                param($secretText)
                $domainAdmin = New-Object -TypeName System.Management.Automation.PSCredential("sqldemo\Administrator", ($secretText | ConvertTo-SecureString -AsPlainText -Force))
                Add-Computer -DomainName "sqldemo.local" -Credential $domainAdmin -ErrorAction Stop
                Write-Host "$($env:COMPUTERNAME) joined 'sqldemo.local' domain successfully 🤝" -ForegroundColor Green
            }
            # restart needed after joining domain
            Invoke-Command -Session $remoteSession {
                Set-NetFirewallProfile -Profile Domain -Enabled False -Verbose
                Restart-Computer -Force
            }
            Wait-ServerEvent -VMName $vmDbName -WaitWhile {
                (Get-PSSession -Name $vmDbName).State -eq "Opened" -and (Get-PSSession -Name $vmDbName).Availability -eq "Available"
            } -TextMsg "$vmDbName is restarting" -ErrorMsg "max. wait time reached but $vmDbName has not been restarted yet." -MaxTimeout 40 -SleepTime 2
            $remoteSession = Wait-WinRMSession -VMName $vmDbName -MaxTimeout 120 -SleepTime 5 -AsDomainAdmin
            # install SQL Server
            Invoke-Command -Session $remoteSession -ArgumentList ($SecurePass | ConvertFrom-SecureString -AsPlainText) {
                param($secretText)
                D:\setup.exe /ACTION="install" /FEATURES=SQLENGINE,REPLICATION /INSTANCENAME=MSSQLSERVER `
                    /IACCEPTSQLSERVERLICENSETERMS /QUIET /INDICATEPROGRESS=true `
                    /SQLSYSADMINACCOUNTS="SQLDEMO\Administrator" /SQLSVCPASSWORD="$secretText" `
                    /TCPENABLED=1 /NPENABLED=1 /SQLTEMPDBFILECOUNT=2 /SQLTEMPDBFILESIZE=8
                # TODO: Find a way to change service account successfully.
                #$service = Get-WmiObject Win32_Service | Where-Object Name -eq "MSSQLSERVER"
                #$service.Change($null,$null,$null,$null,$null,$null,"SQLDEMO\Administrator","$secretText",$null, $null, $null)
                #Get-Service -Name "MSSQLSERVER" | Restart-Service -Verbose
                #$service | Select-Object Name,State,StartName
                #New-NetFirewallRule -DisplayName "SQLServer Engine" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow -Profile Domain,Public,Private | Out-Null
                #New-NetFirewallRule -DisplayName "SQLServer Browser" -Direction Inbound -LocalPort 1434 -Protocol UDP -Action Allow -Profile Domain,Public,Private | Out-Null
            }
            Remove-PSSession -Session $remoteSession
        }
        Write-Host  "DB0$_`t👌🏼"
    }
}

function New-Win25AppServer {
    [CmdletBinding()]
    param (
        # edition index for Windows Server Editions
        [parameter(Position=0, Mandatory=$true, HelpMessage="Enter the edition index for the Windows Server 2025")]
        [int]$EditionIndex
    )
    $vmAppName= "win25-app01"
    $win25AppPath = "$($HddPath)\$($vmAppName).vhdx"

    Deploy-UnattendedXml -VMName $vmAppName -EditionIndex $EditionIndex

    if(-not (Get-VM -Name $vmAppName -ErrorAction SilentlyContinue)) {
        Write-Verbose "Creating new VM: $vmAppName"
        $win25App = New-VM -Name $vmAppName -Generation 2 -MemoryStartupBytes 1GB -VHDPath $win25AppPath -SwitchName "Private-Lan10"
        $win25App | Set-VMProps -Processors 2 -MaxMemory 4GB
    }

    Start-VM $vmAppName -WarningAction SilentlyContinue | Write-Verbose "Starting $vmAppName"
    $remoteSession = Wait-WinRMSession -VMName $vmAppName -MaxTimeout 60 -SleepTime 5
    # rename the external network interface
    Invoke-Command -Session $remoteSession { Get-NetAdapter | Rename-NetAdapter -NewName "Private-Lan10" }
    Write-Verbose "Updating IP addresses for LAN interfaces"
    Invoke-Command -Session $remoteSession {
        New-NetIPAddress -InterfaceAlias "Private-Lan10" -IPAddress "10.10.10.100" -PrefixLength 24 -DefaultGateway "10.10.10.1" | Out-Null
        Set-DnsClientServerAddress -InterfaceAlias "Private-Lan10" -ServerAddresses "10.10.10.53"
        Set-NetConnectionProfile -InterfaceAlias "Private-Lan10" -NetworkCategory Private
    }
    Start-Sleep -Seconds 5
    Write-Verbose (Invoke-Command -Session $remoteSession { ipconfig } | Out-String)
    # install WSFC Role w/Management Tools
    Invoke-Command -Session $remoteSession { Add-WindowsFeature -Name Failover-Clustering -IncludeManagementTools }
    # join the domain
    Invoke-Command -Session $remoteSession -ArgumentList ($SecurePass | ConvertFrom-SecureString -AsPlainText) {
        param($secretText)
        $domainAdmin = New-Object -TypeName System.Management.Automation.PSCredential("sqldemo\Administrator", ($secretText | ConvertTo-SecureString -AsPlainText -Force))
        Add-Computer -DomainName "sqldemo.local" -Credential $domainAdmin
        Write-Host "$($env:COMPUTERNAME) joined 'sqldemo.local' domain successfully 🤝" -ForegroundColor Green
    }
    # restart needed after joining domain
    Invoke-Command -Session $remoteSession {
        Set-NetFirewallProfile -Profile Domain -Enabled False -Verbose
        Restart-Computer -Force
    }
    Wait-ServerEvent -VMName $vmAppName -WaitWhile {
        (Get-PSSession -Name $vmAppName).State -eq "Opened" -and (Get-PSSession -Name $vmAppName).Availability -eq "Available"
    } -TextMsg "$vmAppName is restarting" -ErrorMsg "max. wait time reached but $vmAppName has not been restarted yet." -MaxTimeout 40 -SleepTime 2
    $remoteSession = Wait-WinRMSession -VMName $vmAppName -MaxTimeout 120 -SleepTime 5 -AsDomainAdmin
    Invoke-Command -Session $remoteSession {
        # install SQL Management Studio 21
        Write-Host "Starting SQL Server Management Studio 21 installation in the background" -ForegroundColor Cyan
        Start-Job -ScriptBlock {
            winget install -id Microsoft.SQLServerManagementStudio.21 --silent --disable-interactivity --accept-package-agreements --accept-source-agreements
        }
        Write-Host "If fails, you can manually re-install using installer file on the desktop." -ForegroundColor Cyan
        Invoke-WebRequest -Uri "https://aka.ms/ssms/21/release/vs_SSMS.exe" -OutFile "$($Env:USERPROFILE)\Desktop\vs_SSMS.exe"
        Write-Host "Installing latest PowerShell also in the background" -ForegroundColor Cyan
        Start-Job -ScriptBlock {
            winget install --id Microsoft.PowerShell --silent --source winget
        }
    }
    Remove-PSSession -Session $remoteSession
    Write-Host  "App01`t📐"
}

function Set-FailoverCluster {

    $vmDbName = "win25-db01"
    $domainAdmin = New-Object -TypeName System.Management.Automation.PSCredential("sqldemo\Administrator", ($SecurePass | ConvertTo-SecureString -AsPlainText -Force))
    $remoteSession = New-PSSession -VMName $vmDbName -Credential $domainAdmin -Name $vmDbName

    Invoke-Command -Session $remoteSession {
        Write-Host "Installing Failover clustering management tools"
        Add-WindowsFeature -Name Failover-Clustering -IncludeManagementTools
        $ClusterName = "cluster01"
        # database nodes
        $DbNodes = @(1..3 | ForEach-Object { "win25-db0$($_)" })
        # 10.10.10.250, 10.20.20.250
        $IPAddresses = @(1..2 | ForEach-Object { "10.$(10 * $_).$(10 * $_).250" })
        # create the cluster
        Write-Host "Starting to create failover cluster"
        New-Cluster -Name $ClusterName -Node $DbNodes -StaticAddress $IPAddresses -NoStorage
        $clusterGroup = Get-Cluster | Where-Object Name -eq $ClusterName | Get-ClusterGroup | Where-Object Name -eq "Cluster Group"
        $clusterGroup | Out-Default
        $clusterNodes = Get-Cluster | Where-Object Name -eq $ClusterName | Get-ClusterNode
        $clusterNodes | Out-Default
        Write-Host "Waiting for cluster to be online" -ForegroundColor Cyan -NoNewline
        $maxWaitCycle = 10
        do {
            $clusterGroup = Get-Cluster | Where-Object Name -eq $ClusterName | Get-ClusterGroup | Where-Object Name -eq "Cluster Group"
            if($clusterGroup.State -eq "Online") { break }
            Write-Host "." -ForegroundColor Cyan -NoNewline
            Start-Sleep -Seconds 2
            if(--$maxWaitCycle -eq 0) {
                Write-Host
                Write-Error "max. wait time reached but $ClusterName has not been online yet." -ErrorAction Stop
            }
        } while ($true)
        # change some cluster perameters for multi-subnet clusters
        $clusterResource = Get-ClusterResource | Where-Object { $_.ResourceType -eq "Network Name" } | Where-Object { $_.Name -ne "Cluster Name" }
        $clusterResource | Get-ClusterParameter | Where-Object { $_.Name -eq "HostRecordTTL" -or $_.Name -eq "RegisterAllProvidersIP" }
        $clusterResource | Set-ClusterParameter RegisterAllProvidersIP 0
        $clusterResource | Set-ClusterParameter HostRecordTTL 60
        $clusterResource | Get-ClusterParameter | Where-Object { $_.Name -eq "HostRecordTTL" -or $_.Name -eq "RegisterAllProvidersIP" }
        # updating Lease timeout
        $clusterAG = Get-ClusterResource | Where-Object { $_.ResourceType -like "SQL Server Availability Group" }
        $clusterAG | Get-ClusterParameter LeaseTimeout
        $clusterAG | Set-ClusterParameter LeaseTimeout 30000
        $clusterAG | Get-ClusterParameter LeaseTimeout
        # updating Subnet delays for multi-subnet clusters
        Get-Cluster | Format-List "*subnet*"
        (Get-Cluster).SameSubnetDelay = 1000
        (Get-Cluster).SameSubnetThreshold = 30
        (Get-Cluster).CrossSubnetDelay = 2000
        (Get-Cluster).CrossSubnetThreshold = 100
        Get-Cluster | Format-List "*subnet*"
        # restart to take effect
        $clusterResource | Stop-ClusterResource
        $clusterResource | Start-ClusterResource
        Start-ClusterGroup $clusterResource.OwnerGroup.Name
        # simulate a failover by moving the cluster group to each node
        $ownerNode = (Get-ClusterOwnerNode -Group $clusterGroup | Select-Object -ExpandProperty OwnerNodes).Name
        Write-Host "Current Owner: $ownerNode" -ForegroundColor Green
        $clusterNodes | Where-Object { $_ -notin $ownerNode.Name } | ForEach-Object {
            Move-ClusterGroup -Name "Cluster Group" -Node $_.Name -Verbose -ErrorAction Stop
            Write-Host "Move-ClusterGroup to $($_.Name) is completed. Waiting for 5s..." -ForegroundColor Cyan
            Start-Sleep -Seconds 5
            $ownerNode = (Get-ClusterOwnerNode -Group $clusterGroup | Select-Object -ExpandProperty OwnerNodes).Name
            Write-Host "Current Owner: $ownerNode" -ForegroundColor Green
            if ($clusterGroup.State -ne "Online")
            {
                $clusterGroup
                Write-Error "Cluster failover simulation is not successful.❌"
                break
            }
        }
        Set-ClusterOwnerNode -Group $clusterGroup -Owners "win25-db01" -Verbose
        Move-ClusterGroup -Name "Cluster Group" -Node "win25-db01" -Verbose -ErrorAction Stop
        Get-ClusterOwnerNode -Group $clusterGroup
        Get-ClusterQuorum | Select-Object Cluster,QuorumResource,QuorumType

        Write-Host "Health`t💖"
    }
    Remove-PSSession $remoteSession
}

function Deploy-SQLAlwaysOn {
    Get-PSSession | Remove-PSSession
    $domainAdmin = New-Object -TypeName System.Management.Automation.PSCredential("sqldemo\Administrator", ($SecurePass | ConvertTo-SecureString -AsPlainText -Force))
     1..3 | ForEach-Object {
        $vmDbName= "win25-db0$_"
        $remoteSession = New-PSSession -VMName $vmDbName -Credential $domainAdmin -Name $vmDbName
        Invoke-Command -Session $remoteSession -ArgumentList $_ {
            param($index)
            # do this for db01 only
            if($index -eq 1) {
                $BackupDir = "C:\Backups"
                New-Item -Path $BackupDir -ItemType Directory
                New-SmbShare -Name "DbBackups" -Path $BackupDir
                Grant-SmbShareAccess -Name "DbBackups" -AccountName "SQLDEMO\Administrator" -AccessRight Full -Confirm:$false
                
                $DbName = "northwind"
                Write-Host "downloading $DbName sql"
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/sql-server-samples/refs/heads/master/samples/databases/northwind-pubs/instnwnd.sql" `
                    -OutFile "$($DbName).sql"

                Write-Host "Creating $DbName database"
                Invoke-Sqlcmd -ServerInstance $env:COMPUTERNAME -Query "CREATE DATABASE $DbName"
                Write-Host "Executing sql"
                Invoke-Sqlcmd -ServerInstance $env:COMPUTERNAME -Database $DbName -InputFile "$($DbName).sql"
                # select some data to verify
                Invoke-Sqlcmd -ServerInstance $env:COMPUTERNAME -Database $DbName -Query "SELECT FirstName, LastName FROM Employees"
                
                Write-Host "Backing up $DbName"
                Invoke-Sqlcmd -ServerInstance $env:COMPUTERNAME -Query "
                BACKUP DATABASE [$DbName] TO  DISK = N'$($BackupDir)\$DbName.bak' WITH NOFORMAT, NOINIT,  NAME = N'$DbName-Full Database Backup', SKIP, NOREWIND, NOUNLOAD,  STATS = 10
                GO
                BACKUP LOG [$DbName] TO  DISK = N'$($BackupDir)\$($DbName)_log.bak' WITH NOFORMAT, NOINIT,  NAME = N'$DbName-Log  Database Backup', SKIP, NOREWIND, NOUNLOAD,  STATS = 10
                GO" -Verbose -ErrorAction Stop
            }

            Enable-SqlAlwaysOn -ServerInstance $env:COMPUTERNAME -Force -Verbose -Confirm:$false

            Invoke-Sqlcmd -ServerInstance $env:COMPUTERNAME -Query "SELECT `
                @@SERVERNAME AS ServerName, `
                @@VERSION AS SQLVersion, `
                SERVERPROPERTY('ProductVersion') AS ProductVersion, `
                SERVERPROPERTY('Edition') AS Edition, `
                SERVERPROPERTY('IsHadrEnabled') as AlwaysOnEnabled"
        }
        Remove-PSSession -Session $remoteSession
    }

    #TODO: Run generated SQL Script to create availability group, just like the wizard does from SQL Man. Studio
    #availgroup01
    #dblistener01=10.10.10.43, 10.20.20.43
}

function Start-Provisioning {
<#
.SYNOPSIS
Set up a virtualized environment with multiple VMs to test WSFC/SQL Always On capabilities
.DESCRIPTION
This command will do a lot of things. Do not proceed if you are not comfortable making these changes.

  1. Checks HyperV and installs it, if not installed already
  2. Creates virtual HyperV switches
    - 1 external switch for internet access (external)
    - 1 internal switch for routing network (internal)
    - 2 private networks for virtual machines
  3. Downloads Windows server evaluation ISO/media and extracts WIM file
  4. Creates an Active Directory, Domain Controller & DNS server
  5. Creates 3 SQL Servers
  6. Creates an application server (with desktop experience)
  7. Sets up a Failover Cluster with the SQL Servers
  8. Deploys SQL Always On Availability Group
  
While doing all these, it will also:
    - Create base virtual hard disk images, pre-installed with Windows Server 2025
by mounting hard disks and format partitions.
    
.EXAMPLE
PS C:\> Start-Provisioning -Verbose
#>
    [CmdletBinding(ConfirmImpact="High",SupportsShouldProcess)]
    param (
        [Parameter(HelpMessage="Provide a path to store virtual hard disks.")]
        [ValidateNotNullorEmpty()]
        [ValidateScript({ if (Test-Path $_) { $true } else { throw "VHDX path $_ not found." } })]
        $HddPath = "C:\hdd",

        [Parameter(HelpMessage="Provide a path to download files to.")]
        [ValidateNotNullorEmpty()]
        [ValidateScript({ if (Test-Path $_) { $true } else { throw "Download path $_ not found." } })]
        $DownloadPath = "$($env:USERPROFILE)\Downloads",
        
        [Parameter(HelpMessage="Provide the name for external virtual switch.")]
        [ValidateNotNullorEmpty()]
        $ExternalSwitch = "HyperV-External",

        [Parameter(HelpMessage="Provide the name for internal virtual switch.")]
        [ValidateNotNullorEmpty()]
        $InternalSwitch = "HyperV-Internal",

        [Parameter(HelpMessage="Provide dynamically expanding (max) virtual hard disk size.")]
        [ValidateRange(20GB,64GB)]
        [UInt64]$Script:DiskSize = 32GB,

        [Parameter(HelpMessage="Provide public dns servers.")]
        [ValidateNotNullorEmpty()]
        $DnsServers = @("1.1.1.1", "1.0.0.1")
    )

    begin {
        $verbose = $VerbosePreference
        Write-Verbose "Starting WSFC/SQL Always On virtual environment provisioning..."

        $params = [PSCustomObject]@{
            HddPath = $HddPath
            DownloadPath = $DownloadPath
            ExternalSwitch = $ExternalSwitch
            InternalSwitch = $InternalSwitch
            DiskSize = "$($DiskSize / 1GB)GB"
            DnsServers = $DnsServers
        }
        $params | Format-Table

        $Script:DownloadPath = $DownloadPath
        $Script:HddPath = $HddPath
        $Script:ExternalSwitch = $ExternalSwitch
        $Script:InternalSwitch = $InternalSwitch

        [Int64]$Script:DiskSize = $DiskSize
        $Script:Win25WimFile = Join-Path -Path $DownloadPath -ChildPath "install.wim"
        $Script:Win25ParentVhdx = $null
        $Script:DnsServers = $DnsServers
    }

    process {
        if ($PSCmdlet.ShouldContinue("You are about to start provisioning servers using the parameters above.`
Are you sure you want to continue?", "WARNING!", [ref]$true, [ref]$false, [ref]$false)) {

            Enable-HyperV

            Assert-VMSwitches

            Get-WindowsEvalImage

            Get-AdminCredential

            New-Win25DC -EditionIndex 1

            New-Win25DbServers -EditionIndex 1 -DBServers 3

            New-Win25AppServer -EditionIndex 2

            Set-FailoverCluster

            Deploy-SQLAlwaysOn

        } else {
            Write-Error "Operation aborted." -ErrorAction Stop
        }
    }
    end {
        $VerbosePreference = $verbose
    }
}

Get-AdminCredential