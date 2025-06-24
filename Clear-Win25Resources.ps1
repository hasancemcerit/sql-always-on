#requires -RunAsAdministrator
#requires -modules Hyper-V

function Clear-Win25Resources {
    [CmdletBinding()]
    param()
    $HddPath = "C:\hdd"

    Write-Host "Clearing Win25 resources..." -ForegroundColor Cyan
    # Remove VMSwitches
    #Get-VMSwitch -Name "Private-Lan*" -ErrorAction SilentlyContinue | ForEach-Object {
    #    Write-Host "Removing VMSwitch: $($_.Name)" -ForegroundColor Yellow
    #    Remove-VMSwitch -Name $_.Name -Force -Confirm:$false
    #}
    #Get-VMSwitch -Name $global:ExternalSwitchName -ErrorAction SilentlyContinue | ForEach-Object {
    #    Write-Host "Removing VMSwitch: $($_.Name)" -ForegroundColor Yellow
    #    Remove-VMSwitch -Name $_.Name -Force -Confirm:$false
    #}
    
    # Remove VMs
    Get-VM -Name "Win25*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Removing VM: $($_.Name)" -ForegroundColor Yellow
        Stop-VM -Name $_.Name -Force -Confirm:$false -ErrorAction SilentlyContinue
        Remove-VM -Name $_.Name -Force -Confirm:$false
    }
    # Remove VHDs
    Get-ChildItem -Path "$HddPath\win25*.vhdx" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Removing VHD: $($_.Name)" -ForegroundColor Yellow
        Remove-Item -Path $_.FullName -Force -Confirm:$false
    }
}

Clear-Win25Resources