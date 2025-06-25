# 📜 Introduction

This is a hands-on lab to demonstrate [SQL Always On](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/overview-of-always-on-availability-groups-sql-server?view=sql-server-ver17) capabilities using [Windows Server Failover Clustering (WSFC)](https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/windows/windows-server-failover-clustering-wsfc-with-sql-server?view=sql-server-ver17).

Below is the high level view of the environment.

<img src=../screenshots/high-level-diagram.png>

📖 Please read before proceeding.

This script, should you choose to run the main function, will self-destruct your computer in five seconds.

Wait no, not that message.😄


> This script, should you choose to run the main function, will do **a lot of things** to your computer. 

😇 But fret not, if you read the following, you will know **exactly** what each function does and have the option to skip some to execute yourself to be (more) in control.

Here are the steps you need to execute, in `this` order:

The corresponding function name in the main script file is included in `Function-Name` format below.

1. Install HyperV
   - `Enable-HyperV`
2. Create 3 virtual HyperV switches
   - External (HyperV-External)
      - ⚠️ This is where you'll lose internet connection temporarily because your physical (ethernet or wi-fi) connection will be shared by this new external switch.
   - Internal (HyperV-Internal)
   - 2 Private (Private-Lan10, PrivateLan20)
   - `Assert-VMSwitches`
3. Download [Windows server evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025) ISO/media and extract [Windows image (.WIM)](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/capture-and-apply-windows-using-a-single-wim?view=windows-11) file
   - `Get-WindowsEvalImage`
4. Create Domain Controller - Active Directory
   - `New-Win25DC`
5. Create 3 SQL servers
   - `New-Win25DbServers`
6. Create an application server (with desktop experience)
   - `New-Win25AppServer`
7. Setup Windows failover clustering
   - `Set-FailoverCluster`
8. Create Always on availability group
   - `Deploy-SQLAlwaysOn`

All these Windows 2025 servers will be created automatically, without any user interaction. This is accomplished by injecting an answer (xml-formatted) file to Windows server image called `unattended.xml`.

For more information check out how to [use an answer file while installing Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview?view=windows-11#use-an-answer-file-while-installing-windows).

Once the Windows server installation media is downloaded (step #3 above), and you start to create the first Windows server, it will create a base virtual disk (vhdx) for each Windows Server edition that is used in this demo:

| ImageIndex | ImageName |
| ----- | --- |
| 1 | Windows Server 2025 Standard Evaluation |
| 2 | Windows Server 2025 Standard Evaluation (Desktop Experience) |
| 3 | Windows Server 2025 Datacenter Evaluation |
| 4 | Windows Server 2025 Datacenter Evaluation (Desktop Experience) |

The servers will use the 1 & 2 as the base images. Datacenter edition takes too much space but if you want to use that you must change the `EditionIndex` accordingly.


<br/>

# What you need

## Prerequisite

You need a virtual router (pfSense, in this example) to route traffic between different subnets, and also allow virtual machines to connect to internet.

I used pfSense, but I assume any other alternative will work the same.

You need to set this (router) virtual machine before creating others, because it's required for them to connect both internally and externally.

For more (basic) information how to setup pfSense and configure pfSense, check out: 
[pfSense readme](pfSense.md)

## 🛠️ Toolset

<img src="https://skillicons.dev/icons?i=windows,vscode,powershell" />

You need a decent Windows 11 host machine, with at least:
- 100GB of empty storage space
   - SSD is highly recommended here, because optical disk [sweats](../screenshots/non-ssd-disk-usage.png)🥵
- 64-bit processor with minimum 8 cores
- 8GB of RAM
- UEFI capable and Secure Boot support   
 
ℹ️ This script is tested and confirmed working with Windows 11 and PowerShell version 7.5.

<br/>

# 🚀 Steps


0. Clone the repo

   ```powershell
   git clone git@github.com:hasancemcerit/sql-always-on.git
   cd sql-always-on
   ```

1. Load the script

   Open a PowerShell window as `administrator` and load the main script file. It will ask you for a password for both local and domain administrator accounts for Windows 25 servers.

      ```powershell
      . .\Setup-WindowsFailover.ps1
      Please enter the password for the Domain & Local Administrator account.
      Password: ***********
      Pwd   🔐
      ```
   If you want to double check and see what you set as password you can by:
   ```powershell
   $SecurePass | ConvertFrom-SecureString -AsPlainText
   # Your super secret password will be displayed here.
   ```

2. Create Active Directory & Domain Controller

   Domain controller server will use Standard (Core) edition #1.

   ```powershell
   New-Win25DC -EditionIndex 1
   ```

3. Create Database servers

   Database servers will use Standard (Core) edition #1.

   ```powershell
   New-Win25DbServers -EditionIndex 1 -DBServers 3
   ```

4. Create Application server

   Application server will use Standard (Desktop Experience) edition #2.

   ```powershell
   New-Win25AppServer -EditionIndex 2
   ```

Sit back, relax and have a cup of ☕

```powershell
PS C:\> Start-Provisioning -Verbose

VERBOSE: Target Image Version 10.0.22631.5472
HyperV  🚀
Net     🌎
Lan10   🛜
Lan20   🛜
Iso     💿
Wim     💽

ImageIndex ImageName
---------- ---------
         1 Windows Server 2025 Standard Evaluation
         2 Windows Server 2025 Standard Evaluation (Desktop Experience)
         3 Windows Server 2025 Datacenter Evaluation
         4 Windows Server 2025 Datacenter Evaluation (Desktop Experience)

Pwd     🔐
Base    📦
VERBOSE: New-VHD will create a new virtual hard disk with the path "C:\hdd\win25-dc.vhdx".

VERBOSE: Mount-VHD will mount the virtual hard disk "C:\hdd\win25-dc.vhdx".
VERBOSE: Copying unattend.xml
VERBOSE: Performing the operation "Output to File" on target "E:\Windows\Panther\unattend.xml".
VERBOSE: Dismount-VHD will dismount the virtual hard disk "C:\hdd\win25-dc.vhdx".
VERBOSE: Creating new VM: win25-dc
VERBOSE: Starting win25-dc
Waiting for win25-dc to accept WinRM session...
VERBOSE: Creating remote session to win25-dc
VERBOSE: Adding and renaming LAN network interfaces
VERBOSE: Add-VMNetworkAdapter will add a network adapter to virtual machine "win25-dc".
VERBOSE: Add-VMNetworkAdapter will add a network adapter to virtual machine "win25-dc".
VERBOSE: Updating IP addresses for LAN interfaces
...
```

# Test Cases

This is the whole idea of the setup. To see how SQL Always on handles different failures.

| Case # | Description | Expected Result | Fix | Data Loss |
| - | - | - | - | - |
| 1 | Async node (secondary replica) is down | No downtime | Automatic | None |
| 2 | Sync node (secondary replica) is down | No downtime | Automatic | None |
| 3 | Sync node (primary replica) is down | Minimum downtime | Automatic | None |
| 4 | Both secondary nodes are down | Downtime | Manual Fix #1 | Not Likely |
| 5 | Both primary & secondary nodes are down | Downtime | Manual Fix #2 | Less Likely |

#### Fix #1
Connect to primary node, and run:
```powershell
Get-Service ClusSvc | Stop-Service -Verbose
Start-ClusterNode -Name "{primary-node-name}" -FixQuorum
```
then immediately run the following SQL command:
```sql
ALTER AVAILABILITY GROUP ['{availability-group-name}'] FORCE_FAILOVER_ALLOW_DATA_LOSS;
```
once the failed secondary nodes are up, connect each one and resume data movement by:
```sql
ALTER DATABASE [northwind] SET HADR RESUME;
```

#### Fix #2

This is a simulation of data center serving databases is down.

Connect to secondary asynchronous node, and run:
```powershell
Get-Service ClusSvc | Stop-Service -Verbose
Start-ClusterNode -Name "{async-secondary-node-name}" -FixQuorum
```
then immediately run the following SQL command:
```sql
ALTER AVAILABILITY GROUP [availgroup01] FORCE_FAILOVER_ALLOW_DATA_LOSS;
```
flush DNS if necessary to resolve new cluster IP pointing to the other node/subnet.

once the failed secondary nodes are up, connect to async node and change mode to sync.
```sql
ALTER AVAILABILITY GROUP [availgroup01] MODIFY REPLICA ON N'{async-secondary-node-name}' WITH (AVAILABILITY_MODE = SYNCHRONOUS_COMMIT)
```
Once all database replicas are `SYNCHRONIZED` then you can failback by connecting to primary node:
```sql
ALTER AVAILABILITY GROUP [availgroup01] FAILOVER
```
flush DNS if necessary, and make sure that database failover is successful.

### Troubleshooting

>No matching network interface found for resource 'availgroup01_10.20.20.144' IP address '10.20.20.144' (return code was '5035'). 
If your cluster nodes span different subnets, this may be normal.

>The Endpoints tab lists at least one endpoint that uses only Windows Authentication. However, the server instance might be running under a nondomain account. To use the listed endpoint, change the corresponding SQL Server service account to a domain account. To continue using the nondomain account, alter the endpoint to use a certificate.

>The availability group is not ready for automatic failover. The primary replica and a secondary replica are configured for automatic failover, however, the secondary replica is not ready for an automatic failover. Possibly the secondary replica is unavailable, or its data synchronization state is currently not in the SYNCHRONIZED synchronization state.

>WARNING: If you are running Windows PowerShell remotely, note that some failover clustering cmdlets do not work remotely.
When possible, run the cmdlet locally and specify a remote computer as the target.
To run the cmdlet remotely, try using the Credential Security Service Provider (CredSSP).
All additional errors or warnings from this cmdlet might be caused by running it remotely.

>Error:: New-Cluster : Static address was given for the Cluster Name but no appropriate ClusterandClient network was found
to host it. Networks with default gateways are assigned ClusterAndClient role by default. Please check your networking settings


> Cluster node 'win25-db03' has been quarantined by 'cluster nodes' and cannot join the > cluster. The node will be quarantined until '2025/06/24-16:45:39.446' and then the >node will automatically attempt to re-join the cluster. 
>
> Refer to the System and Application event logs to determine the issues on this node.  When the issue is resolved, quarantine can be manually cleared to allow the node to rejoin with the 'Start-ClusterNode –ClearQuarantine' Windows PowerShell cmdlet.

Do what it says, login to quarantined node and: `Start-ClusterNode –ClearQuarantine`

### To-Do List

Here is to-do list to make things more interesting.

- Open only necessary firewall ports

Currently Windows servers have their domain profile disabled from the firewall. Although there is nothing wrong with that, maybe open selective ports for more security hardening to immitate a production-like environment.

For example, the list of common MSSQL ports for Always on availability groups are:
```
TCP 2383
UDP 2382
UDP 1434
TCP 1433
TCP 5022
```

- Add one more sample database into another availability group

Try to add another sample database and create another availability group using the same underlying setup.

https://github.com/Microsoft/sql-server-samples/releases/tag/adventureworks

- Add SQL Server running on Linux to the mix

Well, why not? 😉

https://learn.microsoft.com/en-us/sql/linux/quickstart-install-connect-docker?view=sql-server-linux-ver16&tabs=cli&pivots=cs1-powershell

https://documentation.ubuntu.com/server/how-to/sssd/with-active-directory/index.html

https://learn.microsoft.com/en-us/sql/linux/sql-server-linux-active-directory-join-domain?view=sql-server-ver17&tabs=ubuntu
