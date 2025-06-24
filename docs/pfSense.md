
https://docs.netgate.com/pfsense/en/latest/config/index.html


How to install : https://www.informaticar.net/how-to-install-and-configure-pfsense-on-hyper-v/

pfSense 2.6 is compatible with UEFI/Gen2 VMs
https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.6.0-RELEASE-amd64.iso.gz

To disable pfSense firewall temporarily and use web configurator, go to shell (option #8) and run
```bash
pfctl -d
```
To re-enable pfSense run:
```
pfctl -e
```


This is how pfSense routes should look like. WAN (hn0) interface should be assigned to give VMs external access. You can choose whatever IP/mask combination according to your own network.


```bash
*** Welcome to pfSense 2.6.0-RELEASE (amd64) on pfSense ***

 WAN (wan)       -> hn0        -> v4: 192.168.1.250/23
 LAN1 (lan)      -> hn1        -> v4: 10.10.10.1/24
 LAN2 (opt1)     -> hn2        -> v4: 10.20.20.1/24

 0) Logout (SSH only)                  9) pfTop
 1) Assign Interfaces                 10) Filter Logs
 2) Set interface(s) IP address       11) Restart webConfigurator
 3) Reset webConfigurator password    12) PHP shell + pfSense tools
 4) Reset to factory defaults         13) Update from console
 5) Reboot system                     14) Disable Secure Shell (sshd)
 6) Halt system                       15) Restore recent configuration
 7) Ping host                         16) Restart PHP-FPM
 8) Shell

```