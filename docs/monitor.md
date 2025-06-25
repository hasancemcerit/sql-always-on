```
Time         Host         IP           Link Role     SyncHealth SyncState    DbState
----         ----         --           ---- ----     ---------- ---------    -------
13:02:15.689 cluster01    10.10.10.250 OK
13:02:15.722 dblistener01 10.10.10.144 OK   LISTENER OK
13:02:15.722 win25-db01   10.10.10.11  OK   PRIMARY  HEALTHY    SYNCHRONIZED ONLINE
13:02:15.722 win25-db02   10.10.10.22  OK   ⁉️       ⁉️         ⁉️           ⁉️
13:02:15.722 win25-db03   10.20.20.33  OK   ⁉️       ⁉️         ⁉️           ⁉️


Time         Host         IP           Link Role      SyncHealth  SyncState         DbState
----         ----         --           ---- ----      ----------  ---------         -------
13:02:49.895 cluster01    10.10.10.250 OK
13:02:49.897 dblistener01 10.10.10.144 OK   LISTENER  OK
13:02:49.898 win25-db01   10.10.10.11  OK   PRIMARY   HEALTHY     SYNCHRONIZED      ONLINE
13:02:49.899 win25-db02   10.10.10.22  OK   ⁉️        ⁉️          ⁉️                ⁉️
13:02:49.901 win25-db03   10.20.20.33  OK   RESOLVING NOT_HEALTHY NOT SYNCHRONIZING RECOVERY_PENDING


Time         Host         IP           Link Role      SyncHealth SyncState     DbState
----         ----         --           ---- ----      ---------- ---------     -------
13:03:04.297 cluster01    10.10.10.250 OK
13:03:04.298 dblistener01 10.10.10.144 OK   LISTENER  OK
13:03:04.300 win25-db01   10.10.10.11  OK   PRIMARY   HEALTHY    SYNCHRONIZED  ONLINE
13:03:04.301 win25-db02   10.10.10.22  OK   SECONDARY HEALTHY    SYNCHRONIZED  ONLINE
13:03:04.303 win25-db03   10.20.20.33  OK   SECONDARY HEALTHY    SYNCHRONIZING ONLINE


Time         Host         IP           Link Role      SyncHealth SyncState     DbState
----         ----         --           ---- ----      ---------- ---------     -------
13:03:07.936 cluster01    10.10.10.250 OK
13:03:07.938 dblistener01 10.10.10.144 OK   LISTENER  OK
13:03:07.939 win25-db01   10.10.10.11  OK   PRIMARY   HEALTHY    SYNCHRONIZED  ONLINE
13:03:07.941 win25-db02   10.10.10.22  OK   SECONDARY HEALTHY    SYNCHRONIZED  ONLINE
13:03:07.942 win25-db03   10.20.20.33  OK   SECONDARY HEALTHY    SYNCHRONIZING ONLINE


Time         Host         IP           Link Role      SyncHealth SyncState     DbState
----         ----         --           ---- ----      ---------- ---------     -------
13:03:11.127 cluster01    10.10.10.250 OK
13:03:11.129 dblistener01 10.10.10.144 OK   LISTENER  OK
13:03:11.130 win25-db01   10.10.10.11  OK   PRIMARY   HEALTHY    SYNCHRONIZED  ONLINE
13:03:11.133 win25-db02   10.10.10.22  OK   SECONDARY HEALTHY    SYNCHRONIZED  ONLINE
13:03:11.134 win25-db03   10.20.20.33  OK   SECONDARY HEALTHY    SYNCHRONIZING ONLINE
```

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a---       2025-06-24 1:10:56 PM         4.9 GB 󰋊  pfSensei.vhdx
-a---       2025-06-24 1:10:54 PM        21.2 GB 󰋊  win25-app01.vhdx
-a---       2025-06-20 8:07:54 PM         7.2 GB 󰋊  win25-core.vhdx
-a---       2025-06-24 1:10:55 PM        12.1 GB 󰋊  win25-db01.vhdx
-a---       2025-06-24 1:10:55 PM        11.6 GB 󰋊  win25-db02.vhdx
-a---       2025-06-24 1:10:56 PM        11.8 GB 󰋊  win25-db03.vhdx
-a---       2025-06-24 1:10:56 PM         7.8 GB 󰋊  win25-dc.vhdx
-a---       2025-06-20 9:54:13 PM        12.4 GB 󰋊  win25-std.vhdx
```

```
Name        State   CPUUsage(%) MemoryAssigned(M) Uptime           Status             Version
----        -----   ----------- ----------------- ------           ------             -------
pfSensei    Running 0           1024              04:39:07.1230000 Operating normally 11.0
win25-app01 Running 0           3436              00:18:24.4430000 Operating normally 11.0
win25-db01  Running 0           2568              00:16:19.6410000 Operating normally 11.0
win25-db02  Running 5           2576              00:11:13.9300000 Operating normally 11.0
win25-db03  Running 5           2514              00:11:11.8250000 Operating normally 11.0
win25-dc    Running 0           1526              00:19:07.8870000 Operating normally 11.0
```