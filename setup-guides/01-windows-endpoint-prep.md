# Windows Endpoint Preparation

This guide tracks the initial Windows Endpoint preparation before full Wazuh integration.

## Installed Components

| Component | Purpose |
|---|---|
| VMware Tools | Better VM integration |
| Wazuh Agent | Sends Windows endpoint logs to Wazuh |
| Sysmon | Provides detailed endpoint telemetry |
| Sysmon config | Controls Sysmon event collection |
| Atomic Red Team | Generates controlled ATT&CK-mapped test activity |

## Current Validation

Sysmon service:

```powershell
Get-Service Sysmon64
```

Sysmon event log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Atomic Red Team:

```powershell
Get-Command Invoke-AtomicTest
```

Wazuh Agent:

```powershell
Get-Service | Where-Object {$_.Name -like "*wazuh*"}
```

Expected service name:

```text
WazuhSvc
```

## Notes

The Wazuh Agent may remain stopped until the Wazuh Server is fully deployed and reachable at:

```text
10.10.10.10
```

Do not run Atomic Red Team tests until Sysmon, Wazuh Agent, and Wazuh Server ingestion are ready.

