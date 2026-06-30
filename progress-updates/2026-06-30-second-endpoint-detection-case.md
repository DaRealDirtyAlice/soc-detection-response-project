# 2026-06-30 Second Endpoint Detection Case

## Summary

This update documents the second endpoint detection case in the SOC Detection Response Project. The case focuses on related PowerShell execution and suspicious file drop evidence observed in Wazuh Threat Hunting.

## Detection Case Added

- [002 - PowerShell Spawned Instance and Suspicious File Drop](../incident-reports/002-powershell-spawned-instance-file-drop.md)

## Key Results

Two related Wazuh alerts were captured from `win-endpoint`:

| Rule ID | Rule level | Description | MITRE mapping |
|---|---:|---|---|
| `92027` | 4 | `Powershell process spawned powershell instance` | `T1059.001` PowerShell |
| `92213` | 15 | `Executable file dropped in folder commonly used by malware` | `T1105` Ingress Tool Transfer |

## Validated Detection Path

```text
Windows Endpoint -> Sysmon -> Wazuh Agent -> Wazuh Threat Hunting
```

## Why This Matters

This case is useful because it links two alert types into a short investigation timeline:

- PowerShell execution behavior.
- File drop activity in a suspicious/common malware location.

The alerts provide clear SOC triage pivots: command line, parent process, file path, user context, hash, and nearby Defender/Sysmon events.

## Next Steps

- Extract full command-line and parent-process fields for rule `92027`.
- Extract file path and hash details for rule `92213`.
- Compare the activity with Defender events from the same time window.
- Continue building repeatable endpoint detection cases before returning to Suricata/Wazuh network telemetry tuning.
