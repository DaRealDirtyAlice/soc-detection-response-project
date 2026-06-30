# 2026-06-30 First Endpoint Detection Validation

## Summary

This update documents the first validated endpoint detection case in the SOC Detection Response Project. The project has moved beyond tool installation into alert review and SOC-style investigation documentation.

## What Was Tested

Atomic Red Team was used to begin testing PowerShell activity related to MITRE ATT&CK T1059.001. Microsoft Defender blocked a higher-risk test attempt, which prevented full execution of the test payload. Wazuh did not show a direct `mimikatz` keyword result, but it did show PowerShell-related Sysmon telemetry from `win-endpoint`.

## Validated Detection Path

```text
Windows Endpoint -> Sysmon -> Wazuh Agent -> Wazuh Threat Hunting
```

## Key Result

Wazuh generated a PowerShell-related alert from Sysmon telemetry:

| Field | Value |
|---|---|
| Agent | `win-endpoint` |
| Rule ID | `92205` |
| Rule level | `9` |
| Rule description | `Powershell process created an executable file in Windows root folder` |
| Data source | Sysmon |
| Sysmon event ID | `11` |

## Documentation Added

- [001 - PowerShell File Creation Alert](../incident-reports/001-powershell-file-creation.md)
- [Windows Defender log collection setup](../setup-guides/02-windows-defender-log-collection.md)

## Next Steps

- Review surrounding Sysmon events for process creation context.
- Add Windows Defender Operational log collection to Wazuh if Defender detections should be searchable in Wazuh.
- Capture a sanitized screenshot for the case report.
- Continue with safer Atomic Red Team tests before moving back to higher-risk payload simulations.
- Revisit Suricata-to-Wazuh forwarding after endpoint detection documentation is stable.
