# 002 - PowerShell Spawned Instance and Suspicious File Drop

## Objective

Validate that controlled PowerShell activity on the Windows Endpoint can produce process execution and suspicious file drop evidence in Wazuh.

## Test Context

After validating the first endpoint detection case, a safer PowerShell execution test was used to generate repeatable endpoint telemetry. Wazuh produced two related alerts:

- A PowerShell process spawned another PowerShell instance.
- An executable file was dropped in a folder commonly used by malware.

This case documents the alert evidence and SOC triage value of the related events.

## Environment

| Field | Value |
|---|---|
| Endpoint | `win-endpoint` |
| Wazuh Manager | `wazuh-server` |
| Data source | Sysmon via Wazuh Agent |
| Wazuh view | Threat Hunting |

## Alert Summary

| Rule ID | Rule level | Description | MITRE mapping |
|---|---:|---|---|
| `92027` | 4 | `Powershell process spawned powershell instance` | `T1059.001` PowerShell |
| `92213` | 15 | `Executable file dropped in folder commonly used by malware` | `T1105` Ingress Tool Transfer |

## Evidence Screenshots

Wazuh rule `92213`:

![Wazuh file drop rule 92213 alert](../screenshots/wazuh-powershell-file-drop-rule-92213.png)

Wazuh rule `92027`:

![Wazuh PowerShell spawned instance rule 92027 alert](../screenshots/wazuh-powershell-spawned-instance-rule-92027.png)

## Key Event Fields

Observed fields for Wazuh rule `92213`:

```text
data.win.system.providerName: Microsoft-Windows-Sysmon
data.win.system.severityValue: INFORMATION
data.win.system.systemTime: 2026-06-30T18:42:58.9098576Z
decoder.name: windows_eventchannel
manager.name: wazuh-server
rule.description: Executable file dropped in folder commonly used by malware
rule.groups: sysmon, sysmon_eid11_detections, windows
rule.id: 92213
rule.level: 15
rule.mitre.id: T1105
rule.mitre.tactic: Command and Control
rule.mitre.technique: Ingress Tool Transfer
timestamp: Jun 30, 2026 @ 14:43:00.743
```

Observed fields for Wazuh rule `92027`:

```text
data.win.system.providerName: Microsoft-Windows-Sysmon
data.win.system.severityValue: INFORMATION
data.win.system.systemTime: 2026-06-30T18:42:58.6540650Z
decoder.name: windows_eventchannel
manager.name: wazuh-server
rule.description: Powershell process spawned powershell instance
rule.groups: sysmon, sysmon_eid1_detections, windows
rule.id: 92027
rule.level: 4
rule.mitre.id: T1059.001
rule.mitre.tactic: Execution
rule.mitre.technique: PowerShell
timestamp: Jun 30, 2026 @ 14:43:00.742
```

## Search Query Used

The initial Wazuh Threat Hunting query was intentionally broad:

```text
agent.name: "win-endpoint"
```

Useful follow-up queries:

```text
agent.name: "win-endpoint" AND "Powershell process spawned powershell instance"
agent.name: "win-endpoint" AND "Executable file dropped"
agent.name: "win-endpoint" AND rule.id:92027
agent.name: "win-endpoint" AND rule.id:92213
agent.name: "win-endpoint" AND data.win.system.providerName:"Microsoft-Windows-Sysmon"
```

## Timeline

| Time | Event | Evidence |
|---|---|---|
| Jun 30, 14:43:00.742 | PowerShell process spawned a PowerShell instance | Wazuh rule `92027` |
| Jun 30, 14:43:00.743 | File drop activity detected in a folder commonly used by malware | Wazuh rule `92213` |

## Analyst Interpretation

The alerts indicate two behaviors that are useful for SOC triage:

- Nested PowerShell execution, which can be seen in living-off-the-land execution chains.
- File drop behavior in a location commonly associated with malware staging or tool transfer.

The two events occurred within the same second, making them useful as related evidence. The rule `92027` event maps to PowerShell execution under ATT&CK `T1059.001`, while rule `92213` maps to `T1105` Ingress Tool Transfer.

This does not automatically prove malicious activity, but it provides a strong investigation pivot. An analyst should review command-line arguments, parent process details, user context, file path, file hash, and nearby Defender or Sysmon events.

## Detection Value

This case demonstrates:

- Wazuh correlation from Sysmon process and file activity.
- MITRE ATT&CK mapping in Wazuh alert details.
- The value of reviewing alerts as a timeline rather than as isolated events.
- A repeatable endpoint-focused detection workflow suitable for SOC documentation.

## Recommended Follow-up

- Review the single-document view for full command-line and parent-process fields.
- Search for additional Sysmon Event ID 1 process creation events around the same timestamp.
- Search for Sysmon Event ID 11 file creation events around the same timestamp.
- Validate whether Microsoft Defender produced any related detection or prevention event.
- Capture file path, hash, and user context if available.
- If malicious behavior is confirmed, isolate the endpoint and preserve forensic evidence.

## Status

Validated:

- Wazuh received Sysmon-based process execution telemetry.
- Wazuh received Sysmon-based suspicious file drop telemetry.
- MITRE mappings were visible for `T1059.001` and `T1105`.
- Screenshot evidence was captured for both alerts.

Needs follow-up:

- Extract full command-line and parent-process fields for deeper timeline reconstruction.
- Determine whether the dropped file was blocked, executed, or only created.
