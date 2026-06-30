# 001 - PowerShell File Creation Alert

## Objective

Validate that PowerShell activity on the Windows Endpoint can generate endpoint telemetry through Sysmon and surface as an alert in Wazuh Threat Hunting.

## Test Context

Atomic Red Team was used to begin validation for PowerShell activity associated with MITRE ATT&CK technique T1059.001. During the initial test attempt, Microsoft Defender blocked higher-risk activity before it fully executed. Even though no Wazuh alert containing the keyword `mimikatz` was observed, Wazuh did receive related PowerShell/Sysmon telemetry from the Windows Endpoint.

This case documents the validated endpoint telemetry path rather than claiming full execution of the blocked test.

## Environment

| Field | Value |
|---|---|
| Endpoint | `win-endpoint` |
| Endpoint IP | `10.10.10.20` |
| Wazuh Manager | `wazuh-server` |
| Data source | Sysmon via Wazuh Agent |
| Wazuh view | Threat Hunting |

## Alert Summary

| Field | Value |
|---|---|
| Alert timestamp | June 22, 2026 at approximately 17:48 local time |
| Wazuh rule ID | `92205` |
| Wazuh rule level | `9` |
| Rule description | `Powershell process created an executable file in Windows root folder` |
| Agent name | `win-endpoint` |
| Sysmon channel | `Microsoft-Windows-Sysmon/Operational` |
| Sysmon event ID | `11` |
| Event type | File created |

## Key Event Fields

Observed fields from Wazuh event details:

```text
agent.name: win-endpoint
agent.ip: 10.10.10.20
data.win.system.channel: Microsoft-Windows-Sysmon/Operational
data.win.system.eventID: 11
data.win.eventdata.image: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
data.win.eventdata.targetFilename: C:\Windows\SystemTemp\__PSScriptPolicyTest_*.ps1
data.win.eventdata.user: NT AUTHORITY\SYSTEM
```

## Search Queries Used

Initial broad validation query:

```text
agent.name: "win-endpoint"
```

PowerShell-focused query:

```text
agent.name: "win-endpoint" AND powershell
```

Keyword searches that did not return direct results:

```text
agent.name: "win-endpoint" AND mimikatz
agent.name: "win-endpoint" AND "Invoke-AtomicTest"
```

## Analyst Interpretation

The alert shows `powershell.exe` creating a script file under a Windows system path. This behavior is security-relevant because PowerShell is commonly used for script execution, payload staging, and post-exploitation automation.

In this case, Microsoft Defender blocked the higher-risk Atomic Red Team test attempt, while Wazuh still captured related PowerShell file creation telemetry through Sysmon. This validates the first endpoint detection path:

```text
Windows Endpoint -> Sysmon -> Wazuh Agent -> Wazuh Threat Hunting
```

## Detection Value

This alert is useful for SOC triage because it provides:

- The endpoint where the activity occurred.
- The process responsible for file creation.
- The target file path.
- The Windows event source.
- The Wazuh rule ID and severity.

It also shows why surrounding-event review is important. A file creation alert alone does not prove malicious execution, but it gives analysts a pivot point for process creation, Defender, parent process, and nearby timeline analysis.

## Recommended Follow-up

- Review nearby Sysmon Event ID 1 process creation events.
- Check the full PowerShell command line if available.
- Review Windows Defender protection history for blocked content.
- Confirm whether the created file was executed.
- Search for additional PowerShell, script, or encoded command activity.
- If malicious behavior is confirmed, isolate the endpoint and collect forensic evidence.

## Status

Validated:

- Sysmon telemetry is being generated on `win-endpoint`.
- Wazuh Agent is forwarding endpoint events.
- Wazuh Threat Hunting displays PowerShell-related Sysmon alerts.

Needs follow-up:

- Add Windows Defender Operational log collection to Wazuh if Defender alerts should be centrally searchable.
- Capture and link a sanitized screenshot of the Wazuh alert.
- Review surrounding documents for process creation context.
