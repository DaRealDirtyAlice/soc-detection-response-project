# Windows Defender Log Collection Setup

This guide documents how to forward Microsoft Defender Operational events from the Windows Endpoint into Wazuh.

## Purpose

The first endpoint detection case showed PowerShell-related Sysmon telemetry in Wazuh while Microsoft Defender blocked higher-risk Atomic Red Team activity locally. Adding Defender log collection allows prevention events to be searched in Wazuh alongside Sysmon events.

## Target System

| Field | Value |
|---|---|
| Endpoint | `win-endpoint` |
| Wazuh Agent service | `WazuhSvc` |
| Defender event channel | `Microsoft-Windows-Windows Defender/Operational` |

## Step 1 - Confirm Defender Events Exist Locally

On `win-endpoint`, open PowerShell as Administrator and run:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 10
```

If the command returns recent events, Defender Operational logging is available locally.

Optional Defender detection history check:

```powershell
Get-MpThreatDetection | Select-Object -First 10
```

## Step 2 - Edit Wazuh Agent Configuration

Open the Wazuh Agent configuration file as Administrator:

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Add the following block before the closing `</ossec_config>` tag:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Save the file.

## Step 3 - Restart Wazuh Agent

Restart the Windows Wazuh Agent:

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

Expected result:

```text
Status   Name      DisplayName
Running  WazuhSvc  Wazuh
```

## Step 4 - Verify Agent Connectivity

On `wazuh-server`, run:

```bash
sudo /var/ossec/bin/agent_control -l
```

Expected result:

```text
win-endpoint     Active
```

## Step 5 - Search Defender Events in Wazuh

In Wazuh Threat Hunting, search:

```text
agent.name: "win-endpoint" AND "Windows Defender"
```

If that is too broad or returns no results, search by event channel:

```text
agent.name: "win-endpoint" AND "Microsoft-Windows-Windows Defender/Operational"
```

Useful follow-up searches:

```text
agent.name: "win-endpoint" AND defender
agent.name: "win-endpoint" AND threat
agent.name: "win-endpoint" AND quarantined
agent.name: "win-endpoint" AND blocked
```

Set the time range to `Last 24 hours` during initial validation.

## Step 6 - Generate a Safe Defender Test Event

If no recent Defender events appear after configuration, generate a safe antivirus test event inside the isolated VM. Use the EICAR antivirus test string only for validation.

On `win-endpoint`, run PowerShell as Administrator:

```powershell
Set-Content -Path "$env:TEMP\eicar-test.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```

Microsoft Defender should detect and block or quarantine the file.

Then search Wazuh again:

```text
agent.name: "win-endpoint" AND "Windows Defender"
```

## Notes

- Do not disable Microsoft Defender for this project phase.
- Defender prevention is useful evidence and should be documented.
- Historical Defender events may not always appear in Wazuh immediately after adding the log source. Generate a new controlled event if validation is needed.
- Do not upload screenshots that expose credentials, API passwords, or unrelated personal information.
