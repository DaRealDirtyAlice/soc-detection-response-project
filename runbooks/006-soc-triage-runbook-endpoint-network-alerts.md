# 006 - SOC Triage Runbook for Endpoint and Network Alerts

## Objective

This runbook documents a repeatable SOC triage workflow for alerts generated in the SOC Detection Response Project.

The goal is to move beyond simply confirming that alerts exist. This runbook defines how to validate alert source, collect key fields, search surrounding activity, correlate endpoint and network telemetry, and write a short analyst conclusion.

## Scope

This runbook applies to alerts from:

- `win-endpoint` through Wazuh Agent, Sysmon, and Microsoft Defender event channels
- `network-sensor` through Wazuh Agent and Suricata EVE JSON
- `wazuh-server` as the central Wazuh Manager, Indexer, and Dashboard

This runbook is based on validated project cases 001 through 005.

## Lab Context

| System | Role | Project IP |
|---|---|---|
| `wazuh-server` | Wazuh Manager / Indexer / Dashboard | `10.10.10.10` |
| `network-sensor` | Suricata gateway and network sensor | `10.10.10.1` |
| `win-endpoint` | Windows monitored endpoint | `10.10.10.20` |

## When to Use This Runbook

Use this runbook when Wazuh shows one or more of the following:

- PowerShell execution alerts
- Sysmon process creation events
- Sysmon file creation events
- Microsoft Defender detection or prevention events
- Suricata IDS alerts
- Endpoint and network events occurring in the same time window

## Alert Intake Checklist

For every alert, collect these fields first:

| Field | Why It Matters |
|---|---|
| `timestamp` | Establishes the investigation timeline |
| `agent.name` | Identifies the reporting system |
| `agent.id` | Confirms the source asset in Wazuh |
| `rule.id` | Identifies the Wazuh rule that fired |
| `rule.description` | Provides the first-level alert meaning |
| `rule.level` | Supports severity review |
| `rule.groups` | Shows alert category such as `sysmon`, `windows`, or `suricata` |
| `location` | Shows the original log source |
| `decoder.name` | Confirms how Wazuh parsed the event |

## Data Source Mapping

| Data Source | Expected Evidence |
|---|---|
| Sysmon Event ID 1 | Process creation, command line, parent process, user, hashes |
| Sysmon Event ID 11 | File creation, target filename, process image, user |
| Microsoft Defender Operational log | Malware or unwanted software detection, protection action, scan activity |
| Suricata EVE JSON | Network alert signature, source and destination IPs, ports, protocol, flow data |
| Wazuh Threat Hunting | Unified search and timeline review |

## Triage Workflow

### Step 1 - Confirm the Reporting Agent

Start with the broadest reliable filter:

```text
agent.name: "win-endpoint"
```

or:

```text
agent.name: "network-sensor"
```

Avoid starting with overly specific keyword searches. Some Wazuh fields are tokenized differently, so broad searches are more reliable during the first pass.

### Step 2 - Identify the Alert Type

Use `rule.description`, `rule.groups`, and `location` to classify the alert.

Common categories in this project:

| Category | Example Rule / Evidence |
|---|---|
| PowerShell execution | `Powershell process spawned powershell instance` |
| Suspicious file creation | `Executable file dropped in folder commonly used by malware` |
| Defender prevention | `Windows Defender: Antimalware platform detected potentially unwanted software` |
| Suricata IDS alert | `Suricata: Alert - GPL ATTACK_RESPONSE id check returned root` |

### Step 3 - Collect Endpoint Fields

For endpoint alerts, collect:

| Field | Purpose |
|---|---|
| `data.win.system.eventID` | Confirms event type |
| `data.win.eventdata.image` | Identifies the executable |
| `data.win.eventdata.commandLine` | Shows exact activity |
| `data.win.eventdata.parentImage` | Shows process lineage |
| `data.win.eventdata.parentCommandLine` | Helps identify how the process started |
| `data.win.eventdata.user` | Identifies user context |
| `data.win.eventdata.processId` | Supports event correlation |
| `data.win.eventdata.processGuid` | Supports stronger process correlation |
| `data.win.eventdata.targetFilename` | Shows file artifact path |
| `data.win.eventdata.hashes` | Supports file reputation or enrichment |

Useful endpoint searches:

```text
agent.name: "win-endpoint" AND data.win.system.eventID:1
```

```text
agent.name: "win-endpoint" AND data.win.system.eventID:11
```

```text
agent.name: "win-endpoint" AND powershell
```

```text
agent.name: "win-endpoint" AND "Windows Defender"
```

### Step 4 - Collect Network Fields

For Suricata alerts, collect:

| Field | Purpose |
|---|---|
| `data.alert.signature` | Shows Suricata rule name |
| `data.alert.category` | Shows alert type |
| `data.alert.severity` | Shows Suricata severity |
| `data.src_ip` | Source IP in the event |
| `data.src_port` | Source port in the event |
| `data.dest_ip` | Destination IP in the event |
| `data.dest_port` | Destination port in the event |
| `data.flow.src_ip` | Flow source IP |
| `data.flow.dest_ip` | Flow destination IP |
| `data.proto` | Protocol |
| `data.app_proto` | Application protocol when available |
| `data.direction` | Traffic direction |
| `data.in_iface` | Sensor interface |

Useful network searches:

```text
agent.name: "network-sensor"
```

```text
agent.name: "network-sensor" AND suricata
```

```text
agent.name: "network-sensor" AND rule.id:86601
```

For controlled test traffic:

```text
agent.name: "network-sensor" AND "GPL ATTACK_RESPONSE"
```

If this exact query returns no result, use a broader search and inspect `rule.description` manually:

```text
agent.name: "network-sensor"
```

## Correlation Workflow

### Step 1 - Define the Time Window

Use the endpoint or network alert timestamp as the anchor.

Start with a small window:

```text
alert time +/- 5 minutes
```

If needed, expand to:

```text
alert time +/- 15 minutes
```

### Step 2 - Compare Asset Identity

For endpoint-to-network correlation, verify whether the endpoint IP appears in the network event.

Expected project endpoint:

```text
win-endpoint = 10.10.10.20
```

If Suricata shows `data.flow.src_ip: 10.10.10.20` or `data.dest_ip: 10.10.10.20`, the event is related to the Windows endpoint traffic path.

### Step 3 - Compare Activity Type

Use this logic:

| Endpoint Evidence | Network Evidence | Interpretation |
|---|---|---|
| PowerShell process execution | HTTP or IDS alert near same time | Possible scripted network activity |
| File created by PowerShell | External connection near same time | Possible download or test artifact creation |
| Defender detection | Suricata alert near same time | Endpoint prevention plus network evidence |
| No endpoint alert | Suricata alert only | Network-only visibility; inspect endpoint logs with broader time range |

### Step 4 - Build a Timeline

Use a short timeline format:

```text
HH:MM:SS - Source - Event summary - Key field
HH:MM:SS - Source - Event summary - Key field
HH:MM:SS - Analyst note - Correlation or gap
```

Example:

```text
11:16:22 - win-endpoint - PowerShell spawned PowerShell instance - rule.id 92027
11:16:22 - win-endpoint - Executable file dropped in malware-used folder - rule.id 92213
11:16:22 - network-sensor - Suricata GPL ATTACK_RESPONSE alert - rule.id 86601
11:17:00 - Analyst note - Endpoint and network alerts occurred in the same investigation window
```

## Severity Review

Use Wazuh rule level as the starting point, but do not rely on it alone.

| Severity | Criteria |
|---|---|
| Low | Known benign traffic, expected lab activity, isolated informational event |
| Medium | Suspicious behavior without confirmed malicious outcome |
| High | Confirmed suspicious execution, suspicious file creation, Defender detection, repeated IDS alerts |
| Critical | Confirmed compromise, credential theft, lateral movement, command and control, or data exfiltration |

## Response Decision Guide

| Situation | Recommended Response |
|---|---|
| Known controlled test | Document evidence and mark as expected lab activity |
| Suspicious endpoint-only alert | Review command line, parent process, user, and file artifacts |
| Suspicious network-only alert | Review flow fields, destination, protocol, and related endpoint events |
| Endpoint and network alerts align | Treat as higher confidence and write a correlation timeline |
| Defender prevention confirmed | Document Defender action and verify whether execution was blocked |
| Unclear or repeated suspicious activity | Preserve evidence, expand search window, and escalate for deeper review |

## False Positive Considerations

Common false positive or expected activity in this project:

- `testmyids.com` traffic is intentional controlled IDS test traffic
- Windows Update peer-to-peer activity can generate Suricata informational alerts
- Microsoft connection tests can appear during normal Windows network checks
- DNS-over-HTTPS alerts may be normal browser or system behavior
- Suricata stream alerts can be noisy unless repeated or paired with other suspicious activity

## Evidence Package Checklist

Each completed investigation should include:

- Alert screenshot from Wazuh
- Agent name and agent ID
- Rule ID and rule description
- Timestamp and time range
- Relevant endpoint fields
- Relevant network fields
- Timeline
- Analyst assessment
- Recommended response
- Known limitations or next steps

## Analyst Report Template

```text
Case ID:
Alert Name:
Primary Data Source:
Affected Asset:
Time Range:

Summary:

Key Evidence:
- 
- 
- 

Timeline:
- 
- 
- 

Assessment:

Response Recommendation:

Limitations:
```

## Current Validation Status

This runbook is based on completed project evidence from:

- Case 001: PowerShell file creation and Defender evidence
- Case 002: PowerShell spawned instance and suspicious file drop
- Case 003: Suricata telemetry visibility
- Case 004: Controlled Suricata IDS alert validation
- Case 005: Endpoint and network telemetry correlation

## Next Improvements

- Add a custom Wazuh rule for one selected PowerShell behavior
- Add a custom Suricata test note with exact rule signature and flow fields
- Create a final response workflow that includes containment, evidence preservation, and post-incident documentation
- Add a short lessons-learned note after each completed case
