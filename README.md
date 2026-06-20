# SOC Detection Response Project

This project documents an open-source SOC detection and response project using **Wazuh**, **Sysmon**, **Suricata**, and **Atomic Red Team**.

The goal is to simulate a practical SOC analyst workflow: collect endpoint and network telemetry, generate controlled ATT&CK-mapped activity, triage alerts, investigate host and network artifacts, write incident reports, and tune custom Wazuh detections.

## Architecture

![SOC Detection Response Project architecture](architecture/soc-detection-response-project-architecture.png)

## Project Scope

This project focuses on an open-source detection and response workflow:

- **Wazuh** for centralized SIEM/XDR alerting and investigation
- **Sysmon** for Windows endpoint telemetry
- **Suricata** for network telemetry through EVE JSON
- **Atomic Red Team** for controlled ATT&CK-mapped test activity
- **Custom Wazuh rules** for detection tuning

This project does not include cross-SIEM rule formats. Detection work is implemented and documented as Wazuh custom rules.

## Target Project Topology

| Machine | Role | Network |
|---|---|---|
| `wazuh-server` | Wazuh Manager / Indexer / Dashboard | VMnet8 NAT + VMnet2 project network |
| `network-sensor` | Suricata gateway and network sensor | VMnet8 NAT + VMnet2 project network |
| `win-endpoint` | Windows test endpoint | VMnet2 project network only |

Planned IP layout:

| Machine | Project IP |
|---|---|
| `network-sensor` | `10.10.10.1/24` |
| `wazuh-server` | `10.10.10.10/24` |
| `win-endpoint` | `10.10.10.20/24` |

## Current Build Status

- VMware project networks created
- Ubuntu Server systems installed for Wazuh Server and Network Sensor
- Static project IPs configured on both Ubuntu servers
- Windows Endpoint installed
- Sysmon installed and producing events
- Atomic Red Team installed
- Wazuh Agent installed on Windows Endpoint

## Planned Detection Scenarios

| Scenario | Data Sources | Purpose |
|---|---|---|
| Suspicious PowerShell execution | Sysmon, Wazuh | Investigate suspicious command execution |
| Scheduled task persistence | Sysmon, Wazuh | Detect persistence behavior |
| Registry Run Key persistence | Sysmon, Wazuh | Detect registry-based persistence |
| Critical file modification | Wazuh FIM | Demonstrate integrity monitoring |
| Suspicious network activity | Suricata, Wazuh | Correlate endpoint and network evidence |

## Expected Project Outputs

- Architecture diagram
- VMware project setup notes
- Wazuh deployment notes
- Windows endpoint telemetry setup notes
- Suricata network sensor setup notes
- Atomic Red Team test records
- Custom Wazuh detection rules
- SOC-style incident reports
- Triage runbooks
- Dashboard screenshots
- Lessons learned

## Repository Structure

```text
soc-detection-response-project/
  README.md
  architecture/
  setup-guides/
  detections/
    wazuh-rules/
  atomic-tests/
  incident-reports/
  runbooks/
  dashboards/
  screenshots/
  lessons-learned/
```

## Portfolio Goal

This project is designed to demonstrate practical SOC analyst skills:

- SIEM monitoring
- Endpoint log analysis
- Network log analysis
- Alert triage
- MITRE ATT&CK mapping
- Incident timeline creation
- Response recommendation writing
- Detection tuning
- Technical documentation
