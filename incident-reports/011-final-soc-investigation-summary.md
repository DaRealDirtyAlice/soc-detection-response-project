# Case 011 - Final SOC Investigation Summary

## Objective

Summarize the completed SOC Detection Response Project as an end-to-end analyst workflow. This final case consolidates the project architecture, telemetry sources, detection cases, response workflow, tuning decisions, dashboard reporting, and lessons learned.

## Project Environment

The project uses three VMware virtual machines to simulate a small SOC environment.

| Machine | Role | Project IP | Purpose |
|---|---|---|---|
| `wazuh-server` | Wazuh Manager / Indexer / Dashboard | `10.10.10.10` | Central SIEM/XDR platform for alert collection, indexing, investigation, and reporting |
| `network-sensor` | Suricata gateway and network sensor | `10.10.10.1` | Captures network telemetry and forwards Suricata EVE JSON alerts into Wazuh |
| `win-endpoint` | Windows endpoint | `10.10.10.20` | Generates endpoint telemetry through Sysmon, Windows Defender, Wazuh Agent, and Atomic Red Team tests |

## Architecture Evidence

![SOC Detection Response Project architecture](../architecture/soc-detection-response-project-architecture.png)

## Detection Coverage

| Area | Tools / Data Sources | Validated Outcome |
|---|---|---|
| Endpoint telemetry | Sysmon, Windows Defender, Wazuh Agent | PowerShell execution, file creation, suspicious file drop, Defender activity, and custom Wazuh rule alerts were collected in Wazuh |
| Network telemetry | Suricata, EVE JSON, Wazuh Agent | Suricata alerts were forwarded from `network-sensor` into Wazuh and validated through controlled test traffic |
| Attack simulation | Atomic Red Team and controlled PowerShell tests | ATT&CK-mapped PowerShell activity was generated and reviewed in Wazuh |
| Custom detection | Wazuh local rule `100101` | PowerShell `ExecutionPolicy Bypass` behavior was detected with a custom level 10 rule |
| Manual response | Windows PowerShell and Wazuh investigation views | Suspicious artifact validation and cleanup were documented |
| Alert quality review | Wazuh Threat Hunting, Sysmon, Suricata | Expected low-priority network telemetry was separated from suspicious endpoint behavior |
| Reporting | Wazuh Threat Hunting dashboards | Endpoint, network, and custom detection views were summarized for SOC reporting |

## Completed Case Summary

| Case | Focus | Result |
|---|---|---|
| 001 | PowerShell file creation | Endpoint telemetry validated through Sysmon and Wazuh |
| 002 | PowerShell spawned instance and suspicious file drop | Sysmon event chain and Wazuh alerting validated |
| 003 | Network sensor Suricata telemetry | Suricata EVE JSON ingestion into Wazuh validated |
| 004 | Controlled Suricata alert | IDS alert generation from Windows endpoint traffic validated |
| 005 | Endpoint and network telemetry correlation | Endpoint and network evidence compared in a single timeline |
| 006 | SOC triage runbook | Analyst workflow for endpoint and network alerts documented |
| 007 | Custom Wazuh rule | Rule `100101` for PowerShell `ExecutionPolicy Bypass` created and validated |
| 008 | Manual response workflow | Suspicious PowerShell artifact review and cleanup documented |
| 009 | False positive review and tuning notes | Expected network telemetry was separated from suspicious endpoint behavior |
| 010 | SOC dashboard and reporting pack | Wazuh dashboard views summarized for reporting |

## End-to-End SOC Workflow

1. Built a segmented VMware environment with a Wazuh server, network sensor, and Windows endpoint.
2. Installed endpoint and network telemetry tools.
3. Validated agent connectivity and log ingestion into Wazuh.
4. Generated controlled endpoint and network activity.
5. Investigated alerts in Wazuh Threat Hunting.
6. Correlated endpoint and network evidence where applicable.
7. Created and validated a custom Wazuh detection rule.
8. Performed a manual response workflow for suspicious PowerShell activity.
9. Reviewed alert quality and documented tuning decisions.
10. Created a dashboard-based SOC reporting pack.

## Key Evidence

### Endpoint Dashboard

![Wazuh endpoint dashboard overview](../screenshots/wazuh-case010-endpoint-dashboard-overview.png)

### Network Sensor Dashboard

![Wazuh network sensor dashboard overview](../screenshots/wazuh-case010-network-sensor-dashboard-overview.png)

### Custom Detection Rule

![Wazuh custom rule dashboard drilldown](../screenshots/wazuh-case010-custom-rule-dashboard-drilldown.png)

## Key Findings

- Wazuh successfully centralized telemetry from both Windows endpoint and network sensor sources.
- Sysmon provided useful process, file creation, parent process, and command-line context for endpoint investigation.
- Suricata provided network alert visibility through `/var/log/suricata/eve.json`.
- Custom Wazuh rules improved detection explainability and made the project stronger than a default-rule-only setup.
- Manual response documentation made the workflow closer to a real SOC investigation cycle.
- Dashboard summaries helped translate raw alerts into a portfolio-ready reporting view.

## Lessons Learned

- Endpoint detections are easier to investigate when command line, parent process, image path, user, and event ID fields are available.
- Network alerts need context. Not every Suricata alert requires escalation, but network telemetry is useful for correlation.
- Custom rules should be tested with controlled commands before being treated as reliable detections.
- A strong SOC project should include triage, validation, response, tuning, and reporting, not only screenshots of alerts.
- Documentation quality matters because the final report is what makes the technical work understandable to reviewers and interviewers.

## Future Improvements

- Add additional Atomic Red Team tests for persistence, credential access, and defense evasion.
- Create more custom Wazuh rules for suspicious PowerShell, registry persistence, and scheduled task activity.
- Build a dashboard focused only on high-priority detections.
- Add a response playbook for each common alert category.
- Document severity tuning decisions for noisy or expected alerts.
- Add a short executive summary for non-technical readers.

## Portfolio Summary

This project demonstrates a practical junior SOC analyst workflow:

- Building a small detection environment
- Collecting host and network telemetry
- Running controlled ATT&CK-mapped activity
- Investigating Wazuh alerts
- Creating custom detection logic
- Performing basic response validation
- Reviewing false positives
- Producing SOC-style documentation and reporting

## Outcome

Case 011 completes the first full version of the SOC Detection Response Project. The project now has a complete detection and response narrative from environment buildout through detection, investigation, response, tuning, and reporting.
