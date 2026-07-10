# Case 010 - SOC Dashboard and Reporting Pack

## Objective

Create an analyst-ready reporting pack that summarizes endpoint telemetry, network sensor telemetry, and validated custom detection coverage in Wazuh.

## Scope

- Wazuh Threat Hunting dashboard
- `win-endpoint` endpoint telemetry
- `network-sensor` Suricata and host telemetry
- Custom Wazuh rule `100101`

## Evidence

### Endpoint Dashboard Overview

![Wazuh endpoint dashboard overview](../screenshots/wazuh-case010-endpoint-dashboard-overview.png)

### Network Sensor Dashboard Overview

![Wazuh network sensor dashboard overview](../screenshots/wazuh-case010-network-sensor-dashboard-overview.png)

### Custom Rule Drilldown

![Wazuh custom rule dashboard drilldown](../screenshots/wazuh-case010-custom-rule-dashboard-drilldown.png)

## Dashboard Summary

| View | Key Metrics | Analyst Interpretation |
|---|---|---|
| `win-endpoint` | 2,428 total alerts, 71 level 12 or above alerts, 0 authentication failures, 6 authentication successes | Endpoint telemetry is active and searchable. High-severity alerts are available for triage and reporting. |
| `network-sensor` | 2,207 total alerts, 51 level 12 or above alerts, 5 authentication failures, 34 authentication successes | Network sensor telemetry is active and includes IDS, Suricata, and host-level events. |
| Custom rule `100101` | 1 matching alert for PowerShell `ExecutionPolicy Bypass`, rule level 10 | The custom Wazuh rule can be tracked from a dashboard view into a single detection record. |

## SOC Reporting Notes

- The endpoint dashboard supports host-based alert review across Sysmon, Windows, and custom Wazuh detections.
- The network sensor dashboard supports review of Suricata and IDS alert volume.
- The custom rule drilldown shows the path from a dashboard count to one specific detection record.
- This reporting pack separates overall telemetry health from high-signal detections that require analyst review.

## Suggested SOC Summary

- Current visibility: endpoint and network telemetry are both active in Wazuh.
- Notable endpoint detection: custom rule `100101` detected PowerShell execution with `ExecutionPolicy Bypass`.
- Network visibility: the `network-sensor` agent is reporting Suricata and IDS telemetry to Wazuh.
- Priority: review level 10+ endpoint detections first, then correlate with network sensor events when the timeline overlaps.
- Tuning note: expected low-priority network telemetry should be separated from actionable endpoint detections.

## Useful Queries

```text
agent.name: "win-endpoint"
agent.name: "network-sensor"
rule.level >= 10
rule.id:100101
agent.name: "network-sensor" AND suricata
agent.name: "win-endpoint" AND powershell
```

## Outcome

Case 010 is complete. The project now includes a SOC dashboard and reporting pack that can be used to summarize telemetry coverage and validated detection outcomes.
