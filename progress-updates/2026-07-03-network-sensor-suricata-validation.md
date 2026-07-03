# 2026-07-03 Network Sensor Suricata Validation

## Summary

This update documents the first network telemetry validation milestone in the SOC Detection Response Project. After validating Windows endpoint telemetry, Suricata events from `network-sensor` were confirmed in Wazuh Threat Hunting.

## Detection Case Added

- [003 - Network Sensor Suricata Telemetry Validation](../incident-reports/003-network-sensor-suricata-telemetry-validation.md)

## Key Results

Wazuh Threat Hunting showed Suricata-related events from `network-sensor`:

| Field | Value |
|---|---|
| Agent name | `network-sensor` |
| Agent ID | `002` |
| Query | `agent.name: "network-sensor" AND suricata` |
| Result count | `144` hits |
| Time range | `Jun 30, 2026 @ 12:33:43.182 - Jul 3, 2026 @ 12:44:58.886` |

Example Suricata alerts included:

- `Suricata: Alert - SURICATA STREAM FIN out of window`
- `Suricata: Alert - ET INFO Windows Update P2P Activity`
- `Suricata: Alert - ET INFO Microsoft Connection Test`

## Validated Telemetry Path

```text
Network Sensor -> Suricata -> Wazuh Agent -> Wazuh Manager -> Wazuh Threat Hunting
```

## Why This Matters

This step moves the project beyond endpoint-only telemetry. The project now has validated evidence that both endpoint telemetry and network telemetry are visible in Wazuh.

Current validated telemetry paths:

- Windows Endpoint -> Sysmon -> Wazuh Agent -> Wazuh Threat Hunting
- Windows Endpoint -> Microsoft Defender -> Wazuh Agent -> Wazuh Threat Hunting
- Network Sensor -> Suricata -> Wazuh Agent -> Wazuh Threat Hunting

## Next Steps

- Open one Suricata alert document detail view and record source IP, destination IP, protocol, signature, and category.
- Generate controlled network activity from `win-endpoint`.
- Correlate endpoint and network telemetry in the same time window.
- Document the first endpoint-plus-network investigation case.
