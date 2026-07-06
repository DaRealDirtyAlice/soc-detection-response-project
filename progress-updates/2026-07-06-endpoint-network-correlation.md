# 2026-07-06 Endpoint and Network Correlation

## Summary

This update documents the first endpoint-plus-network correlation milestone in the SOC Detection Response Project. Endpoint alerts from `win-endpoint` and Suricata alerts from `network-sensor` were reviewed in the same Wazuh Threat Hunting time window.

## Detection Case Added

- [005 - Endpoint and Network Telemetry Correlation](../incident-reports/005-endpoint-network-telemetry-correlation.md)

## Key Results

The investigation window showed endpoint and network alerts within the same second:

| Time | Agent | Rule ID | Description |
|---|---|---:|---|
| Jul 6, 2026 @ 11:16:22.278 | `win-endpoint` | `92027` | `Powershell process spawned powershell instance` |
| Jul 6, 2026 @ 11:16:22.279 | `win-endpoint` | `92213` | `Executable file dropped in folder commonly used by malware` |
| Jul 6, 2026 @ 11:16:22.994 | `network-sensor` | `86601` | `Suricata: Alert - GPL ATTACK_RESPONSE id check returned root` |

## Validated Correlation View

```text
Windows Endpoint alert evidence
        +
Network Sensor IDS evidence
        =
Shared SOC investigation timeline in Wazuh
```

## Why This Matters

This is the first project milestone where endpoint and network telemetry are reviewed together rather than as separate validation cases. It demonstrates a more realistic SOC workflow: identify host-side behavior, pivot to the network sensor, and compare alerts in the same time window.

This update also highlighted a practical lesson: broad agent-based searches and rule ID pivots were more reliable than overly specific keyword searches. For this project, `rule.id` searches are now preferred for repeatable triage.

## Next Steps

- Enrich Case 005 with Document Details for the endpoint PowerShell event.
- Enrich Case 005 with Document Details for the Suricata alert.
- Add a triage runbook for endpoint and network correlation.
- Begin documenting custom Wazuh rule or tuning work.
