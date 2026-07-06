# 2026-07-06 Controlled Suricata Alert Validation

## Summary

This update documents a controlled Suricata alert validation milestone in the SOC Detection Response Project. A known IDS test request from the Windows Endpoint triggered a Suricata alert on the Network Sensor, and the alert was reviewed in Wazuh Threat Hunting.

## Detection Case Added

- [004 - Controlled Suricata Alert Validation](../incident-reports/004-controlled-suricata-alert-validation.md)

## Key Results

The controlled HTTP test produced a Suricata alert in Wazuh:

| Field | Value |
|---|---|
| Agent name | `network-sensor` |
| Agent ID | `002` |
| Source log | `/var/log/suricata/eve.json` |
| Signature | `GPL ATTACK_RESPONSE id check returned root` |
| App protocol | `http` |
| Transport protocol | `TCP` |
| Direction | `to_client` |
| Windows Endpoint IP | `10.10.10.20` |
| Wazuh rule ID | `86601` |

## Validated Alert Path

```text
Windows Endpoint -> Network Sensor -> Suricata -> Wazuh Agent -> Wazuh Manager -> Wazuh Threat Hunting
```

## Why This Matters

This case is stronger than general background network telemetry because it uses a controlled test that produced a predictable IDS signature. It confirms that the Network Sensor is not only forwarding low-level network events, but can also generate recognizable Suricata alerts that are usable for SOC-style triage.

The alert also demonstrated an important analysis detail: packet direction and flow direction may not look the same. The signature triggered on server-to-client HTTP response traffic, so the remote server appeared as `data.src_ip`, while the Windows Endpoint appeared as `data.dest_ip`. The flow fields still showed the Windows Endpoint as the original client.

## Next Steps

- Correlate this network alert with an endpoint event from the same time window.
- Build the first endpoint-plus-network investigation case.
- Add a lightweight triage runbook for Suricata IDS alerts.
- Continue documenting field-level evidence instead of only relying on screenshots.
