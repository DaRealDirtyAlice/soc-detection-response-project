# 2026-07-10 - False Positive Review and Detection Tuning

## Summary

Documented Case 009 for false positive review and detection tuning. This update focuses on alert quality rather than only alert generation.

## Completed

- Reviewed a Suricata `ET INFO Microsoft Connection Test` alert from `network-sensor`.
- Confirmed that the event shows outbound HTTP visibility from `10.10.10.20` to `www.msftconnecttest.com`.
- Classified the Microsoft Connection Test alert as expected Windows connectivity behavior.
- Reviewed the custom Wazuh PowerShell rule `100101` from `win-endpoint`.
- Confirmed the rule detects PowerShell launched with `ExecutionPolicy Bypass`.
- Documented why the PowerShell alert should remain enabled while the Microsoft Connection Test alert can be treated as low-priority telemetry.

## Evidence Added

### Network Sensor - Microsoft Connection Test

![Network Microsoft Connection Test alert fields](../screenshots/wazuh-case009-network-microsoft-connection-alert-fields.png)

![Network Microsoft Connection Test flow fields](../screenshots/wazuh-case009-network-microsoft-connection-flow-fields.png)

![Network Microsoft Connection Test rule fields](../screenshots/wazuh-case009-network-microsoft-connection-rule-fields.png)

### Endpoint - Custom PowerShell Detection

![Endpoint custom PowerShell command line](../screenshots/wazuh-case009-endpoint-custom-powershell-commandline.png)

![Endpoint custom PowerShell process fields](../screenshots/wazuh-case009-endpoint-custom-powershell-process-fields.png)

![Endpoint custom PowerShell rule fields](../screenshots/wazuh-case009-endpoint-custom-powershell-rule-fields.png)

## Result

The project now includes an alert-quality review case. This shows the difference between:

- Low-priority expected network telemetry
- Suspicious endpoint behavior that requires triage
- Practical tuning decisions that reduce noise without hiding useful detections

## Related Case

- [Case 009 - False Positive Review and Detection Tuning Notes](../incident-reports/009-false-positive-review-and-detection-tuning-notes.md)
