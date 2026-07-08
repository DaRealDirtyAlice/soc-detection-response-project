# 2026-07-08 - Custom Wazuh Rule Validation

## Summary

Validated the first custom Wazuh detection rule in the SOC Detection Response Project.

The rule detects PowerShell process creation where the command line includes `ExecutionPolicy Bypass`. This expands the project from default alert validation into detection tuning.

## Completed

- Added custom Wazuh rule `100101`.
- Mapped the detection to MITRE ATT&CK `T1059.001 - PowerShell`.
- Tested the rule with controlled PowerShell execution on `win-endpoint`.
- Confirmed that Wazuh Threat Hunting displayed the custom alert.
- Captured event-list and Document Details screenshots.
- Documented the case as Case 007.

## Evidence

- [Case 007 report](../incident-reports/007-custom-wazuh-rule-powershell-executionpolicy-bypass.md)
- [Custom Wazuh rule](../detections/wazuh-rules/100101-powershell-executionpolicy-bypass.xml)
- [Event list screenshot](../screenshots/wazuh-case007-custom-rule-events.png)
- [Document details screenshot](../screenshots/wazuh-case007-custom-rule-document-details.png)

## Status

Case 007 is validated.

Next recommended step: build a response workflow case that documents what a SOC analyst should do after a suspicious endpoint alert is confirmed.
