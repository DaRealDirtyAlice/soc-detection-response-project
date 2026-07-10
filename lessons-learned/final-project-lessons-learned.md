# Final Project Lessons Learned

## What Worked Well

- Wazuh provided a practical central location for endpoint, network, and custom detection review.
- Sysmon gave strong endpoint context for PowerShell and file creation activity.
- Suricata provided useful network visibility through EVE JSON ingestion.
- Atomic Red Team and controlled PowerShell commands helped generate repeatable test activity.
- Custom Wazuh rule `100101` made the project more detection-focused and easier to explain.

## What Needed Adjustment

- Some Wazuh searches required broader queries first before narrowing into exact fields.
- Network alerts needed careful interpretation because some Suricata alerts were expected or low priority.
- Windows Defender and Sysmon evidence needed to be reviewed together to understand endpoint behavior.
- Screenshots were useful, but the strongest evidence came from documenting fields such as `agent.name`, `rule.id`, `rule.description`, `data.win.eventdata.commandLine`, and Suricata flow metadata.

## Analyst Takeaways

- Start broad when hunting, then narrow the search by agent, rule ID, event ID, process image, or command line.
- Treat alert severity as a starting point, not a final conclusion.
- Build timelines from multiple fields instead of relying on one alert message.
- Separate expected telemetry from suspicious behavior during tuning.
- Document investigation logic so another analyst can reproduce the finding.

## Interview-Ready Summary

I built an end-to-end SOC detection and response project using Wazuh, Sysmon, Suricata, and Atomic Red Team. I configured endpoint and network telemetry, validated log ingestion, generated controlled ATT&CK-mapped activity, investigated alerts, created a custom Wazuh detection rule, performed manual response validation, reviewed false positives, and summarized the results through SOC-style reporting.

## Future Work

- Add persistence and credential access test cases.
- Add more custom Wazuh detections.
- Create alert-specific response playbooks.
- Build a compact executive dashboard.
- Turn the final case summaries into a short portfolio presentation.
