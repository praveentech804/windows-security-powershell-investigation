# Investigation Methodology

## Scope
This project uses Splunk Enterprise and SPL to investigate a Windows
Security and PowerShell-related training dataset.

## Steps
1. Confirm the selected index and time range.
2. Review event ID counts to understand the dataset.
3. Inspect failed logons (4625) and successful logons (4624).
4. Review process creation events (4688).
5. Search command-line fields for potentially suspicious patterns.
6. Build a chronological timeline from the available events.
7. Document evidence, limitations, and recommended follow-up actions.

## Interpretation
- Repeated failed logons may be caused by mistakes, misconfiguration,
  or malicious activity; investigate the surrounding context.
- Encoded commands, hidden windows, and download-related commands
  require review but are not proof of malicious execution by themselves.
- Administrative utilities can be used for legitimate administration.
- Validate timestamps, field extraction, host identity, and event context.

## Limitations
The available training dataset may not contain source IP, username,
parent process, or complete script-block information as searchable
fields. Do not infer missing evidence. Confirm field availability in
Splunk before using it for attribution.

This methodology describes a manual Splunk investigation workflow.
