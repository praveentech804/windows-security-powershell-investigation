# Windows Security & PowerShell Triage Summary

> Training dataset triage only. Alerts are leads for validation, not proof of compromise.

## Dataset integrity

- Input file: `windows_security_powershell_logs.csv`
- SHA-256: `4716dfb6b213c2c9d045ab6005606b3c4a7ba4afe22b9bb5d6f063b19f212d68`
- Rows analyzed: **32**
- Valid UTC timestamps: **32**
- Time span (UTC): **2024-03-04T08:15:23+00:00** to **2024-03-04T17:15:33+00:00**

## Event ID counts

- `(blank)`: 4
- `4624`: 6
- `4625`: 6
- `4634`: 4
- `4688`: 12

## Generated finding counts

- HIGH: 3
- LOW: 2
- MEDIUM: 6

## Rule counts

- `ADMIN-UTILITY-EXECUTION`: 2
- `FAILURES-THEN-SUCCESS`: 1
- `PROCESS-EXECUTION-POLICY-BYPASS`: 1
- `PS-ENCODED-COMMAND`: 1
- `PS-EXECUTION-POLICY-BYPASS`: 2
- `PS-HIDDEN-WINDOW`: 1
- `PS-IEX`: 1
- `PS-REMOTE-DOWNLOAD-EXEC`: 1
- `REPEATED-FAILED-LOGONS`: 1

## Analyst interpretation

- Prioritize PowerShell encoded-command and remote-download patterns for contextual review.
- Correlate repeated failed logons followed by success with identity, endpoint, and network evidence.
- Administrative utilities and policy-bypass options can be legitimate; do not classify them as malicious based on a name or flag alone.
- The source CSV is a training sample and does not include all fields needed for definitive attribution or incident confirmation.

## Output

- Detailed rows: `findings.csv`
