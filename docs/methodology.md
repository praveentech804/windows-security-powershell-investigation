# Methodology and Field Notes

## Event identifiers represented in the sample
- `4624`: successful logon
- `4625`: failed logon
- `4634`: logoff
- `4688`: process creation

These event IDs are interpreted in the context of the supplied CSV's normalized fields. Production Windows event XML may include additional useful fields (logon type, process ID, parent process, status/substatus, token elevation, and more).

## Detection logic
- Repeated failures: at least 3 failures from the same source IP/account/host within 10 minutes.
- Failures followed by success: at least 3 failures from the same source IP/account/host in the 10 minutes preceding a successful logon.
- PowerShell command patterns: encoded command, hidden window, remote download methods, execution-policy bypass, and expression evaluation.
- Administrative utilities: `net.exe`, `net1.exe`, and `reg.exe` are surfaced at low severity for context review.

## Severity is triage priority, not confidence
Severity communicates a starting priority. It does not mean an event is confirmed malicious. Tune thresholds against a known-good baseline and organizational policies.

## Evidence gaps to close
- Original Windows Event XML and event record IDs
- Logon type and authentication package
- Process ID, parent process, signer/hash, and process tree
- PowerShell Operational 4103/4104 records where enabled
- DNS, proxy, firewall, and endpoint network telemetry
- Asset criticality, account owner, approved admin activity, and change records
