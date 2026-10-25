# Windows Security & PowerShell Log Investigation

A portfolio-style SOC Analyst L1 project for triaging Windows Security and PowerShell logs with Python and Splunk SPL.

> **Dataset note:** The included CSV is a small training dataset. Findings are indicators for analyst review, not proof of compromise. Validate alerts against original endpoint telemetry, user context, and approved baselines before making incident declarations.

## Objectives
- Triage Windows logon events (`4624`, `4625`, `4634`) and process creation (`4688`).
- Identify repeated failed logons and a subsequent successful logon from the same source.
- Flag PowerShell command-line patterns that merit review, such as encoded commands, hidden windows, and remote script download/execute patterns.
- Generate reproducible CSV findings and a Markdown summary.
- Provide ready-to-adapt Splunk SPL searches.

## Repository layout
```text
windows-security-powershell-investigation/
├── data/raw/       # Source training CSV
├── docs/            # Methodology and field notes
├── reports/         # Generated findings and summary
├── splunk/          # SPL searches and detection ideas
├── src/             # Python triage script
├── tests/           # Lightweight validation tests
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements
- Python 3.9+
- No third-party Python packages required
- Splunk Enterprise or Splunk Cloud for the SPL searches (optional)

## Run locally
```bash
python3 src/analyze_logs.py \
  --input data/raw/windows_security_powershell_logs.csv \
  --output-dir reports
```

Outputs:
- `reports/findings.csv`
- `reports/summary.md`

Validate the dataset structure:
```bash
python3 -m unittest discover -s tests -v
```

## Load the CSV into Splunk
1. In Splunk, select **Add Data → Upload** and choose `data/raw/windows_security_powershell_logs.csv`.
2. Use a dedicated index such as `windows_investigation` if you have permission to create one.
3. Confirm field names and timestamp parsing. The CSV timestamp is UTC in ISO-8601 format.
4. Run queries from `splunk/queries.spl`, adjusting `index=windows_investigation` to your actual index and field extractions.

## Initial investigation questions
1. Which accounts and source IPs produced repeated failed logons?
2. Did a successful logon follow a burst of failures from the same source?
3. Which PowerShell command lines use encoded-command, hidden-window, or remote-download patterns?
4. Which process executions on servers warrant analyst context checks?
5. What additional evidence would be needed before classifying an event as malicious?

## Detection caveats
- Thresholds are intentionally simple and need tuning to environment baselines.
- `powershell.exe`, `net.exe`, `reg.exe`, and `-ExecutionPolicy Bypass` can appear in legitimate administration.
- A pattern match is not a verdict. Correlate with parent process, user role, script-block logs, network telemetry, endpoint alerts, and change tickets.
- The sample CSV is dated 2024-03-04; use an appropriate time range in Splunk.

## Evidence handling
Preserve the original input, record its SHA-256 hash, work on copies, document UTC timestamps, and avoid claiming attribution without corroboration.
