# Windows Security Log Investigation with Splunk

## Project Overview
A beginner SOC analyst project focused on investigating Windows Security
and PowerShell-related log events using Splunk Enterprise and SPL.

## Tools Used
- Splunk Enterprise
- Search & Reporting
- Search Processing Language (SPL)
- Windows Security and PowerShell training logs

## Investigation Objectives
1. Review Windows authentication events.
2. Identify repeated failed logon events.
3. Review successful logons and build an event timeline.
4. Search process-creation events for suspicious PowerShell patterns.
5. Review administrative utility execution.
6. Document observations and recommended follow-up checks.

## Project Workflow
1. Load the training CSV into Splunk.
2. Confirm the index, time range, and available fields.
3. Run and refine the SPL searches in `splunk/queries.spl`.
4. Review matching events in Splunk.
5. Document evidence, limitations, and investigation conclusions.

## Important Limitations
This project uses a training dataset. Search matches are investigation
leads, not proof of compromise. Findings must be validated against
the available event context.

The analysis workflow is Splunk-based. This repository does not claim
Python-based log analysis, PowerShell scripting, or automated detection.

## Repository Contents
- `data/raw/`: Training log dataset
- `docs/`: Investigation methodology
- `splunk/queries.spl`: SPL investigation queries
- `reports/`: Report documentation and analyst notes
