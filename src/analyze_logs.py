#!/usr/bin/env python3
"""Defensive triage of Windows Security and PowerShell CSV logs."""
from __future__ import annotations
import argparse
import csv
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED = {
    "timestamp_utc", "host", "user", "event_id", "log_channel",
    "source_ip", "process_name", "command_line", "outcome", "details"
}

def parse_time(value: str):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def read_rows(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
        rows = []
        for row in reader:
            row["_dt"] = parse_time(row.get("timestamp_utc", ""))
            rows.append(row)
        return rows

def analyze(rows):
    findings = []
    failures = defaultdict(list)
    for row in rows:
        eid = (row.get("event_id") or "").strip()
        channel = (row.get("log_channel") or "").lower()
        command = (row.get("command_line") or "").lower()
        source_ip = (row.get("source_ip") or "").strip()
        user = (row.get("user") or "").strip()
        host = (row.get("host") or "").strip()
        dt = row.get("_dt")

        if eid == "4625" and source_ip and dt:
            failures[(source_ip, user, host)].append(dt)

        if channel == "powershell" or "powershell" in (row.get("process_name") or "").lower():
            patterns = [
                ("PS-ENCODED-COMMAND", "-encodedcommand" in command or " -enc " in command,
                 "PowerShell encoded-command pattern"),
                ("PS-HIDDEN-WINDOW", "-windowstyle hidden" in command or "-w hidden" in command,
                 "PowerShell hidden-window pattern"),
                ("PS-REMOTE-DOWNLOAD-EXEC", "downloadstring" in command or "downloadfile" in command,
                 "PowerShell remote-download/execute pattern"),
                ("PS-EXECUTION-POLICY-BYPASS", "-executionpolicy bypass" in command,
                 "PowerShell execution-policy bypass option"),
                ("PS-IEX", "iex " in command or "invoke-expression" in command,
                 "PowerShell expression-evaluation pattern"),
            ]
            for rule_id, matched, description in patterns:
                if matched:
                    findings.append(make_finding(row, rule_id, "HIGH" if rule_id in {
                        "PS-ENCODED-COMMAND", "PS-REMOTE-DOWNLOAD-EXEC"
                    } else "MEDIUM", description,
                    "Review script-block content, parent process, destination, user authorization, and endpoint/network telemetry."))

        if eid == "4688":
            pname = (row.get("process_name") or "").lower()
            if pname in {"net.exe", "net1.exe", "reg.exe"}:
                findings.append(make_finding(row, "ADMIN-UTILITY-EXECUTION", "LOW",
                    f"Administrative utility executed: {pname}",
                    "Validate the command, account role, change ticket, and parent process; these tools are commonly legitimate."))
            if " -executionpolicy bypass" in command:
                findings.append(make_finding(row, "PROCESS-EXECUTION-POLICY-BYPASS", "MEDIUM",
                    "Process command line contains ExecutionPolicy Bypass",
                    "Determine why policy bypass was used and correlate with PowerShell script-block and endpoint logs."))

    # Repeated failures: >= 3 for same source/user/host within any 10-minute window.
    for (ip, user, host), times in failures.items():
        times.sort()
        left = 0
        for right, current in enumerate(times):
            while current - times[left] > timedelta(minutes=10):
                left += 1
            count = right - left + 1
            if count >= 3:
                matching = [r for r in rows if r.get("source_ip") == ip and
                            r.get("user") == user and r.get("host") == host and
                            (r.get("event_id") or "").strip() == "4625" and
                            r.get("_dt") and current - timedelta(minutes=10) <= r["_dt"] <= current]
                if matching:
                    findings.append(make_finding(matching[-1], "REPEATED-FAILED-LOGONS", "MEDIUM",
                        f"{count} failed logons from {ip} for {user} on {host} within 10 minutes",
                        "Check whether the failures are expected; correlate with successful logons, source ownership, and account lockout policy."))
                break

    # Same source + user: successful logon within 10 minutes after multiple failures.
    groups = defaultdict(list)
    for row in rows:
        if row.get("_dt") and row.get("source_ip") and row.get("user"):
            groups[(row["source_ip"], row["user"], row.get("host", ""))].append(row)
    for (ip, user, host), items in groups.items():
        items.sort(key=lambda r: r["_dt"])
        for idx, row in enumerate(items):
            if (row.get("event_id") or "").strip() != "4624":
                continue
            prior = [x for x in items[:idx] if (x.get("event_id") or "").strip() == "4625"
                     and timedelta(0) <= row["_dt"] - x["_dt"] <= timedelta(minutes=10)]
            if len(prior) >= 3:
                findings.append(make_finding(row, "FAILURES-THEN-SUCCESS", "HIGH",
                    f"Successful logon followed {len(prior)} failed logons from {ip} for {user}",
                    "Validate the identity and source, review authentication type and surrounding events, and confirm whether the success was authorized."))
                break

    # Deduplicate identical rule/event combinations.
    unique = {}
    for f in findings:
        key = (f["rule_id"], f["timestamp_utc"], f["host"], f["user"], f["source_ip"], f["command_line"])
        unique[key] = f
    return sorted(unique.values(), key=lambda f: (f["timestamp_utc"], f["severity"], f["rule_id"]))

def make_finding(row, rule_id, severity, title, recommendation):
    return {
        "timestamp_utc": row.get("timestamp_utc", ""),
        "severity": severity,
        "rule_id": rule_id,
        "title": title,
        "host": row.get("host", ""),
        "user": row.get("user", ""),
        "source_ip": row.get("source_ip", ""),
        "event_id": row.get("event_id", ""),
        "process_name": row.get("process_name", ""),
        "command_line": row.get("command_line", ""),
        "recommendation": recommendation,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Input CSV path")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory for generated reports")
    args = parser.parse_args()
    rows = read_rows(args.input)
    findings = analyze(rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    output_csv = args.output_dir / "findings.csv"
    fields = ["timestamp_utc", "severity", "rule_id", "title", "host", "user", "source_ip",
              "event_id", "process_name", "command_line", "recommendation"]
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)

    event_counts = Counter((r.get("event_id") or "(blank)") for r in rows)
    severity_counts = Counter(f["severity"] for f in findings)
    rule_counts = Counter(f["rule_id"] for f in findings)
    first = min((r["_dt"] for r in rows if r["_dt"]), default=None)
    last = max((r["_dt"] for r in rows if r["_dt"]), default=None)
    summary = [
        "# Windows Security & PowerShell Triage Summary", "",
        "> Training dataset triage only. Alerts are leads for validation, not proof of compromise.", "",
        "## Dataset integrity", "",
        f"- Input file: `{args.input.name}`",
        f"- SHA-256: `{sha256_file(args.input)}`",
        f"- Rows analyzed: **{len(rows)}**",
        f"- Valid UTC timestamps: **{sum(1 for r in rows if r['_dt'])}**",
        f"- Time span (UTC): **{first.isoformat() if first else 'unknown'}** to **{last.isoformat() if last else 'unknown'}**", "",
        "## Event ID counts", ""
    ]
    summary += [f"- `{eid}`: {count}" for eid, count in sorted(event_counts.items())]
    summary += ["", "## Generated finding counts", ""]
    summary += [f"- {sev}: {count}" for sev, count in sorted(severity_counts.items())] or ["- No rules matched."]
    summary += ["", "## Rule counts", ""]
    summary += [f"- `{rule}`: {count}" for rule, count in sorted(rule_counts.items())] or ["- No rules matched."]
    summary += ["", "## Analyst interpretation", "",
        "- Prioritize PowerShell encoded-command and remote-download patterns for contextual review.",
        "- Correlate repeated failed logons followed by success with identity, endpoint, and network evidence.",
        "- Administrative utilities and policy-bypass options can be legitimate; do not classify them as malicious based on a name or flag alone.",
        "- The source CSV is a training sample and does not include all fields needed for definitive attribution or incident confirmation.", "",
        "## Output", "", "- Detailed rows: `findings.csv`", ""]
    (args.output_dir / "summary.md").write_text("\n".join(summary), encoding="utf-8")
    print(f"Rows analyzed: {len(rows)}")
    print(f"Findings generated: {len(findings)}")
    print(f"CSV report: {output_csv}")
    print(f"Summary: {args.output_dir / 'summary.md'}")

if __name__ == "__main__":
    main()
