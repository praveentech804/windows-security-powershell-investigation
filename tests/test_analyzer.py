import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "src" / "analyze_logs.py"
FIELDS = ["timestamp_utc", "host", "user", "event_id", "log_channel",
          "source_ip", "process_name", "command_line", "outcome", "details"]

class AnalyzerTests(unittest.TestCase):
    def test_repeated_failures_and_success(self):
        rows = [
            ["2024-01-01T10:00:00Z","SRV-1","admin","4625","Security","192.0.2.5","","","failure","bad password"],
            ["2024-01-01T10:01:00Z","SRV-1","admin","4625","Security","192.0.2.5","","","failure","bad password"],
            ["2024-01-01T10:02:00Z","SRV-1","admin","4625","Security","192.0.2.5","","","failure","bad password"],
            ["2024-01-01T10:03:00Z","SRV-1","admin","4624","Security","192.0.2.5","","","success","network logon"],
        ]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            input_csv = td / "input.csv"
            output = td / "out"
            with input_csv.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f); w.writerow(FIELDS); w.writerows(rows)
            subprocess.run([sys.executable, str(SCRIPT), "--input", str(input_csv),
                            "--output-dir", str(output)], check=True, capture_output=True, text=True)
            with (output / "findings.csv").open(newline="", encoding="utf-8") as f:
                findings = list(csv.DictReader(f))
            rules = {row["rule_id"] for row in findings}
            self.assertIn("REPEATED-FAILED-LOGONS", rules)
            self.assertIn("FAILURES-THEN-SUCCESS", rules)

    def test_encoded_powershell_pattern(self):
        row = ["2024-01-01T10:00:00Z","SRV-1","admin","","PowerShell","","powershell.exe",
               "powershell.exe -EncodedCommand AAAA","success","script block"]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td); input_csv = td / "input.csv"; output = td / "out"
            with input_csv.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f); w.writerow(FIELDS); w.writerow(row)
            subprocess.run([sys.executable, str(SCRIPT), "--input", str(input_csv),
                            "--output-dir", str(output)], check=True, capture_output=True, text=True)
            with (output / "findings.csv").open(newline="", encoding="utf-8") as f:
                findings = list(csv.DictReader(f))
            self.assertTrue(any(x["rule_id"] == "PS-ENCODED-COMMAND" for x in findings))

if __name__ == "__main__":
    unittest.main()
