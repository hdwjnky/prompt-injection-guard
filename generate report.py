"""
Security Log Report Generator
------------------------------
Parses security_log.txt (written by prompt_injection_guard.py) and
produces a summary report: how many attempts were blocked vs sanitized,
broken down by risk level and by category, plus an optional CSV export
for spreadsheets or a portfolio writeup.

Usage:
    python generate_report.py
    python generate_report.py --log path/to/security_log.txt
    python generate_report.py --csv report.csv
"""

import argparse
import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class LogEntry:
    timestamp: str = ""
    event_type: str = ""
    risk_level: str = ""
    score: int = 0
    categories: list = field(default_factory=list)
    user_input: str = ""


def parse_log(log_path: str) -> list:
    """Parse security_log.txt into a list of LogEntry objects."""
    entries = []
    current = None

    with open(log_path, "r") as file:
        for line in file:
            line = line.rstrip("\n")

            if line.startswith("[") and line.endswith("]"):
                if current is not None:
                    entries.append(current)
                current = LogEntry(timestamp=line.strip("[]"))
            elif current is None:
                continue
            elif line.startswith("Type:"):
                current.event_type = line.split("Type:", 1)[1].strip()
            elif line.startswith("Risk Level:"):
                current.risk_level = line.split("Risk Level:", 1)[1].strip()
            elif line.startswith("Score:"):
                current.score = int(line.split("Score:", 1)[1].strip())
            elif line.strip().startswith("- ["):
                match = re.match(r"-\s*\[(\w+)\]", line.strip())
                if match:
                    current.categories.append(match.group(1))
            elif line.startswith("User input:"):
                current.user_input = line.split("User input:", 1)[1].strip()
            elif line.startswith("----"):
                if current is not None:
                    entries.append(current)
                    current = None

    if current is not None:
        entries.append(current)

    return entries


def print_report(entries: list) -> None:
    if not entries:
        print("No security events logged yet.")
        return

    total = len(entries)
    by_type = Counter(e.event_type for e in entries)
    by_risk = Counter(e.risk_level for e in entries)
    by_category = Counter(cat for e in entries for cat in e.categories)
    avg_score = sum(e.score for e in entries) / total

    print("=" * 50)
    print("SECURITY LOG REPORT")
    print("=" * 50)
    print(f"Total flagged events: {total}")
    print(f"Average risk score:   {avg_score:.1f}")

    print("\nBy event type:")
    for event_type, count in by_type.most_common():
        print(f"  {event_type:<30} {count}")

    print("\nBy risk level:")
    for risk_level, count in by_risk.most_common():
        print(f"  {risk_level:<30} {count}")

    print("\nBy detection category:")
    for category, count in by_category.most_common():
        print(f"  {category:<30} {count}")

    print("\nMost recent 5 events:")
    for entry in entries[-5:]:
        print(f"  [{entry.timestamp}] {entry.event_type} — {entry.risk_level} "
              f"(score {entry.score}) — {entry.user_input!r}")

    print("=" * 50)


def write_csv(entries: list, csv_path: str) -> None:
    import csv
    with open(csv_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "event_type", "risk_level", "score",
                          "categories", "user_input"])
        for entry in entries:
            writer.writerow([
                entry.timestamp,
                entry.event_type,
                entry.risk_level,
                entry.score,
                ";".join(entry.categories),
                entry.user_input,
            ])
    print(f"CSV report written to {csv_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate a report from security_log.txt")
    parser.add_argument("--log", default="security_log.txt",
                         help="Path to the security log file (default: security_log.txt)")
    parser.add_argument("--csv", default=None,
                         help="Optional path to also write a CSV export")
    args = parser.parse_args()

    try:
        entries = parse_log(args.log)
    except FileNotFoundError:
        print(f"No log file found at '{args.log}' yet — run the guard and trigger "
              f"a few flagged questions first.")
        return

    print_report(entries)

    if args.csv:
        write_csv(entries, args.csv)


if __name__ == "__main__":
    main()