#!/usr/bin/env python3
"""
ARGUS Phase 3 - Step 5: Human-in-the-Loop Gate
Runs INSIDE the isolated analysis VM. No internet required or used.

This script does NOT make the accept/reject decision, it presents the
validated candidate rule and records whichever decision the analyst
(you) actually makes. That decision, and any reasoning behind it, is
yours, not something this pipeline generates for you.

Three outcomes:
  [A]ccept  - appends the rule as-is to the local rule database (.yar file)
  [M]odify  - tells you where to edit the file directly; nothing is
              appended until you re-run this script afterward
  [R]eject  - logs the rejection (with a reason you type) and appends
              nothing

Usage:
    py human_gate.py candidate_v1.yar --db detections.yar
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def append_to_log(log_path: Path, entry: dict):
    entries = []
    if log_path.exists():
        try:
            entries = json.loads(log_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            entries = []
    entries.append(entry)
    log_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="ARGUS human-in-the-loop accept/modify/reject gate")
    parser.add_argument("rule", help="Path to the validated candidate .yar file")
    parser.add_argument("--db", default="detections.yar", help="Path to the local rule database to append to")
    parser.add_argument("--log", default="decisions_log.json", help="Path to the decision history log")
    args = parser.parse_args()

    rule_path = Path(args.rule)
    if not rule_path.exists():
        print(f"[!] Rule file not found: {rule_path}")
        return

    rule_text = rule_path.read_text(encoding="utf-8")

    print("=" * 70)
    print(f"Candidate rule: {rule_path.name}")
    print("=" * 70)
    print(rule_text)
    print("=" * 70)
    print()
    print("This rule passed automated validation (true-positive + false-positive).")
    print("That does NOT mean it's necessarily good, that call is yours to make.")
    print()

    decision = input("[A]ccept / [M]odify / [R]eject? ").strip().lower()

    timestamp = datetime.now(timezone.utc).isoformat()

    if decision.startswith("a"):
        db_path = Path(args.db)
        with open(db_path, "a", encoding="utf-8") as f:
            f.write(f"\n// Accepted {timestamp} from {rule_path.name}\n")
            f.write(rule_text)
            f.write("\n")
        append_to_log(Path(args.log), {
            "timestamp": timestamp,
            "rule_file": str(rule_path),
            "decision": "accepted",
        })
        print(f"[+] Appended to {db_path}.")

    elif decision.startswith("m"):
        print()
        print(f"[*] Edit {rule_path} directly (Notepad, VS Code, whatever you're comfortable with).")
        print("[*] Once you're satisfied, re-run validate_rule.py against your edited version,")
        print("    and then re-run this script again to accept or reject the revised rule.")
        append_to_log(Path(args.log), {
            "timestamp": timestamp,
            "rule_file": str(rule_path),
            "decision": "sent_for_manual_modification",
        })

    elif decision.startswith("r"):
        reason = input("Reason for rejecting (this gets logged, not the .yar db): ").strip()
        append_to_log(Path(args.log), {
            "timestamp": timestamp,
            "rule_file": str(rule_path),
            "decision": "rejected",
            "reason": reason,
        })
        print("[+] Rejection logged. Nothing appended to the rule database.")

    else:
        print("[!] Didn't recognize that input, nothing was changed. Run the script again.")


if __name__ == "__main__":
    main()
