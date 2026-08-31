#!/usr/bin/env python3
"""
ARGUS Phase 3 - Step 4: Validation Engine
Runs INSIDE the isolated analysis VM only. No internet required or used.

Compiles a candidate YARA-X rule and runs two checks:
  1. True-positive test: the rule MUST fire on the source sample.
  2. False-positive test: the rule must NOT fire on a corpus of clean files
     (defaults to a sample of .exe/.dll files from C:\\Windows\\System32).

If either check fails, writes a JSON "failure report" describing exactly
what happened, in a shape draft_rule.py's --feedback flag can consume
directly for a tightening pass. If both checks pass, this is the point
where the spec's human-in-the-loop gate takes over, this script does NOT
auto-accept anything, it just tells you the rule is ready for your review.

Usage:
    py validate_rule.py candidate_v1.yar --sample "C:\\path\\to\\sample.exe"

Optional:
    --clean-corpus DIR     folder of known-clean files to test against
                            (default: C:\\Windows\\System32)
    --max-clean-files N    cap how many clean files to scan (default 300,
                            scanning all of System32 can be slow)
    --report PATH          where to write the failure report if something
                            fails (default: <rule_name>.failure.json)
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import yara_x
except ImportError:
    sys.exit(
        "[!] The 'yara_x' package isn't installed in this Python environment.\n"
        "    Install it with: py -m pip install yara_x-<version>-cp38-abi3-win_amd64.whl\n"
        "    (same wheel file used earlier in the ARGUS tool install)"
    )


def compile_rule(rule_text: str):
    try:
        return yara_x.compile(rule_text), None
    except Exception as e:  # yara_x raises its own error types on bad syntax
        return None, str(e)


def scan_file(rules, path: Path):
    try:
        data = path.read_bytes()
    except (PermissionError, OSError):
        return None  # unreadable file, skip rather than fail the whole run
    try:
        results = rules.scan(data)
    except Exception:
        return None
    return [m.identifier for m in results.matching_rules]


def main():
    parser = argparse.ArgumentParser(description="ARGUS YARA-X validation engine")
    parser.add_argument("rule", help="Path to the candidate .yar file")
    parser.add_argument("--sample", required=True, help="Path to the true-positive sample")
    parser.add_argument("--clean-corpus", default=r"C:\Windows\System32")
    parser.add_argument("--max-clean-files", type=int, default=300)
    parser.add_argument("--report", default=None)
    args = parser.parse_args()

    rule_path = Path(args.rule)
    sample_path = Path(args.sample)
    if not rule_path.exists():
        sys.exit(f"[!] Rule file not found: {rule_path}")
    if not sample_path.exists():
        sys.exit(f"[!] Sample not found: {sample_path}")

    rule_text = rule_path.read_text(encoding="utf-8")
    report_path = Path(args.report) if args.report else rule_path.with_suffix(".failure.json")

    print(f"[*] Compiling {rule_path.name} with yara_x...")
    rules, compile_error = compile_rule(rule_text)

    if compile_error:
        print(f"[!] COMPILE FAILED: {compile_error}")
        report = {
            "rule_file": str(rule_path),
            "failure_type": "compile_error",
            "detail": compile_error,
            "instructions_for_model": (
                "The candidate rule failed to compile with yara_x. Fix the specific "
                "syntax error described above and return a corrected rule."
            ),
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Failure report written to: {report_path}")
        print("    Feed this back into draft_rule.py with --previous-rule and --feedback.")
        sys.exit(1)

    print("[+] Compiled successfully.")

    # --- True-positive test ---
    print(f"[*] Running true-positive test against {sample_path.name}...")
    tp_matches = scan_file(rules, sample_path)
    tp_passed = bool(tp_matches)
    print(f"[*] True-positive test: {'PASS' if tp_passed else 'FAIL'} "
          f"(matched rules: {tp_matches if tp_matches else 'none'})")

    # --- False-positive test ---
    corpus_dir = Path(args.clean_corpus)
    fp_hits = []
    scanned_count = 0
    if corpus_dir.exists():
        candidates = [p for p in corpus_dir.iterdir()
                      if p.is_file() and p.suffix.lower() in (".exe", ".dll")]
        candidates = candidates[: args.max_clean_files]
        print(f"[*] Running false-positive test against {len(candidates)} files in {corpus_dir}...")
        for f in candidates:
            matches = scan_file(rules, f)
            scanned_count += 1
            if matches:
                fp_hits.append({"file": str(f), "matched_rules": matches})
    else:
        print(f"[!] Clean corpus folder not found: {corpus_dir}, skipping false-positive test.")

    fp_passed = len(fp_hits) == 0
    print(f"[*] False-positive test: {'PASS' if fp_passed else 'FAIL'} "
          f"({len(fp_hits)} hit(s) out of {scanned_count} clean files scanned)")

    # --- Overall result ---
    if tp_passed and fp_passed:
        print()
        print("[+] VALIDATION PASSED. Both true-positive and false-positive tests succeeded.")
        print("[+] This rule is ready for the human accept/modify/reject gate, not auto-final.")
        return

    print()
    print("[!] VALIDATION FAILED. See details below.")
    report = {
        "rule_file": str(rule_path),
        "sample": str(sample_path),
        "true_positive": {"passed": tp_passed, "matched_rules": tp_matches},
        "false_positive": {
            "passed": fp_passed,
            "hits": fp_hits,
            "files_scanned": scanned_count,
        },
        "instructions_for_model": (
            "The candidate rule failed validation. "
            + ("It did NOT fire on the true-positive sample, it needs to be loosened "
               "or corrected so it actually matches the sample's real characteristics. "
               if not tp_passed else "")
            + (f"It incorrectly matched {len(fp_hits)} clean file(s), see 'hits' for which "
               "files and which parts of the rule matched; tighten the condition so it no "
               "longer fires on these." if not fp_passed else "")
        ),
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Failure report written to: {report_path}")
    print("    Carry this report to the host and feed it into draft_rule.py with --feedback.")
    sys.exit(1)


if __name__ == "__main__":
    main()
