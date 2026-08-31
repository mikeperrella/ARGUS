#!/usr/bin/env python3
"""
ARGUS Phase 3 - Step 1: Feature Extraction
Runs INSIDE the isolated analysis VM only. No internet required or used.

Runs, in order:
  1. DIE (Detect It Easy) - packing/entropy gate
  2. CAPA - capabilities, ATT&CK + MBC mappings
  3. FLOSS - string extraction

...and writes everything into a single combined JSON "context" file. That
context file is the ONLY thing that should ever leave the VM, it gets carried
to the host-side rule-drafting script (step 2), since that's the step that
actually needs internet access to reach the Claude API.

Usage:
    py extract_features.py "C:\\path\\to\\sample.exe"

Optional flags:
    --diec PATH             override path to diec.exe
    --capa PATH             override path to capa.exe
    --floss PATH            override path to floss.exe
    --out PATH              override output JSON path
    --entropy-threshold N   override the gate's entropy cutoff (default 7.0)
    --force                 proceed past the gate even if it fails
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Default tool locations on this VM, per the ARGUS build so far.
# Adjust these if your tools ended up somewhere different.
DEFAULT_DIEC = r"C:\Tools\DIE\die\diec.exe"
DEFAULT_CAPA = r"C:\Tools\capa\capa.exe"
DEFAULT_FLOSS = r"C:\Tools\floss\floss.exe"

ENTROPY_THRESHOLD = 7.0


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_json_tool(cmd, label):
    """Run a subprocess expected to print JSON to stdout, and parse it.
    Warnings/info logs that tools send to stderr (like FLOSS's .NET
    warnings) are captured separately and don't pollute the JSON."""
    print(f"[*] Running {label}: {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] {label} exited with code {result.returncode}")
        if result.stderr.strip():
            print(f"    stderr: {result.stderr.strip()[:500]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[!] {label} did not return valid JSON. Raw output saved instead.")
        return {"_raw_stdout": result.stdout, "_raw_stderr": result.stderr}


def check_entropy_gate(die_entropy_result, threshold):
    """Mirrors the spec's rule: halt if total entropy > threshold.
    (Named-packer detection from the plain `-j` scan is left for you to
    eyeball in die_detects for now, since DIE's own per-section 'packed'
    label runs on a more sensitive internal heuristic than this flat
    threshold, as we saw firsthand on the AgentTesla sample.)"""
    total_entropy = die_entropy_result.get("total")
    if total_entropy is None:
        return True, "No entropy value returned by DIE; proceeding, but flag this for manual review."
    if total_entropy > threshold:
        return False, f"Total entropy {total_entropy:.2f} exceeds threshold {threshold}."
    return True, f"Total entropy {total_entropy:.2f} is under threshold {threshold}."


def main():
    parser = argparse.ArgumentParser(description="ARGUS feature extraction (DIE + CAPA + FLOSS)")
    parser.add_argument("sample", help="Path to the sample .exe")
    parser.add_argument("--diec", default=DEFAULT_DIEC)
    parser.add_argument("--capa", default=DEFAULT_CAPA)
    parser.add_argument("--floss", default=DEFAULT_FLOSS)
    parser.add_argument("--out", default=None)
    parser.add_argument("--entropy-threshold", type=float, default=ENTROPY_THRESHOLD)
    parser.add_argument("--force", action="store_true",
                         help="Continue past the entropy gate even if it fails")
    args = parser.parse_args()

    sample_path = Path(args.sample).resolve()
    if not sample_path.exists():
        sys.exit(f"[!] Sample not found: {sample_path}")

    sample_hash = sha256_of(sample_path)
    print(f"[*] Sample:  {sample_path.name}")
    print(f"[*] SHA256:  {sample_hash}")
    print()

    # --- Step 1: packing/entropy gate ---
    die_detects = run_json_tool([args.diec, "-j", str(sample_path)], "DIE (file type / detects)")
    die_entropy = run_json_tool([args.diec, "-j", "-e", str(sample_path)], "DIE (entropy)")

    gate_passed, gate_reason = check_entropy_gate(die_entropy, args.entropy_threshold)
    print(f"[*] Entropy gate: {'PASS' if gate_passed else 'FAIL'} - {gate_reason}")

    if not gate_passed and not args.force:
        print("[!] Halting per the packing/entropy gate. Manual unpacking required before proceeding.")
        print("    Re-run with --force to proceed anyway (e.g. after manual review).")
        sys.exit(1)
    print()

    # --- Step 2: feature extraction ---
    capa_result = run_json_tool([args.capa, "-j", str(sample_path)], "CAPA")
    floss_result = run_json_tool([args.floss, "-j", str(sample_path)], "FLOSS")
    print()

    # --- Combine into one context file ---
    context = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "path": str(sample_path),
            "filename": sample_path.name,
            "sha256": sample_hash,
            "size_bytes": sample_path.stat().st_size,
        },
        "entropy_gate": {
            "passed": gate_passed,
            "reason": gate_reason,
            "threshold": args.entropy_threshold,
            "forced": bool(args.force and not gate_passed),
        },
        "die": {
            "detects": die_detects,
            "entropy": die_entropy,
        },
        "capa": capa_result,
        "floss": floss_result,
    }

    out_path = Path(args.out) if args.out else sample_path.parent / "results" / "pipeline_context.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(context, indent=2), encoding="utf-8")

    print(f"[+] Combined context written to: {out_path}")
    print("[+] This is the ONLY file that needs to leave the VM. Carry it to the host for rule drafting.")


if __name__ == "__main__":
    main()
