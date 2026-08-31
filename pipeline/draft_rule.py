#!/usr/bin/env python3
"""
ARGUS Phase 3 - Step 2: Rule Drafting (Claude API)
Runs on your HOST machine (or anywhere with real internet). Never run this
inside the isolated analysis VM, it has no internet path and doesn't need one
for this step.

Reads the pipeline_context.json produced by extract_features.py inside the
VM, sends it to the Claude API with a system prompt instructing it to draft
a candidate YARA-X rule targeting the sample's BEHAVIORAL logic (not just a
hash or a handful of one-off strings, so the rule has a chance of catching
variants, not just this exact file), and writes the candidate out as a .yar
file plus a short rationale.

Also supports a tightening pass: if the validation step (script 3, back
inside the VM) reports a true-positive or false-positive failure, feed that
failure data back in here with --previous-rule and --feedback, and it'll ask
Claude to revise the rule accordingly.

Setup (one-time):
    pip install anthropic
    Set an environment variable ANTHROPIC_API_KEY to your API key
    (https://console.anthropic.com/settings/keys)

Usage:
    python draft_rule.py pipeline_context.json --out candidate_v1.yar

Tightening a rule that failed validation:
    python draft_rule.py pipeline_context.json --out candidate_v2.yar \\
        --previous-rule candidate_v1.yar --feedback fp_failure_notes.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import anthropic
except ImportError:
    sys.exit(
        "[!] The 'anthropic' package isn't installed.\n"
        "    Run: pip install anthropic"
    )

MODEL = "claude-sonnet-5"
MAX_CONTEXT_CHARS = 60000  # safety cap so one huge CAPA/FLOSS dump doesn't blow the context window

SYSTEM_PROMPT = """You are a detection engineer drafting a candidate YARA-X rule for ARGUS, \
a supervised detection-engineering pipeline. A human will review, edit, or reject whatever \
you produce, nothing you write is treated as final.

You will be given structured output from DIE (packer/entropy scan), CAPA (capabilities, \
ATT&CK and MBC mappings), and FLOSS (extracted strings) for one malware sample.

Your job: draft a YARA-X rule that targets the sample's BEHAVIORAL LOGIC, the combination of \
capabilities, API usage patterns, and structural characteristics CAPA identified, rather than \
brittle single-sample fingerprints. Avoid keying the rule on the file's own hash, and avoid \
relying solely on strings that look unique to this one build (random-looking build paths, \
GUIDs), since those won't generalize to other samples in the same family/campaign. Structural \
and behavioral conditions (imports, PE characteristics, combinations of capability-derived \
strings) generalize better than any single string.

If you are given a previous candidate rule plus feedback describing why it failed validation \
(didn't fire on the true-positive sample, or fired on a clean file it shouldn't have), revise \
that rule to address the specific failure, don't start over from scratch unless the feedback \
indicates the whole approach was wrong.

Respond with ONLY a JSON object, no markdown fences, no prose outside the JSON, in exactly \
this shape:
{
  "rule": "<the complete YARA-X rule text, ready to save directly to a .yar file>",
  "rationale": "<a few sentences on what the rule targets and why, for the human reviewer>"
}
"""


def truncate(text: str, limit: int, label: str) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [TRUNCATED, {label} exceeded {limit} chars, full data is in the context file] ..."


def build_user_message(context: dict, previous_rule: str | None, feedback: str | None) -> str:
    sample = context.get("sample", {})
    entropy_gate = context.get("entropy_gate", {})
    die = context.get("die", {})
    capa = context.get("capa", {})
    floss = context.get("floss", {})

    parts = [
        "## Sample",
        f"Filename: {sample.get('filename')}",
        f"SHA256: {sample.get('sha256')}",
        f"Size: {sample.get('size_bytes')} bytes",
        "",
        "## Entropy gate result",
        json.dumps(entropy_gate, indent=2),
        "",
        "## DIE output (file type / packing detects)",
        truncate(json.dumps(die.get("detects", {}), indent=2), 8000, "DIE detects"),
        "",
        "## DIE output (per-section entropy)",
        truncate(json.dumps(die.get("entropy", {}), indent=2), 4000, "DIE entropy"),
        "",
        "## CAPA output (capabilities, ATT&CK, MBC)",
        truncate(json.dumps(capa, indent=2), MAX_CONTEXT_CHARS // 2, "CAPA output"),
        "",
        "## FLOSS output (extracted strings)",
        truncate(json.dumps(floss, indent=2), MAX_CONTEXT_CHARS // 2, "FLOSS output"),
    ]

    if previous_rule:
        parts += [
            "",
            "## Previous candidate rule (failed validation)",
            previous_rule,
        ]
    if feedback:
        parts += [
            "",
            "## Validation failure feedback",
            feedback,
            "",
            "Revise the previous rule above to address this specific failure.",
        ]

    return "\n".join(parts)


def parse_model_response(raw_text: str) -> dict:
    """Model is asked for bare JSON, but strip code fences defensively in
    case it wraps the response anyway."""
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Fall back to treating the whole response as the rule text, so a
        # malformed response doesn't just crash and lose the output.
        print("[!] Response wasn't valid JSON as requested. Saving raw text as the rule body,")
        print("    inspect it manually before trusting it.")
        return {"rule": raw_text, "rationale": "(model did not return the requested JSON shape)"}


def main():
    parser = argparse.ArgumentParser(description="ARGUS rule drafting via the Claude API")
    parser.add_argument("context", help="Path to pipeline_context.json from extract_features.py")
    parser.add_argument("--out", required=True, help="Output path for the candidate .yar file")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--previous-rule", help="Path to a previous candidate rule that failed validation")
    parser.add_argument("--feedback", help="Path to a text/JSON file describing why validation failed")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        sys.exit("[!] Set the ANTHROPIC_API_KEY environment variable first.")

    context_path = Path(args.context)
    if not context_path.exists():
        sys.exit(f"[!] Context file not found: {context_path}")
    context = json.loads(context_path.read_text(encoding="utf-8"))

    previous_rule = Path(args.previous_rule).read_text(encoding="utf-8") if args.previous_rule else None
    feedback = Path(args.feedback).read_text(encoding="utf-8") if args.feedback else None

    user_message = build_user_message(context, previous_rule, feedback)

    print(f"[*] Sending context for {context.get('sample', {}).get('filename')} to {args.model}...")
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=args.model,
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    print(f"[*] stop_reason: {response.stop_reason}")
    print(f"[*] content block types: {[block.type for block in response.content]}")

    raw_text = "".join(block.text for block in response.content if block.type == "text")

    if not raw_text.strip():
        print("[!] No text content came back at all. Dumping the full response for diagnosis:")
        print(response.model_dump_json(indent=2))
        sys.exit(1)

    parsed = parse_model_response(raw_text)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(parsed.get("rule", ""), encoding="utf-8")

    notes_path = out_path.with_suffix(".notes.txt")
    notes_path.write_text(parsed.get("rationale", ""), encoding="utf-8")

    print(f"[+] Candidate rule written to: {out_path}")
    print(f"[+] Rationale written to:      {notes_path}")
    print()
    print("--- Rationale ---")
    print(parsed.get("rationale", "(none provided)"))
    print()
    print("[+] Carry the .yar file back into the VM for validation (script 3).")


if __name__ == "__main__":
    main()
