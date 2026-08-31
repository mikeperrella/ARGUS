# CLAUDE.md — ARGUS (Automated Rule Generation Under Supervision)

This file is context for Claude Code. Read it before doing anything on this
project. It covers what ARGUS is, what's already built, and exactly where
Phase 5 (the viewer) picks up.

**The repo already exists and is live**: `github.com/mikeperrella/ARGUS`.
Clone it directly rather than starting a new project folder — everything
described below as "already built" is already committed and pushed there.

---

## 1. What ARGUS is

A reverse-engineering and detection-engineering portfolio project. Third in
a series, after Aegis Triage (agentic SOC alert triage) and VIGCAP (GRC /
identity governance). A credible, entry-level-appropriate RE foundation
paired with a genuine detection-engineering automation pipeline: run CAPA
against a real malware sample, extract indicators, draft a candidate YARA
rule via the Claude API, validate it against true-positive/false-positive
tests, and require a human accept/reject decision before it's treated as
final. Documented as a "Detection Story" per sample. The name reflects the
design: rule generation that is automated, but never unsupervised.

**Explicitly not**: GRC (that's VIGCAP), network/cloud security (a planned
fourth project), a claim to malware-analyst-level RE depth, a vehicle for
resume bullets, or vulnerability research/exploit development.

## 2. What's already built (do not redo this)

### Isolated lab (VMware Workstation Pro)
- Host pre-flight done: Memory Integrity off, Hyper-V/VMP/WHP off, verified
  via msinfo32 ("Virtualization-based security: Not enabled")
- **VMnet2**: isolated host-only network, host adapter unchecked, DHCP
  unchecked, subnet `10.0.0.0/24` — genuine air gap, not VMware's default
- **REMnux** (gateway/sinkhole): static IP `10.0.0.2`, INetSim running,
  bound to `0.0.0.0`, configured to survive reboots
- **Windows 11 Pro analysis VM** (`ARGUS-Win11-Analysis`): attached to
  VMnet2, static IP `10.0.0.3`, gateway/DNS `10.0.0.2`, VMware Tools
  installed
- **Defender fully disabled**: the durable Group Policy path was required
  (`Computer Configuration → Administrative Templates → Windows Components
  → Microsoft Defender Antivirus → Real-time Protection → "Turn off
  real-time protection" = Enabled`) — the broader "Turn off Microsoft
  Defender Antivirus" policy alone was NOT sufficient on this build.

### Tooling installed on the analysis VM
All under `C:\Tools\`:
- **Ghidra 12.1.x** — installed and available, but not used for this
  sample. It's poorly suited to a .NET target: native disassembly offers
  far less insight on managed code than direct IL decompilation.
- **Mandiant CAPA v9.4.0** — the primary source of structured
  capability/ATT&CK/MBC findings for this sample
- **FLARE-FLOSS v3.1.1** — note: does NOT support .NET string
  deobfuscation, only plain static-string extraction on .NET samples
- **Detect It Easy v3.21**
- **YARA-X 1.20.0** — Python module on Python 3.14 via the Python Install
  Manager — use `py`/`py -m pip`, not bare `python`/`pip`
- **x64dbg** — installed and available, same reasoning as Ghidra: wrong
  fit for a .NET binary
- **dnSpyEx** (`C:\Tools\dnSpyEx\dnSpy.exe`) — the tool actually used for
  code-level analysis of this .NET sample. Use the Search panel
  (`Ctrl+Shift+K`) to find methods/fields by name; use Edit → Go to Token
  for jumping straight to a known metadata token (format: `0x0600XXXX`
  hex).
- **7-Zip** — needed for MalwareBazaar's password-protected sample zips

**Lesson for future samples**: check the sample's runtime/format (native
PE vs. .NET vs. something else) before assuming Ghidra/x64dbg are the
right tools. For .NET samples, dnSpy is the better fit.

### Pipeline scripts (`pipeline/` in the repo)
Four Python scripts, split across host/guest because the VM has no
internet but the Claude API call needs it:

1. **`extract_features.py`** (runs in the VM) — DIE entropy gate → CAPA →
   FLOSS, writes `pipeline_context.json`. Only file that needs to leave
   the VM.
2. **`draft_rule.py`** (runs on the HOST, needs internet) — calls the
   Claude API (`claude-sonnet-5`, `max_tokens=4000`), drafts a candidate
   YARA-X rule, writes `candidate_vN.yar` + `.notes.txt`. Requires
   `anthropic` installed against the same Python interpreter `py`
   resolves to — if multiple Python installs exist on a machine, verify
   with `py -m pip install anthropic`, not bare `pip install anthropic`.
   Requires a **single-workspace-scoped** `ANTHROPIC_API_KEY` — a
   multi-workspace/identity-linked key fails with `anthropic-workspace-id
   is required`.
3. **`validate_rule.py`** (runs in the VM) — compiles with `yara_x`, runs
   true-positive + false-positive tests. Writes a JSON failure report on
   failure, shaped for `draft_rule.py --feedback`. Note: only writes a
   report file on failure — a passing run prints the result to the
   console but writes no report file, even if `--report` is passed.
4. **`human_gate.py`** (runs in the VM) — interactive accept/modify/reject,
   appends accepted rules to `detections.yar`, logs every decision to
   `decisions_log.json`.

The tightening loop (validate → fail → feedback → redraft → validate →
pass) has been fully exercised and confirmed working end to end — see
`pipeline/tightening_loop_test/` and `decisions_log.json` for the record.

### Sample #1 — fully processed end-to-end
- **AgentTesla**, SHA256
  `0d736040f6fcab61ef390639d0f9deb1270c8b3492dd7abd9cdc8ec43a100364`,
  sourced from MalwareBazaar
- Entropy gate passed (total 6.61, under the 7.0 threshold), though the
  `.text` section alone measures 6.63 and DIE's own per-section heuristic
  independently flagged it "packed" — a real discrepancy between DIE's
  heuristic and the spec's flat threshold, documented rather than treated
  as a contradiction
- Rule accepted: `AgentTesla_PrivacyShield_DotNet_Crypter`, in
  `detections.yar`
- Full six-section Detection Story: `stories/detection_story_agenttesla_01.md`,
  covering the reflective-loading chain (T1620), the process-injection
  evidence (T1055.012), a systematic naming-disguise pattern across
  methods and fields, and a statically-unreachable trigger condition
  found in one disguised branch

**No second sample is planned.** Treat Phase 4 as complete with one
sample.

## 3. Working style for this project

- Work in scoped steps — one instruction/step at a time, confirmed before
  moving to the next, not large multi-step dumps.
- For Phase 5's design decisions specifically: when the design-taste skill
  runs its audience/tone/mood interview, confirm the resulting direction
  with Mike before proceeding rather than locking it in from the first
  suggestion.

## 4. Phase 5 — the actual task

A web viewer for browsing Detection Stories, given a real design pass
rather than a plain template. Split of concerns per spec: the pipeline,
the CLI scripts, and the Detection Story content itself stay plain,
technical, unstyled — that substance is what gets evaluated. **The viewer
is the only place visual craft belongs.**

### Step 1 — install the design-taste skill (pick ONE, not both)

**Option A — taste-skill:**
```
npx skills add https://github.com/Leonxlnx/taste-skill --skill "design-taste-frontend"
```
(or: `/plugin install taste-skill@Leonxlnx/taste-skill`)

**Option B — Hallmark:**
```
npx skills add https://github.com/Nutlope/hallmark
```
(or manually: copy `SKILL.md` + `references/` into `~/.claude/skills/hallmark/`)

Both interview for audience/tone/mood — that interview is the right moment
to lock in the exact aesthetic direction (spec's own suggestion: "a dark,
technical, confident feel over a SaaS-landing-page feel"). Confirm
whatever direction it proposes with Mike before proceeding.

### Step 2 — install oil-motion

Tell Claude Code directly: "install the oil-motion Skill from
https://github.com/oil-oil/oil-motion". Use it for one or two tasteful
touches only (a subtle reveal, a hover state on ATT&CK tags) — NOT full
scroll-driven product animation.

### Step 3 — component library and diagrams
- **shadcn/ui** as the underlying component library
- **Mermaid** — a version of the pipeline diagram already lives in the
  repo's root `README.md` (renders plainly on GitHub). A more
  custom-styled version of the same diagram inside the live viewer is a
  good candidate for a Figma-designed or `fireworks-tech-graph` version
  instead.

### Step 4 — optional: Figma-first path
`figma-generate-design` → `figma-design-to-code` if a real design pass
before code is preferred over letting the taste skill design directly in
code. Either path is legitimate.

### Step 5 — content structure
- **Index page**: lists every analyzed sample with family, TTPs, and a
  link to its full story. Exactly **one** entry (AgentTesla), and no
  second sample is planned — the index should look correct and
  uncluttered with a single real entry, not fake placeholders.
- **One page per Detection Story**: renders
  `stories/detection_story_agenttesla_01.md`'s six sections.
- **Supporting screenshots** available in `screenshots/` (Defender-disabled
  confirmation, sample hash verification, capa's rendered ATT&CK/MBC/
  Capability table, the tool-install listing) — good candidates for
  embedding into either the index page or the Detection Story page as
  visual evidence.

### Step 6 — hosting
GitHub Pages, free, no server to maintain, off the existing
`github.com/mikeperrella/ARGUS` repo.

### Explicitly NOT used for the viewer
`servicenow-sdk`, `stackhawk-api` (for building it), `modern-web-guidance:
chrome-extensions` — none do frontend design/generation work.
`html-anything` is a separate local tool better suited to a one-off
artifact. `awesome-design-md`, `diagram-design`, `google/skills`,
`shadcn/improve` are reference material, not build steps.

### After the viewer is live — QA pass (do this, not optional)
- **Playwright CLI** — automated click-through and rendering checks on
  the finished viewer
- **Strix** — an AI pentesting agent, run against the live viewer;
  preferred over a plain StackHawk DAST scan for this step

## 5. Repo structure (already live)

```
ARGUS/                             (github.com/mikeperrella/ARGUS)
├── README.md                       # project overview + Mermaid diagram
├── LICENSE                         # MIT
├── .gitignore
├── pipeline/
│   ├── extract_features.py
│   ├── draft_rule.py
│   ├── validate_rule.py
│   ├── human_gate.py
│   ├── candidate_v1.yar
│   ├── candidate_v1.notes.txt
│   ├── detections.yar
│   ├── decisions_log.json
│   ├── pipeline_context.json
│   ├── capa_output.json
│   ├── floss_output.json
│   ├── floss_static.txt
│   └── tightening_loop_test/       # proof the validate→fail→feedback→
│                                    # redraft loop works end to end
├── stories/
│   └── detection_story_agenttesla_01.md
└── screenshots/
```
