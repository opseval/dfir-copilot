# DFIR Co-Pilot — Comprehensive User Guide

A complete guide to installing, running, understanding, and extending the local DFIR co-pilot.
If you just want to get going, the one-liner is `./install.sh` then `./dfir-copilot verify` — the
rest of this document is here when you want depth.

**Contents**
1. [What this is (and isn't)](#1-what-this-is-and-isnt)
2. [Installation](#2-installation)
3. [The two ways you'll use it](#3-the-two-ways-youll-use-it)
4. [Command reference](#4-command-reference)
5. [Walkthroughs](#5-walkthroughs)
6. [How it decides things](#6-how-it-decides-things)
7. [Extending coverage](#7-extending-coverage)
8. [The forensic tools (Docker)](#8-the-forensic-tools-docker)
9. [Safety & evidence handling](#9-safety--evidence-handling)
10. [Limitations & known behavior](#10-limitations--known-behavior)
11. [Configuration](#11-configuration)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)

---

## 1. What this is (and isn't)

The DFIR co-pilot is an **advisory** assistant for digital-forensics and incident-response work that
runs **entirely on your Mac**. It does two things well:

- **Drafts queries** — you ask a question in plain English about a CSV artifact (a parsed log,
  an EZTools export, a timeline) and it writes the DuckDB SQL, runs it read-only, and shows you both
  the answer and the query so you can approve it.
- **Triages tool output** — you pipe the output of a forensic tool (Volatility, Plaso, an event-log
  export) into it and it returns a verdict, the concrete indicators it found, and the suggested next
  commands.

**The operating principle, in one line:** *the model drafts, a deterministic harness decides, and
you approve.* The small model is never trusted to make the call on its own — it proposes, and rules
+ execution + your judgment dispose.

**What it is not:** it is not an autonomous agent that runs forensic tools by itself, not a malware
sandbox, and not a replacement for an analyst. It raises the floor — it helps a mixed-experience SOC
team move faster and miss less — but a human stays in the loop on every action and every verdict.

**Why it's built this way:** an extensive local test campaign showed
that fine-tuning a small model on forensic data *hurt* — the structured, untuned model beat the
fine-tuned one 3.5× on held-out queries. So the intelligence lives in the harness (grounding +
constrained decoding + deterministic detectors), and the model is a frozen, swappable component.

---

## 2. Installation

### 2.1 The one command

```bash
cd dfir-copilot
./install.sh
```

On a **fresh Mac**, this installs Homebrew (it will ask for your password — that's Homebrew's own
installer, not us), Python, and the Python dependencies; downloads the model (~2.6 GB); creates the
`dfir-copilot` launcher; and runs a self-test. On an **existing Mac**, it detects what's already
present and installs only what's missing. **Re-running is always safe.**

### 2.2 Flags

| Flag | Effect |
|---|---|
| (none) | Install the co-pilot "brain" (model + structure stack) and verify it. |
| `--with-tools` | Also install Docker Desktop, Rosetta 2 (for amd64 tools), and pull the forensic-tool images. |
| `--no-model` | Wire everything up but skip the model download (e.g., to pre-stage on a metered connection). |
| `--quick-verify` | Skip the slow end-to-end model test during verification. |
| `--help` | Show usage. |

### 2.3 What gets installed, and where

- A Python virtual environment at `dfir-copilot/.venv` (nothing touches your system Python).
- Python packages: `mlx-lm`, `outlines` + `llguidance` (constrained decoding), `duckdb`,
  `huggingface_hub`.
- The model in the standard Hugging Face cache (`~/.cache/huggingface`).
- A launcher script `dfir-copilot/dfir-copilot`. If `~/.local/bin` is on your `PATH`, it's symlinked
  there so you can run `dfir-copilot` from anywhere; otherwise you run `./dfir-copilot`.

**To call it from any directory yourself**, from the repo folder either add the repo to your `PATH`:

```bash
echo "export PATH=\"$PWD:\$PATH\"" >> ~/.zshrc && source ~/.zshrc   # zsh is the macOS default shell
```

or symlink the launcher into a directory already on your `PATH` (may prompt for `sudo`):

```bash
ln -sf "$PWD/dfir-copilot" /usr/local/bin/dfir-copilot
```

After either, `dfir-copilot query "…" artifact.csv` works from anywhere. (This guide's examples use
`./dfir-copilot`, which works from inside the repo.)

### 2.4 Verifying

```bash
./dfir-copilot verify
```

This runs four checks: dependencies import, DuckDB reads a sample artifact, deterministic triage
produces a correct verdict, and the model loads and constrained decoding produces a real, executing
query. All four should say `PASS`. (Add `--quick` to skip the slow model check.)

---

## 3. The two ways you'll use it

### Query mode — questions about CSV artifacts

Use this when you have a **parsed/structured artifact as CSV** (a log converted to columns, an
EZTools `.csv` export, a Plaso `psort` CSV) and a question.

```bash
./dfir-copilot query "<your question>" <artifact.csv>
```

The co-pilot reads the artifact's real schema and sample values, writes a DuckDB query, runs it
(read-only), and prints the SQL, the result, and a self-consistency score (how many of its samples
agreed). **You read the SQL and decide whether to trust the number.**

### Triage mode — verdicts from raw tool output

Use this when you have **raw output from a forensic tool** and want a fast, deterministic read on
whether it's interesting.

```bash
<tool> ... | ./dfir-copilot triage
# or
./dfir-copilot triage saved_output.txt
```

You get a verdict (`MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `UNDETERMINED`), the priority finding and
why, every indicator with its evidence, and suggested next commands. **No model is involved** in the
verdict — it's deterministic rules, which is exactly why it's trustworthy. Add a grounded prose
summary with `narrate` instead of `triage` if you want the model to explain it (the verdict still
comes from the rules).

---

## 4. Command reference

### `query "<question>" <artifact.csv>`
Draft and verify a DuckDB query over a CSV artifact.
- **Input:** a natural-language question, and a path to a CSV file.
- **Output:** the SQL, the executed result, and the self-consistency vote (`votes=4/5`).
- **Exit code:** `0` if a verified query was produced, `2` if not.
- **Notes:** the first call loads the model (~30–60 s); later calls are fast. The query is always
  read-only. If it can't produce a working query it tells you the last error rather than guessing.

### `triage [file]`
Deterministic verdict + findings from tool output. Reads `file` or stdin.
- **Output:** verdict, priority finding + rationale, all findings with evidence, suggested next commands.
- **No model.** Fast and offline. The safe default for "is this interesting?"

### `narrate [file]`
Same as `triage`, plus an optional model-written prose summary grounded in the deterministic findings.
- The verdict from the rules is authoritative; the narration is advisory color.

### `verify [--quick]`
Run the install smoke tests. `--quick` skips the slow model check.

### `tools <tool> <args...>`
Run a dockerized forensic tool against artifacts in the current directory (mounted **read-only**).
- `tools list` — show configured tools and their images.
- `tools pull` — pull all tool images.
- `tools plaso <args>` / `tools vol3 <args>` / `tools remnux <args>` — run that tool.
- Requires `./install.sh --with-tools` first.

---

## 5. Walkthroughs

### 5.1 SSH brute-force triage from an auth log

You have an `OpenSSH` auth log parsed to CSV (columns like `Content`, `EventId`, `Time`).

```bash
./dfir-copilot query "how many failed password attempts are there?" auth.csv
./dfir-copilot query "which single source IP has the most events, and how many?" auth.csv
./dfir-copilot query "how many distinct usernames were tried in invalid-user attempts?" auth.csv
./dfir-copilot query "how many lines were flagged as POSSIBLE BREAK-IN ATTEMPT?" auth.csv
```

Each prints the SQL it used (e.g. `... WHERE Content LIKE '%Failed password%'`) so you can confirm it
matched what you meant before you put the number in a report. The top-IP result is your next pivot.

### 5.2 Memory triage with Volatility

```bash
# draft + approve the command, then run it (read-only mount)
./dfir-copilot tools vol3 -f /data/mem.raw windows.malfind | ./dfir-copilot triage
```

If `malfind` shows an RWX region inside `lsass.exe`, triage returns `MALICIOUS`, names the indicator,
and suggests dumping the region and pivoting to `windows.netscan`/`windows.pstree`. Run those next:

```bash
./dfir-copilot tools vol3 -f /data/mem.raw windows.pstree | ./dfir-copilot triage
```

### 5.3 Timeline pivot with Plaso

```bash
./dfir-copilot tools plaso log2timeline.py --storage-file /data/case.plaso /data/image.E01
./dfir-copilot tools plaso psort.py -o dynamic -w /data/timeline.csv /data/case.plaso
# now ask questions of the timeline as a CSV artifact
./dfir-copilot query "how many events occurred between the first and last logon?" timeline.csv
```

The pattern is always: **co-pilot drafts → you approve → tool runs read-only → feed the output back
to triage or query.**

---

## 6. How it decides things

Understanding this is what lets you trust the output.

### Query path (the "draft" intelligence)
1. **M-Schema.** It reads the artifact's real columns, types, and a few sample cell values, and puts
   them in the model's context. Seeing `Content` actually contains `"Failed password for invalid
   user ..."` is what teaches it to filter with `LIKE`, not invent a column.
2. **Forensic dictionary.** A reusable cheat-sheet of `term → SQL-pattern` mappings (e.g. *invalid
   user* → `Content LIKE '%Invalid user %'`) plus SQL-discipline rules, injected as context. This is
   editable knowledge, not baked-in weights.
3. **Constrained decoding.** The model is forced to emit only valid SQL whose table and column names
   come from *this* artifact's schema. It is *structurally impossible* for it to corrupt the table
   name or invent a column — the single biggest reliability win in the whole system.
4. **Best-of-N + self-consistency + retry.** It generates several candidates, runs each, and keeps
   the answer the most candidates agree on (voting on *results*, never on the ground truth). If all
   fail, it feeds the database error back and retries.

### Triage path (the "decide" intelligence)
1. **Pre-extraction.** 14 deterministic detectors scan the tool output for known-bad patterns
   (Office spawning a script host, RWX memory in `lsass`, LOLBins with network, persistence keys,
   specific Windows Event IDs, webshell writes, …).
2. **Triage.** The verdict is taken from the highest-severity finding. The model is *not* in this
   path. If nothing matches, it returns `UNDETERMINED — manual review`, never a confident guess.

**Why the model never owns the verdict:** in testing, the model *with* the findings still over-called
benign activity as malicious (false positives), while the deterministic rules got 11/12 with zero
dangerous misses. So the rules decide; the model, at most, narrates.

---

## 7. Extending coverage

The cheapest and most effective way to make the co-pilot smarter is **editing knowledge, not
training**. The campaign showed fine-tuning hurts; adding to these files costs nothing and helps.

### Add forensic query patterns
Edit `copilot/domain_pack.py` → `DOMAIN_DICT`. Add lines mapping a concept to its SQL pattern, e.g.:

```
- Kerberos pre-auth failure -> Content LIKE '%pre-authentication failed%'
- pull the workstation name  -> regexp_extract(Content, 'WORKSTATION=(\\S+)', 1)
```

Keep them **general** (real analyst knowledge, not tied to one case's answer). New patterns take
effect immediately — no retraining.

### Add triage detectors
Edit `copilot/preextract.py` — add a detector function that appends a finding `{indicator, evidence,
why, severity, next}` when it matches, and register it in the `DETECTORS` list. The verdict and the
suggested next commands update automatically.

### Swap the base model
Set `DFIR_MODEL` to any MLX-compatible chat model and re-run. The structure stack is model-agnostic.
Testing found that bigger/different bases did **not** beat the 3B under this stack (and cost 2× the
memory), so the default is the right call for a 16 GB machine — but the knob is there.

---

## 8. The forensic tools (Docker)

After `./install.sh --with-tools`, the dockerized tools are available through the `tools` subcommand.
They run against files in your **current directory**, mounted **read-only** at `/data` inside the
container, so the tool can read evidence but cannot modify it.

```bash
cd /path/to/case/artifacts
../dfir-copilot tools list                       # see configured tools + images
../dfir-copilot tools vol3 -f /data/mem.raw windows.pstree
../dfir-copilot tools plaso psort.py -o dynamic -w /data/timeline.csv /data/case.plaso
```

- **EZTools and REMnux are amd64.** On Apple Silicon they run via Rosetta 2 (installed by
  `--with-tools`) and are slower but functional.
- **Override any image** with an env var (e.g. `DFIR_IMG_VOL3=yourorg/vol3:tag`) — see
  `tools/dfir-tools.sh`.

---

## 9. Safety & evidence handling

- **Read-only evidence.** The tool wrappers mount artifacts read-only. The query path only ever runs
  `SELECT`. Nothing in normal operation writes to or alters evidence.
- **Local only.** No artifact, query, or output ever leaves the machine. The model runs on-device.
- **Advisory by design.** The co-pilot *proposes*; you approve before any tool command runs. For the
  query path, the SQL is shown alongside the result so you can confirm it before trusting the number.
- **Anti-forensic refusal.** The system is built to assist authorized investigation. It will not help
  destroy, alter, or wipe evidence or timestamps.
- **No silent success.** If the query path can't produce a working query, it says so and shows the
  error rather than inventing an answer. If triage finds nothing, it returns `UNDETERMINED` rather
  than guessing benign.

---

## 10. Limitations & known behavior

Knowing these keeps you out of trouble.

- **The model is a narrator, not an adjudicator.** Trust the deterministic verdict; treat any model
  prose (`narrate`) as color, and the drafted SQL as a proposal to review.
- **Schema novelty vs semantic novelty.** The query path adapts automatically to *any new CSV schema*
  (it reads columns + samples). But its *domain semantics* come from the forensic dictionary — on an
  artifact type the dictionary doesn't cover, it will still produce valid SQL but may pick the wrong
  filter. The fix is to add a few dictionary lines (Section 7), not to fine-tune.
- **It's a small model.** It handles the common, well-trodden questions reliably. For unusual
  multi-step analytical reasoning, write the SQL yourself or escalate to a larger model — the
  co-pilot's job is to handle the 80% so you can focus on the hard 20%.
- **Triage covers known patterns.** The 14 detectors catch well-established indicators; a novel TTP
  with no matching detector returns `UNDETERMINED` (safe, but it means "look yourself"). Add detectors
  as your coverage needs grow.
- **First call latency.** The model loads once per process (~30–60 s); batch your questions in a
  session rather than one process per question if latency matters.

---

## 11. Configuration

Set these as environment variables before running (all optional):

| Variable | Default | Purpose |
|---|---|---|
| `DFIR_MODEL` | `mlx-community/granite-4.1-3b-mxfp4` | the base model (any MLX chat model) |
| `DFIR_BEST_OF_N` | `5` | candidates sampled per query (higher = more robust, slower) |
| `DFIR_MAX_RETRIES` | `3` | execute-and-retry rounds on failure |
| `DFIR_TEMP` | `0.5` | sampling temperature for the non-greedy candidates |
| `DFIR_MAX_TOKENS` | `256` | max tokens per generated query |
| `DFIR_IMG_VOL3` / `DFIR_IMG_PLASO` / `DFIR_IMG_REMNUX` | see `tools/dfir-tools.sh` | override tool images |

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| `brew` asks for a password (fresh Mac) | Expected — it's Homebrew's installer, not ours. |
| "Docker engine not running" | Open Docker Desktop once, then `./install.sh --with-tools`. |
| First query hangs ~30–60 s | One-time model load; subsequent calls in the same session are fast. |
| `mlx` aborts on import in your own scripts | `export MLX_MPI_LIBNAME=libmpi_disabled_does_not_exist.dylib` (the package sets this itself). |
| A query returns "could not produce a verified query" | Rephrase more concretely, or check the artifact has the columns you assume. The shown error tells you what failed. |
| Re-install needed | `./install.sh` is idempotent — just run it again. |
| Out of memory with another big model loaded | The co-pilot peaks ~2.75 GB; close other large local models if you're near the limit. |

---

## 13. FAQ

**Does anything leave my machine?** No. The model and all processing are local.

**Can I run it on Intel Mac / Linux?** It targets Apple Silicon + MLX. Intel works but is slow; Linux
is out of scope for the installer (the structure stack itself is portable if you bring your own MLX/
alternative runtime).

**Why not just fine-tune the model on our cases?** It was tried thoroughly and it *hurt* — a
fine-tuned specialist scored 4/17 on held-out queries where the untuned model + structure scored
14/17, and a local skill-RFT made it worse still. Knowledge belongs in the dictionary and detectors
(editable, $0), not the weights.

**Should we pay for cloud training?** Not to ship — the local system already clears the bar. If you
ever want to push the ceiling, a domain
continued-pretraining pass is a ~$6–65 "coffee-break" run; a full execution-reward GRPO project is
~$500–2,500. Neither is needed for normal operation.

**How do I teach it about a new tool or log type?** Add patterns to `copilot/domain_pack.py` and/or a
detector to `copilot/preextract.py`. No retraining.
