# DFIR Co-Pilot — Comprehensive User Guide

A complete guide to installing, running, understanding, and extending the local DFIR co-pilot.
If you just want to get going, the one-liner is `./install.sh` then `clue verify` — the rest of this
document is here when you want depth. Everything is `clue <command>`; `clue` on its own prints the
cheat sheet, and `./dfir-copilot` inside the repo is the same program under its long name.

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
14. [Uninstalling](#14-uninstalling)

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

**The operating principle, in one line:** *the models draft, a deterministic harness decides, and
you approve.* No small model is ever trusted to make the call on its own — it proposes, and rules
+ execution + your judgment dispose.

**Two models, fixed roles.** On macOS 27 the co-pilot uses Apple's built-in on-device model for two
narrow jobs: routing a question into the intent catalog (it only picks among options; the harness
writes the SQL) and narrating findings. The frozen Granite-4.1-3B model is the only one that writes
free-form SQL, and only under a grammar. If Apple's model is absent, off, or unsure, everything falls
through to Granite.

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
| `--with-tools` | Set up a container runtime (prefers an existing Colima or Docker Desktop; installs **Colima** if neither is found), Rosetta 2 (for amd64 tools), and pull the forensic-tool images. |
| `--no-model` | Wire everything up but skip the model download (e.g., to pre-stage on a metered connection). |
| `--quick-verify` | Skip the slow end-to-end model test during verification. |
| `--help` | Show usage. |

### 2.3 What gets installed, and where

- A Python virtual environment at `dfir-copilot/.venv` (nothing touches your system Python).
- Python packages: `mlx-lm`, `outlines` + `llguidance` (constrained decoding), `duckdb`,
  `huggingface_hub`.
- The model in the standard Hugging Face cache (`~/.cache/huggingface`).
- The **`clue`** command: a launcher script (`dfir-copilot/dfir-copilot`) linked onto your `PATH` as
  `clue` and, under its long name, `dfir-copilot` — into `~/.local/bin` if that is already on your
  `PATH`, otherwise into Homebrew's bin directory (user-writable; no `sudo`, no shell-rc edits). It
  never overwrites a command that is already there. `DFIR_ALIAS=` before `./install.sh` skips the
  short name; `DFIR_ALIAS=yourname` picks another.

**If the installer could not link it** (it tells you), link the launcher yourself into a directory on
your `PATH` (may prompt for `sudo`); until then `./dfir-copilot` inside the repo is the same program:

```bash
[ -e /usr/local/bin/clue ] || sudo ln -s "$PWD/dfir-copilot" /usr/local/bin/clue
```

### 2.4 Verifying

```bash
clue verify
```

This runs the hard checks — dependencies import, DuckDB reads a sample artifact, deterministic triage
produces a correct verdict, every intent-catalog plan becomes one executing `SELECT`, and Granite loads
and constrained decoding produces a real, executing query — plus two informational ones for Apple's
on-device model (availability, and routing the sample question). The hard checks must say `PASS`; the
Apple ones say `WARN` on a Mac that can't use it, which never fails the install. (Add `--quick` to skip
the slow Granite check.) Unit tests: `pip install -r requirements-dev.txt && pytest`.

---

## 3. The two ways you'll use it

### Query mode — questions about CSV artifacts

Use this when you have a **parsed/structured artifact as CSV** (a log converted to columns, an
EZTools `.csv` export, a Plaso `psort` CSV) and a question.

```bash
clue query "<your question>" <artifact.csv>
```

Two things can happen, and the output says which (`path: catalog` or `path: granite`):

- **Routed (catalog).** If the artifact is a type the catalog knows and Apple's on-device model
  recognises the question as one of the catalog's intents (two votes must agree), the harness writes
  the SQL from a template, runs it, and prints the SQL, a **`meaning:`** line in plain English saying
  exactly what was counted, and the result — in about three seconds, without loading Granite.
- **Granite.** Otherwise the co-pilot reads the artifact's real schema and sample values, has Granite
  write a DuckDB query under the grammar, runs it (read-only), and prints the SQL, the result, and a
  self-consistency score (how many of its samples agreed).

**You read the SQL and decide whether to trust the number.** Add `--cross-check` to run both paths on
a routed question and see whether two independent methods agree; `--backend granite|auto|afm` picks a
path explicitly.

### Triage mode — verdicts from raw tool output

Use this when you have **raw output from a forensic tool** and want a fast, deterministic read on
whether it's interesting.

```bash
<tool> ... | clue triage
# or
clue triage saved_output.txt
```

You get a verdict (`MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `UNDETERMINED`), the priority finding and
why, every indicator with its evidence, and suggested next commands. **No model is involved** in the
verdict — it's deterministic rules, which is exactly why it's trustworthy. Add a grounded prose
summary with `narrate` instead of `triage` if you want the model to explain it (the verdict still
comes from the rules).

---

## 4. Command reference

Every command is `clue <command> …`. `clue` alone prints the cheat sheet; `clue <command> --help`
prints that command's options.

### `query "<question>" <artifact.csv> [--backend auto|granite|afm] [--cross-check]`
Answer a question over a CSV artifact with a verified, read-only DuckDB query.
- **Input:** a natural-language question and a path to a CSV file, question first. The file may
  come first instead: when the second argument is a sentence (it contains a space, is not an
  existing file, and is not path-like) and the first is a file or path-like, the two are swapped.
  Path-like means it ends in a data-file extension (`.csv`, `.tsv`, `.txt`, `.log`, `.gz`, `.json`,
  `.parquet` — spaces or not) or is a single token containing a `/`. In every other case the order
  given stands — `clue query notes.csv typo.csv`, `clue query notes.csv count` and `clue query
  notes.csv "missing artifact.csv"` all report the second argument as missing rather than guessing.
  (The one thing this cannot catch: a file given second that is mistyped, contains a space *and* has
  no data-file extension; it would be read as the question, which the first lines of the output show.)
  The artifact must be an existing file or a glob pattern such as `logs/*.csv`; a typo or a directory
  is reported immediately, before any model loads.
- **Output:** the path taken (`catalog` or `granite`), the SQL, the executed result, a `meaning:` line
  (catalog path) and the agreement (`2/2 router votes`, or the Granite self-consistency vote `4/5`).
- **`--backend`:** `auto` (default: Apple router first, Granite for everything else), `granite`
  (never call Apple's model), `afm` (Apple only; errors instead of falling through — for evaluation).
- **`--cross-check`:** on a routed answer, also run Granite and print `AGREE` or `DISAGREE` with the
  other query and result. Disagreement means read both before trusting either.
- **Exit code:** `0` if a verified query was produced, `2` if not.
- **Notes:** a routed question takes ~3 s; the first Granite call loads the model (~30–60 s), later
  ones are fast. If it can't produce a working query it tells you the last error rather than guessing.

### `ocr <image> [-o file]`
Transcribe a screenshot or photo of tool output with Apple's Vision framework and print the text (or
write it to `file`). No language model is involved: hex dumps, base64 blobs and pipe names come out
as written, which is what the triage detectors need — a language model "reading" the image would
paraphrase them. It is best-effort OCR all the same (a blurry photo can drop or swap a character), so
read the text before relying on a verdict built on it. Phone photos are read the way they display
(EXIF orientation is honoured); `-o` refuses to overwrite the input image. Typical use:
`clue ocr shot.png | clue triage`. Needs macOS (the `pyobjc-framework-Vision`
binding is installed by `install.sh`); elsewhere it explains why it can't run.

### `backends`
Show which models this Mac can use right now: Apple's on-device model (available or why not, licence
status, OS build) and Granite (model id, cached or not). Loads nothing.

### `triage [file]`
Deterministic verdict + findings from tool output. Reads `file` or stdin.
- **Output:** verdict, priority finding + rationale, all findings with evidence, suggested next commands.
- **No model.** Fast and offline. The safe default for "is this interesting?"

### `narrate [file] [--backend auto|granite|afm]`
Same as `triage`, plus an optional model-written prose summary grounded in the deterministic findings.
- The verdict from the rules is authoritative; the narration is advisory color. The last line says who
  narrated (`[narrated by afm]` or `granite`). Apple's model answers in 2–3 s; Granite is the fallback.
- The prompt is bounded: the findings plus an excerpt of the tool output that keeps the lines carrying
  evidence first, so a huge dump still narrates.

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
clue query "how many failed password attempts are there?" auth.csv
clue query "which single source IP has the most events, and how many?" auth.csv
clue query "how many distinct usernames were tried in invalid-user attempts?" auth.csv
clue query "how many lines were flagged as POSSIBLE BREAK-IN ATTEMPT?" auth.csv
```

Each prints the SQL it used (e.g. `... WHERE Content LIKE '%Failed password%'`) so you can confirm it
matched what you meant before you put the number in a report. The top-IP result is your next pivot.

### 5.2 Memory triage with Volatility

```bash
# draft + approve the command, then run it (read-only mount)
clue tools vol3 -f /data/mem.raw windows.malfind | clue triage
```

If `malfind` shows an RWX region inside `lsass.exe`, triage returns `MALICIOUS`, names the indicator,
and suggests dumping the region and pivoting to `windows.netscan`/`windows.pstree`. Run those next:

```bash
clue tools vol3 -f /data/mem.raw windows.pstree | clue triage
```

### 5.2b A photo of a screen

An analyst sends you a phone photo of a locked workstation's console, or pastes a screenshot into a
ticket. Transcribe it and triage the text exactly as you would the tool's own output:

```bash
clue ocr console_photo.jpg | clue triage
```

No language model touches the text, so nothing is paraphrased or invented — but it is OCR: read it
before you trust a verdict on it (a blurry photo can drop or swap a character in a hash or an address).

### 5.3 Timeline pivot with Plaso

```bash
clue tools plaso log2timeline.py --storage-file /out/case.plaso /data/image.E01
clue tools plaso psort.py -o dynamic -w /out/timeline.csv /out/case.plaso
# now ask questions of the timeline as a CSV artifact
clue query "how many events occurred between the first and last logon?" out/timeline.csv
```

Evidence is mounted read-only at `/data`. Anything a tool writes goes to `/out`: by default that is
`./out` on the host, created and mounted only when a command names `/out` (a path such as
`/data/outlook.pst` does not count); if you set `DFIR_OUT=/path`, that directory is created and
mounted on every `clue tools` run instead — never the evidence directory itself or a parent of it,
which is refused.

The pattern is always: **co-pilot drafts → you approve → tool runs read-only → feed the output back
to triage or query.**

---

## 6. How it decides things

Understanding this is what lets you trust the output.

### Query path — routing first (deterministic + Apple's model)
0. **Family and vocabulary.** The harness looks at the CSV header and scans the data for the words
   the catalog knows (`Failed password`, `rhost=`, …). No catalog for this artifact → straight to
   Granite. Otherwise Apple's on-device model is shown the full catalog of options and asked which
   filter, which extracted field and which aggregate answer the question. It answers twice (greedy,
   then sampled); the two must agree after validation, or the question goes to Granite. The harness
   then checks the choice against the artifact and against the analyst's own words: a chosen filter
   whose words never occur in this file is rejected; a question that names a kind of event ("failed
   password"), a field ("source IP" or "rhost", "username", "EventId"), "distinct" or "most" pins that
   part of the plan, a filter other than "all events" must be named in the question or in a quoted
   phrase, and a field must be one its lines can carry — so two votes agreeing on a plausible-but-wrong
   plan are still declined. Anything the analyst
   quotes, and whether the question is about `root`, is taken from the question by the harness, never
   from the model. The harness also declines what the catalog cannot represent — a negation ("except",
   "without"), an account other than root, an unquoted literal value (an IP, a host name, a number),
   a time window, a comparison or an aggregate it lacks ("least", "average", "ratio"), several kinds
   of event at once, or a listing / per-group result — so those questions go to Granite rather than
   getting an answer to a slightly different question. Templates then write one `SELECT` and a
   plain-English explanation. A template that fails to run also falls through.

### Query path — Granite (the "draft" intelligence)
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
dangerous misses. So the rules decide; a model, at most, narrates — Apple's on-device model first
(fast, nothing to load), Granite when it is unavailable.

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

### Add an intent to the catalog
`copilot/catalog.py` holds the same patterns as data so the router can offer them as options: an
`EventFilter` (the substrings a line must contain, a description for the model, a label for the
explanation, and a canonical `root_form` where one exists) or an `Extract` (a regex with one capture
group, or a column). Add the matching line to `DOMAIN_DICT` too — a unit test fails if the two drift
apart. A new artifact family is a header fingerprint in `copilot/family.py` plus its own catalog.

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
container, so the tool can read evidence but cannot modify it. The container engine is **Colima** by
default (free/open-source) — or an existing Docker Desktop — set up by `--with-tools`; if neither is
present, the installer installs and starts Colima (with Rosetta on Apple Silicon).

```bash
cd /path/to/case/artifacts
clue tools list                       # see configured tools + images
clue tools vol3 -f /data/mem.raw windows.pstree
clue tools plaso psort.py -o dynamic -w /out/timeline.csv /out/case.plaso   # outputs land in ./out
```

Tools cannot write under `/data`. Anything they produce goes to `/out`: `./out` on the host, created
and mounted only when a command names `/out` — or, with `DFIR_OUT=/path` set, that directory on
every run (never the evidence directory or a parent of it; that is refused).

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
- **First call latency.** Granite loads once per process (~30–60 s); a routed question does not load
  it (a declined route or `--cross-check` does), so on a Mac with Apple's model the routine questions
  answer in seconds.
- **Apple's model is optional, and not pinned.** It needs macOS 27 with Apple Intelligence on, can be
  switched off by device management, and changes with OS updates (every routed answer records the OS
  build; re-run `verify` after an upgrade). The router only takes questions it is sure about (two
  votes must agree, filters must occur in the data); everything else is Granite's, exactly as before.
- **The `fm` tool has its own terms.** Apple's CLI ties use of its model to the macOS licence and
  asks you to agree once (`fm license`). The co-pilot pins the on-device model and never uses Apple's
  cloud model.

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
| `DFIR_SEED` | unset | seed Granite's sampler for reproducible candidates (evaluation runs) |
| `DFIR_BACKEND` | `auto` | `auto` (Apple router first, Granite fallback), `granite`, or `afm` (Apple only) |
| `DFIR_FM_BIN` | `/usr/bin/fm` | Apple's CLI; point it at a fake to test the fall-through |
| `DFIR_AFM_TIMEOUT` / `DFIR_AFM_PROBE_TIMEOUT` | `30` / `10` | seconds per Apple generation / availability check |
| `DFIR_AFM_GUARDRAILS` | `permissive-content-transformations` | Apple guardrail level for narration and routing |
| `DFIR_ROUTER_VOTES` | `2` | routing votes that must agree (greedy + sampled) |
| `DFIR_NARRATE_MAX_CHARS` | `6000` | tool-output budget in the narration prompt |
| `DFIR_IMG_VOL3` / `DFIR_IMG_PLASO` / `DFIR_IMG_REMNUX` | see `tools/dfir-tools.sh` | override tool images |
| `DFIR_OUT` | unset (`./out`, only when a command names `/out`) | host directory mounted writable at `/out` for tool output; when set, mounted on every `clue tools` run; never the evidence directory or a parent of it |

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| `brew` asks for a password (fresh Mac) | Expected — it's Homebrew's installer, not ours. |
| Container engine not running | `colima start` (Colima), or open Docker Desktop, then `./install.sh --with-tools`. |
| First query hangs ~30–60 s | One-time Granite load; routed questions skip it, and later Granite calls in the same session are fast. |
| `backends` says Apple's model is unavailable | Run `fm license` once, turn on Apple Intelligence (macOS 27+), or ignore it — Granite answers everything. |
| `path: granite` on a question you expected routed | The `router: declined -- …` line says why: the two votes disagreed, the filter's words aren't in this file, or the question has a qualifier the catalog can't represent (a negation, another account, an unquoted IP/host/number, a time window — quote a literal value to match it as text). Nothing is lost; Granite answered. |
| `--cross-check` prints `DISAGREE` | The two paths computed different results. Read both queries; the difference is usually an ambiguity in the question (e.g. whether "message repeated" summary lines count). |
| `mlx` aborts on import in your own scripts | `export MLX_MPI_LIBNAME=libmpi_disabled_does_not_exist.dylib` (the package sets this itself). |
| A query returns "could not produce a verified query" | Rephrase more concretely, or check the artifact has the columns you assume. The shown error tells you what failed. |
| Re-install needed | `./install.sh` is idempotent — just run it again. |
| Out of memory with another big model loaded | The co-pilot peaks ~2.75 GB; close other large local models if you're near the limit. |

---

## 13. FAQ

**Does anything leave my machine?** No. Both models run on-device and all processing is local. Apple's
model is pinned to the on-device `system` model; Apple's cloud model is never used.

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

---

## 14. Uninstalling

The co-pilot is self-contained: it installs into its own virtualenv and the standard Hugging Face model
cache, and it never modifies your system Python. Removing it is a handful of deletes. **Run these from
the repo directory.**

```bash
# 1. the virtualenv and the launcher (created by install.sh)
rm -rf .venv dfir-copilot

# 2. the PATH links -- only symlinks that point at THIS repo's launcher are removed, whatever their names
for d in ~/.local/bin "$(brew --prefix 2>/dev/null || echo /nonexistent)/bin" /usr/local/bin; do
  for f in "$d"/*; do [ -L "$f" ] && [ "$(readlink "$f")" = "$PWD/dfir-copilot" ] && rm "$f"; done
done

# 3. the downloaded model (~2.6 GB) from the shared Hugging Face cache
rm -rf ~/.cache/huggingface/hub/models--mlx-community--granite-4.1-3b-mxfp4
```

If you added the repo to your `PATH`, remove the line you appended to `~/.zshrc`
(`export PATH="…/dfir-copilot:$PATH"`).

If you installed the dockerized forensic tools (`./install.sh --with-tools`), remove their images
(optional — these are shared Docker images):

```bash
docker rmi log2timeline/plaso:latest sk4la/volatility3:latest remnux/remnux-distro:focal
```

If `--with-tools` installed Colima for you (and nothing else uses it), remove it too:

```bash
colima stop && colima delete && brew uninstall colima docker
```

Finally, delete the repo directory itself.

**What the uninstall deliberately leaves alone:** Homebrew, Python, git, the container runtime (Colima
or Docker Desktop), and Rosetta 2 are shared system tools. `install.sh` installed them only if they were missing, but other software may
now depend on them — remove those yourself only if you're certain nothing else needs them. (If you set a
custom `DFIR_MODEL`, delete that model's directory under `~/.cache/huggingface/hub/` instead of the
Granite one in step 3.)
