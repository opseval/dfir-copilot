# DFIR Co-Pilot

An **advisory** digital-forensics/incident-response co-pilot that runs entirely on your Mac.
Two small on-device models do the drafting — Apple's built-in model (macOS 27) **routes** a
plain-English question into a curated intent catalog and **narrates** findings, and a frozen
Granite-4.1-3B (via Apple MLX) **drafts** free-form DuckDB queries under a grammar — while a
deterministic harness **owns correctness**, and **you approve** before anything is acted on. It fits
a 16 GB MacBook Air with room to spare for the forensic tools.

It is built on one hard-won result: with the right *structure* around it, an **untuned** 3B model
beats a fine-tuned one **3.5×** on held-out forensic queries — so we ship the base model frozen
and put the intelligence in the harness, not the weights.

---

## Install (one command)

```bash
./install.sh
```

That's it. On a **fresh** Mac it installs Homebrew, Python, the dependencies, downloads the model
(~2.6 GB), wires up the `dfir-copilot` command, and runs a self-test. On an **existing** Mac it
detects what you already have and installs only what's missing. Safe to re-run.

Add the dockerized forensic tools (Volatility 3, Plaso, …) when you want them:

```bash
./install.sh --with-tools
```

Other flags: `--no-model` (wire everything but skip the download), `--quick-verify` (skip the slow
end-to-end model test). Run `./install.sh --help` for the list.

### Run it from anywhere (optional)

The installer drops a `dfir-copilot` launcher in the repo. If `~/.local/bin` is already on your
`PATH`, it's symlinked there automatically and you can just type `dfir-copilot` from any directory.
Otherwise, **from the repo directory**, add it to your `PATH` once (zsh is the macOS default shell):

```bash
echo "export PATH=\"$PWD:\$PATH\"" >> ~/.zshrc && source ~/.zshrc
```

…or symlink the launcher into a directory already on your `PATH` (may prompt for `sudo`):

```bash
ln -sf "$PWD/dfir-copilot" /usr/local/bin/dfir-copilot
```

After either, `dfir-copilot query "…" artifact.csv` works from anywhere. The `./dfir-copilot` examples
below also work as-is from inside the repo.

> New here? The **[comprehensive user guide](USER_GUIDE.md)** covers everything — installation
> details, every command, end-to-end investigation walkthroughs, how it decides things, how to
> extend it, safety, limitations, and an FAQ.

---

## Use

**Ask a question about a CSV artifact** (a routine question is routed through the intent catalog and
answered from deterministic SQL in ~3 s, with a plain-English line saying what the query computes;
anything else goes to Granite, which writes the SQL under a grammar; either way it runs read-only and
shows you the result and the query to approve):

```bash
./dfir-copilot query "how many failed password attempts are there?" copilot/sample/auth_sample.csv
./dfir-copilot query "which single source IP has the most events?" auth.csv --cross-check   # both paths, flag disagreement
./dfir-copilot backends                                                                     # which models this Mac can use
```

**Triage tool output** (deterministic verdict + findings + suggested next commands — no model needed):

```bash
volatility3 -f mem.raw windows.malfind | ./dfir-copilot triage
```

**Triage with an optional grounded summary** from the model (the verdict above is still authoritative):

```bash
./dfir-copilot narrate suspicious_output.txt
```

**Triage a screenshot or photo of tool output** (a console someone photographed, a screenshot pasted into
a ticket): Apple's Vision framework transcribes it with no language model in the loop — hex and encoded
blobs come through as written rather than paraphrased — and the text goes into triage. It is still OCR:
read the transcription before relying on a verdict built on it.

```bash
./dfir-copilot ocr screenshot.png | ./dfir-copilot triage
```

**Run a forensic tool** the co-pilot drafted a command for (after `--with-tools`):

```bash
./dfir-copilot tools vol3 -f /data/mem.raw windows.pstree
```

**Re-check everything works:**

```bash
./dfir-copilot verify
```

---

## What you'd actually use it for

**Who it's for:** a mixed-experience security team — from a tier-1 SOC analyst who isn't a forensics specialist, up to a seasoned DFIR examiner. It **raises the floor** (juniors miss less and move faster) without slowing the experts down. It is strictly **advisory**: it drafts and explains; you approve and run everything.

Two concrete jobs, matching the two modes above:

**1. Ask a question about an artifact in plain English (query mode).** You have a parsed log or tool export as a CSV — an SSH auth log, a Windows event-log export, an EZTools artifact, a Plaso timeline — and a question you'd otherwise hand-write SQL for. You ask in plain English; it writes the query, runs it **read-only**, and shows you *both* the answer and the exact SQL, so you can confirm it asked what you meant before trusting the number. Typical questions:
- "How many failed password attempts are in this auth log?"
- "Which single source IP has the most events, and how many?"
- "How many distinct usernames were tried in invalid-user attempts?"

**2. Triage whether tool output is interesting (triage mode).** You pipe the raw output of a forensic tool — a Volatility memory scan, a Plaso timeline, an event-log dump — into it and get back a **verdict** (`MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `UNDETERMINED`), the specific **indicators** found with the evidence for each, and the **suggested next commands**. For example, a Volatility `malfind` hit showing an executable-and-writable region inside `lsass.exe` comes back `MALICIOUS`, names the indicator, and suggests dumping the region and pivoting to the network and process-tree views — so a junior doesn't already have to know how to read `malfind`.

**The workflow is always the same shape:** **drafts → you approve → the tool runs read-only → you feed the output back** into the next triage or query. A human is in the loop on every action.

**What it is *not*:** not an autonomous agent that runs investigations by itself, not a malware sandbox or detonation platform, and not a substitute for an analyst's judgment. It handles the common, well-trodden **80%** quickly so you can spend your attention on the hard **20%**.

---

## How it works (the short version)

```
  you ──▶ dfir-copilot
              │
              │   QUERY path
              │     ├─ artifact family: deterministic (header fingerprint + the words actually in the data)
              │     ├─ in the catalog?  Apple's on-device model picks an INTENT — enums only, two votes must agree —
              │     │      and the harness writes the SQL from templates, plus a plain-English explanation   (~3 s)
              │     └─ otherwise Granite-4.1-3B (frozen) under the grammar:
              │            M-Schema (real column types + sample values) + forensic dictionary (curated cheat-sheet)
              │            + constrained decoding (it CAN'T emit a wrong table/column)
              │            + best-of-5 + self-consistency + execute-and-retry  → verified SQL
              │
              │   TRIAGE path
              │     ├─ pre-extraction: 14 deterministic detectors over tool output
              │     └─ triage: verdict from the highest-severity finding; a model only narrates (Apple first, Granite fallback)
              ▼
        you approve ──▶ run the command in a dockerized tool
```

- **The models draft; the harness decides; you approve.** No model ever owns a verdict (they
  over-call); the deterministic rules do.
- **Two models, fixed roles.** Apple's model only ever chooses among catalog options or narrates
  findings — it never writes a SQL value and never touches a verdict. Granite is the only model that
  writes SQL, and only under the grammar. Whenever Apple's model is unavailable (older macOS, Apple
  Intelligence off, a timeout, or a question the router isn't sure about) the co-pilot falls through
  to Granite: the same workflow and the same guarantees, with Granite's SQL and result — which can
  differ from the catalog's on the questions the two paths read differently — and its load time.
- **Constrained decoding** is the key lever for free-form queries — it makes corrupted table names
  and invented columns structurally impossible, which is what fine-tuning kept getting wrong.
- **Everything is local.** No data leaves the machine; Apple's cloud model is never used.

Want to broaden coverage to a new artifact type? Add patterns to
`copilot/domain_pack.py` — that's the cheap, $0 way to teach new domain semantics (far better than
fine-tuning, which this project showed actively hurts).

---

## What "the scaffolding" actually is, in plain terms

"Scaffolding" (or "structure") means **the ordinary, rule-based software wrapped around the model** — the part that does the reliable work. A mental picture: the untuned model is a *fast but over-confident junior* who will happily write something that looks authoritative even when it's wrong. The scaffolding is what a good senior puts in front of that junior. Each piece, and the failure it prevents:

**For drafting queries**

- **The schema sheet ("M-Schema").** Before the model writes anything, the software reads the *actual* artifact and hands it the real column names, types, and a few sample values. *Without it* the model invents columns; *with it* it can see that `Content` literally contains `"Failed password for invalid user…"` and filter on that. (`copilot/schema.py`)
- **The forensic phrasebook (domain dictionary).** A hand-curated cheat-sheet mapping an analyst's concepts to the right query pattern (*"invalid user"* → the exact `LIKE` filter), supplied as **editable text, not baked into the model** — this is the file you grow over time instead of retraining. (`copilot/domain_pack.py`)
- **The intent catalog (the phrasebook as data).** The same patterns, structured so that software can fill them in: Apple's on-device model is shown the catalog's *options* (which kind of line, what to pull out, how to aggregate — and and picks one; the harness rejects a choice whose words do not occur in the artifact; two votes must agree; then plain templates write the SQL and a one-line explanation. The model never writes a value, so the dictionary's discipline rules (drop syslog "message repeated" wrappers, ignore empty extractions) are applied every time. A test keeps catalog and phrasebook in lock-step. (`copilot/catalog.py`, `copilot/router.py`, `copilot/family.py`)
- **The stencil (constrained decoding).** The model's output is forced to fit valid SQL using only columns that exist in *this* file, so emitting a wrong table or invented column is **physically impossible** — the single biggest reliability win, and exactly what fine-tuning kept getting wrong. (`copilot/grammar.py`)
- **Ask-five-and-check (best-of-N + self-consistency + execute-and-retry).** It drafts several candidate queries, **actually runs each one**, keeps the answer the most candidates agree on, and on failure feeds the database's own error back and retries — so a wrong outlier gets out-voted and a query that doesn't run can't masquerade as correct. (`copilot/query_engine.py`)

**For interpreting tool output**

- **The detector bank (deterministic rules).** Plain, auditable rules scan tool output for known danger signs (Office spawning a script host, executable-writable memory in `lsass`, persistence registry keys, specific Windows Event IDs, webshell writes, …). **The model is not involved in the verdict at all.** If no rule matches, it returns `UNDETERMINED — manual review` rather than guessing. (`copilot/preextract.py`, `copilot/triage.py`)
- **The narrator (optional).** Only *after* the rules have decided does the model get a turn — to write a readable summary of what the rules found. Its prose is advisory color; the verdict belongs to the rules. (`copilot/interp_engine.py`)

**Read-only by construction**

There is no write path to evidence anywhere in the product: the query side is restricted to read-only `SELECT` (the constrained-decoding grammar enforces it), and the dockerized forensic tools run against evidence mounted **read-only**. Combined with *you approve before anything runs*, evidence cannot be altered in normal operation.

The thread through all of it: **anything that has to be *correct* is owned by deterministic, auditable code; the model is only ever a drafter and narrator on top.** That's why swapping in a different base model barely changes the results — the reliability was never coming from the model's "brain."

---

## Honest limitations

Most of these are deliberate consequences of the "structure beats weights" design, not rough edges to be filed off later.

- **The model never makes the call — by design.** Trust the deterministic verdict and the *shown* SQL; treat any model prose as color, not authority.
- **It adapts to new file *layouts*, not new *meaning*.** Point it at a CSV it has never seen and it reads the columns and writes valid SQL. But what's *forensically interesting* in a given artifact type comes from the curated phrasebook and detectors — on an uncovered type it still produces valid, runnable queries but may filter on the wrong thing. It degrades gracefully (wrong-but-valid, or "undetermined") rather than failing loudly. The fix is a few lines of curation in `copilot/domain_pack.py`, **never** retraining.
- **Interpretation only covers patterns someone has written a rule for.** A genuinely novel technique with no matching detector returns `UNDETERMINED — manual review`. That's the *safe* failure mode (never a confident wrong "all-clear"), but coverage is only as broad as the rules you've written, and it grows by adding detectors.
- **It's a small model, by requirement.** It reliably handles common, well-trodden questions; for unusual multi-step analytical reasoning, write the SQL yourself or escalate to a larger model. It does the routine 80%, not the senior-examiner 20%.
- **Scope is single, structured artifacts.** Query mode works on one CSV-shaped artifact at a time; it does not correlate across many sources for you, build the timeline itself, or do dynamic / malware-detonation analysis.
- **It only ever advises; a human must act.** Every tool command is proposed for approval and run by the analyst; nothing executes autonomously.
- **Operational limits.** Apple-Silicon Macs (via MLX); Granite loads once per session (~30–60 s on the first call, fast thereafter) and peaks ~2.75 GB of memory, so watch your RAM if you run other large local models alongside the forensic tools. A routed question does not load it; a declined route or `--cross-check` does.
- **Apple's model is optional and can change under you.** The routed path needs macOS 27 with Apple Intelligence on; a managed Mac may have it switched off, and the model updates with the OS rather than being pinned like Granite — so every routed answer records the OS build it came from, and `dfir-copilot backends` shows what is active. The `fm` tool's terms tie its use to the macOS licence; read them once (`fm license`). Without it, everything still works through Granite.
- **Coverage is an ongoing curation commitment.** Because the intelligence lives in editable files (the dictionary and detectors), the system is only as good as the team keeps them current — transparent and **$0** to extend, but a continuing *human* responsibility, not something the model improves on its own.

---

## Requirements

- **macOS on Apple Silicon** (M1/M2/M3/M4). Intel works but is slow.
- **macOS 27 with Apple Intelligence enabled** for the fast routed path (optional — everything works without it).
- ~**4 GB** free disk for the model + deps; **16 GB** unified memory is plenty (Granite peaks ~2.75 GB; Apple's model costs nothing extra).
- **A container runtime** only if you want the dockerized forensic tools (`--with-tools`). It prefers an
  existing Colima or Docker Desktop, and installs **[Colima](https://github.com/abiosoft/colima)** (free,
  open-source, no subscription) if neither is present.

The installer handles the rest.

---

## Troubleshooting

- **`brew` asks for a password** on a fresh machine — that's Homebrew's own installer; it's expected.
- **Docker tools say "engine not running"** — start your engine (`colima start`, or open Docker Desktop), then `./install.sh --with-tools`.
- **First query is slow** (~30-60 s) — that's the one-time Granite load; routed questions skip it, and subsequent Granite calls in a process are fast.
- **`backends` says the Apple model is unavailable** — run `fm license` once, turn on Apple Intelligence (macOS 27+), or just carry on: the Granite path answers everything, only slower.
- **`mlx` aborts on import** — handled automatically (`copilot/config.py` disables MPI auto-load), but
  if you hit it in your own scripts, `export MLX_MPI_LIBNAME=libmpi_disabled_does_not_exist.dylib`.
- **Re-running the installer** is always safe — it skips what's already done.

---

## Uninstall

The co-pilot is self-contained — it installs into its own virtualenv and the standard model cache and
never touches your system Python. To remove it cleanly, **from inside the repo**:

```bash
rm -rf .venv dfir-copilot                                     # virtualenv + launcher
rm -f  ~/.local/bin/dfir-copilot /usr/local/bin/dfir-copilot  # any PATH symlinks
rm -rf ~/.cache/huggingface/hub/models--mlx-community--granite-4.1-3b-mxfp4   # the model (~2.6 GB)
```

If you added the repo to your `PATH`, also delete that `export PATH=…` line from `~/.zshrc`. If you
installed the dockerized tools (`--with-tools`), drop their images (optional):

```bash
docker rmi log2timeline/plaso:latest sk4la/volatility3:latest remnux/remnux-distro:focal
```

If the installer set up Colima for you (and nothing else uses it), remove it too:
`colima stop && colima delete && brew uninstall colima docker`.

Then delete the repo directory. Homebrew, Python, the container runtime (Colima/Docker Desktop), and
Rosetta are shared system tools — the installer only added them if missing; remove those only if nothing
else uses them. Full detail: [USER_GUIDE.md › Uninstalling](USER_GUIDE.md#14-uninstalling).

---

## What's in here

| Path | What |
|---|---|
| `install.sh` | the one-command installer + self-test |
| `verify.py` | the smoke-test suite |
| `copilot/` | the product: query engine (Apple router + intent catalog, Granite grammar path), interpretation engine, forensic dictionary, Vision OCR, CLI |
| `tests/` | unit tests (`pytest`; no model needed — a fake `fm` stands in for Apple's CLI) |
| `tools/dfir-tools.sh` | Docker wrappers for Volatility 3 / Plaso / REMnux |
