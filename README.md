# DFIR Co-Pilot

An **advisory** digital-forensics/incident-response co-pilot that runs entirely on your Mac.
A small local model (Granite-4.1-3B via Apple MLX) **drafts** DuckDB queries and **narrates**
tool output; a deterministic harness **owns correctness**; and **you approve** before anything
is acted on. It fits a 16 GB MacBook Air with room to spare for the forensic tools.

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

**Draft a query over a CSV artifact** (the model writes the SQL, runs it read-only, shows you the
result and the query to approve):

```bash
./dfir-copilot query "how many failed password attempts are there?" copilot/sample/auth_sample.csv
```

**Triage tool output** (deterministic verdict + findings + suggested next commands — no model needed):

```bash
volatility3 -f mem.raw windows.malfind | ./dfir-copilot triage
```

**Triage with an optional grounded summary** from the model (the verdict above is still authoritative):

```bash
./dfir-copilot narrate suspicious_output.txt
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

## How it works (the short version)

```
  you ──▶ dfir-copilot ──▶ small local model (Granite-4.1-3B, frozen)
                │                │
                │   QUERY path   ├─ M-Schema: real column types + sample values from the artifact
                │                ├─ forensic dictionary: term → SQL-pattern cheat-sheet (curated, injected in-context)
                │                ├─ constrained decoding: the model CAN'T emit a wrong table/column
                │                └─ best-of-5 + self-consistency + execute-and-retry  → verified SQL
                │
                │   TRIAGE path  ├─ pre-extraction: 14 deterministic detectors over tool output
                │                └─ triage: verdict from the highest-severity finding (model only narrates)
                ▼
        you approve ──▶ run the command in a dockerized tool
```

- **The model drafts; the harness decides; you approve.** The model never owns a verdict (it
  over-calls); the deterministic rules do.
- **Constrained decoding** is the key lever for queries — it makes corrupted table names and
  invented columns structurally impossible, which is what fine-tuning kept getting wrong.
- **Everything is local.** No data leaves the machine.

Want to broaden coverage to a new artifact type? Add patterns to
`copilot/domain_pack.py` — that's the cheap, $0 way to teach new domain semantics (far better than
fine-tuning, which this project showed actively hurts).

---

## Requirements

- **macOS on Apple Silicon** (M1/M2/M3/M4). Intel works but is slow.
- ~**4 GB** free disk for the model + deps; **16 GB** unified memory is plenty (the model peaks ~2.75 GB).
- **Docker Desktop** only if you want the dockerized forensic tools (`--with-tools`).

The installer handles the rest.

---

## Troubleshooting

- **`brew` asks for a password** on a fresh machine — that's Homebrew's own installer; it's expected.
- **Docker tools say "engine not running"** — open Docker Desktop once, then `./install.sh --with-tools`.
- **First query is slow** (~30-60 s) — that's the one-time model load; subsequent calls are fast.
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

Then delete the repo directory. Homebrew, Python, Docker Desktop, and Rosetta are shared system tools —
the installer only added them if missing; remove those only if nothing else uses them. Full detail:
[USER_GUIDE.md › Uninstalling](USER_GUIDE.md#14-uninstalling).

---

## What's in here

| Path | What |
|---|---|
| `install.sh` | the one-command installer + self-test |
| `verify.py` | the smoke-test suite |
| `copilot/` | the product: query engine, interpretation engine, grammar, forensic dictionary, CLI |
| `tools/dfir-tools.sh` | Docker wrappers for Volatility 3 / Plaso / REMnux |
