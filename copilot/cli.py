#!/usr/bin/env python3
"""clue -- the analyst-facing command line (the launcher is also linked as `dfir-copilot`).

  clue                                     the cheat sheet below
  clue query "<question>" <artifact.csv>   answer a plain-English question with a verified, read-only query
  clue triage <tool_output.txt>            deterministic verdict + findings (no model)
  clue narrate <tool_output.txt>           the verdict plus a short grounded model summary
  clue ocr <image> [-o out.txt]            transcribe a screenshot of tool output (no language model) -> pipe into triage
  clue backends                            which model backends this Mac can use
  clue verify                              run the install smoke tests
  clue tools ...                           run a dockerized DFIR tool read-only (see tools/dfir-tools.sh)

Design: the model DRAFTS, the deterministic harness owns correctness, the analyst APPROVES.
"""
import argparse
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _print_query(res, question, artifact):
    print(f"\n  question : {question}")
    print(f"  artifact : {artifact}")
    print("  " + "-" * 60)
    if res["ok"]:
        routed = res.get("path") == "catalog"
        print(f"  path     : {res.get('path')}  "
              + ("(Apple router -> intent catalog -> deterministic SQL)" if routed else "(Granite, grammar-constrained)"))
        if res.get("decline_reason"):
            print(f"  router   : declined -- {res['decline_reason']}")
        print(f"  SQL      : {res['sql']}")
        if res.get("explanation"):
            print(f"  meaning  : {res['explanation']}")
        print(f"  result   : {res['result']}")
        print(f"  agreement: {res['votes']} " + ("router votes" if routed else "samples  (self-consistency)"))
        prov = res.get("provenance") or {}
        if routed:
            print(f"  answered : Apple on-device model, macOS {prov.get('macos', '?')}  (the model changes with the OS; this build is your record)")
        elif prov.get("model"):
            print(f"  answered : Granite {prov['model']}")
        cc = res.get("cross_check")
        if cc:
            if not cc.get("executed"):
                print(f"  cross    : NOT CHECKED -- Granite produced no runnable query ({cc.get('other_error')})")
            elif cc["agree"]:
                print(f"  cross    : AGREE -- Granite reached the same result via: {cc['other_sql']}")
            else:
                print(f"  cross    : DISAGREE -- Granite got {cc['other_result']!r} via: {cc['other_sql']}")
                print("             Review both queries before relying on either.")
        print("\n  -> Review the SQL above and approve before relying on it.\n")
    else:
        print(f"  Could not produce a verified query. Last error: {res['error']}")
        print("  -> Try rephrasing, or check the artifact/columns.\n")


_DATA_EXT = {".csv", ".tsv", ".txt", ".log", ".gz", ".json", ".parquet"}


def _pathiness(s):
    """How much a `query` positional looks like the artifact: 2 = an existing regular file; 1 = path-like
    (ends in a data-file extension, spaces or not, or is a single token with a path separator); 0 = neither."""
    if os.path.isfile(s):
        return 2
    if os.path.splitext(s)[1].lower() in _DATA_EXT or (os.sep in s and not re.search(r"\s", s)):
        return 1
    return 0


def _sentence(s):
    """Prose, not a path: contains whitespace and is neither an existing file nor path-like. A string
    that ends in a data-file extension is never a sentence, so `"missing artifact.csv"` stays a path."""
    return bool(re.search(r"\s", s)) and _pathiness(s) == 0


def _is_glob(s):
    return any(c in s for c in "*?[")


def cmd_query(args):
    import duckdb
    from . import config
    from . import schema as S
    from .grammar import columns_of
    from .query_engine import answer
    # The file may come first. Rule (USER_GUIDE § 4): swap only when the artifact slot holds a sentence
    # (whitespace, and not a file or a path-like token) and the question slot holds a file or a path-like
    # token. Every other combination keeps the documented order (question first), so a mistyped
    # artifact -- `typo.csv`, or a bare `missing` -- is reported as such, never displaced by a guess.
    if _sentence(args.artifact) and _pathiness(args.question) > 0:
        args.question, args.artifact = args.artifact, args.question
    # Anything that is not a regular file is reported here, before any model loads. A directory is
    # never read implicitly (even one named like a glob); glob patterns are left to DuckDB to expand.
    if os.path.isdir(args.artifact):
        print(f"Error: artifact is a directory: {args.artifact} (pass a file, or a pattern such as "
              f"'{args.artifact.rstrip(os.sep)}/*.csv')", file=sys.stderr)
        return 2
    if not os.path.isfile(args.artifact) and not _is_glob(args.artifact):
        print(f"Error: artifact not found: {args.artifact}", file=sys.stderr)
        return 2
    try:                                            # DuckDB must be able to read it -- before any model loads
        search_path, csv = S.split_path(args.artifact)
        columns_of(csv, search_path)
    except duckdb.Error as e:                       # empty glob, not a CSV, unreadable: one line, no traceback
        print(f"Error: could not read {args.artifact}: {str(e).strip().splitlines()[0]}", file=sys.stderr)
        return 2
    backend = args.backend or config.BACKEND
    if backend == "granite":
        print("  loading model + building schema grammar (first call is slowest)...", flush=True)
    elif backend == "afm":
        print("  backend=afm: Apple router + intent catalog only (no Granite fallback)"
              + ("; Granite loads (~30-60 s) for the cross-check" if args.cross_check else "") + "...", flush=True)
    else:
        print("  backend=auto: Apple router first; Granite loads (~30-60 s) only if the router declines"
              + (" or for the cross-check" if args.cross_check else "") + "...", flush=True)
    try:
        res = answer(args.question, args.artifact, backend=backend, cross_check=args.cross_check)
    except duckdb.Error as e:                       # backstop: the artifact changed under us, or a new read path
        print(f"Error: could not read {args.artifact}: {str(e).strip().splitlines()[0]}", file=sys.stderr)
        return 2
    _print_query(res, args.question, args.artifact)
    return 0 if res["ok"] else 2


def _read_input(file):
    if not file:
        return sys.stdin.read()
    try:
        with open(file) as fh:
            return fh.read()
    except FileNotFoundError:
        print(f"Error: file not found: {file}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error: could not read {file}: {e}", file=sys.stderr)
        return None


def cmd_triage(args):
    from .interp_engine import triage
    raw = _read_input(args.file)
    if raw is None:
        return 2
    print(triage(raw)["report"])
    return 0


def cmd_narrate(args):
    from . import config
    from .interp_engine import triage, narrate
    raw = _read_input(args.file)
    if raw is None:
        return 2
    print(triage(raw)["report"])  # deterministic verdict first (authoritative)
    backend = args.backend or config.BACKEND
    print(f"\n  --- model narration (backend={backend}; advisory; verdict above is authoritative) ---")
    try:
        out = narrate(raw, backend=backend)
        print("  " + out["text"].strip().replace("\n", "\n  "))
        print(f"  [narrated by {out['provenance'].get('backend')}]")
    except Exception as e:
        print(f"  (narration unavailable: {e}; the verdict above is deterministic and stands)")
    return 0


def cmd_ocr(args):
    """Screenshot / photo of tool output -> text with Apple's Vision framework (best-effort OCR; no language model).
    Pipe the result into `triage`."""
    from .ocr import OCRUnavailable, ocr
    if args.out:
        try:                                    # never write over the evidence image (also via links)
            if os.path.exists(args.out) and os.path.samefile(args.out, args.image):
                print("Error: the output path is the input image; choose another file", file=sys.stderr)
                return 2
        except OSError as e:
            print(f"Error: cannot check {args.out}: {e}", file=sys.stderr)
            return 2
    try:
        text = ocr(args.image)
    except OCRUnavailable as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    if args.out:
        try:
            with open(args.out, "w") as fh:
                fh.write(text + "\n")
        except OSError as e:
            print(f"Error: cannot write {args.out}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {len(text.splitlines())} lines to {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_backends(args):
    """Report which backends this Mac can use right now. Loads no model."""
    from . import afm, config
    ok, reason = afm.available(refresh=True)
    print("\n  Apple Foundation Models (on-device, macOS 27+)")
    print(f"    status  : {'available' if ok else 'unavailable'} -- {reason}")
    print(f"    binary  : {config.FM_BIN}")
    print(f"    macOS   : {afm.provenance()['macos']}")
    print("    role    : question routing + narration (never SQL values, never verdicts)")
    try:                                   # a COMPLETE local snapshot, not merely a cache directory
        from huggingface_hub import snapshot_download
        snapshot_download(config.MODEL_ID, local_files_only=True)
        cached = "yes"
    except Exception:
        cached = "no (or incomplete) -- run ./install.sh"
    print("\n  Granite (local MLX, grammar-constrained SQL)")
    print(f"    model   : {config.MODEL_ID}")
    print(f"    cached  : {cached}")
    print(f"\n  default backend: {config.BACKEND}   (DFIR_BACKEND=granite|auto|afm)\n")
    return 0


def cmd_verify(args):
    argv = [sys.executable, os.path.join(_ROOT, "verify.py")]
    if args.quick:
        argv.append("--quick")
    return subprocess.call(argv)


def cmd_tools(args):
    script = os.path.join(_ROOT, "tools", "dfir-tools.sh")
    return subprocess.call([script] + args.rest)


def cheatsheet(prog):
    """What `clue` on its own prints: the handful of things you do with it, one line each."""
    return f"""
  {prog} — advisory DFIR co-pilot. Everything runs on this Mac; it drafts, you approve.

    {prog} query "<question>" <artifact.csv>     ask a plain-English question of a CSV artifact
                                                (the file may come first; the SQL is shown for approval)
    <tool> ... | {prog} triage                    verdict + findings from tool output (deterministic, no model)
    {prog} narrate <output.txt>                  the verdict plus a short grounded summary
    {prog} ocr <screenshot.png> | {prog} triage    transcribe a screenshot or photo of tool output, then triage it
    {prog} backends                              what this Mac can use (Apple on-device model, Granite)
    {prog} verify                                self-test the install
    {prog} tools vol3|plaso|remnux ...           run a dockerized forensic tool read-only (after --with-tools)

  Add --help to any command for its options.
"""


def main(argv=None):
    # the launcher exports the name it was invoked by (`clue` or `dfir-copilot`) so help reads naturally;
    # anything that is not a plain command name is ignored (argparse prints prog verbatim)
    prog = os.environ.get("DFIR_PROG") or ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", prog):
        prog = "dfir-copilot"
    p = argparse.ArgumentParser(prog=prog, description="Advisory DFIR co-pilot (local, MLX).",
                                epilog=f"run `{prog}` with no arguments for the cheat sheet")
    sub = p.add_subparsers(dest="cmd")

    q = sub.add_parser("query", help="draft + verify a DuckDB query over a CSV artifact")
    q.add_argument("question"); q.add_argument("artifact")
    q.add_argument("--backend", choices=["auto", "granite", "afm"], default=None,
                   help="auto = Apple router first, Granite fallback; granite = the constrained model only; "
                        "afm = Apple only (default: DFIR_BACKEND)")
    q.add_argument("--cross-check", action="store_true",
                   help="on a routed answer, also run Granite and report whether the two paths agree")
    q.set_defaults(fn=cmd_query)

    t = sub.add_parser("triage", help="deterministic verdict + findings from tool output")
    t.add_argument("file", nargs="?"); t.set_defaults(fn=cmd_triage)

    n = sub.add_parser("narrate", help="deterministic verdict + an optional grounded model summary")
    n.add_argument("file", nargs="?")
    n.add_argument("--backend", choices=["auto", "granite", "afm"], default=None,
                   help="who narrates: auto = Apple first, Granite fallback (default: DFIR_BACKEND)")
    n.set_defaults(fn=cmd_narrate)

    o = sub.add_parser("ocr", help="transcribe a screenshot or photo of tool output (Vision.framework; no language model)")
    o.add_argument("image"); o.add_argument("-o", "--out", help="write the text here instead of stdout")
    o.set_defaults(fn=cmd_ocr)

    b = sub.add_parser("backends", help="show which model backends this Mac can use"); b.set_defaults(fn=cmd_backends)

    v = sub.add_parser("verify", help="run install smoke tests")
    v.add_argument("--quick", action="store_true", help="skip the slow model test")
    v.set_defaults(fn=cmd_verify)

    to = sub.add_parser("tools", help="run a dockerized DFIR tool")
    to.add_argument("rest", nargs=argparse.REMAINDER); to.set_defaults(fn=cmd_tools)

    args = p.parse_args(argv)
    if not args.cmd:                                # `clue` alone is a question, not a mistake
        print(cheatsheet(prog))
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
