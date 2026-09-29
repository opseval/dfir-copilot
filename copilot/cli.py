#!/usr/bin/env python3
"""dfir-copilot -- analyst-facing command line.

  dfir-copilot query "<question>" <artifact.csv>   draft + verify a DuckDB query (read-only)
  dfir-copilot triage <tool_output.txt>            deterministic verdict + findings (no model)
  dfir-copilot narrate <tool_output.txt>           optional grounded model summary
  dfir-copilot backends                            which model backends this Mac can use
  dfir-copilot verify                              run the install smoke tests
  dfir-copilot tools ...                           run a dockerized DFIR tool (see tools/dfir-tools.sh)

Design: the model DRAFTS, the deterministic harness owns correctness, the analyst APPROVES.
"""
import argparse
import os
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


def cmd_query(args):
    from . import config
    from .query_engine import answer
    backend = args.backend or config.BACKEND
    if backend == "granite":
        print("  loading model + building schema grammar (first call is slowest)...", flush=True)
    elif backend == "afm":
        print("  backend=afm: Apple router + intent catalog only (no Granite fallback)"
              + ("; Granite loads (~30-60 s) for the cross-check" if args.cross_check else "") + "...", flush=True)
    else:
        print("  backend=auto: Apple router first; Granite loads (~30-60 s) only if the router declines"
              + (" or for the cross-check" if args.cross_check else "") + "...", flush=True)
    res = answer(args.question, args.artifact, backend=backend, cross_check=args.cross_check)
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
    return subprocess.call([sys.executable, os.path.join(_ROOT, "verify.py")])


def cmd_tools(args):
    script = os.path.join(_ROOT, "tools", "dfir-tools.sh")
    return subprocess.call([script] + args.rest)


def main(argv=None):
    p = argparse.ArgumentParser(prog="dfir-copilot", description="Advisory DFIR co-pilot (local, MLX).")
    sub = p.add_subparsers(dest="cmd", required=True)

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

    b = sub.add_parser("backends", help="show which model backends this Mac can use"); b.set_defaults(fn=cmd_backends)

    v = sub.add_parser("verify", help="run install smoke tests"); v.set_defaults(fn=cmd_verify)

    to = sub.add_parser("tools", help="run a dockerized DFIR tool")
    to.add_argument("rest", nargs=argparse.REMAINDER); to.set_defaults(fn=cmd_tools)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
