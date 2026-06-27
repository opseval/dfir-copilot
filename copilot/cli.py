#!/usr/bin/env python3
"""dfir-copilot -- analyst-facing command line.

  dfir-copilot query "<question>" <artifact.csv>   draft + verify a DuckDB query (read-only)
  dfir-copilot triage <tool_output.txt>            deterministic verdict + findings (no model)
  dfir-copilot narrate <tool_output.txt>           optional grounded model summary
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
        print(f"  SQL      : {res['sql']}")
        print(f"  result   : {res['result']}")
        print(f"  agreement: {res['votes']} samples  (self-consistency)")
        print("\n  -> Review the SQL above and approve before relying on it.\n")
    else:
        print(f"  Could not produce a verified query. Last error: {res['error']}")
        print("  -> Try rephrasing, or check the artifact/columns.\n")


def cmd_query(args):
    from .query_engine import answer
    print("  loading model + building schema grammar (first call is slowest)...", flush=True)
    res = answer(args.question, args.artifact)
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
    from .interp_engine import triage, narrate
    raw = _read_input(args.file)
    if raw is None:
        return 2
    print(triage(raw)["report"])  # deterministic verdict first (authoritative)
    print("\n  --- model narration (advisory; verdict above is authoritative) ---")
    try:
        print("  " + narrate(raw).strip().replace("\n", "\n  "))
    except Exception as e:
        print(f"  (narration unavailable: {e}; the verdict above is deterministic and stands)")
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
    q.add_argument("question"); q.add_argument("artifact"); q.set_defaults(fn=cmd_query)

    t = sub.add_parser("triage", help="deterministic verdict + findings from tool output")
    t.add_argument("file", nargs="?"); t.set_defaults(fn=cmd_triage)

    n = sub.add_parser("narrate", help="deterministic verdict + an optional grounded model summary")
    n.add_argument("file", nargs="?"); n.set_defaults(fn=cmd_narrate)

    v = sub.add_parser("verify", help="run install smoke tests"); v.set_defaults(fn=cmd_verify)

    to = sub.add_parser("tools", help="run a dockerized DFIR tool")
    to.add_argument("rest", nargs=argparse.REMAINDER); to.set_defaults(fn=cmd_tools)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
