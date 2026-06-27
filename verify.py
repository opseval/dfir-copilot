#!/usr/bin/env python3
"""Smoke tests run at the end of install.sh (and via `dfir-copilot verify`).

Proves the whole stack actually works end-to-end:
  1. dependencies import (mlx_lm, outlines, duckdb, llguidance)
  2. DuckDB reads a CSV artifact
  3. deterministic pre-extraction + triage produce a correct verdict
  4. the model loads and constrained decoding produces a VALID, EXECUTING query
Run with --quick to skip the (slow) model test.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import copilot.config  # noqa: E402  -- sets MLX env first

SAMPLE = os.path.join(HERE, "copilot", "sample", "auth_sample.csv")
PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []


def check(name, fn):
    try:
        fn()
        print(f"  [{PASS}] {name}")
        results.append(True)
    except Exception as e:
        print(f"  [{FAIL}] {name}\n         {type(e).__name__}: {str(e)[:160]}")
        results.append(False)


def t_imports():
    import mlx_lm, outlines, duckdb, llguidance  # noqa: F401


def t_duckdb():
    import duckdb
    con = duckdb.connect()
    n = con.execute(f"SELECT count(*) FROM read_csv_auto('{SAMPLE}')").fetchone()[0]
    assert n > 0, "sample CSV read returned 0 rows"


def t_triage():
    from copilot.interp_engine import triage
    raw = ("TimeCreated,Image,ParentImage,CommandLine\n"
           "2026-06-25T11:48:02Z,C:\\Windows\\System32\\wscript.exe,"
           "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE,"
           "\"wscript.exe C:\\Users\\dpatel\\AppData\\Local\\Temp\\report_macro.vbs\"")
    out = triage(raw)
    assert out["verdict"].lower() in ("malicious", "suspicious"), f"got verdict={out['verdict']}"
    assert out["findings"], "no findings extracted"


def t_model_query():
    from copilot.query_engine import answer
    res = answer("How many total log events are there?", SAMPLE)
    assert res["ok"], f"query engine could not produce a verified query: {res.get('error')}"
    assert "SELECT" in (res["sql"] or "").upper(), f"unexpected sql: {res['sql']}"


def main():
    quick = "--quick" in sys.argv
    print("\nDFIR co-pilot — verification")
    print("=" * 40)
    check("dependencies import (mlx_lm, outlines, duckdb, llguidance)", t_imports)
    check("DuckDB reads the sample artifact", t_duckdb)
    check("deterministic pre-extraction + triage verdict", t_triage)
    if quick:
        print("  [skip] model + constrained query (--quick)")
    else:
        print("  ... loading model for the end-to-end query test (~30-60s on first run)")
        check("model loads + constrained decoding produces an executing query", t_model_query)
    print("=" * 40)
    ok = all(results)
    print(("All checks passed. The co-pilot is ready.\n" if ok
           else "Some checks failed — see above.\n"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
