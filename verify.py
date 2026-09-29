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
PASS, FAIL, WARN = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m", "\033[33mWARN\033[0m"
results = []


def check(name, fn):
    try:
        fn()
        print(f"  [{PASS}] {name}")
        results.append(True)
    except Exception as e:
        print(f"  [{FAIL}] {name}\n         {type(e).__name__}: {str(e)[:160]}")
        results.append(False)


def warn_check(name, fn):
    """Informational only: the optional Apple backend must never fail an install (it can be absent,
    switched off by device management, or change with an OS update); the Granite path stands."""
    try:
        msg = fn()
        print(f"  [{PASS}] {name}" + (f"  ({msg})" if msg else ""))
    except Exception as e:
        print(f"  [{WARN}] {name}\n         {type(e).__name__}: {str(e)[:160]}")


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


def t_catalog():
    """Every plan the intent catalog accepts becomes ONE SELECT that executes on the sample artifact. No model."""
    from copilot import catalog as C
    from copilot.schema import execute
    n = 0
    for q in ("How many events are there in total?", "How many 'Accepted' lines are there?",
              "Which source IP appears most often?", "How many 'session opened' events for the root user?"):
        for ef in C.EVENT_FILTERS:
            for ex in C.EXTRACTS:
                for ag in C.AGGREGATES:
                    plan = {"event_filter": ef, "extract_field": ex, "aggregate": ag}
                    if C.validate(plan, q)[0] is None:
                        continue
                    sql = C.plan_to_sql(plan, q, os.path.basename(SAMPLE))
                    assert sql.startswith("SELECT "), sql
                    _, err = execute(sql, os.path.dirname(SAMPLE))
                    assert err is None, f"{plan}: {err}"
                    n += 1
    assert n > 0, "no valid plans"


def t_afm():
    """Optional on-device Apple model (macOS 27+): reports availability; never required."""
    from copilot import afm
    ok, reason = afm.available(refresh=True)
    if not ok:
        raise RuntimeError(f"unavailable: {reason} -- the Granite path is used instead")
    return reason


def t_router():
    """Optional: the Apple router sends the README sample question to the catalog and matches DuckDB."""
    from copilot import afm
    from copilot.query_engine import answer
    from copilot.schema import execute
    ok, reason = afm.available(refresh=True)
    if not ok:
        raise RuntimeError(f"skipped: {reason}")
    res = answer("how many failed password attempts are there?", SAMPLE, backend="afm")
    assert res["ok"], f"router fell through: {res.get('error')}"
    truth, _ = execute("SELECT count(*) FROM read_csv_auto('auth_sample.csv') WHERE Content LIKE '%Failed password%' "
                       "AND Content NOT LIKE '%message repeated%'", os.path.dirname(SAMPLE))
    assert res["result"] == truth, f"catalog result {res['result']} != DuckDB truth {truth}"
    return f"path={res['path']}, result={res['result']}, votes={res['votes']}"


def t_model_query():
    from copilot.query_engine import answer
    res = answer("How many total log events are there?", SAMPLE, backend="granite")
    assert res["ok"], f"query engine could not produce a verified query: {res.get('error')}"
    assert "SELECT" in (res["sql"] or "").upper(), f"unexpected sql: {res['sql']}"


def main():
    quick = "--quick" in sys.argv
    print("\nDFIR co-pilot — verification")
    print("=" * 40)
    check("dependencies import (mlx_lm, outlines, duckdb, llguidance)", t_imports)
    check("DuckDB reads the sample artifact", t_duckdb)
    check("deterministic pre-extraction + triage verdict", t_triage)
    check("intent catalog: every plan is one executing SELECT (no model)", t_catalog)
    warn_check("Apple Foundation Models on-device backend (optional)", t_afm)
    warn_check("Apple router -> intent catalog on the sample question (optional)", t_router)
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
