"""DuckDB helpers + M-Schema builder.

M-Schema = each column rendered as (name:TYPE, examples: [..real sampled cell values..]).
The example values are what teach the model that e.g. 'failed password' lives as a
substring inside Content -- this fixed hallucinated columns and term->filter errors.
Everything is auto-derived from the artifact, so it generalizes to ANY new CSV schema.
"""
import os
import duckdb


def _q(s):
    """Escape a value for a single-quoted SQL string literal (double the quotes)."""
    return str(s).replace("'", "''")


sql_literal = _q


def table_literal(csv_path):
    """The one table the co-pilot ever reads: read_csv_auto('<file>'), resolved via file_search_path."""
    return f"read_csv_auto('{_q(csv_path)}')"


def _ident(name):
    """Escape a DuckDB identifier (double any embedded double-quotes)."""
    return '"' + str(name).replace('"', '""') + '"'


def connect(search_path):
    con = duckdb.connect()
    con.execute(f"SET file_search_path='{_q(search_path)}'")
    return con


def run_sql(sql, search_path):
    """Execute and normalize: scalar for 1x1, list for one row, list-of-lists otherwise."""
    con = connect(search_path)
    r = con.execute(sql).fetchall()
    if len(r) == 1 and len(r[0]) == 1:
        return r[0][0]
    if len(r) == 1:
        return list(r[0])
    return [list(x) for x in r]


def execute(sql, search_path):
    """Return (result, error). error is the verbatim first line of any DuckDB error."""
    if not sql:
        return None, "no sql emitted"
    try:
        return run_sql(sql, search_path), None
    except Exception as e:
        return None, str(e).splitlines()[0][:180]


def sensible(got):
    # "executed without error" is success. 0, [], "" are legitimate answers a query
    # can return (e.g. zero failed-password attempts), so only a true no-result is excluded.
    return got is not None and got != [[]]


def mschema(csv_path, search_path, k=4):
    con = connect(search_path)
    cl = _q(csv_path)
    cols = con.execute(f"DESCRIBE SELECT * FROM read_csv_auto('{cl}')").fetchall()
    lines = []
    for n, t, *_ in cols:
        col = _ident(n)
        rows = con.execute(
            f"SELECT DISTINCT {col} FROM read_csv_auto('{cl}') "
            f"WHERE {col} IS NOT NULL LIMIT {k}").fetchall()
        ex = []
        for (v,) in rows:
            s = str(v)
            ex.append(s if len(s) <= 90 else s[:90] + "...")
        lines.append(f"  ({n}:{t}, examples: {ex})")
    return "\n".join(lines)


def split_path(artifact):
    """A user passes an absolute or relative CSV path; DuckDB reads by basename + search_path."""
    artifact = os.path.abspath(artifact)
    return os.path.dirname(artifact), os.path.basename(artifact)
