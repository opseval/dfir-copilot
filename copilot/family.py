"""Artifact-family detection: deterministic, from the CSV header plus a vocabulary check.

A family is a header fingerprint the catalog knows. The vocabulary check guards the semantics: a
LogHub-shaped CSV whose Content never mentions any catalog term (an HDFS log, say) gets no family,
so the router is skipped and the question goes to Granite. To add a family: add its fingerprint here
and its catalog in catalog.py.
"""
from . import catalog
from . import schema as S

LOGHUB_COLS = {"LineId", "Content", "EventId", "EventTemplate"}
# Unambiguous sshd / PAM markers in the message text. Catalog substrings such as 'Accepted ' or
# 'authentication failure' also occur in unrelated logs, so the family needs one of these somewhere in
# the data as well. PAM's pam_unix message format ('rhost=', 'logname=', 'session opened for user',
# 'check pass; user unknown') counts because syslog-style logs keep 'sshd'/'pam_unix' in another column.
STRONG_MARKERS = ("sshd", "pam_unix", "Failed password", "Invalid user ", "POSSIBLE BREAK-IN ATTEMPT",
                  "rhost=", "logname=", "session opened for user", "check pass; user unknown")


IPV6_PREDICATE = (f"(regexp_matches({catalog.TEXT_COLUMN}, '(?i)(?:^|[^0-9a-f:])(?:[0-9a-f]{{1,4}}:){{2,}}[0-9a-f]{{1,4}}(?:$|[^0-9a-f:])') "
                  f"AND regexp_extract({catalog.TEXT_COLUMN}, '(?i)(?:[0-9a-f]{{1,4}}:){{2,}}[0-9a-f]{{1,4}}') ~ '(?i)[a-f]') "
                  f"OR {catalog.TEXT_COLUMN} LIKE '%::%'")


def has_ipv6(csv, search_path):
    """True when any message carries an IPv6-looking address (hex letters or '::' inside a colon
    group -- clock times like 06:55:46 do not count). The catalog's IP extractors are IPv4-only, so
    such artifacts get no routed IP extraction."""
    con = S.connect(search_path)
    cl = S.sql_literal(csv)
    return bool(con.execute(f"SELECT count(*) FILTER (WHERE {IPV6_PREDICATE}) FROM read_csv_auto('{cl}')").fetchone()[0])


def present_filters(csv, search_path):
    """Names of the catalog's event filters whose vocabulary occurs ANYWHERE in the artifact (one
    read-only scan), plus the filters that need no vocabulary (all_events, quoted_phrase). The router
    is only ever offered these, so it cannot pick an sshd filter for a PAM-only log, or vice versa."""
    con = S.connect(search_path)
    cl = S.sql_literal(csv)
    checks = {name: f.include for name, f in catalog.EVENT_FILTERS.items() if f.include}
    exprs = ", ".join(
        "count(*) FILTER (WHERE " + " AND ".join(f"{catalog.TEXT_COLUMN} LIKE '%{S.sql_literal(s)}%'" for s in inc) + ")"
        for inc in checks.values())
    counts = con.execute(f"SELECT {exprs} FROM read_csv_auto('{cl}')").fetchone()
    present = {name for name, n in zip(checks, counts) if n}
    present |= {name for name, f in catalog.EVENT_FILTERS.items() if not f.include}
    return present


def detect(csv, search_path):
    """Return catalog.FAMILY when the artifact has the LogHub header AND an unambiguous sshd / PAM
    marker in its data AND at least one catalog term, else None (a LogHub-shaped HDFS log whose
    lines say 'Accepted block' gets no family)."""
    con = S.connect(search_path)
    cl = S.sql_literal(csv)
    cols = {n for n, *_ in con.execute(f"DESCRIBE SELECT * FROM read_csv_auto('{cl}')").fetchall()}
    if not LOGHUB_COLS <= cols:
        return None
    marks = ", ".join(f"count(*) FILTER (WHERE {catalog.TEXT_COLUMN} LIKE '%{S.sql_literal(m)}%')" for m in STRONG_MARKERS)
    if not any(con.execute(f"SELECT {marks} FROM read_csv_auto('{cl}')").fetchone()):
        return None
    with_vocab = {name for name, f in catalog.EVENT_FILTERS.items() if f.include}
    return catalog.FAMILY if present_filters(csv, search_path) & with_vocab else None
