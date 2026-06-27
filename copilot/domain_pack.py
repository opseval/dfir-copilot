"""Forensic SQL knowledge pack (RAG context) for the NL->DuckDB query engine.

Every pattern is GENERAL sshd / Linux-auth / log-analysis analyst knowledge -- the kind
on a cheat-sheet -- or derives from the artifact's own columns. It encodes term->pattern
mappings and SQL discipline, NOT any specific answer. Extend DOMAIN_DICT to cover more
artifact types; that is the cheap, $0 way to broaden domain coverage.
"""

DOMAIN_DICT = """FORENSIC SQL CHEAT-SHEET (general sshd / Linux-auth knowledge).
The log message text lives as a SUBSTRING inside the Content column, so match with LIKE '%...%'.
Reusable analyst patterns:
- failed SSH password login      -> Content LIKE '%Failed password%'
- login attempt for a user that does not exist (invalid user) -> Content LIKE '%Invalid user %'
- successful SSH login            -> Content LIKE '%Accepted %'   (e.g. 'Accepted password', 'Accepted publickey')
- sshd reverse-DNS / spoof warning (break-in) -> Content LIKE '%POSSIBLE BREAK-IN ATTEMPT%'
- a PAM session was opened        -> Content LIKE '%session opened%'   (add 'for user root' to scope to root)
- PAM authentication failure (Linux /var/log) -> Content LIKE '%authentication failure%'
- PAM probe of a non-existent account -> Content LIKE '%user unknown%'  (often 'check pass; user unknown')
- pull the source IPv4 out of a line  -> regexp_extract(Content, '(\\d+\\.\\d+\\.\\d+\\.\\d+)')
- pull the PAM remote host IPv4       -> regexp_extract(Content, 'rhost=(\\d+\\.\\d+\\.\\d+\\.\\d+)', 1)
- pull the attempted username after 'Invalid user' -> regexp_extract(Content, 'Invalid user (\\w+)', 1)
- when extracting with regexp_extract, exclude non-matches with: WHERE <the same regexp_extract...> <> ''
- "how many distinct X"            -> count(DISTINCT X)
- "which X is most frequent / most-targeted, and how many" -> SELECT X, count(*) c ... GROUP BY 1 ORDER BY c DESC LIMIT 1
- distinct event templates / event types -> the EventId column: count(DISTINCT EventId)
- total number of events           -> count(*)
GENERAL SQL DISCIPLINE (avoid common mistakes):
- FILTER rows with Content LIKE '%phrase%'. Use regexp_extract ONLY in the SELECT to pull a value, and it MUST contain a parenthesised capture group with ,1. Do NOT filter with regexp_extract on a literal that has no (...) group -- it returns '' for every row and drops all of them.
- When counting DISTINCT over an extraction, drop non-matching rows: add WHERE regexp_extract(Content,'...(...)',1) <> '' (use the identical extraction expression).
- round() is ONLY for numbers (e.g. percentages). NEVER wrap a string/IP/username extraction in round() -- it will error.
- syslog/auth logs emit aggregation lines like 'message repeated N times: [ ... ]'. When counting individual events by substring, exclude them so you count real events not the wrapper: add AND Content NOT LIKE '%message repeated%'.
"""

# Worked exemplars on DIFFERENT concepts (Connection-closed, port, Pid) than typical
# questions -- they teach the SQL SHAPE, not answers. Fence-free: the constrained grammar
# forces a bare SELECT, so priming with ```sql backticks would let the model ramble.
EXEMPLARS_NOFENCE = """WORKED EXAMPLES (different log, shown only to teach the SQL shape; reply with only one SELECT):
Q: How many log lines mention 'Connection closed'?
SQL: SELECT count(*) FROM read_csv_auto('example.csv') WHERE Content LIKE '%Connection closed%'
Q: Which destination port shows up most often, and how many times?
SQL: SELECT regexp_extract(Content,'port (\\d+)',1) p, count(*) c FROM read_csv_auto('example.csv') WHERE regexp_extract(Content,'port (\\d+)',1) <> '' GROUP BY 1 ORDER BY c DESC LIMIT 1
Q: How many distinct process IDs (Pid) appear in the log?
SQL: SELECT count(DISTINCT Pid) FROM read_csv_auto('example.csv')
"""
