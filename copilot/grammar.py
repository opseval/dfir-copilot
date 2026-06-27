"""Per-CSV Lark grammar for a useful DuckDB SQL subset.

Makes two failure classes STRUCTURALLY IMPOSSIBLE under constrained decoding:
  1. corrupted / invented table names -> the FROM target is a single fixed literal
     terminal  read_csv_auto('<thisfile>')
  2. invented / misspelled columns     -> column identifiers are a closed terminal set
     = exactly this CSV's columns.
Free single-quoted STRING content (LIKE / regex patterns) is allowed -- those are values,
not identifiers, and the model's knowledge supplies them. This grammar earned the +5 jump
that took the structure stack to its deployable score.
"""
import duckdb


def _q(s):
    return str(s).replace("'", "''")


def columns_of(csv_path, search_path):
    con = duckdb.connect()
    con.execute(f"SET file_search_path='{_q(search_path)}'")
    rows = con.execute(f"DESCRIBE SELECT * FROM read_csv_auto('{_q(csv_path)}')").fetchall()
    return [n for n, *_ in rows]


def grammar_for(table_literal, columns):
    col_alt = "\n        | ".join('"%s"' % c for c in columns)
    return r'''
start: query
query: "SELECT" sel_list "FROM" table where? groupby? orderby? limit?
sel_list: sel_item ("," sel_item)*
sel_item: expr alias?
alias: ALIAS
table: TABLE
where: "WHERE" cond
cond: pred (BOOLOP pred)*
pred: expr LIKE STRING
    | expr "NOT" LIKE STRING
    | expr CMP expr
groupby: "GROUP" "BY" term ("," term)*
orderby: "ORDER" "BY" ord ("," ord)*
ord: term DIR?
limit: "LIMIT" INT
term: INT | ALIAS | expr
expr: agg | regex_fn | round_fn | col | STRING | INT
agg: "count" "(" "*" ")" filter?
   | "count" "(" "DISTINCT" expr ")" filter?
   | "count" "(" expr ")" filter?
filter: "FILTER" "(" "WHERE" cond ")"
regex_fn: "regexp_extract" "(" expr "," STRING ("," INT)? ")"
round_fn: "round" "(" expr ("," INT)? ")"
col: COLUMN
COLUMN: ''' + col_alt + r'''
TABLE: "''' + table_literal + r'''"
ALIAS: "c" | "u" | "p" | "ip" | "n" | "cnt" | "x" | "t" | "ct"
LIKE: "LIKE"
BOOLOP: "AND" | "OR"
DIR: "ASC" | "DESC"
CMP: "<>" | "!=" | ">=" | "<=" | "=" | ">" | "<"
STRING: "'" /[^'\r\n`]*/ "'"
INT: /[0-9]+/
WS: /[ \t\r\n]+/
%ignore WS
'''


def grammar_for_csv(csv_path, search_path):
    table_literal = "read_csv_auto('%s')" % _q(csv_path)
    cols = columns_of(csv_path, search_path)
    return grammar_for(table_literal, cols), cols
