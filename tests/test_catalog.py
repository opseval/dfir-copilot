"""The intent catalog: quoted-phrase rules, validation, SQL templates (single SELECT over one
read_csv_auto source, discipline rules applied, escaping proven by execution), explanations, and
bidirectional consistency with DOMAIN_DICT."""
import json
import os
import re

import duckdb
import pytest

from copilot import catalog as C
from copilot.domain_pack import DOMAIN_DICT
from copilot.schema import table_literal

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "copilot", "sample")
CSV = "auth_sample.csv"
T = table_literal(CSV)


def plan(ef="all_events", ex="none", ag="count_rows", sc="any_user"):
    return {"event_filter": ef, "extract_field": ex, "aggregate": ag, "account_scope": sc}


def parse(sql):
    """DuckDB's own parser: the statement list of `sql` (no execution)."""
    doc = json.loads(duckdb.connect().execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    assert not doc.get("error"), doc
    return doc["statements"]


def assert_one_select_over(sql, csv):
    stmts = parse(sql)
    assert len(stmts) == 1 and stmts[0]["node"]["type"] == "SELECT_NODE"
    src = stmts[0]["node"]["from_table"]
    assert src["type"] == "TABLE_FUNCTION", src
    fn = src["function"]
    assert fn["function_name"] == "read_csv_auto" and len(fn["children"]) == 1
    assert fn["children"][0]["value"]["value"] == csv
    assert json.dumps(stmts).count('"read_csv_auto"') == 1, "exactly one table source"


def run(sql, directory):
    con = duckdb.connect()
    con.execute(f"SET file_search_path='{directory}'")
    return con.execute(sql).fetchall()


# ---------------------------------------------------------------- quoted phrases
@pytest.mark.parametrize("q,expected", [
    ("How many lines did sshd flag as 'POSSIBLE BREAK-IN ATTEMPT'?", ["POSSIBLE BREAK-IN ATTEMPT"]),
    ("How many events report 'check pass; user unknown', and what does it suggest?", ["check pass; user unknown"]),
    ("How many 'session opened' events for the root user?", ["session opened"]),
    ('count lines with "Failed password" please', ["Failed password"]),
    ("what's the most common IP and don't miss any", []),
    ("compare 'a' and 'b'", ["a", "b"]),
    ("it's the analyst's call", []),
])
def test_quoted_phrases(q, expected):
    assert C.quoted_phrases(q) == expected


# ---------------------------------------------------------------- validation / normalization
def test_validate_normalizes_count_rows_extract():
    p, why = C.validate(plan("failed_password", "event_id", "count_rows"), "how many failed password attempts?")
    assert why is None and p["extract_field"] == "none"


@pytest.mark.parametrize("p,q", [
    (plan("all_events", "none", "count_distinct_values"), "how many distinct?"),
    (plan("all_events", "none", "most_frequent_value_and_count"), "which is most frequent?"),
    (plan("quoted_phrase", "none", "count_rows"), "no quotes here"),
    (plan("failed_password", "none", "count_rows"), "failed logins for root?"),      # root derived, no root form
    (plan("quoted_phrase", "none", "count_rows"), "how many 'session opened' for the root user"),
    ({"event_filter": "nope", "extract_field": "none", "aggregate": "count_rows", "account_scope": "any_user"}, "q"),
    ({"event_filter": "all_events"}, "q"),
    (dict(plan(), extra="x"), "q"),
    (dict(plan(), event_filter=["all_events"]), "q"),
    (dict(plan(), aggregate={"a": 1}), "q"),
    (dict(plan(), extract_field=None), "q"),
    ("not a dict", "q"),
    (None, "q"),
])
def test_validate_rejects(p, q):
    assert C.validate(p, q)[0] is None


# ---------------------------------------------------------------- SQL templates
QS = ["How many 'Accepted' lines are there?", "How many 'session opened' events for the root user?",
      "Which source IP appears most often?"]


@pytest.mark.parametrize("q,why", [
    ("count events except failed passwords", "negated"),
    ("how many logins without a password?", "negated"),
    ("don’t count \"Failed password\" lines", "negated"),                 # curly apostrophe
    ("How many sessions opened for alice?", "account 'alice'"),
    ("sessions opened by alice", "account 'alice'"),
    ("how many events for user dpatel", "account 'dpatel'"),
    ("how many failed logins from 173.234.31.186?", "literal value '173.234.31.186'"),
    ("how many events mention ns.marryaldkfaczcz.com", "literal value"),
    ("how many failed logins in the last 24 hours?", "literal value '24'"),
    ("how many events between the first and last logon?", "time scoping"),
    ("how many failed logins per hour?", "per-group"),            # 'per' is a per-group shape before it is a time cue
    ("How many accepted logins weren't password-based?", "negated"),
    ("logins that didn't come from the office", "negated"),
    ("sessions opened for x", "account 'x'"),
    ("how many events mention attacker.example", "literal value 'attacker.example'"),
    ("how many events reference evidence.json", "literal value 'evidence.json'"),
    ("how many events from C:\\Users\\dpatel\\x.log", "literal value"),
    ("how many events touch /var/log/auth.log", "literal value"),
    ("failed logins this morning", "time scoping ('morning')"),
    ("logins on Monday", "time scoping ('Monday')"),
    ("attempts at noon", "time scoping ('noon')"),
    ("overnight sessions", "time scoping ('overnight')"),
    ("recent failed logins", "time scoping ('recent')"),
    ("How many failed-password and accepted logins are there?", "combines several kinds of event"),
    ("invalid user attempts versus session opened events", "aggregate or comparison"),
    ("Which source IP appears least often?", "'least'"),
    ("what's the average number of attempts per IP?", "per-group"),
    ("what's the average number of attempts?", "'average'"),
    ("what percentage of logins failed?", "'percentage'"),
])
def test_unrepresentable_qualifiers_are_declined(q, why):
    p, reason = C.validate(plan("all_events"), q)
    assert p is None and why in reason, reason


@pytest.mark.parametrize("q,p,why", [
    ("How many failed password attempts are there?", plan("invalid_user"), "names failed_password events but the plan chose invalid_user"),
    ("How many failed password attempts are there?", plan("all_events"), "names failed_password events but the plan chose all_events"),
    ("How many distinct source IPs appear?", plan("all_events", "none", "count_rows"), "distinct values but the plan is not a distinct count"),
    ("Which source IP appears most often?", plan("all_events", "event_id", "most_frequent_value_and_count"), "asks about ip values but the plan extracts event_id"),
    ("How many distinct usernames were tried in invalid-user attempts?", plan("invalid_user", "source_ip", "count_distinct_values"), "asks about user values but the plan extracts source_ip"),
    ("Which source IP is responsible for the most events?", plan("all_events", "none", "count_rows"), "most frequent but the plan is a plain count"),
])
def test_two_agreeing_but_wrong_votes_are_caught_by_the_question_cues(q, p, why):
    got, reason = C.validate(p, q)
    assert got is None and why in reason, reason


def test_quoted_event_name_pins_the_filter_and_the_result_is_right():
    q = "How many 'Failed password' lines are there?"
    got, reason = C.validate(plan("invalid_user"), q)
    assert got is None and "quoted text names failed_password" in reason, reason
    for ef in ("failed_password", "quoted_phrase"):
        sql = C.plan_to_sql(plan(ef), q, CSV)
        assert_one_select_over(sql, CSV)
        assert run(sql, SAMPLE_DIR) == [(13,)], sql          # 14 lines mention it; one is a 'message repeated' wrapper


@pytest.mark.parametrize("q,p,why", [
    ("Which source IP appears most often?", plan("all_events", "source_ip", "count_distinct_values"), "most frequent but the plan is a distinct count"),
    ("How many distinct remote-host IPv4 addresses (rhost=) appear?", plan("all_events", "source_ip", "count_distinct_values"), "rhost= field but the plan extracts the source IP"),
    ("Which source IP appears most often?", plan("all_events", "pam_rhost_ip", "most_frequent_value_and_count"), "source IP but the plan extracts the rhost="),
    ("How many distinct IPs are there?", plan("all_events", "source_ip", "count_distinct_values"), "'IP' is ambiguous"),
    ("How many distinct usernames were used in accepted logins?", plan("accepted_login", "invalid_username", "count_distinct_values"), "do not carry invalid_username"),
    ("How many failed logins came from alice?", plan("failed_password"), "scoping to 'alice'"),
    ("How many disconnected sessions are there?", plan("session_opened"), "event kind the catalog does not have"),
    ("How many brute force attempts are there?", plan("failed_password"), "nothing in the question names failed_password"),
    ("How many sessions were there?", plan("session_opened"), "nothing in the question names session_opened"),
    ("Which source IPs made failed password attempts?", plan("failed_password", "source_ip", "count_distinct_values"), "does not ask for distinct values"),
    ("Which source IPs made failed password attempts?", plan("failed_password", "source_ip", "most_frequent_value_and_count"), "does not ask which value is most frequent"),
    ("Which source IPs made failed password attempts?", plan("failed_password", "none", "count_rows"), "names a field"),
    ("How many source IPs attempted logins?", plan("all_events", "none", "count_rows"), "names a field"),
    ("How many sessions opened under alice's account?", plan("session_opened"), "account 'alice'"),
    ("How many sessions opened under the alice account?", plan("session_opened"), "account 'alice'"),
    ("How many failed logins used publickey authentication?", plan("failed_password"), "authentication method 'publickey'"),
    ("How many failed password attempts came from outside our network?", plan("failed_password"), "network scope 'outside'"),
    ("How many failed password attempts from the corporate VPN?", plan("failed_password"), "network scope"),
    ("Which source IPs made the most failed password attempts?", plan("failed_password", "source_ip", "most_frequent_value_and_count"), "plural field with 'most'"),
])
def test_round_three_wrong_answer_paths_are_declined(q, p, why):
    got, reason = C.validate(p, q)
    assert got is None and why in reason, reason


@pytest.mark.parametrize("q,p,why", [
    ("How many distinct values are present?", plan("all_events", "none", "count_rows"), "distinct values but the plan is not a distinct count"),
    ("How many distinct values are present?", plan("all_events", "source_ip", "count_distinct_values"), "does not say which field"),
    ("Which value occurs most often?", plan("all_events", "none", "count_rows"), "most frequent but the plan is a plain count"),
    ("Which value occurs most often?", plan("all_events", "event_id", "most_frequent_value_and_count"), "does not say which field"),
])
def test_distinct_and_most_are_enforced_without_field_cues(q, p, why):
    got, reason = C.validate(p, q)
    assert got is None and why in reason, reason


@pytest.mark.parametrize("q,p", [
    ("How many failed password attempts are there?", plan("failed_password")),
    ("How many distinct source IPs appear?", plan("all_events", "source_ip", "count_distinct_values")),
    ("Which source IP appears most often?", plan("all_events", "source_ip", "most_frequent_value_and_count")),
    ("How many logins succeeded?", plan("accepted_login")),                         # paraphrase: cue-free plan choice
    ("How many total log events are there?", plan("all_events")),
    ("How many distinct remote-host IPv4 addresses (rhost=) appear in auth events?", plan("all_events", "pam_rhost_ip", "count_distinct_values")),
    ("How many distinct sshd event templates (EventId values) does this log contain?", plan("all_events", "event_id", "count_distinct_values")),
])
def test_consistent_plans_pass_the_cue_check(q, p):
    got, reason = C.validate(p, q)
    assert got is not None, reason


@pytest.mark.parametrize("q", [
    "List all distinct source IPs",
    "Give counts per source IP",
    "Show me every invalid username",
    "breakdown of failed logins by IP",
    "rank the source IPs by attempts",
])
def test_listing_and_per_group_shapes_are_declined(q):
    got, reason = C.validate(plan("all_events", "source_ip", "count_distinct_values"), q)
    assert got is None and "listing / per-group" in reason, reason


def test_abbreviations_are_not_literals():
    p, reason = C.validate(plan("all_events"), "how many events, e.g. sessions, i.e. anything, etc.")
    assert p is not None, reason


@pytest.mark.parametrize("q,p", [
    ("How many invalid-user login attempts (logins for users that don't exist) are there?", plan("invalid_user")),
    ("Which single source IP is responsible for the most events? Give the IP and its count.",
     plan("all_events", "source_ip", "most_frequent_value_and_count")),
    ("How many distinct source IP addresses appear in the log?", plan("all_events", "source_ip", "count_distinct_values")),
    ("How many lines did sshd flag as 'POSSIBLE BREAK-IN ATTEMPT'?", plan("possible_break_in")),
    ("How many 'session opened' events for the root user?", plan("session_opened")),
    ("How many events report 'check pass; user unknown', and what does a cluster of these suggest?", plan("pam_user_unknown")),
    ("how many events mention ‘173.234.31.186’ exactly?", plan("quoted_phrase")),   # quoted literal is representable
    ("sessions opened by root", plan("session_opened")),
])
def test_representable_questions_are_accepted(q, p):
    got, reason = C.validate(p, q)
    assert got is not None, reason


def test_smart_quotes_are_phrases_too():
    assert C.quoted_phrases("count “Failed password” and ‘Accepted’ lines") == ["Failed password", "Accepted"]


def test_root_predicate_has_a_word_boundary(tmp_path):
    rows = ["session opened for user root by (uid=0)", "session opened for user rootkit by (uid=0)",
            "session opened for user roots by (uid=0)", "session opened for user root"]
    lines = ["LineId,Content,EventId,EventTemplate"] + [f'{i},"{c}",E{i},t' for i, c in enumerate(rows, 1)]
    (tmp_path / "s.csv").write_text("\n".join(lines) + "\n")
    sql = C.plan_to_sql(plan("session_opened"), "how many sessions opened for root?", "s.csv")
    assert "regexp_matches" in sql and "rootkit" not in sql
    assert_one_select_over(sql, "s.csv")
    assert run(sql, str(tmp_path)) == [(2,)]


@pytest.mark.parametrize("q", [
    "how many logins excluding 'publickey' ones?",
    "count 'Accepted' lines but not 'password' ones",
    "lines with 'foo' or 'bar'",
    "how many 'session opened' events without root",
    "how many lines that don't say 'Accepted'",
])
def test_negated_or_combined_quotes_are_not_representable(q):
    p, why = C.validate(plan("all_events"), q)
    assert p is None and "not representable" in why


TOP_IP = plan("all_events", "source_ip", "most_frequent_value_and_count")


@pytest.mark.parametrize("q,p,accepted", [
    ("How many logins were there? Given that, what's your read?", TOP_IP, False),
    ("Tell me how many IPs there are", TOP_IP, False),
    ("Which single source IP is responsible for the most events? Give the IP and its count.", TOP_IP, True),
    ("What is the single most-targeted invalid username, and how many times was it tried?",
     plan("invalid_user", "invalid_username", "most_frequent_value_and_count"), True),
    ("Which remote host IP appears most often in auth events, and how many times?",
     plan("all_events", "pam_rhost_ip", "most_frequent_value_and_count"), True),
])
def test_how_many_questions_cannot_be_most_frequent_plans(q, p, accepted):
    got, why = C.validate(p, q)
    assert (got is not None) is accepted, why


def test_targeting_wrapper_text_does_not_exclude_it():
    q = 'how many "message repeated" summary lines are there?'
    sql = C.plan_to_sql(plan("quoted_phrase"), q, CSV)
    assert sql.count("message repeated") == 1 and "NOT LIKE" not in sql
    assert "excluded" not in C.plan_to_english(plan("quoted_phrase"), q)
    assert run(sql, SAMPLE_DIR)[0][0] >= 1, "the sample contains wrapper lines and they must be counted"
ALL_VALID = [(plan(ef, ex, ag), q)
             for q in QS for ef in C.EVENT_FILTERS for ex in C.EXTRACTS for ag in C.AGGREGATES
             if C.validate(plan(ef, ex, ag), q)[0]]


def test_root_scope_is_derived_from_the_question_not_the_model():
    p, _ = C.validate(plan("session_opened", "none", "count_rows", "any_user"), "sessions opened for root?")
    assert p["account_scope"] == "root", "the model's any_user is overridden by the analyst's words"
    p, _ = C.validate(plan("session_opened", "none", "count_rows", "root"), "how many sessions opened?")
    assert p["account_scope"] == "any_user", "a model-invented root scope is dropped"
    p, _ = C.validate({k: v for k, v in plan("session_opened").items() if k != "account_scope"}, "sessions opened for root")
    assert p["account_scope"] == "root"
    assert not C.mentions_root("what is the root cause") is False   # 'root' as a word still counts; Granite handles it


@pytest.mark.parametrize("p,q", ALL_VALID)
def test_every_valid_plan_is_one_select_that_executes(p, q):
    sql = C.plan_to_sql(p, q, CSV)
    assert sql.startswith("SELECT ")
    assert_one_select_over(sql, CSV)
    run(sql, SAMPLE_DIR)                                 # read-only against the sample artifact
    assert C.plan_to_english(p, q).endswith(".")


def test_hostile_file_names_still_give_one_select_over_that_file():
    for csv in ["we'ird.csv", "x'); DROP TABLE t; --.csv", "a.csv') JOIN read_csv_auto('b.csv"]:
        sql = C.plan_to_sql(plan("failed_password"), "how many failed password attempts?", csv)
        assert_one_select_over(sql, csv)


def test_count_rows_applies_repeated_wrapper_exclusion_only_with_a_filter():
    assert "message repeated" in C.plan_to_sql(plan("failed_password"), "how many failed password attempts?", CSV)
    assert "message repeated" not in C.plan_to_sql(plan("all_events"), "q", CSV)
    assert "message repeated" not in C.plan_to_sql(plan("failed_password", "source_ip", "count_distinct_values"),
                                                   "how many distinct source IPs had failed password attempts?", CSV)
    assert "message repeated" in C.plan_to_sql(plan("failed_password", "source_ip", "most_frequent_value_and_count"),
                                               "which source IP had the most failed password attempts?", CSV)


def test_extraction_gets_the_empty_guard_and_top_value_shape():
    sql = C.plan_to_sql(plan("invalid_user", "invalid_username", "most_frequent_value_and_count"),
                        "which invalid username was tried most?", CSV)
    assert sql == ("SELECT regexp_extract(Content, 'Invalid user\\s+(\\S+)', 1) AS v, count(*) AS c FROM "
                   + T + " WHERE Content LIKE '%Invalid user %' AND Content NOT LIKE '%message repeated%' "
                   "AND regexp_extract(Content, 'Invalid user\\s+(\\S+)', 1) <> '' GROUP BY 1 ORDER BY c DESC, v ASC LIMIT 1")


def test_column_extract_has_no_regex_guard():
    assert C.plan_to_sql(plan("all_events", "event_id", "count_distinct_values"),
                         "how many distinct EventId templates are there?", CSV) == f"SELECT count(DISTINCT EventId) FROM {T}"


def test_root_scope_uses_the_canonical_form():
    sql = C.plan_to_sql(plan("session_opened"), "sessions opened for root?", CSV)
    assert "regexp_matches(Content, 'session\\ opened\\ for\\ user\\ root(\\s|$)')" in sql and "'%session opened%'" not in sql
    sql = C.plan_to_sql(plan("session_opened"), "How many 'session opened' events for the root user?", CSV)
    assert "regexp_matches" in sql and sql.count("LIKE") == 1, "the quoted phrase is implied by the root form; only the wrapper exclusion remains"


def test_quoted_phrase_refines_a_dictionary_filter():
    q = "How many events report 'check pass; user unknown'?"
    sql = C.plan_to_sql(plan("pam_user_unknown"), q, CSV)
    assert "'%check pass; user unknown%'" in sql and "'%user unknown%'" not in sql
    assert_one_select_over(sql, CSV)


# ---------------------------------------------------------------- escaping, proven by execution
ROWS = ["100% done", "100 done", "a_b", "axb", "back\\slash", "it's odd", "x; DROP TABLE t; --", "plain"]


@pytest.fixture
def tricky_csv(tmp_path):
    lines = ["LineId,Content,EventId,EventTemplate"]
    for i, c in enumerate(ROWS, 1):
        lines.append(f'{i},"{c.replace(chr(34), chr(34) * 2)}",E{i},t')
    (tmp_path / "t.csv").write_text("\n".join(lines) + "\n")
    return str(tmp_path)


@pytest.mark.parametrize("phrase,expected", [
    ("100% done", 1), ("a_b", 1), ("back\\slash", 1), ("it's odd", 1),
    ("x; DROP TABLE t; --", 1), ("plain", 1), ("100", 2), ("done", 2), ("nomatch", 0),
])
def test_quoted_phrases_match_literally(tricky_csv, phrase, expected):
    sql = C.plan_to_sql(plan("quoted_phrase"), f'count lines containing "{phrase}"', "t.csv")
    assert_one_select_over(sql, "t.csv")
    assert run(sql, tricky_csv) == [(expected,)], sql
    assert run("SELECT count(*) FROM read_csv_auto('t.csv')", tricky_csv) == [(len(ROWS),)], "artifact untouched"


# ---------------------------------------------------------------- explanations
def test_explanations_read_correctly():
    assert C.plan_to_english(plan("failed_password"), "how many failed password attempts?") == \
        "Counts lines recording a failed SSH password attempt (syslog 'message repeated' summary lines are excluded)."
    assert C.plan_to_english(plan("all_events", "source_ip", "most_frequent_value_and_count"), "which source IP appears most often?") == \
        "Finds the source IP address that appears most often across all log lines, and in how many lines (one value; if several tie, the alphabetically first is shown)."
    assert C.validate(plan("session_opened"), "how many sessions opened under root's account?")[0] is not None
    assert C.plan_to_english(plan("invalid_user", "invalid_username", "count_distinct_values"),
                             "how many distinct usernames were tried in invalid user attempts?") == \
        "Counts how many different invalid usernames appear across lines recording a login attempt for a non-existent (invalid) user."


# ---------------------------------------------------------------- schema shape + dictionary consistency
def test_schema_is_exactly_the_fm_object_shape():
    s = C.build_schema()
    assert set(s) == {"title", "type", "properties", "x-order", "required", "additionalProperties"}
    assert s["x-order"] == s["required"] == list(C.MODEL_KEYS) and "account_scope" not in s["properties"]
    for name, p in s["properties"].items():
        assert set(p) == {"type", "enum", "description"} and p["type"] == "string"
    assert s["properties"]["event_filter"]["enum"] == list(C.EVENT_FILTERS)
    with pytest.raises(ValueError):
        C.build_schema("sysmon")


def _canonical(rx):
    return rx.replace("\\s+", " ").replace("\\S+", "\\w+")


def test_catalog_and_dictionary_agree_both_ways():
    dict_likes = set(re.findall(r"LIKE '%([^%']+)%'", DOMAIN_DICT))
    dict_regexes = set(re.findall(r"regexp_extract\(Content, '([^']+)'", DOMAIN_DICT))
    catalog_likes = {s for f in C.EVENT_FILTERS.values() for s in f.include}
    catalog_regexes = {_canonical(e.regex) for e in C.EXTRACTS.values() if e.regex}
    # catalog -> dictionary: every catalog pattern is a dictionary pattern
    assert catalog_likes <= dict_likes, catalog_likes - dict_likes
    assert catalog_regexes <= dict_regexes, catalog_regexes - dict_regexes
    # dictionary -> catalog: every dictionary pattern is a catalog filter/extract (or the wrapper rule / the generic placeholder)
    assert dict_likes - catalog_likes <= {C.REPEATED_WRAPPER, "phrase", "..."}, dict_likes - catalog_likes
    assert dict_regexes == catalog_regexes
    # the root scoping and the EventId column come from the dictionary too
    line = next(l for l in DOMAIN_DICT.splitlines() if "session opened" in l)
    assert C.EVENT_FILTERS["session_opened"].root_form == "session opened for user root" and "for user root" in line
    assert "EventId" in DOMAIN_DICT and C.EXTRACTS["event_id"].column == "EventId"
    assert C.REPEATED_WRAPPER in DOMAIN_DICT
