"""Intent catalog: the forensic dictionary as DATA, so the harness -- not a model -- writes the SQL.

The router asks the on-device Apple model one closed-set question ("which filter, extraction and
aggregate answer the analyst?"). The answer is validated here and turned into a single SELECT by
templates that apply the dictionary's discipline rules every time (exclude syslog 'message repeated'
wrappers when counting events by substring, drop empty extractions, ...). Everything a model touches
is an enum; every free-text value (a quoted phrase) comes from the analyst's own question.

Entries are the same general sshd / Linux-auth analyst patterns as DOMAIN_DICT -- a unit test
cross-checks them -- never case- or test-specific answers. Extend by adding entries; never by letting
the model write SQL values.
"""
import re
from dataclasses import dataclass

from .schema import sql_literal, table_literal

FAMILY = "loghub_auth"            # LogHub-structured sshd / Linux auth logs: Content + EventId columns
TEXT_COLUMN = "Content"


@dataclass(frozen=True)
class EventFilter:
    include: tuple                # every substring must occur in Content
    description: str              # shown to the router (what the analyst means)
    label: str                    # noun phrase for the plain-English explanation
    root_form: str = None         # canonical text when the question scopes to root, if PAM has one


@dataclass(frozen=True)
class Extract:
    regex: str                    # regex with ONE capture group over Content, or None
    column: str                   # or a plain column
    description: str
    noun: str                     # for explanations: "source IP address"


EVENT_FILTERS = {
    "all_events": EventFilter((), "the question does not restrict to one kind of event "
                              "(e.g. 'total events', 'most events overall', 'all lines')", "all log lines"),
    "failed_password": EventFilter(("Failed password",), "an sshd 'Failed password' event (an SSH password was rejected)",
                                   "lines recording a failed SSH password attempt"),
    "invalid_user": EventFilter(("Invalid user ",), "a login attempt for a user that does not exist (invalid user)",
                                "lines recording a login attempt for a non-existent (invalid) user"),
    "accepted_login": EventFilter(("Accepted ",), "a successful SSH login (Accepted password / Accepted publickey)",
                                  "lines recording a successful SSH login"),
    "possible_break_in": EventFilter(("POSSIBLE BREAK-IN ATTEMPT",),
                                     "sshd's reverse-DNS / spoofing warning 'POSSIBLE BREAK-IN ATTEMPT'",
                                     "lines sshd flagged as POSSIBLE BREAK-IN ATTEMPT"),
    "session_opened": EventFilter(("session opened",), "a PAM session was opened (a login session started)",
                                  "lines recording a PAM session being opened",
                                  root_form="session opened for user root"),
    "pam_auth_failure": EventFilter(("authentication failure",),
                                    "a PAM 'authentication failure' event (the literal phrase 'authentication failure' "
                                    "in a Linux auth log)",
                                    "lines recording a PAM authentication failure"),
    "pam_user_unknown": EventFilter(("user unknown",), "a PAM probe of a non-existent account ('check pass; user unknown')",
                                    "lines recording a PAM 'user unknown' probe"),
    "quoted_phrase": EventFilter((), "the question quotes the exact log text to match; only the quoted words are used",
                                 "lines containing the quoted text"),
}

EXTRACTS = {
    "none": Extract(None, None, "nothing is pulled out of the lines; the question is a plain count of matching lines", "line"),
    "source_ip": Extract(r"(\d+\.\d+\.\d+\.\d+)", None,
                         "the source IPv4 address written in the message (sshd lines end '... from 1.2.3.4')",
                         "source IP address"),
    "pam_rhost_ip": Extract(r"rhost=(\d+\.\d+\.\d+\.\d+)", None,
                            "the remote-host IPv4 after 'rhost=' in PAM lines (rhost= itself marks an auth event)",
                            "remote host (rhost=) IP address"),
    # whitespace-robust form of the dictionary's 'Invalid user (\w+)': real sshd lines vary the spacing
    # ('Invalid user  0101 from ...') and usernames can carry punctuation, so \s+ / \S+ capture the name
    # the analyst means instead of an empty string.
    "invalid_username": Extract(r"Invalid user\s+(\S+)", None, "the username tried, taken from 'Invalid user <name>'",
                                "invalid username"),
    "event_id": Extract(None, "EventId", "the EventId column: the log's event template / event type",
                        "event template (EventId)"),
}

AGGREGATES = {
    "count_rows": "how many matching log lines there are (a plain 'how many events / lines / attempts' "
                  "question that does not ask WHICH value)",
    "count_distinct_values": "how many DIFFERENT values of the extracted field occur across the matching lines "
                             "('how many distinct / unique / different X')",
    "most_frequent_value_and_count": "WHICH single value of the extracted field occurs most, and how often "
                                     "('which X is most common / appears most often / is responsible for the "
                                     "most events', 'the top X and its count')",
}

ACCOUNT_SCOPE = {
    "any_user": "the question does not single out one account",
    "root": "the question is specifically about the root account",
}

REPEATED_WRAPPER = "message repeated"   # syslog 'message repeated N times: [ ... ]' summary lines
MODEL_KEYS = ("event_filter", "extract_field", "aggregate")   # what the model chooses (all enums)
PLAN_KEYS = MODEL_KEYS + ("account_scope",)                    # + what the harness derives from the question
_ROOT_RE = re.compile(r"\broot\b", re.I)
# Question form vs. aggregate form: a question that opens with "how many" asks for a count, never for
# "which value occurs most". The harness checks the model's classification against the analyst's own
# words and declines a mismatch rather than answering a different question.
_HOW_MANY_RE = re.compile(r"^\s*(?:\W*\w+\s+){0,3}?how\s+many\b", re.I)
_SMART = {"‘": "'", "’": "'", "‚": "'", "′": "'", "´": "'", "“": '"', "”": '"',
          "„": '"', "″": '"'}

# Qualifiers the catalog cannot represent. Every catalog plan is a positive filter over one kind of
# line with an optional quoted phrase; a question that also negates, names an account other than
# root, names a literal value (an IP, a host, a number) outside quotes, or scopes a time window would
# get an answer to a DIFFERENT question, so the harness declines it and Granite answers instead.
_IDIOM_RE = re.compile(r"\b(?:do|does|did|don't|doesn't|didn't)\s+(?:not\s+)?exist\w*\b|\bnon-?existent\b|"
                       r"\bnot\s+exist\w*\b|\binvalid[- ]user\b", re.I)
_NEGATION_RE = re.compile(r"\b(excluding|exclude|except|without|not|no|none|neither|nor|other than|but not|apart from|"
                          r"ignoring|minus|don't|doesn't|didn't|isn't|aren't|wasn't|weren't|can't|cannot|couldn't|"
                          r"won't|wouldn't|shouldn't|hasn't|haven't|hadn't|never)\b", re.I)
_ACCOUNT_RE = re.compile(r"\b(?:for|by|as|of)\s+(?:the\s+)?(?:user|account)\s+([\w.-]+)"
                         r"|\bfor\s+(?:the\s+)?([A-Za-z][\w.-]*)\s+(?:user|account)\b"
                         r"|\b(?:user|account)\s+named\s+([\w.-]+)"
                         r"|\b(?:for|by|as)\s+([A-Za-z][\w.-]{0,31})\b", re.I)
_ACCOUNT_STOP = {"the", "a", "an", "this", "that", "these", "those", "its", "it", "which", "what", "how", "count",
                 "counts", "number", "source", "destination", "ip", "ips", "address", "addresses", "host", "hosts",
                 "user", "users", "username", "usernames", "account", "accounts", "far", "well", "much", "many",
                 "most", "least", "all", "any", "each", "every", "one", "per", "of", "in", "on", "at", "to", "and",
                 "or", "default", "descending", "ascending", "order", "frequency", "name", "names", "type", "types",
                 "event", "events", "line", "lines", "time", "date", "template", "templates", "eventid", "sshd",
                 "pam", "failed", "successful", "invalid", "accepted", "distinct", "unique", "different", "total",
                 "same", "single", "remote", "local", "each", "example", "instance", "reference", "comparison",
                 "sure", "now", "me", "us", "you", "them", "him", "her", "attempt", "attempts", "login", "logins",
                 "session", "sessions", "failure", "failures", "request", "requests", "connection", "connections",
                 "authentication", "password", "passwords", "message", "messages", "log", "logs", "entry", "entries"}
# Literal values: IPv4s, any dotted label (hosts, files, domains -- except common abbreviations),
# path-shaped tokens, bare numbers.
_LITERAL_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[\w-]+(?:\.[\w-]+)+\b|[A-Za-z]:\\\S+|(?<!\S)/[\w./-]+|\\\\\S+|\b\d+\b", re.I)
_ABBREVIATIONS = {"e.g", "i.e", "etc", "vs", "cf", "a.m", "p.m", "sshd.auth", "pam_unix.sshd"}
_TIME_RE = re.compile(r"\b(between|before|after|since|during|until|within|last|first|earliest|latest|recent|recently|"
                      r"ago|earlier|later|previous|prior|past|next|upcoming|hours?|minutes?|seconds?|days?|weeks?|"
                      r"months?|years?|today|yesterday|tomorrow|tonight|overnight|morning|afternoon|evening|night|"
                      r"noon|midnight|o'clock|weekday|weekend|monday|tuesday|wednesday|thursday|friday|saturday|sunday|"
                      r"january|february|march|april|may|june|july|august|september|october|november|december|"
                      r"timestamp|timestamps|time window|over time|per hour|per day|when|while)\b", re.I)
# Aggregate forms the catalog does not have (it has count, distinct-count and MOST-frequent only) and
# comparison words that signal a question about several kinds of event at once.
_UNSUPPORTED_AGG_RE = re.compile(r"\b(least|fewest|minimum|bottom|rarest|smallest|lowest|average|mean|median|percent|"
                                 r"percentage|proportion|share|sum|rate|ratio|deviation|trend|correlat\w*|compar\w*|"
                                 r"versus|vs|than)\b", re.I)
# Result shapes the catalog does not produce (it returns one number or one value+count): listings,
# per-group breakdowns, rankings.
_SHAPE_RE = re.compile(r"\b(list|listing|lists|show|enumerate|dump|print|display|every|each|per|breakdown|grouped?\s+by|"
                       r"rank\w*|histogram|distribution|table of|all of the|all the)\b", re.I)
# Cues that pin the plan's fields to the analyst's words. When a cue is present the model's choice
# must agree with it; the model may still choose freely when the question is a paraphrase.
_IP_CUE = re.compile(r"\b(ips?|ip address(?:es)?|address(?:es)?|hosts?|rhost|remote[- ]hosts?)\b", re.I)
_USER_CUE = re.compile(r"\b(user ?names?|account names?|login names?)\b", re.I)
_EID_CUE = re.compile(r"\b(event ?ids?|event templates?|event types?|templates?)\b", re.I)
_DISTINCT_RE = re.compile(r"\b(distinct|different|unique)\b", re.I)
_MOST_RE = re.compile(r"\b(most|top|commonest|frequent\w*|often)\b", re.I)
_SRC_IP_CUE = re.compile(r"\bsource\b", re.I)                       # 'source IP', 'source address'
_RHOST_CUE = re.compile(r"\brhost\b|\bremote[- ]hosts?\b", re.I)    # PAM's rhost= field
# Event kinds analysts ask about that the catalog does not have; a plan for them would be a guess.
_UNSUPPORTED_EVENT_RE = re.compile(r"\b(disconnect\w*|closed|closes|closing|logout|logged out|log out|timeout|timed out|"
                                   r"expired|expir\w+|refused|reset|rejected|denied|banned|blocked|locked|kicked|dropped)\b", re.I)
# 'from <name>' scopes to an origin the catalog cannot filter on (IPs are caught by the literal rule).
_FROM_RE = re.compile(r"\b(?:came\s+|coming\s+|originat\w+\s+)?from\s+(?:the\s+)?([A-Za-z][\w.-]*)\b", re.I)
_FROM_STOP = {"the", "this", "that", "these", "those", "a", "an", "outside", "inside", "external", "internal", "anywhere",
              "elsewhere", "where", "known", "unknown", "any", "all", "each", "every", "log", "logs", "file", "files", "data",
              "home", "work", "users", "user", "accounts", "account", "which", "what", "here", "there", "it", "them", "us",
              "me", "you", "different", "distinct", "same", "other", "another", "multiple", "several", "many", "few", "one",
              "two", "three", "various", "remote", "local", "root", "invalid", "failed", "accepted", "sshd", "pam"}
# Possessive / 'under ... account' scoping, authentication-method and network-zone qualifiers, and
# plural field nouns next to a 'most' cue (a list of tied winners, which LIMIT 1 cannot return).
_POSSESSIVE_RE = re.compile(r"\b([A-Za-z][\w.-]*)'s\s+(?:accounts?|sessions?|logins?|attempts?|activity)\b"
                            r"|\bunder\s+(?:the\s+)?([A-Za-z][\w.-]*)(?:'s)?\s+(?:accounts?|users?|logins?)\b", re.I)
_AUTH_METHOD_RE = re.compile(r"\b(publickey|public[- ]key|password authentication|keyboard[- ]interactive|kerberos|gssapi|"
                             r"certificate|hostbased|host[- ]based|two[- ]factor|2fa|mfa|token)\b", re.I)
_NETWORK_ZONE_RE = re.compile(r"\b(outside|inside|internal|external|our network|the network|subnet|netblock|cidr|range|"
                              r"vpn|dmz|private|public|corporate|on-?prem\w*|cloud|geo\w*|country|countries)\b", re.I)
_PLURAL_FIELD_RE = re.compile(r"\b(ips|addresses|hosts|usernames|users|accounts|templates|event ?ids)\b", re.I)
# Which filters' lines actually carry each extracted field; anything else is a guess that returns 0 / [].
COMPATIBLE = {
    "source_ip": {"all_events", "failed_password", "invalid_user", "accepted_login", "possible_break_in", "pam_auth_failure", "quoted_phrase"},
    "pam_rhost_ip": {"all_events", "pam_auth_failure", "quoted_phrase"},
    "invalid_username": {"all_events", "invalid_user", "quoted_phrase"},
}
# Words that name a kind of event; two different kinds in one question = a combination the catalog
# cannot express with its single filter.
_CLASS_CUES = {
    "failed_password": ("failed password", "failed-password", "password failure", "failed login", "wrong password"),
    "invalid_user": ("invalid user", "invalid-user", "nonexistent user", "non-existent user"),
    "accepted_login": ("accepted", "successful login", "succeeded", "logged in successfully", "successful ssh"),
    "possible_break_in": ("break-in", "break in attempt", "breakin"),
    "session_opened": ("session opened", "sessions opened", "opened session", "session open"),
    "pam_auth_failure": ("authentication failure", "authentication-failure", "auth failure"),
    "pam_user_unknown": ("user unknown", "check pass"),
}


def normalize(question):
    """Fold smart quotes and apostrophes to their ASCII forms before any parsing."""
    return "".join(_SMART.get(c, c) for c in question)


def mentions_root(question):
    """Account scoping is derived from the analyst's own words, never chosen by the model."""
    return bool(_ROOT_RE.search(normalize(question)))


def _unquoted(question):
    q = normalize(question)
    for rx in _QUOTE_RES:
        q = rx.sub(" ", q)
    return q


def unsupported_qualifier(question):
    """The reason this question cannot be answered by a catalog plan, or None."""
    q = _unquoted(question)
    if _NEGATION_RE.search(_IDIOM_RE.sub(" ", q)):
        return "a negated condition ('except', 'without', 'not', ...) is not representable"
    m = _SHAPE_RE.search(q)
    if m:
        return f"'{m.group(0)}' asks for a listing / per-group result; the catalog returns one number or one value"
    for m in _ACCOUNT_RE.finditer(q):
        name = next(g for g in m.groups() if g)
        if name.lower() in _ACCOUNT_STOP or name.lower() == "root":
            continue
        return f"scoping to account '{name}' is not representable (only root has a canonical form)"
    for m in _LITERAL_RE.finditer(q):
        if m.group(0).lower().rstrip(".") in _ABBREVIATIONS:
            continue
        return f"the literal value '{m.group(0)}' cannot be applied; quote it to match it as text"
    m = _TIME_RE.search(q)
    if m:
        return f"time scoping ('{m.group(0)}') is not representable"
    m = _UNSUPPORTED_AGG_RE.search(q)
    if m:
        return f"'{m.group(0)}' asks for an aggregate or comparison the catalog does not have"
    kinds = [k for k, cues in _CLASS_CUES.items() if any(c in q.lower() for c in cues)]
    if len(kinds) > 1:
        return f"the question combines several kinds of event ({', '.join(kinds)}); one filter cannot express that"
    m = _UNSUPPORTED_EVENT_RE.search(q)
    if m:
        return f"'{m.group(0)}' names an event kind the catalog does not have"
    m = _NETWORK_ZONE_RE.search(q)
    if m:
        return f"the network scope '{m.group(0)}' is not representable"
    m = _AUTH_METHOD_RE.search(q)
    if m:
        return f"the authentication method '{m.group(0)}' is not a catalog filter; quote the log text to match it"
    for m in _FROM_RE.finditer(q):
        name = m.group(1)
        if name.lower() not in _FROM_STOP:
            return f"scoping to '{name}' is not representable; quote a literal value to match it as text"
    for m in _POSSESSIVE_RE.finditer(q):
        name = next(g for g in m.groups() if g)
        if name.lower() != "root":
            return f"scoping to account '{name}' is not representable (only root has a canonical form)"
    if _MOST_RE.search(q) and _PLURAL_FIELD_RE.search(q):
        return "a plural field with 'most' asks for several (possibly tied) values; the catalog returns one"
    return None


def plan_disagrees_with_question(plan, question):
    """The harness's own reading of the analyst's words vs. the model's enum choices: a question that
    names a kind of event, a field, 'distinct' or 'most' pins the corresponding field. Returns the
    reason for a mismatch, or None. Two agreeing votes on a plausible-but-wrong plan are caught here."""
    q = _unquoted(question)
    ql = q.lower()
    ef, ex, ag = plan["event_filter"], plan["extract_field"], plan["aggregate"]
    kinds = [k for k, cues in _CLASS_CUES.items() if any(c in ql for c in cues)]
    if len(kinds) == 1 and ef != kinds[0]:
        return f"the question names {kinds[0]} events but the plan chose {ef}"
    # a quoted event name ('Failed password') is the analyst's filter too: the plan must be that kind
    # (or quoted_phrase); any other kind would AND two different events together and return 0 rows.
    quoted_kinds = {k for p in quoted_phrases(question) for k, cues in _CLASS_CUES.items()
                    if any(c in p.lower() for c in cues) or any(s.lower() in p.lower() for s in EVENT_FILTERS[k].include)}
    if len(quoted_kinds) == 1 and ef not in (next(iter(quoted_kinds)), "quoted_phrase"):
        return f"the quoted text names {next(iter(quoted_kinds))} events but the plan chose {ef}"
    if ef not in ("all_events", "quoted_phrase") and ef not in kinds and ef not in quoted_kinds:
        return f"nothing in the question names {ef} events; the plan would be a guess"
    ip, user, eid = bool(_IP_CUE.search(ql)), bool(_USER_CUE.search(ql)), bool(_EID_CUE.search(ql))
    field_of = {"source_ip": "ip", "pam_rhost_ip": "ip", "invalid_username": "user", "event_id": "eid"}
    named = {"ip": ip, "user": user, "eid": eid}
    if ex != "none":
        others = [n for n, present in named.items() if present and n != field_of[ex]]
        if others and not named[field_of[ex]]:
            return f"the question asks about {others[0]} values but the plan extracts {ex}"
        if not named[field_of[ex]]:
            return f"the question does not say which field to extract; the plan's {ex} would be a guess"
        if ex in ("source_ip", "pam_rhost_ip"):
            src, rh = bool(_SRC_IP_CUE.search(ql)), bool(_RHOST_CUE.search(ql))
            if ex == "source_ip" and rh and not src:
                return "the question asks about the rhost= field but the plan extracts the source IP"
            if ex == "pam_rhost_ip" and src and not rh:
                return "the question asks about the source IP but the plan extracts the rhost= field"
            if not src and not rh:
                return "'IP' is ambiguous here; say 'source IP' or 'rhost' (the plan's choice would be a guess)"
        if ex in COMPATIBLE and ef not in COMPATIBLE[ex]:
            return f"{ef} lines do not carry {ex}; the plan would return nothing"
    distinct, most = bool(_DISTINCT_RE.search(ql)), bool(_MOST_RE.search(ql) and not _HOW_MANY_RE.search(question))
    if distinct and ag != "count_distinct_values":
        return "the question asks for distinct values but the plan is not a distinct count"
    if most and ag != "most_frequent_value_and_count":
        return ("the question asks which value is most frequent but the plan is "
                + ("a plain count" if ag == "count_rows" else "a distinct count"))
    # the aggregate must be asked for, not inferred: a question that names a field without saying
    # 'distinct' or 'most' wants the values themselves (a listing), which the catalog cannot return
    if ag == "count_distinct_values" and not distinct:
        return "the question does not ask for distinct values; a distinct count would be a guess"
    if ag == "most_frequent_value_and_count" and not most:
        return "the question does not ask which value is most frequent; a top-value plan would be a guess"
    if ag == "count_rows" and (ip or user or eid):
        return "the question names a field (IP / username / EventId); a plain line count would discard it"
    return None

# A single-quoted span opens only after start / whitespace / '(' and closes only before end /
# whitespace / punctuation, so "what's" and "don't" never start a phrase. Double and curly quotes
# are unambiguous.
_QUOTE_RES = [re.compile(r'"([^"\n]+)"'), re.compile(r"“([^”\n]+)”"),
              re.compile(r"(?<![^\s(])'([^'\n]+)'(?![^\s.,;:?!)])")]


def quoted_phrases(question):
    """Literal log text the analyst put in quotes, in order, de-duplicated. From the question only."""
    out = []
    question = normalize(question)
    for rx in _QUOTE_RES:
        for m in rx.finditer(question):
            p = m.group(1).strip()
            if p and p not in out:
                out.append(p)
    return out


def build_schema(family=FAMILY):
    """The router's JSON schema: exactly the `fm schema object` shape (enums + descriptions), nothing
    else. Always the FULL catalog: the model names what the analyst asked for; whether the artifact
    contains it is checked afterwards by the harness (router + family.present_filters)."""
    if family != FAMILY:
        raise ValueError(f"no catalog for family {family!r}")

    def opts(d, key=lambda v: v.description if hasattr(v, "description") else v):
        return "; ".join(f"{k} = {key(v)}" for k, v in d.items())

    props = {
        "event_filter": {"type": "string", "enum": list(EVENT_FILTERS),
                         "description": "Which kind of log line the question restricts to. " + opts(EVENT_FILTERS)},
        "extract_field": {"type": "string", "enum": list(EXTRACTS),
                          "description": "The value pulled out of each matching line (needed for distinct / "
                                         "most-frequent questions; none for plain counts). " + opts(EXTRACTS)},
        "aggregate": {"type": "string", "enum": list(AGGREGATES),
                      "description": "What is computed over the matching lines. " + opts(AGGREGATES)},
    }
    return {"title": "QueryIntent", "type": "object", "properties": props, "x-order": list(MODEL_KEYS),
            "required": list(MODEL_KEYS), "additionalProperties": False}


def validate(plan, question):
    """Return (normalized plan, None) or (None, reason). Only plans the templates can honour survive.
    The model's plan carries MODEL_KEYS; account_scope is derived here from the question (a plan that
    already carries one is accepted and overridden)."""
    if not isinstance(plan, dict):
        return None, "plan is not an object"
    if set(plan) not in (set(MODEL_KEYS), set(PLAN_KEYS)):
        return None, f"plan keys must be exactly {MODEL_KEYS}"
    if not all(isinstance(v, str) for v in plan.values()):
        return None, "plan values must be strings"
    ef, ex, ag = (plan[k] for k in MODEL_KEYS)
    if ef not in EVENT_FILTERS or ex not in EXTRACTS or ag not in AGGREGATES:
        return None, "value outside the catalog"
    phrases = quoted_phrases(question)
    if ef == "quoted_phrase" and not phrases:
        return None, "quoted_phrase chosen but the question quotes nothing"
    if len(phrases) > 1:
        return None, "several quoted phrases: their relationship (and / or) is not representable"
    why = unsupported_qualifier(question)
    if why:
        return None, why
    if ag == "most_frequent_value_and_count" and _HOW_MANY_RE.search(question):
        return None, "a 'how many' question cannot be a most-frequent-value plan"
    if ag == "count_rows":
        ex = "none"
    why = plan_disagrees_with_question({"event_filter": ef, "extract_field": ex, "aggregate": ag}, question)
    if why:
        return None, why
    sc = "root" if mentions_root(question) else "any_user"
    if sc == "root" and not EVENT_FILTERS[ef].root_form:
        return None, f"the question scopes to root but {ef} has no canonical root form"
    if ag == "count_rows":
        ex = "none"                                  # nothing to extract for a plain count
    elif ex == "none":
        return None, f"{ag} needs an extract_field"
    return {"event_filter": ef, "extract_field": ex, "aggregate": ag, "account_scope": sc}, None


def _includes(plan, question):
    f = EVENT_FILTERS[plan["event_filter"]]
    inc = [f.root_form] if plan["account_scope"] == "root" else list(f.include)
    for p in quoted_phrases(question):          # the analyst's literal text always applies
        if any(p.lower() in i.lower() for i in inc):
            continue                             # already implied by a dictionary substring
        inc = [i for i in inc if i.lower() not in p.lower()]   # the phrase is the more specific form
        inc.append(p)
    return inc


def _excludes_wrappers(plan, includes):
    """The dictionary rule: when counting events by substring, drop syslog 'message repeated' wrapper
    lines -- unless the analyst is asking about the wrappers themselves."""
    counts_events = plan["aggregate"] in ("count_rows", "most_frequent_value_and_count")
    targets_wrappers = any(REPEATED_WRAPPER.lower() in s.lower() for s in includes)
    return counts_events and bool(includes) and not targets_wrappers


def _root_match(root_form):
    """Boundary-aware root predicate: 'session opened for user root' must not match '... user rootkit'."""
    return f"regexp_matches({TEXT_COLUMN}, '{sql_literal(re.escape(root_form))}(\\s|$)')"


def _like(sub):
    """Content LIKE '%sub%', escaping LIKE metacharacters only when the phrase contains them."""
    if any(ch in sub for ch in "%_\\"):
        esc = sub.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"{TEXT_COLUMN} LIKE '%{sql_literal(esc)}%' ESCAPE '\\'"
    return f"{TEXT_COLUMN} LIKE '%{sql_literal(sub)}%'"


def _expr(extract):
    e = EXTRACTS[extract]
    if e.column:
        return e.column
    return f"regexp_extract({TEXT_COLUMN}, '{sql_literal(e.regex)}', 1)"


def plan_to_sql(plan, question, csv):
    """One read-only SELECT over read_csv_auto('<csv>'); the table literal is built here from the
    file name, so no caller can hand in a different FROM clause."""
    plan, why = validate(plan, question)
    if plan is None:
        raise ValueError(why)
    table = table_literal(csv)
    inc = _includes(plan, question)
    root_form = EVENT_FILTERS[plan["event_filter"]].root_form if plan["account_scope"] == "root" else None
    where = [_root_match(s) if s == root_form else _like(s) for s in inc]
    ag, ex = plan["aggregate"], plan["extract_field"]
    if _excludes_wrappers(plan, inc):
        where.append(f"{TEXT_COLUMN} NOT LIKE '%{REPEATED_WRAPPER}%'")
    if ex != "none" and EXTRACTS[ex].regex:
        where.append(f"{_expr(ex)} <> ''")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    if ag == "count_rows":
        return f"SELECT count(*) FROM {table}{w}"
    if ag == "count_distinct_values":
        return f"SELECT count(DISTINCT {_expr(ex)}) FROM {table}{w}"
    # one row: the most frequent value; on a tie the smallest value wins deterministically (ties are
    # declared in the explanation, and a question asking for several values is declined upstream)
    return (f"SELECT {_expr(ex)} AS v, count(*) AS c FROM {table}{w} "
            f"GROUP BY 1 ORDER BY c DESC, v ASC LIMIT 1")


def plan_to_english(plan, question):
    """What the generated query computes, from templates (never from a model)."""
    plan, why = validate(plan, question)
    if plan is None:
        raise ValueError(why)
    f = EVENT_FILTERS[plan["event_filter"]]
    inc = _includes(plan, question)
    if plan["account_scope"] == "root":
        what = f"{f.label} for the root user"
    else:
        what = f.label
    extra = [p for p in quoted_phrases(question) if p in inc and p not in f.include]
    if extra and plan["event_filter"] != "quoted_phrase":
        what += " that also contain " + " and ".join(f"'{p}'" for p in extra)
    elif plan["event_filter"] == "quoted_phrase":
        what = "lines containing " + " and ".join(f"'{p}'" for p in extra)
    ag, ex = plan["aggregate"], plan["extract_field"]
    noun = EXTRACTS[ex].noun
    excl = " (syslog 'message repeated' summary lines are excluded)" if _excludes_wrappers(plan, inc) else ""
    if ag == "count_rows":
        return f"Counts {what}{excl}."
    if ag == "count_distinct_values":
        return f"Counts how many different {noun}s appear across {what}."
    return (f"Finds the {noun} that appears most often across {what}, and in how many lines{excl} "
            f"(one value; if several tie, the alphabetically first is shown).")
