"""NL->DuckDB query engine: the Apple-routed intent catalog in front of the constrained Granite stack.

Two paths, one contract (a result + the SQL that produced it, for analyst approval):

  catalog  family.detect (deterministic) -> router (the on-device Apple model picks catalog enums,
           two votes must agree) -> catalog.plan_to_sql (templates, dictionary discipline applied)
           -> execute. The model never writes a SQL value; the explanation is a template.
  granite  the deployable 14/17 structure stack, unchanged: M-Schema (real example values) +
           forensic dictionary in context -> constrained decoding (per-CSV Lark grammar: identifiers
           locked to this schema) -> best-of-N + self-consistency (majority vote on EXECUTION
           RESULTS, answer-blind) -> execute-and-retry on all-fail (verbatim DuckDB error fed back).

`backend` = auto (the default: catalog first, Granite for anything the router does not take, or
whenever Apple's model is unavailable) | granite (the constrained model only) | afm (catalog only;
errors instead of falling through -- for evaluation). The Granite model is the
UNTUNED base, frozen; the structure -- not the weights -- is what makes it reliable.
"""
import os
import re
from collections import Counter

from . import catalog, config, family, router
from .domain_pack import DOMAIN_DICT, EXEMPLARS_NOFENCE
from .grammar import grammar_for_csv
from . import schema as S

BACKENDS = ("auto", "granite", "afm")

_model = _tok = None
_greedy = _sampled = None
_cfg_cache = {}


def _lazy_load():
    global _model, _tok, _greedy, _sampled
    if _model is not None:
        return
    import mlx_lm
    from mlx_lm.sample_utils import make_sampler
    import outlines
    if config.SEED is not None:            # reproducible sampled candidates (whole-session sequence)
        import mlx.core as mx
        mx.random.seed(config.SEED)
    base, tok = mlx_lm.load(config.MODEL_ID)
    _model = outlines.from_mlxlm(base, tok)
    _tok = tok
    _greedy = make_sampler(temp=0.0)
    _sampled = make_sampler(temp=config.SAMPLE_TEMP)


def _extract_sql(text):
    if not text:
        return None
    m = re.search(r'```sql\s+(.*?)```', text, re.S | re.I)
    if m:
        return m.group(1).strip().rstrip(";").strip() or None
    m = re.search(r'(?is)\b(SELECT\b.+)', text)
    if m:
        return m.group(1).strip().strip("`").strip().rstrip(";").strip() or None
    return None


def _system_prompt(csv_basename, mschema_text):
    return ("You are a DuckDB query specialist for forensic log analysis.\n"
            f"The ONLY table is read_csv_auto('{csv_basename}').\n"
            "Columns (name:type with real example cell values):\n"
            f"{mschema_text}\n\n"
            f"{DOMAIN_DICT}\n{EXEMPLARS_NOFENCE}\n"
            f"Now answer the analyst's question about read_csv_auto('{csv_basename}'). "
            "Output ONLY the raw DuckDB SQL query, starting with the word SELECT. "
            "No code fences, no prose, no semicolon. Use the real table name above, not example.csv.")


def _key(v):
    import json
    return json.dumps(v, default=str, sort_keys=True)


def _answer_granite(question, artifact_csv):
    """The constrained Granite stack. Returns {result, sql, votes, ok, error, path, ...}. `ok` means a
    query ran and returned a sensible value (the analyst still approves before anything is acted on)."""
    _lazy_load()
    from outlines.types import CFG

    search_path, csv = S.split_path(artifact_csv)
    cache_key = os.path.abspath(artifact_csv)   # not basename — avoid same-name collisions
    if cache_key not in _cfg_cache:
        grammar, _cols = grammar_for_csv(csv, search_path)
        _cfg_cache[cache_key] = CFG(grammar)
    cfg = _cfg_cache[cache_key]
    sysm = _system_prompt(csv, S.mschema(csv, search_path))
    msgs = [{"role": "system", "content": sysm}, {"role": "user", "content": question}]

    chosen_sql = chosen_got = None
    votes = 0
    last_err = None
    for att in range(1, config.MAX_RETRIES + 1):
        cands = []
        for i in range(config.BEST_OF_N):
            prompt = _tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
            out = _model(prompt, cfg, backend="llguidance", max_tokens=config.MAX_TOKENS,
                         sampler=(_greedy if i == 0 else _sampled))
            sql = _extract_sql(out)
            got, err = S.execute(sql, search_path)
            cands.append({"sql": sql, "got": got, "err": err})
        ok = [(c["sql"], c["got"]) for c in cands if c["err"] is None and S.sensible(c["got"])]
        if ok:  # self-consistency: most common execution result wins (answer-blind)
            cnt = Counter(_key(g) for _, g in ok)
            best_key, votes = cnt.most_common(1)[0]
            chosen_sql, chosen_got = next((s, g) for s, g in ok if _key(g) == best_key)
            break
        last_err = next((c["err"] for c in cands if c["err"]), "empty/zero result")
        first_sql = next((c["sql"] for c in cands if c["sql"]), None)
        if att < config.MAX_RETRIES:
            msgs += [{"role": "assistant", "content": first_sql or ""},
                     {"role": "user", "content": f"That query failed ({last_err}). Return one corrected DuckDB SQL query."}]

    # a query that RAN (even returning 0 / empty) is a valid answer for the analyst to review;
    # only "no candidate executed" is a failure.
    ran = chosen_sql is not None
    return {"result": chosen_got, "sql": chosen_sql, "votes": f"{votes}/{config.BEST_OF_N}",
            "ok": ran, "error": None if ran else last_err, "path": "granite", "plan": None,
            "explanation": None, "provenance": {"backend": "granite", "model": config.MODEL_ID}}


def _answer_catalog(question, artifact_csv):
    """The routed path: (result, None) or (None, reason). A decline always means 'let Granite try',
    never 'give the analyst nothing'; the reason travels with the answer so nothing fails silently.
    Every step is guarded -- an unreadable artifact declines here and is reported properly by Granite."""
    try:
        search_path, csv = S.split_path(artifact_csv)
        fam = family.detect(csv, search_path)
        if fam is None:
            return None, "no intent catalog for this artifact's layout"
        present = family.present_filters(csv, search_path)
        r, why = router.route(question, fam, present, ipv6=family.has_ipv6(csv, search_path))
        if r is None:
            return None, why
        sql = catalog.plan_to_sql(r.plan, question, csv)
        got, err = S.execute(sql, search_path)
        if err is not None:
            return None, f"catalog query failed to run: {err}"
        return {"result": got, "sql": sql, "votes": f"{r.votes}/{r.votes}", "ok": True, "error": None,
                "path": "catalog", "plan": r.plan, "family": fam,
                "explanation": catalog.plan_to_english(r.plan, question), "provenance": r.provenance}, None
    except Exception as e:
        return None, f"routed path error: {type(e).__name__}: {str(e)[:160]}"


def answer(question, artifact_csv, backend=None, cross_check=False):
    """Translate an analyst NL question into a verified DuckDB query over `artifact_csv`.

    Returns dict: {result, sql, votes, ok, error, path, plan, explanation, provenance[, decline_reason]
    [, cross_check]}. `path` is 'catalog' or 'granite'; when the router declined and Granite answered,
    `decline_reason` says why. With cross_check=True on a routed answer (backend auto or afm), Granite
    runs too and `cross_check` reports whether the two independent paths agree on the executed result."""
    backend = backend or config.BACKEND
    if backend not in BACKENDS:
        raise ValueError(f"backend must be one of {BACKENDS}, got {backend!r}")
    if backend == "granite":
        return _answer_granite(question, artifact_csv)
    res, why = _answer_catalog(question, artifact_csv)
    if res is None:
        if backend == "afm":
            try:
                from . import afm
                prov = afm.provenance()
            except Exception:                    # the decline must be structured even if provenance fails
                prov = {"backend": "afm"}
            return {"result": None, "sql": None, "votes": None, "ok": False, "path": None, "plan": None,
                    "explanation": None, "provenance": prov, "decline_reason": why,
                    "error": f"Apple backend declined: {why} (see `clue backends`)"}
        res = _answer_granite(question, artifact_csv)
        res["decline_reason"] = why
        return res
    if cross_check:
        res["cross_check"] = _cross_check(res, question, artifact_csv)
    return res


def _cross_check(res, question, artifact_csv):
    """Run Granite on the same question and compare EXECUTED results. `executed` is False when Granite
    produced no runnable query or raised -- that is 'not checked', never 'disagreed'."""
    base = {"other_path": "granite", "executed": False, "agree": None, "other_sql": None, "other_result": None,
            "other_ok": False, "other_error": None}
    try:
        other = _answer_granite(question, artifact_csv)
    except Exception as e:
        return dict(base, other_error=f"{type(e).__name__}: {str(e)[:160]}")
    base.update(other_sql=other.get("sql"), other_result=other.get("result"), other_ok=bool(other.get("ok")),
                other_error=other.get("error"))
    if not other.get("ok"):
        return base
    return dict(base, executed=True, agree=_key(other["result"]) == _key(res["result"]))
