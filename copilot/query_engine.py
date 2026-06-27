"""Constrained NL->DuckDB query engine -- the deployable 14/17 structure stack.

Pipeline: M-Schema (real example values) + forensic dictionary in context
       -> constrained decoding (per-CSV Lark grammar: identifiers locked to this schema)
       -> best-of-N + self-consistency (majority vote on EXECUTION RESULTS, answer-blind)
       -> execute-and-retry on all-fail (verbatim DuckDB error fed back).

The model is the UNTUNED base, frozen. The structure -- not the weights -- is what makes
it reliable. Output is one of: a result + the SQL that produced it (for analyst approval),
or a clear "could not produce a query" with the last error.
"""
import os
import re
from collections import Counter

from . import config
from .domain_pack import DOMAIN_DICT, EXEMPLARS_NOFENCE
from .grammar import grammar_for_csv
from . import schema as S

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


def answer(question, artifact_csv):
    """Translate an analyst NL question into a verified DuckDB query over `artifact_csv`.

    Returns dict: {result, sql, votes, attempts, ok, error}. `ok` means a query ran and
    returned a sensible value (the analyst still approves before anything is acted on)."""
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
            "ok": ran, "error": None if ran else last_err}
