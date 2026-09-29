"""Interpretation engine: deterministic pre-extraction + triage owns the VERDICT;
a model is an optional NARRATOR only.

Campaign result: deterministic triage = 11/12 (12/12 malicious-vs-benign, 0 dangerous
misses) vs an untuned 3B at 2/12 and even +findings at 9/12 WITH false-positives. So the
harness owns the verdict; the model never adjudicates.

narrate() prefers the on-device Apple model (2-3 s, nothing to load) and falls through to
Granite. Both get the same bounded prompt: the findings block plus an excerpt of the raw
output that keeps evidence-bearing lines first, so a large tool dump still fits a small
context window and the narration stays anchored to what the detectors actually matched.
"""
import os
import re
import sys

_HERE = os.path.dirname(__file__)
sys.path.insert(0, _HERE)
import preextract as PX   # noqa: E402
import triage as TR       # noqa: E402
from . import config      # noqa: E402

BACKENDS = ("auto", "granite", "afm")
SYSTEM = ("You are a DFIR analyst assistant. You are given deterministic pre-extracted findings as "
          "GROUND TRUTH. Write a brief, factual analyst summary grounded ONLY in those findings. Do NOT "
          "invent indicators, names, addresses or numbers that are not in the findings or the excerpt. "
          "Do NOT override the findings or add a verdict of your own. If no findings were extracted, say "
          "that no known indicators matched and describe only what the excerpt literally shows.")


def triage(raw_tool_output):
    """Deterministic verdict + findings + suggested next commands. NO model. The default."""
    return TR.triage(raw_tool_output)


def findings(raw_tool_output):
    return PX.extract(raw_tool_output)


def _evidence_tokens(found):
    toks = set()
    for f in found:
        for t in re.split(r"[\s,;:()\[\]\"']+", str(f.get("evidence", ""))):
            if len(t) >= 4:
                toks.add(t.lower())
    return toks


_HEAD = "RAW TOOL OUTPUT"
_TAIL = "\n\nWrite a 2-4 sentence grounded summary."
_FRAME = 160                                      # headers, the omission notes, separators


def _fit_lines(text, limit, label):
    """Keep whole leading lines of `text` within `limit` chars; say how many were dropped."""
    if len(text) <= limit:
        return text
    kept, used, lines = [], 0, text.splitlines()
    for l in lines:
        if used + len(l) + 1 > limit:
            break
        kept.append(l)
        used += len(l) + 1
    return "\n".join(kept) + f"\n... ({len(lines) - len(kept)} more {label} lines omitted to fit the model's context)"


def narration_prompt(raw_tool_output, max_chars=None):
    """Findings block + a bounded excerpt of the raw output, with the WHOLE prompt held under
    `max_chars`: the findings get at most half the budget, the excerpt the rest. Excerpt lines that
    carry a finding's evidence are selected first, then the head of the output; the excerpt is printed
    in the original order and says how many lines were omitted."""
    budget = max_chars or config.NARRATE_MAX_CHARS
    found = PX.extract(raw_tool_output)
    block = _fit_lines(PX.findings_block(raw_tool_output), max(0, (budget - _FRAME) // 2), "finding")
    excerpt_budget = max(0, budget - _FRAME - len(block))
    lines = raw_tool_output.splitlines()
    toks = _evidence_tokens(found)
    evidence = [i for i, l in enumerate(lines) if any(t in l.lower() for t in toks)]
    evidence_set = set(evidence)
    rest = [i for i in range(len(lines)) if i not in evidence_set]
    chosen, used = [], 0
    for i in evidence + rest:                     # priority order, output in original order
        cost = len(lines[i]) + 1
        if used + cost > excerpt_budget:
            continue
        chosen.append(i)
        used += cost
    chosen.sort()
    excerpt = "\n".join(lines[i] for i in chosen)
    omitted = len(lines) - len(chosen)
    note = f" ({len(chosen)} of {len(lines)} lines shown; {omitted} omitted to fit the model's context)" if omitted else ""
    prompt = f"{block}\n\n{_HEAD}{note}:\n{excerpt}{_TAIL}"
    return prompt if len(prompt) <= budget else prompt[:budget]     # hard guarantee, never exceeded


def _narrate_granite(user_prompt):
    import mlx_lm
    from mlx_lm.sample_utils import make_sampler
    model, tok = mlx_lm.load(config.MODEL_ID)
    prompt = tok.apply_chat_template(
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_prompt}],
        add_generation_prompt=True, tokenize=False)
    return mlx_lm.generate(model, tok, prompt, max_tokens=300,
                           sampler=make_sampler(temp=0.0), verbose=False)


def narrate(raw_tool_output, backend=None):
    """OPTIONAL: a grounded prose summary anchored to the deterministic findings. Returns
    {"text", "provenance"}. The verdict still comes from triage(), never from this.
    backend: auto (Apple first, Granite fallback) | granite | afm (Apple only, raises on failure)."""
    backend = backend or config.BACKEND
    if backend not in BACKENDS:
        raise ValueError(f"backend must be one of {BACKENDS}, got {backend!r}")
    user = narration_prompt(raw_tool_output)
    if backend in ("auto", "afm"):
        from . import afm
        try:
            return {"text": afm.respond(SYSTEM, user, greedy=True), "provenance": afm.provenance()}
        except Exception:                 # any failure of the Apple attempt: fall through in auto, raise in afm
            if backend == "afm":
                raise
    return {"text": _narrate_granite(user), "provenance": {"backend": "granite", "model": config.MODEL_ID}}
