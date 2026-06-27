"""Interpretation engine: deterministic pre-extraction + triage owns the VERDICT;
the LLM is an optional NARRATOR only.

Campaign result: deterministic triage = 11/12 (12/12 malicious-vs-benign, 0 dangerous
misses) vs an untuned 3B at 2/12 and even +findings at 9/12 WITH false-positives. So the
harness owns the verdict; the model never adjudicates. `narrate()` is off by default.
"""
import os
import sys

_HERE = os.path.dirname(__file__)
sys.path.insert(0, _HERE)
import preextract as PX   # noqa: E402
import triage as TR       # noqa: E402


def triage(raw_tool_output):
    """Deterministic verdict + findings + suggested next commands. NO model. The default."""
    return TR.triage(raw_tool_output)


def findings(raw_tool_output):
    return PX.extract(raw_tool_output)


def narrate(raw_tool_output):
    """OPTIONAL: a grounded prose summary from the small model, anchored to the
    deterministic findings. The verdict still comes from triage(), never from this."""
    from . import config  # noqa: F401  (ensures MLX env is set)
    import mlx_lm
    from mlx_lm.sample_utils import make_sampler
    from .config import MODEL_ID
    fb = PX.findings_block(raw_tool_output)
    sysm = ("You are a DFIR analyst assistant. You are given deterministic pre-extracted "
            "findings as GROUND TRUTH. Write a brief, factual analyst summary grounded ONLY "
            "in those findings. Do NOT invent indicators. Do NOT override the findings.")
    user = f"{fb}\n\nRAW TOOL OUTPUT:\n{raw_tool_output}\n\nWrite a 2-4 sentence grounded summary."
    model, tok = mlx_lm.load(MODEL_ID)
    prompt = tok.apply_chat_template(
        [{"role": "system", "content": sysm}, {"role": "user", "content": user}],
        add_generation_prompt=True, tokenize=False)
    return mlx_lm.generate(model, tok, prompt, max_tokens=300,
                           sampler=make_sampler(temp=0.0), verbose=False)
