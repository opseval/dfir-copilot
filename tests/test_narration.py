"""Narration: the bounded prompt keeps evidence lines and fits the budget; narrate() prefers the
Apple backend, falls through to Granite on any failure, and raises only for backend=afm."""
import json
import os

import pytest

from copilot import afm, config
from copilot import interp_engine as IE

FAKE = os.path.join(os.path.dirname(__file__), "fakes", "fm")
MALFIND = ("Volatility 3 Framework 2.7.0\n"
           "PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\n"
           "672\tlsass.exe\t0x1f0a0000\t0x1f0a1fff\tVadS\tPAGE_EXECUTE_READWRITE\n")


@pytest.fixture
def fake_fm(monkeypatch, tmp_path):
    log = tmp_path / "argv.jsonl"
    monkeypatch.setattr(config, "FM_BIN", FAKE)
    monkeypatch.setattr(afm, "_avail", None)
    monkeypatch.setenv("FAKE_FM_LOG", str(log))
    for var in ("FAKE_FM_MODE", "FAKE_FM_GREEDY", "FAKE_FM_SAMPLED", "FAKE_FM_TEXT", "FAKE_FM_SLEEP"):
        monkeypatch.delenv(var, raising=False)
    return lambda: [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture
def granite_stub(monkeypatch):
    calls = []
    monkeypatch.setattr(IE, "_narrate_granite", lambda user: calls.append(user) or "granite says")
    return calls


def test_prompt_is_bounded_and_keeps_evidence_lines():
    filler = "\n".join(f"filler line {i} " + "x" * 60 for i in range(3000))
    raw = filler + "\n" + MALFIND
    p = IE.narration_prompt(raw, max_chars=4000)
    body = p.split("RAW TOOL OUTPUT")[1]
    assert len(body) < 4000 + 400
    assert "lsass.exe" in body and "PAGE_EXECUTE_READWRITE" in body, "evidence-bearing lines are kept first"
    assert "omitted to fit the model's context" in p
    assert "RWX executable memory inside lsass.exe" in p, "findings block is included"


def test_whole_prompt_stays_under_budget_even_with_huge_findings():
    # thousands of distinct staging-path hits -> thousands of findings; the cap must hold for the WHOLE prompt
    raw = "\n".join(f"C:\\Users\\u\\AppData\\Local\\Temp\\dropper{i}.exe" for i in range(3000))
    for budget in (800, 4000, 6000):
        p = IE.narration_prompt(raw, max_chars=budget)
        assert len(p) <= budget
        assert "more finding lines omitted" in p and "omitted to fit" in p


def test_small_output_is_shown_whole():
    p = IE.narration_prompt(MALFIND)
    assert "omitted" not in p and MALFIND.strip().splitlines()[-1] in p


def test_empty_output_still_makes_a_prompt():
    assert "no known indicators matched" in IE.narration_prompt("")


def test_auto_prefers_apple(fake_fm, granite_stub, monkeypatch):
    monkeypatch.setenv("FAKE_FM_GREEDY", "apple says")
    out = IE.narrate(MALFIND, backend="auto")
    assert out["text"] == "apple says" and out["provenance"]["backend"] == "afm" and granite_stub == []
    argv = [a for a in fake_fm() if a[0] == "respond"][0]
    assert argv[argv.index("--guardrails") + 1] == config.AFM_GUARDRAILS and "--greedy" in argv


@pytest.mark.parametrize("mode", ["exit1", "error", "nomodel", "nolicense"])
def test_auto_falls_through_to_granite(fake_fm, granite_stub, monkeypatch, mode):
    monkeypatch.setenv("FAKE_FM_MODE", mode)
    out = IE.narrate(MALFIND, backend="auto")
    assert out["text"] == "granite says" and out["provenance"]["backend"] == "granite" and len(granite_stub) == 1
    assert "RWX executable memory inside lsass.exe" in granite_stub[0], "Granite gets the same bounded prompt"


def test_auto_falls_through_on_unexpected_apple_errors(fake_fm, granite_stub, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(afm, "respond", boom)
    out = IE.narrate(MALFIND, backend="auto")
    assert out["provenance"]["backend"] == "granite" and len(granite_stub) == 1
    with pytest.raises(RuntimeError):
        IE.narrate(MALFIND, backend="afm")


def test_afm_only_raises(fake_fm, granite_stub, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "exit1")
    with pytest.raises(afm.AFMError):
        IE.narrate(MALFIND, backend="afm")
    assert granite_stub == []


def test_granite_only_never_calls_fm(fake_fm, granite_stub):
    out = IE.narrate(MALFIND, backend="granite")
    assert out["provenance"]["backend"] == "granite" and fake_fm() == []


def test_unknown_backend_rejected(granite_stub):
    with pytest.raises(ValueError):
        IE.narrate(MALFIND, backend="cloud")
