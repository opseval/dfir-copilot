"""copilot.afm against the fake `fm` in tests/fakes/fm: availability, the failure contract, and the
pinned argv (model=system, use-case=general, prompt on stdin, greedy flag)."""
import json
import os

import pytest

from copilot import afm, config

FAKE = os.path.join(os.path.dirname(__file__), "fakes", "fm")


@pytest.fixture
def fake_fm(monkeypatch, tmp_path):
    """Route copilot.afm at the fake binary with a clean cache and an argv log."""
    log = tmp_path / "argv.jsonl"
    monkeypatch.setattr(config, "FM_BIN", FAKE)
    monkeypatch.setattr(afm, "_avail", None)
    monkeypatch.setenv("FAKE_FM_LOG", str(log))
    for var in ("FAKE_FM_MODE", "FAKE_FM_GREEDY", "FAKE_FM_SAMPLED", "FAKE_FM_TEXT", "FAKE_FM_SLEEP"):
        monkeypatch.delenv(var, raising=False)

    def argv_log():
        return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []

    return argv_log


def test_available_ok(fake_fm):
    ok, reason = afm.available()
    assert ok and "available" in reason.lower()
    cmds = [a[0] for a in fake_fm()]
    assert cmds == ["license", "available"], "licence must be checked before the model"


def test_available_is_cached(fake_fm):
    afm.available()
    afm.available()
    assert len(fake_fm()) == 2


def test_unavailable_when_licence_not_agreed(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "nolicense")
    ok, reason = afm.available()
    assert not ok and "fm license" in reason
    assert [a[0] for a in fake_fm()] == ["license"], "must not probe the model without a licence"


def test_unavailable_when_model_missing(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "nomodel")
    ok, reason = afm.available()
    assert not ok and "unavailable" in reason.lower()


def test_probe_error_line_means_unavailable(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "probeerror")     # rc=0 but an `Error:` line, which mentions 'available'
    ok, reason = afm.available()
    assert not ok and reason.startswith("Error:")


def test_unavailable_when_binary_missing(monkeypatch):
    monkeypatch.setattr(config, "FM_BIN", "/nonexistent/fm")
    monkeypatch.setattr(afm, "_avail", None)
    ok, reason = afm.available()
    assert not ok and "not found" in reason
    with pytest.raises(afm.AFMUnavailable):
        afm.respond("i", "p")


def test_respond_text_and_pinned_argv(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_GREEDY", "hello")
    assert afm.respond("be brief", "-what is this?") == "hello"
    argv = fake_fm()[-1]
    assert argv[0] == "respond"
    assert argv[argv.index("--model") + 1] == "system"
    assert argv[argv.index("--use-case") + 1] == "general"
    assert argv[argv.index("--guardrails") + 1] == config.AFM_GUARDRAILS
    assert "--no-stream" in argv and "--greedy" in argv
    assert "-what is this?" not in argv, "the prompt goes on stdin, never argv"
    assert "pcc" not in " ".join(argv).lower()


def test_prompt_goes_over_stdin_verbatim(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "echo")
    assert afm.respond("i", "--model pcc please") == "--model pcc please"


def test_sampled_call_has_no_greedy_flag(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_SAMPLED", "s")
    assert afm.respond("i", "p", greedy=False) == "s"
    assert "--greedy" not in fake_fm()[-1]


def test_respond_schema_returns_object(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_GREEDY", '{"a": 1}')
    out = afm.respond("i", "p", schema={"title": "T", "type": "object", "properties": {}})
    assert out == {"a": 1}
    argv = fake_fm()[-1]
    assert "--schema" in argv and argv[argv.index("--schema") + 1].endswith(".json")
    assert not os.path.exists(argv[argv.index("--schema") + 1]), "temp schema file is removed"


@pytest.mark.parametrize("mode", ["error", "colorerror", "exit1", "empty"])
def test_respond_failure_contract(fake_fm, monkeypatch, mode):
    monkeypatch.setenv("FAKE_FM_MODE", mode)
    with pytest.raises(afm.AFMError):
        afm.respond("i", "p")


def test_invalid_bytes_do_not_escape_the_contract(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "badbytes")
    assert afm.respond("i", "p").startswith("ok ")          # decoded with replacement, never UnicodeDecodeError


def test_respond_bad_json_for_schema(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "badjson")
    with pytest.raises(afm.AFMError):
        afm.respond("i", "p", schema={"title": "T", "type": "object", "properties": {}})


def test_respond_timeout(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "sleep")
    monkeypatch.setenv("FAKE_FM_SLEEP", "3")
    with pytest.raises(afm.AFMError, match="timed out"):
        afm.respond("i", "p", timeout=0.5)


def test_provenance_shape(monkeypatch):
    monkeypatch.setattr(afm, "_prov", None)
    p = afm.provenance()
    assert p["backend"] == "afm" and p["model"] == "system" and p["macos"]
