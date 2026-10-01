"""The CLI reports itself under the name it was invoked by (`clue` or `dfir-copilot`)."""
import os

import pytest

from copilot import cli


def test_prog_follows_the_invoked_name(monkeypatch, capsys):
    monkeypatch.setenv("DFIR_PROG", "clue")
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert capsys.readouterr().out.startswith("usage: clue ")

    monkeypatch.delenv("DFIR_PROG")
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert capsys.readouterr().out.startswith("usage: dfir-copilot ")


def test_no_arguments_prints_the_cheat_sheet(monkeypatch, capsys):
    monkeypatch.setenv("DFIR_PROG", "clue")
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    for line in ("clue query", "clue triage", "clue narrate", "clue ocr", "clue backends", "clue verify", "clue tools"):
        assert line in out
    assert "error" not in out.lower()


def test_query_accepts_the_artifact_and_question_in_either_order(monkeypatch, tmp_path, capsys):
    import copilot.query_engine as QE
    seen = []

    def fake_answer(question, artifact, backend=None, cross_check=False):
        seen.append((question, artifact))
        return {"ok": True, "sql": "SELECT 1", "result": 1, "votes": "2/2", "path": "catalog",
                "explanation": "x", "provenance": {"backend": "afm", "macos": "test"}, "error": None}

    monkeypatch.setattr(QE, "answer", fake_answer)
    csv = tmp_path / "auth.csv"
    csv.write_text("LineId,Content\n1,x\n")
    assert cli.main(["query", str(csv), "how many lines?"]) == 0
    assert cli.main(["query", "how many lines?", str(csv)]) == 0
    assert seen == [("how many lines?", str(csv))] * 2


def _recording_answer(seen):
    def fake(question, artifact, backend=None, cross_check=False):
        seen.append((question, artifact))
        return {"ok": True, "sql": "SELECT 1", "result": 1, "votes": "2/2", "path": "catalog",
                "explanation": "x", "provenance": {"backend": "afm", "macos": "test"}, "error": None}
    return fake


def test_query_keeps_the_given_order_when_both_arguments_are_files(monkeypatch, tmp_path):
    """Both existing: no guessing -- the documented order (question first) stands."""
    import copilot.query_engine as QE
    seen = []
    monkeypatch.setattr(QE, "answer", _recording_answer(seen))
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    a.write_text("x\n"); b.write_text("y\n")
    assert cli.main(["query", str(a), str(b)]) == 0
    assert seen == [(str(a), str(b))]


def test_query_does_not_swap_for_a_filename_like_question(monkeypatch, tmp_path):
    """A question that merely looks like a file name never displaces a real artifact."""
    import copilot.query_engine as QE
    seen = []
    monkeypatch.setattr(QE, "answer", _recording_answer(seen))
    csv = tmp_path / "auth.csv"
    csv.write_text("x\n")
    assert cli.main(["query", "events.csv", str(csv)]) == 0
    assert seen == [("events.csv", str(csv))]


@pytest.mark.parametrize("second", ["typo.csv", "missing", "evidence.E01", "count", "missing artifact.csv",
                                    "my case/auth.csv", "Case Notes.CSV"])
def test_query_never_lets_a_file_given_first_displace_a_path_like_second_argument(monkeypatch, tmp_path, capsys, second):
    """`clue query notes.csv typo.csv`, `clue query README.md missing`, `clue query auth.csv "missing artifact.csv"`:
    the second argument is a single token or ends in a data-file extension, so it could be a mistyped file;
    the order stands and that argument is reported as missing."""
    import copilot.query_engine as QE

    def must_not_run(*a, **k):
        raise AssertionError("answer() ran with the first argument as the artifact")

    monkeypatch.setattr(QE, "answer", must_not_run)
    first = tmp_path / "README.md"
    first.write_text("a,b\n1,2\n")
    assert cli.main(["query", str(first), second]) == 2
    assert f"artifact not found: {second}" in capsys.readouterr().err


@pytest.mark.parametrize("question", ["how many failed logins?", "which IP has the most events, and how many?",
                                      "count rows", "list the /etc/passwd reads"])
def test_query_swaps_when_the_file_comes_first_and_the_second_argument_is_a_sentence(monkeypatch, tmp_path, question):
    import copilot.query_engine as QE
    seen = []
    monkeypatch.setattr(QE, "answer", _recording_answer(seen))
    csv = tmp_path / "auth.csv"
    csv.write_text("LineId,Content\n1,x\n")
    assert cli.main(["query", str(csv), question]) == 0
    assert seen == [(question, str(csv))]


def test_query_reports_a_missing_artifact_before_any_model_work(monkeypatch, tmp_path, capsys):
    import copilot.query_engine as QE

    def must_not_run(*a, **k):
        raise AssertionError("answer() ran for a missing artifact")

    monkeypatch.setattr(QE, "answer", must_not_run)
    missing = str(tmp_path / "typo.csv")
    for argv in (["query", "how many lines?", missing], ["query", missing, "how many lines?"]):
        assert cli.main(argv) == 2
        assert f"artifact not found: {missing}" in capsys.readouterr().err
    # neither argument is path-shaped: the given order stands and the second is reported
    assert cli.main(["query", "how many lines", "in the log"]) == 2
    assert "artifact not found: in the log" in capsys.readouterr().err


def test_query_refuses_a_directory(monkeypatch, tmp_path, capsys):
    import copilot.query_engine as QE

    def must_not_run(*a, **k):
        raise AssertionError("answer() ran for a directory")

    monkeypatch.setattr(QE, "answer", must_not_run)
    for name in ("case", "case[1]", "run?"):      # a directory named like a glob is still a directory
        d = tmp_path / name
        d.mkdir()
        for argv in (["query", "how many lines?", str(d)], ["query", str(d) + os.sep, "how many lines?"]):
            assert cli.main(argv) == 2
            err = capsys.readouterr().err
            assert "artifact is a directory" in err and f"{d}/*.csv" in err


def test_query_leaves_glob_patterns_to_duckdb(monkeypatch, tmp_path):
    import copilot.query_engine as QE
    seen = []

    def fake_answer(question, artifact, backend=None, cross_check=False):
        seen.append(artifact)
        return {"ok": False, "error": "n/a"}

    monkeypatch.setattr(QE, "answer", fake_answer)
    (tmp_path / "a.csv").write_text("LineId,Content\n1,x\n")       # the pattern matches something
    pattern = str(tmp_path / "*.csv")
    assert cli.main(["query", "how many lines?", pattern]) == 2     # the engine's own failure, not ours
    assert seen == [pattern]


@pytest.mark.parametrize("backend", ["afm", "granite", "auto"])
def test_query_reports_an_unreadable_artifact_in_one_line_on_every_backend(monkeypatch, tmp_path, capsys, backend):
    """A real empty glob, no mocking: DuckDB's multi-line error is reduced to one line before any
    backend runs (the afm path used to fold it into a multi-line decline reason)."""
    import copilot.query_engine as QE

    def must_not_run(*a, **k):
        raise AssertionError("a backend ran for an unreadable artifact")

    monkeypatch.setattr(QE, "answer", must_not_run)
    pattern = str(tmp_path / "*.csv")
    assert cli.main(["query", "how many lines?", pattern, "--backend", backend]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"Error: could not read {pattern}: IO Error: No files found")
    assert len(err.strip().splitlines()) == 1
    assert "LINE 1" not in err and "Traceback" not in err


def test_query_backstops_duckdb_errors_raised_by_the_engine(monkeypatch, tmp_path, capsys):
    import duckdb
    import copilot.query_engine as QE

    def raising_answer(question, artifact, backend=None, cross_check=False):
        raise duckdb.IOException("IO Error: file vanished\n\nLINE 1: ...")

    monkeypatch.setattr(QE, "answer", raising_answer)
    csv = tmp_path / "auth.csv"
    csv.write_text("LineId,Content\n1,x\n")
    assert cli.main(["query", "how many lines?", str(csv)]) == 2
    err = capsys.readouterr().err
    assert err == f"Error: could not read {csv}: IO Error: file vanished\n"


def test_verify_forwards_quick(monkeypatch):
    import subprocess
    calls = []
    monkeypatch.setattr(subprocess, "call", lambda argv: calls.append(argv) or 0)
    assert cli.main(["verify"]) == 0
    assert cli.main(["verify", "--quick"]) == 0
    assert len(calls[0]) == 2 and calls[0][-1].endswith("verify.py")
    assert calls[1][-2].endswith("verify.py") and calls[1][-1] == "--quick"


@pytest.mark.parametrize("bad", ["", "clue\nusage: sudo", "\x1b[31mclue\x1b[0m", "../clue", "x" * 80, "-clue"])
def test_unsafe_or_empty_prog_falls_back(monkeypatch, capsys, bad):
    monkeypatch.setenv("DFIR_PROG", bad)
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert capsys.readouterr().out.startswith("usage: dfir-copilot ")
