"""answer() orchestration with the Granite path stubbed: backend switch, fall-through ordering with
reasons, the afm-only error, cross-check agreement. The catalog path runs for real on the sample."""
import os

import pytest

from copilot import catalog, config, family, router
from copilot import query_engine as QE

SAMPLE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "copilot", "sample", "auth_sample.csv"))
Q = "how many failed password attempts are there?"
PLAN = {"event_filter": "failed_password", "extract_field": "none", "aggregate": "count_rows", "account_scope": "any_user"}
ROUTE = router.Route(plan=PLAN, provenance={"backend": "afm", "model": "system", "macos": "test"}, votes=2)
TRUTH = 13   # failed-password lines in the sample, excluding 'message repeated' wrappers


@pytest.fixture
def granite_stub(monkeypatch):
    calls = []

    def fake(question, artifact):
        calls.append(question)
        return {"result": TRUTH, "sql": "SELECT count(*) FROM read_csv_auto('auth_sample.csv') WHERE Content LIKE '%Failed password%'",
                "votes": "5/5", "ok": True, "error": None, "path": "granite", "plan": None,
                "explanation": None, "provenance": {"backend": "granite"}}

    monkeypatch.setattr(QE, "_answer_granite", fake)
    return calls


def routed(monkeypatch):
    monkeypatch.setattr(router, "route", lambda q, f, p=None, ipv6=False: (ROUTE, None))


def declined(monkeypatch, why="router votes disagreed"):
    monkeypatch.setattr(router, "route", lambda q, f, p=None, ipv6=False: (None, why))


def test_granite_backend_bypasses_router(granite_stub, monkeypatch):
    monkeypatch.setattr(router, "route", lambda *a: pytest.fail("router must not run for backend=granite"))
    res = QE.answer(Q, SAMPLE, backend="granite")
    assert res["path"] == "granite" and granite_stub == [Q] and "decline_reason" not in res


def test_auto_takes_the_catalog_when_routed(granite_stub, monkeypatch):
    routed(monkeypatch)
    res = QE.answer(Q, SAMPLE, backend="auto")
    assert res["path"] == "catalog" and res["ok"] and res["result"] == TRUTH
    assert res["sql"].startswith("SELECT count(*) FROM read_csv_auto('auth_sample.csv') WHERE")
    assert res["explanation"].startswith("Counts lines recording a failed SSH password attempt")
    assert res["votes"] == "2/2" and res["provenance"]["backend"] == "afm" and res["plan"] == PLAN
    assert granite_stub == [], "Granite must not load for a routed question"


def test_auto_falls_through_with_the_reason(granite_stub, monkeypatch):
    declined(monkeypatch)
    res = QE.answer(Q, SAMPLE, backend="auto")
    assert res["path"] == "granite" and granite_stub == [Q] and res["decline_reason"] == "router votes disagreed"


def test_auto_falls_through_for_an_artifact_without_a_catalog(granite_stub, monkeypatch, tmp_path):
    p = tmp_path / "sysmon.csv"
    p.write_text("TimeCreated,Image,ParentImage,CommandLine\n2026-01-01T00:00:00Z,a.exe,b.exe,a.exe\n")
    monkeypatch.setattr(router, "route", lambda *a: pytest.fail("no family, so the router must not run"))
    res = QE.answer(Q, str(p), backend="auto")
    assert res["path"] == "granite" and "no intent catalog" in res["decline_reason"]


def test_auto_falls_through_for_an_unreadable_artifact(granite_stub, monkeypatch, tmp_path):
    monkeypatch.setattr(router, "route", lambda *a: pytest.fail("must not route"))
    res = QE.answer(Q, str(tmp_path / "missing.csv"), backend="auto")
    assert res["path"] == "granite" and res["decline_reason"].startswith("routed path error")


@pytest.mark.parametrize("target,attr", [(QE.S, "split_path"), (family, "detect"), (family, "present_filters"),
                                         (catalog, "plan_to_sql"), (catalog, "plan_to_english")])
def test_any_exception_in_the_routed_path_falls_through(granite_stub, monkeypatch, target, attr):
    routed(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(target, attr, boom)
    res = QE.answer(Q, SAMPLE, backend="auto")
    assert res["path"] == "granite" and "RuntimeError: boom" in res["decline_reason"]


def test_catalog_sql_that_does_not_run_falls_through(granite_stub, monkeypatch):
    routed(monkeypatch)
    monkeypatch.setattr(catalog, "plan_to_sql", lambda p, q, csv: f"SELECT no_such_column FROM read_csv_auto('{csv}')")
    res = QE.answer(Q, SAMPLE, backend="auto")
    assert res["path"] == "granite" and res["decline_reason"].startswith("catalog query failed to run")


def test_afm_backend_errors_with_the_concrete_reason(granite_stub, monkeypatch):
    declined(monkeypatch, "the artifact contains no 'failed_password' lines")
    res = QE.answer(Q, SAMPLE, backend="afm")
    assert not res["ok"] and res["path"] is None and granite_stub == []
    assert "no 'failed_password' lines" in res["error"] and res["decline_reason"].startswith("the artifact")


def test_cross_check_agreement(granite_stub, monkeypatch):
    routed(monkeypatch)
    res = QE.answer(Q, SAMPLE, backend="auto", cross_check=True)
    assert res["path"] == "catalog" and res["cross_check"]["agree"] is True and granite_stub == [Q]


def test_cross_check_is_honoured_for_afm_backend(granite_stub, monkeypatch):
    routed(monkeypatch)
    res = QE.answer(Q, SAMPLE, backend="afm", cross_check=True)
    assert res["path"] == "catalog" and res["cross_check"]["agree"] is True and granite_stub == [Q]


def test_cross_check_disagreement(granite_stub, monkeypatch):
    routed(monkeypatch)
    monkeypatch.setattr(QE, "_answer_granite", lambda q, a: {"result": 99, "sql": "SELECT 99", "ok": True,
                                                              "error": None, "votes": "3/5", "path": "granite"})
    cc = QE.answer(Q, SAMPLE, backend="auto", cross_check=True)["cross_check"]
    assert cc["executed"] is True and cc["agree"] is False and cc["other_result"] == 99 and cc["other_path"] == "granite"


def test_cross_check_not_executed_when_granite_has_no_query(granite_stub, monkeypatch):
    routed(monkeypatch)
    monkeypatch.setattr(QE, "_answer_granite", lambda q, a: {"result": None, "sql": None, "ok": False,
                                                              "error": "no candidate executed", "votes": "0/5", "path": "granite"})
    res = QE.answer(Q, SAMPLE, backend="auto", cross_check=True)
    assert res["ok"] and res["path"] == "catalog", "the catalog answer is kept"
    cc = res["cross_check"]
    assert cc["executed"] is False and cc["agree"] is None and cc["other_error"] == "no candidate executed"


def test_cross_check_survives_a_granite_exception(granite_stub, monkeypatch):
    routed(monkeypatch)

    def boom(q, a):
        raise RuntimeError("model load failed")

    monkeypatch.setattr(QE, "_answer_granite", boom)
    res = QE.answer(Q, SAMPLE, backend="auto", cross_check=True)
    assert res["ok"] and res["result"] == TRUTH
    assert res["cross_check"]["executed"] is False and "model load failed" in res["cross_check"]["other_error"]


def test_afm_decline_is_structured_even_if_provenance_fails(granite_stub, monkeypatch):
    declined(monkeypatch)
    from copilot import afm

    def boom():
        raise RuntimeError("sw_vers exploded")

    monkeypatch.setattr(afm, "provenance", boom)
    res = QE.answer(Q, SAMPLE, backend="afm")
    assert not res["ok"] and res["provenance"] == {"backend": "afm"} and "declined" in res["error"]


def test_default_backend_comes_from_config(granite_stub, monkeypatch):
    monkeypatch.setattr(config, "BACKEND", "granite")
    monkeypatch.setattr(router, "route", lambda *a: pytest.fail("router must not run"))
    assert QE.answer(Q, SAMPLE)["path"] == "granite"


def test_unknown_backend_is_rejected(granite_stub):
    with pytest.raises(ValueError):
        QE.answer(Q, SAMPLE, backend="cloud")
