"""The router against the fake fm: agreement, disagreement, invalid plans, absent filters, fm failures,
unavailability -- every non-happy path is (None, reason), never an exception."""
import json
import os

import pytest

from copilot import afm, catalog, config, router

FAKE = os.path.join(os.path.dirname(__file__), "fakes", "fm")
Q = "how many failed password attempts are there?"
PLAN = {"event_filter": "failed_password", "extract_field": "none", "aggregate": "count_rows"}
NORM = dict(PLAN, account_scope="any_user")
PRESENT = {"all_events", "quoted_phrase", "failed_password", "invalid_user"}


@pytest.fixture
def fake_fm(monkeypatch, tmp_path):
    log = tmp_path / "argv.jsonl"
    monkeypatch.setattr(config, "FM_BIN", FAKE)
    monkeypatch.setattr(config, "ROUTER_VOTES", 2)
    monkeypatch.setattr(afm, "_avail", None)
    monkeypatch.setenv("FAKE_FM_LOG", str(log))
    for var in ("FAKE_FM_MODE", "FAKE_FM_GREEDY", "FAKE_FM_SAMPLED", "FAKE_FM_TEXT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("FAKE_FM_GREEDY", json.dumps(PLAN))
    monkeypatch.setenv("FAKE_FM_SAMPLED", json.dumps(PLAN))
    return lambda: [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []


def test_agreeing_votes_route(fake_fm):
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert why is None and r.plan == NORM and r.votes == 2 and r.provenance["backend"] == "afm"
    responds = [a for a in fake_fm() if a[0] == "respond"]
    assert len(responds) == 2 and "--greedy" in responds[0] and "--greedy" not in responds[1], "greedy first, then sampled"
    assert all("--schema" in a for a in responds)


def test_schema_offered_is_the_full_catalog(fake_fm, monkeypatch):
    seen = {}
    real = afm.respond

    def spy(instructions, prompt, schema=None, greedy=True, timeout=None):
        seen["enum"] = schema["properties"]["event_filter"]["enum"]
        return real(instructions, prompt, schema=schema, greedy=greedy, timeout=timeout)

    monkeypatch.setattr(afm, "respond", spy)
    router.route(Q, catalog.FAMILY, {"all_events", "quoted_phrase", "pam_auth_failure"})
    assert seen["enum"] == list(catalog.EVENT_FILTERS), "the model always sees every filter, so it can name an absent one"


def test_absent_filter_is_declined_not_coerced(fake_fm):
    r, why = router.route(Q, catalog.FAMILY, {"all_events", "quoted_phrase", "pam_auth_failure"})
    assert r is None and "no 'failed_password' lines" in why


def test_normalization_makes_votes_agree(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_SAMPLED", json.dumps(dict(PLAN, extract_field="event_id")))  # count_rows ignores it
    assert router.route(Q, catalog.FAMILY, PRESENT)[0].plan == NORM


def test_disagreeing_votes_fall_through(fake_fm, monkeypatch):
    # the cue rules make valid plans nearly unique, so exercise the disagreement path with validation stubbed
    monkeypatch.setattr(catalog, "validate", lambda plan, q: (dict(plan, account_scope="any_user"), None))
    monkeypatch.setenv("FAKE_FM_SAMPLED", json.dumps(dict(PLAN, event_filter="invalid_user")))
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert r is None and why == "router votes disagreed"


def test_a_vote_contradicting_the_question_is_invalid(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_SAMPLED", json.dumps(dict(PLAN, event_filter="invalid_user")))
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert r is None and why.startswith("invalid plan") and "failed_password" in why


def test_invalid_plan_falls_through(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_GREEDY", json.dumps(dict(PLAN, aggregate="count_distinct_values")))  # needs an extract
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert r is None and why.startswith("invalid plan")


def test_out_of_catalog_value_falls_through(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_GREEDY", json.dumps(dict(PLAN, event_filter="delete_everything")))
    assert router.route(Q, catalog.FAMILY, PRESENT)[0] is None


@pytest.mark.parametrize("mode", ["error", "exit1", "badjson", "empty", "nomodel", "nolicense"])
def test_fm_failures_fall_through(fake_fm, monkeypatch, mode):
    monkeypatch.setenv("FAKE_FM_MODE", mode)
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert r is None and why


def test_timeout_falls_through(fake_fm, monkeypatch):
    monkeypatch.setenv("FAKE_FM_MODE", "sleep")
    monkeypatch.setenv("FAKE_FM_SLEEP", "3")
    monkeypatch.setattr(config, "AFM_TIMEOUT", 0.5)
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert r is None and "timed out" in why


def test_unknown_family_never_calls_fm(fake_fm):
    r, why = router.route(Q, "sysmon", PRESENT)
    assert r is None and "no intent catalog" in why and fake_fm() == []


def test_missing_binary_falls_through(monkeypatch):
    monkeypatch.setattr(config, "FM_BIN", "/nonexistent/fm")
    monkeypatch.setattr(afm, "_avail", None)
    r, why = router.route(Q, catalog.FAMILY, PRESENT)
    assert r is None and "unavailable" in why


def test_never_fewer_than_two_votes(fake_fm, monkeypatch):
    monkeypatch.setattr(config, "ROUTER_VOTES", 1)
    r, _ = router.route(Q, catalog.FAMILY, PRESENT)
    assert r.votes == 2 and len([a for a in fake_fm() if a[0] == "respond"]) == 2


def test_ipv6_artifacts_decline_ip_extractions(fake_fm, monkeypatch):
    q = "how many distinct source IPs are there?"
    a = {"event_filter": "all_events", "extract_field": "source_ip", "aggregate": "count_distinct_values"}
    monkeypatch.setenv("FAKE_FM_GREEDY", json.dumps(a))
    monkeypatch.setenv("FAKE_FM_SAMPLED", json.dumps(a))
    assert router.route(q, catalog.FAMILY, PRESENT, ipv6=False)[0] is not None
    r, why = router.route(q, catalog.FAMILY, PRESENT, ipv6=True)
    assert r is None and "IPv6" in why
    monkeypatch.setenv("FAKE_FM_GREEDY", json.dumps(PLAN))
    monkeypatch.setenv("FAKE_FM_SAMPLED", json.dumps(PLAN))
    assert router.route(Q, catalog.FAMILY, PRESENT, ipv6=True)[0] is not None, "plain counts are unaffected"


def test_more_votes_when_configured(fake_fm, monkeypatch):
    monkeypatch.setattr(config, "ROUTER_VOTES", 3)
    assert router.route(Q, catalog.FAMILY, PRESENT)[0].votes == 3
