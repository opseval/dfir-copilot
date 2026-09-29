"""Vocabulary check: the router may only accept filters whose words occur in the artifact."""
import os

from copilot import catalog, family

SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "copilot", "sample"))


def test_present_filters_reflect_the_data():
    present = family.present_filters("auth_sample.csv", SAMPLE_DIR)
    assert {"all_events", "quoted_phrase", "failed_password", "invalid_user", "possible_break_in"} <= present


def test_pam_only_log_has_no_sshd_filters(tmp_path):
    p = tmp_path / "linux.csv"
    p.write_text("LineId,Content,EventId,EventTemplate\n"
                 "1,pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4,E1,t\n"
                 "2,session opened for user root by (uid=0),E2,t\n")
    assert family.present_filters("linux.csv", str(tmp_path)) == {"all_events", "quoted_phrase", "pam_auth_failure", "session_opened"}


def test_schema_always_offers_the_full_catalog():
    assert catalog.build_schema()["properties"]["event_filter"]["enum"] == list(catalog.EVENT_FILTERS)
