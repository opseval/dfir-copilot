"""Deterministic family detection: header fingerprint AND vocabulary check."""
import os

from copilot import catalog, family

SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "copilot", "sample"))


def test_sample_auth_log_is_detected():
    assert family.detect("auth_sample.csv", SAMPLE_DIR) == catalog.FAMILY


def test_loghub_shape_without_auth_vocabulary_is_not_a_family(tmp_path):
    p = tmp_path / "hdfs.csv"
    p.write_text("LineId,Content,EventId,EventTemplate\n1,Receiving block blk_1 src: /10.0.0.1:5000,E1,Receiving block <*>\n")
    assert family.detect("hdfs.csv", str(tmp_path)) is None


def test_vocabulary_collision_is_not_a_family(tmp_path):
    p = tmp_path / "hdfs2.csv"
    p.write_text("LineId,Content,EventId,EventTemplate\n1,Accepted block blk_1 from 10.0.0.1,E1,t\n"
                 "2,authentication failure talking to namenode,E2,t\n")
    assert family.detect("hdfs2.csv", str(tmp_path)) is None, "'Accepted ' alone is not an sshd marker"


def test_pam_log_without_sshd_word_is_still_a_family(tmp_path):
    p = tmp_path / "pam.csv"
    p.write_text("LineId,Content,EventId,EventTemplate\n1,pam_unix(login:auth): authentication failure; rhost=1.2.3.4,E1,t\n")
    assert family.detect("pam.csv", str(tmp_path)) == catalog.FAMILY


def test_ipv6_is_detected_but_clock_times_are_not(tmp_path):
    (tmp_path / "v6.csv").write_text("LineId,Content,EventId,EventTemplate\n"
                                     "1,Failed password for root from 2001:db8::1 port 22 ssh2,E1,t\n")
    (tmp_path / "v4.csv").write_text("LineId,Content,EventId,EventTemplate\n"
                                     "1,Dec 10 06:55:46 Failed password for root from 10.0.0.1 port 22 ssh2,E1,t\n"
                                     "2,session opened for user root by (uid=0) at 12:00:01,E2,t\n")
    assert family.has_ipv6("v6.csv", str(tmp_path)) is True
    assert family.has_ipv6("v4.csv", str(tmp_path)) is False
    assert family.has_ipv6("auth_sample.csv", SAMPLE_DIR) is False


def test_other_headers_are_not_a_family(tmp_path):
    p = tmp_path / "sysmon.csv"
    p.write_text("TimeCreated,Image,ParentImage,CommandLine\n2026-01-01T00:00:00Z,a.exe,b.exe,a.exe\n")
    assert family.detect("sysmon.csv", str(tmp_path)) is None
