#!/usr/bin/env python3
"""Tests for src/core/certstream_monitor.py (no network)."""

import pytest

from src.config.settings import CertStreamConfig
from src.core.certstream_monitor import STATE_KEY, CertStreamMonitor
from src.models.database import Database


def message(domains, issuer=None, source="Argon2026"):
    return {
        "message_type": "certificate_update",
        "data": {
            "source": {"name": source},
            "leaf_cert": {
                "all_domains": domains,
                "issuer": issuer or {"O": "Let's Encrypt", "CN": "R3"},
                "fingerprint": "AA:BB",
                "not_before": 1,
                "not_after": 2,
                "serial_number": "01",
            },
        },
    }


@pytest.fixture
def monitor():
    cfg = CertStreamConfig(keywords=["qnb", "qa", "974", "qatar"], heartbeat_interval=2)
    return CertStreamMonitor(cfg)


class TestMatching:
    def test_short_keywords_match_tokens_only(self, monitor):
        assert monitor.match_keywords("hawkwind.com") == []
        assert monitor.match_keywords("qnb-qa.com") == ["qnb", "qa"]
        assert monitor.match_keywords("login.something.qa") == ["qa", ".qa"]
        assert monitor.match_keywords("q8car.com") == []
        assert monitor.match_keywords("974-car.com") == ["974"]

    def test_short_keywords_anchor_to_token_edges(self):
        cfg = CertStreamConfig(keywords=["qat", "qcb", "qpay", "qrcs", "qatar"])
        m = CertStreamMonitor(cfg)
        assert m.match_keywords("qatarbank.com") == ["qat", "qatar"]
        assert m.match_keywords("e-qcb.qa") == ["qcb", ".qa"]
        assert m.match_keywords("lqpay.example.com") == ["qpay"]
        assert m.match_keywords("fckvvqrxxcfveswhtjskuw.example.dev") == []
        assert m.match_keywords("qcbfmcdtytlkzfswjwrtsj.example.dev") == []
        assert m.match_keywords("kkunalsanga123.workers.dev") == []
        assert m.match_keywords("qpojmlgqcblmxprow.com") == []

    def test_long_keywords_substring(self, monitor):
        assert monitor.match_keywords("qnbonline.com") == ["qnb"]
        assert monitor.match_keywords("myqnbonline.com") == []  # mid-token: left to deep match
        assert monitor.match_keywords("QATARbank.tk") == ["qatar"]


class TestProcessing:
    def test_events_dedupe_wildcards_and_dispatch(self, monitor):
        got = []
        monitor.add_callback(got.append)
        monitor._handle_message(
            message(["*.qnb-login.xyz", "qnb-login.xyz", "www.qnb-login.xyz", "other.com"])
        )
        assert [e.domain for e in got] == ["qnb-login.xyz", "www.qnb-login.xyz"]
        first = got[0]
        assert first.is_wildcard is True
        assert first.matched_keywords == ["qnb"]
        assert first.source == "Argon2026"
        assert first.issuer_name == "Let's Encrypt"
        assert first.risk_score > 20
        assert first.to_dict()["domain"] == "qnb-login.xyz"
        stats = monitor.get_stats()
        assert stats["total_certs"] == 1
        assert stats["matched_certs"] == 1
        assert stats["matched_domains"] == 2
        assert stats["last_event"]

    def test_ignore_wildcards_option(self):
        cfg = CertStreamConfig(keywords=["qnb"], ignore_wildcards=True)
        m = CertStreamMonitor(cfg)
        events = m.process_certificate(message(["*.qnb.xyz"])["data"])
        assert events == []

    def test_non_certificate_messages_ignored(self, monitor):
        monitor._handle_message({"message_type": "heartbeat"})
        assert monitor.get_stats()["total_certs"] == 0

    def test_callback_errors_are_counted(self, monitor):
        def bad(event):
            raise RuntimeError("boom")

        monitor.add_callback(bad)
        monitor._handle_message(message(["qnb.xyz"]))
        assert monitor.get_stats()["callback_errors"] == 1

    def test_risk_score_heuristics(self, monitor):
        low = monitor.process_certificate(message(["qnb-news.com"])["data"])[0].risk_score
        high = monitor.process_certificate(
            message(["a.b.c.qnb-secure-login-verify-2024.tk"])["data"]
        )[0].risk_score
        assert high > low
        assert high <= 100

    def test_malformed_message_counts_error(self, monitor):
        monitor._handle_message(
            {
                "message_type": "certificate_update",
                "data": {"leaf_cert": {"all_domains": [None, 5]}},
            }
        )
        assert monitor.get_stats()["total_certs"] == 1


class TestPersistence:
    def test_events_and_heartbeat_persisted(self, tmp_path):
        db = Database(str(tmp_path / "m.db"))
        cfg = CertStreamConfig(keywords=["qnb"], heartbeat_interval=2)
        m = CertStreamMonitor(cfg, db=db)
        m._handle_message(message(["qnb-a.com"]))
        assert db.count_certstream_events() == 1
        assert db.get_state(STATE_KEY) is None
        m._handle_message(message(["qnb-b.com"]))
        state = db.get_state(STATE_KEY)
        assert state["total_certs"] == 2 and state["matched_domains"] == 2
        assert db.get_recent_certstream_events()[0]["domain"] == "qnb-b.com"
        m.stop()
        assert db.get_state(STATE_KEY)["status"] == "stopped"

    def test_persist_events_disabled(self, tmp_path):
        db = Database(str(tmp_path / "m2.db"))
        cfg = CertStreamConfig(keywords=["qnb"], persist_events=False)
        m = CertStreamMonitor(cfg, db=db)
        m._handle_message(message(["qnb-a.com"]))
        assert db.count_certstream_events() == 0

    def test_start_requires_certstream(self, monitor, monkeypatch):
        import src.core.certstream_monitor as mod

        monkeypatch.setattr(mod, "certstream", None)
        monitor.config.source = "certstream"
        with pytest.raises(ImportError):
            monitor.start()


def test_national_cctld_is_watched_but_qa_token_is_not_a_keyword():
    """Names under .qa are always worth seeing; the bare token qa is quality-assurance noise, not Qatar."""
    cfg = CertStreamConfig(keywords=["qatar", "974"], watch_cctld=True, cctld="qa")
    m = CertStreamMonitor(cfg)
    assert m.match_keywords("portal.example.qa") == [".qa"]
    assert m.match_keywords("qa.ci.example.com") == []
    assert m.match_keywords("qatar-login.example.qa") == ["qatar", ".qa"]
    assert m.match_keywords("974-pay.com") == ["974"]
    assert m.match_keywords("0be99974-c350.example.com") == []
    assert m.match_keywords("amira1974.workers.dev") == []
    off = CertStreamMonitor(CertStreamConfig(keywords=["qatar"], watch_cctld=False))
    assert off.match_keywords("portal.example.qa") == []
