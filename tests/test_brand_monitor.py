#!/usr/bin/env python3
"""Tests for src/core/brand_monitor.py."""

import pytest

from src.config.settings import Settings
from src.core.brand_monitor import QATAR_BRANDS, BrandMonitor, BrandProfile


@pytest.fixture
def monitor():
    return BrandMonitor(dedupe_window_seconds=0)


def alert_types(monitor, domain):
    return {(a.brand_name, a.alert_type, a.severity) for a in monitor.check_domain(domain)}


class TestProfiles:
    def test_default_brand_count_and_shape(self):
        assert len(QATAR_BRANDS) >= 25
        names = {b.short_name for b in QATAR_BRANDS}
        assert {"QNB", "QIB", "Sadad", "NCSA", "MOI", "Vodafone Qatar", "Qatar Airways"} <= names
        for b in QATAR_BRANDS:
            assert b.keywords and (b.domains or b.aliases)
            assert b.priority in ("critical", "high", "medium", "low")

    def test_short_labels_are_excluded(self):
        kahramaa = next(b for b in QATAR_BRANDS if b.short_name == "Kahramaa")
        assert "km" not in kahramaa.primary_labels()
        assert "kahramaapay" in kahramaa.alias_labels()

    def test_labels_split_primary_and_alias(self):
        qnb = next(b for b in QATAR_BRANDS if b.short_name == "QNB")
        assert qnb.primary_labels() == {"qnb"}
        assert "qnbonline" in qnb.alias_labels()
        assert "qnbgroup" in qnb.alias_labels()
        assert qnb.labels() == qnb.primary_labels() | qnb.alias_labels()

    def test_phrases(self):
        qib = next(b for b in QATAR_BRANDS if b.short_name == "QIB")
        assert ["qatar", "islamic", "bank"] in qib.phrases()

    def test_from_dict_and_to_dict_roundtrip(self):
        data = {
            "name": "Test Bank",
            "domains": ["TestBank.com"],
            "keywords": ["testbank", "test bank"],
            "aliases": ["tbank"],
            "arabic_keywords": ["تست"],
            "industry": "banking",
            "priority": "critical",
        }
        profile = BrandProfile.from_dict(data)
        assert profile.domains == ["testbank.com"]
        assert profile.to_dict()["priority"] == "critical"
        assert profile.is_legitimate("login.testbank.com")


class TestLegitimateAndTraps:
    @pytest.mark.parametrize(
        "domain",
        [
            "qnb.com",
            "login.qnb.com",
            "www.qnb.com.qa",
            "qib.com.qa",
            "hukoomi.gov.qa",
            "hukoomi.ncsa.gov.qa",
            "qa.ooredoo.com",
            "google.com",
            "example.com",
            "kibana.io",
            "mohammed.com",
            "pacific.com",
            "moisture.com",
            "stcoupon.com",
            "zainab.com",
            "qibla.com",
            "nbc.com",
            "kfc.com",
            "abc.com",
            "mom.com",
            "qatar.com",
            "qatar-jobs.com",
            "q8car.com",
            "10.0.0.1",
            "",
        ],
    )
    def test_no_alert(self, monitor, domain):
        assert monitor.check_domain(domain) == []

    def test_allowlist(self):
        m = BrandMonitor(dedupe_window_seconds=0, allowlist=["qnb-login.com"])
        assert m.check_domain("qnb-login.com") == []
        assert m.check_domain("www.qnb-login.com") == []
        assert m.get_stats()["allowlisted"] == 2
        m.remove_allowlist("qnb-login.com")
        assert m.check_domain("qnb-login.com")


class TestDetections:
    @pytest.mark.parametrize(
        "domain,short,alert_type,severity",
        [
            ("qnb.xyz", "QNB", "domain_squat", "critical"),
            ("qnb-login.com", "QNB", "combo_squat", "critical"),
            ("сbq.qa", "CBQ", "idn_homograph", "critical"),
            ("qnb0nline.com", "QNB", "domain_squat", "critical"),
            ("qnbb.com", "QNB", "typosquat", "high"),
            ("qnb.com.verify-login.tk", "QNB", "subdomain_abuse", "critical"),
            ("qatar-national-bank.com", "QNB", "brand_keyword_abuse", "high"),
            ("xn----5mcdfcm0lqa0ave.com", "Hukoomi", "arabic_brand_keyword", "high"),
            ("الريان-تحديث.com", "Al Rayan", "arabic_brand_keyword", "high"),
            ("qatar-islamic-bank.com", "QIB", "brand_keyword_abuse", "high"),
            ("sadadpay.info", "Sadad", "domain_squat", "critical"),
            ("sa-dad.com", "Sadad", "domain_squat", "high"),
            ("moi-fines.top", "MOI", "combo_squat", "critical"),
            ("ncsa-qatarid.com", "NCSA", "combo_squat", "critical"),
            ("hukoomi-app.com", "Hukoomi", "combo_squat", "critical"),
            ("alrayaan.com", "Al Rayan", "typosquat", "high"),
            ("vodafonepay.com", "Vodafone Qatar", "combo_squat", "critical"),
            ("vodafoneqa.com", "Vodafone Qatar", "domain_squat", "critical"),
            ("talabat-offers.com", "Talabat", "combo_squat", "medium"),
            ("qatarairways-booking.com", "Qatar Airways", "combo_squat", "critical"),
            ("qnb-secure-login.web.app", "QNB", "combo_squat", "critical"),
        ],
    )
    def test_detection(self, monitor, domain, short, alert_type, severity):
        brand = monitor.get_brand(short)
        alerts = [a for a in monitor.check_domain(domain) if a.brand_name == brand.name]
        assert alerts, f"{domain} should alert for {short}"
        assert alerts[0].alert_type == alert_type
        assert alerts[0].severity == severity

    def test_strong_match_suppresses_noise_for_other_brands(self, monitor):
        alerts = monitor.check_domain("qnb.xyz")
        assert {a.brand_name for a in alerts} == {"Qatar National Bank (QNB)"}

    def test_ambiguous_typo_reports_both(self, monitor):
        brands = {a.brand_name for a in monitor.check_domain("ddohabank.com")}
        assert {"Doha Bank", "Dukhan Bank"} == brands

    def test_evidence_contents(self, monitor):
        alert = monitor.check_domain("qnb-login.tk")[0]
        ev = alert.evidence
        assert ev["suspicious_domain"] == "qnb-login.tk"
        assert ev["registrable_domain"] == "qnb-login.tk"
        assert ev["tld_risk"] == "high"
        assert "login" in ev["phishing_keywords"]
        assert ev["combo_keywords"] == ["login"]
        assert alert.risk_score == 90.0
        assert alert.domain == "qnb-login.tk"
        assert alert.alert_id.startswith("BA-")
        assert alert.to_dict()["brand"] == alert.brand_name

    def test_wildcard_and_url_inputs(self, monitor):
        assert monitor.check_domain("*.qnb-login.com")
        assert monitor.check_domain("https://QNB-login.com/verify")

    def test_source_recorded(self, monitor):
        alert = monitor.check_domain("qnb-login.com", source="certstream")[0]
        assert alert.evidence["source"] == "certstream"


class TestDedupeAndState:
    def test_dedupe_window(self):
        clock = {"t": 1000.0}
        m = BrandMonitor(dedupe_window_seconds=60, now=lambda: clock["t"])
        assert len(m.check_domain("qnb-login.com")) == 1
        assert m.check_domain("qnb-login.com") == []
        assert m.check_domain("www.qnb-login.com")  # different hostname
        clock["t"] += 61
        assert len(m.check_domain("qnb-login.com")) == 1
        assert m.get_stats()["deduplicated"] == 1

    def test_record_false_skips_state(self, monitor):
        alerts = monitor.check_domain("qnb-login.com", record=False)
        assert alerts and monitor.alerts == []

    def test_alert_management(self, monitor):
        monitor.check_domain("qnb-login.com")
        monitor.check_domain("qib-login.com")
        alert = monitor.alerts[0]
        assert monitor.get_alerts(severity="critical")
        assert monitor.get_alerts(brand="Qatar Islamic")
        updated = monitor.update_alert_status(alert.alert_id, "resolved", assignee="ali")
        assert updated.status == "resolved" and updated.assignee == "ali"
        assert monitor.get_alerts(status="open")
        assert monitor.update_alert_status("missing", "resolved") is None
        stats = monitor.get_stats()
        assert stats["total_alerts"] == 2
        assert stats["by_industry"]["banking"] == 2
        assert stats["by_type"]["combo_squat"] == 2
        monitor.clear_alerts()
        assert monitor.alerts == []

    def test_add_remove_get_brand(self, monitor):
        monitor.add_brand(
            BrandProfile(name="Acme Qatar", domains=["acmekw.com"], keywords=["acmekw"])
        )
        assert monitor.get_brand("acme qatar")
        assert monitor.check_domain("acmekw-login.com")
        assert monitor.find_brand_by_domain("shop.acmekw.com").name == "Acme Qatar"
        assert monitor.remove_brand("Acme Qatar") is True
        assert monitor.remove_brand("Acme Qatar") is False
        assert "qnb.com" in monitor.protected_domains()

    def test_from_settings_merges_custom_brands(self):
        settings = Settings()
        settings.brands = [
            {"name": "Test Bank", "domains": ["testbank.com"], "keywords": ["testbank"]},
            {"name": "Broken", "domains": [], "keywords": []},
        ]
        settings.domain_analysis.allowlist = ["qnb-login.com"]
        m = BrandMonitor.from_settings(settings)
        assert m.get_brand("Test Bank")
        assert len(m.brands) == len(QATAR_BRANDS) + 1
        assert m.check_domain("qnb-login.com") == []
        settings.brands_replace_defaults = True
        only = BrandMonitor.from_settings(settings)
        assert [b.name for b in only.brands] == ["Test Bank"]
