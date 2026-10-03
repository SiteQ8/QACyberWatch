#!/usr/bin/env python3
"""Tests for src/core/domain_analyzer.py."""

import pytest

from src.config.settings import DomainAnalysisConfig
from src.core.domain_analyzer import DomainAnalyzer, detect_techniques


@pytest.fixture
def analyzer():
    return DomainAnalyzer(DomainAnalysisConfig())


def techniques(domain_label, brand_label, **qa):
    return detect_techniques(domain_label, brand_label, **qa)["techniques"]


class TestDetectTechniques:
    def test_identical_is_not_an_attack(self):
        info = detect_techniques("qnb", "qnb")
        assert info["techniques"] == [] and info["similarity"] == 1.0

    def test_homoglyph(self):
        assert "homoglyph" in techniques("xn--bq-nmc", "cbq", unicode_label="сbq")

    def test_leet(self):
        assert techniques("qnb0nline", "qnb") == ["combo_squat"]
        assert techniques("s4dad", "sadad") == ["leet_substitution"]

    def test_hyphenation(self):
        assert techniques("sa-dad", "sadad") == ["hyphenation"]

    @pytest.mark.parametrize(
        "label,brand,keyword",
        [
            ("qnb-login", "qnb", "login"),
            ("qnblogin", "qnb", "login"),
            ("login-qnb-qa", "qnb", "login"),
            ("sadadpay", "sadad", "pay"),
            ("wwwqnb", "qnb", "www"),
            ("myqnbbank", "qnb", "bank"),
            ("qatarairways-booking", "qatarairways", "booking"),
        ],
    )
    def test_combo_squat(self, label, brand, keyword):
        info = detect_techniques(label, brand)
        assert "combo_squat" in info["techniques"]
        assert keyword in info["combo_keywords"]

    def test_addition_of_digits(self):
        assert techniques("qnb2024", "qnb") == ["addition"]

    def test_brand_embedding_requires_token_or_long_brand(self):
        assert techniques("qnb-xyzzy", "qnb") == ["brand_embedding"]
        assert techniques("alrayanxyz", "alrayan") == ["brand_embedding"]
        assert techniques("kibana", "cbq") == []
        assert techniques("mcitizen", "mcit") == []
        assert techniques("pacific", "ncsa") == []
        assert techniques("mohammed", "moph") == []

    def test_typos_scaled_to_length(self):
        assert "typosquat" in techniques("qnbb", "qnb")
        assert "repetition" in techniques("qnbb", "qnb")
        assert "transposition" in techniques("nqb", "qnb")
        assert techniques("cbq", "qnb") == []  # 3 edits on a 3-char brand
        assert "insertion" in techniques("alraxyan", "alrayan")
        assert "omission" in techniques("alryan", "alrayan")
        assert "vowel_swap" in techniques("alrayon", "alrayan")

    def test_short_brand_single_edits_are_weak(self):
        info = detect_techniques("qnc", "qnb")
        assert "bitsquat" in info["techniques"] and info["weak"] is True
        info = detect_techniques("qnd", "qnb")
        assert info["weak"] is True
        assert detect_techniques("nkb", "qnb")["weak"] is False

    def test_generic_word_inside_long_brand_is_ignored(self):
        assert techniques("qatar", "qnbqatar") == []

    def test_allow_typo_false(self):
        assert techniques("qnbb", "qnb", allow_typo=False) == []


class TestAnalyzer:
    def test_exact_and_legit_subdomains_ignored(self, analyzer):
        assert analyzer.analyze("qnb.com") == []
        assert analyzer.analyze("login.qnb.com") == []
        assert analyzer.analyze("https://www.qib.com.qa/login") == []

    def test_other_protected_brand_is_not_a_typo(self, analyzer):
        results = analyzer.analyze("qnb.xyz")
        assert [r.target_domain for r in results] == ["qnb.com", "qnb.com.qa"]
        assert results[0].attack_types == ["tld_swap"]
        assert results[0].risk_level == "high"

    def test_legitimate_domains_extension(self):
        a = DomainAnalyzer(DomainAnalysisConfig(), legitimate_domains=["qnb.com.qa"])
        assert a.analyze("www.qnb.com.qa") == []

    def test_allowlist(self):
        cfg = DomainAnalysisConfig(allowlist=["qnb-login.com"])
        assert DomainAnalyzer(cfg).analyze("www.qnb-login.com") == []

    @pytest.mark.parametrize(
        "domain,brand,attack",
        [
            ("qnb-login.com", "qnb.com", "combo_squat"),
            ("сbq.qa", "cbq.qa", "homoglyph"),
            ("xn--bq-nmc.qa", "cbq.qa", "homoglyph"),
            ("qnb.com.verify-login.tk", "qnb.com", "subdomain_abuse"),
            ("qnb.evil.com", "qnb.com", "subdomain_abuse"),
            ("qnb-secure-login.web.app", "qnb.com", "combo_squat"),
            ("sadadpay.info", "sadad.qa", "combo_squat"),
            ("moilogin.com", "moi.gov.qa", "combo_squat"),
            ("alrayaan.com", "alrayan.com", "typosquat"),
            ("qpost.xyz", "qpost.qa", "tld_swap"),
            ("sa-dad.com", "sadad.qa", "hyphenation"),
            ("qnb0nline.com", "qnb.com", "combo_squat"),
        ],
    )
    def test_detections(self, analyzer, domain, brand, attack):
        results = analyzer.analyze(domain)
        match = [r for r in results if r.target_domain == brand]
        assert match, f"{domain} should match {brand}: {results}"
        assert attack in match[0].attack_types

    @pytest.mark.parametrize(
        "domain",
        [
            "google.com",
            "example.com",
            "kibana.io",
            "mohammed.com",
            "pacific.com",
            "nbc.com",
            "abc.com",
            "mom.com",
            "qatar.com",
            "qatar-jobs.com",
            "zainab.com",
            "192.168.1.1",
            "",
        ],
    )
    def test_no_false_positives(self, analyzer, domain):
        assert analyzer.analyze(domain) == []

    def test_weak_match_with_context_is_reported(self, analyzer):
        results = analyzer.analyze("qnc-qatar-login.top")
        assert any(r.target_domain == "qnb.com" for r in results)

    def test_risk_escalation_on_risky_tld(self, analyzer):
        plain = analyzer.analyze("qnb-login.com")[0]
        risky = analyzer.analyze("qnb-login.tk")[0]
        assert plain.risk_level == "high"
        assert risky.risk_level == "critical"
        assert "tld:high" in risky.details["context"]

    def test_result_to_dict(self, analyzer):
        r = analyzer.analyze("qnb-login.com")[0]
        d = r.to_dict()
        assert d["target"] == "qnb.com"
        assert d["attack_types"] == ["combo_squat"]
        assert 0 < d["confidence"] <= 1

    def test_results_sorted_by_confidence(self, analyzer):
        results = analyzer.analyze("dohabank-secure.com")
        assert len(results) >= 1
        assert all(
            results[i].confidence >= results[i + 1].confidence for i in range(len(results) - 1)
        )

    def test_legacy_helpers(self, analyzer):
        assert analyzer._levenshtein("kitten", "sitting") == 3
        assert analyzer._check_bitsquat("qnc", "qnb") is True
        assert analyzer._check_bitsquat("qnb", "qnd") is False
        assert analyzer._check_homoglyph("сbq", "cbq") is True
        assert analyzer._check_vowel_swap("alrayon", "alrayan") is True


class TestPermutations:
    def test_label_permutations_backwards_compatible(self, analyzer):
        perms = analyzer.generate_permutations("qnb.com")
        assert len(perms) > 10
        assert "qb" in perms  # omission
        assert "nqb" in perms  # transposition
        assert "qnbb" in perms  # repetition
        assert "q-nb" in perms  # hyphenation
        assert "qnb-login" in perms  # combo
        assert "qnb" not in perms

    def test_detailed_permutations(self, analyzer):
        perms = analyzer.generate_permutations_detailed(
            "qnb.com", tlds=["com", "qa", "com.qa"], max_results=500
        )
        domains = {p["domain"] for p in perms}
        assert "qnb.qa" in domains and "qnb.com.qa" in domains
        assert "qnb.com" not in domains
        by_tech = {p["technique"] for p in perms}
        assert {"tld_swap", "omission", "transposition", "combo_squat", "homoglyph"} <= by_tech
        assert all(p["domain"].isascii() for p in perms)
        assert len(perms) <= 500

    def test_detailed_flags(self, analyzer):
        perms = analyzer.generate_permutations_detailed(
            "sadad.qa", include_combos=False, include_homoglyphs=False
        )
        techs = {p["technique"] for p in perms}
        assert "combo_squat" not in techs and "homoglyph" not in techs and "addition" not in techs
        assert all(p["tld"] == "qa" for p in perms)

    def test_max_permutations_config(self):
        a = DomainAnalyzer(DomainAnalysisConfig(max_permutations=25))
        assert len(a.generate_permutations_detailed("alrayan.com", tlds=["com", "net"])) == 25
