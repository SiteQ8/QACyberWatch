#!/usr/bin/env python3
"""
QACyberWatch - Brand Protection Monitor

Matches hostnames against protected brand profiles (Qatari banks, telecoms,
government services, airlines, energy companies and more) and raises
brand-impersonation alerts.

Matching rules, in order of confidence:

* the brand's registrable label used under another suffix (``qnb.xyz``),
* IDN homographs and leetspeak of the label (``nbк.com``, ``qnb0nline.com``),
* combo-squats (``qnb-login.com``, ``sadadpay.info``),
* typos scaled to the label length (``qnbb.com``, ``alrayaan.com``),
* brand label inside a subdomain (``qnb.com.verify-login.tk``),
* multi-word and Arabic-script keywords (``qatar-finance-house.com``,
  ``الريان-تحديث.com``).

Anything on a protected brand's own domains (``login.qnb.com``) or on the
allowlist is never reported, and identical (brand, domain) pairs are
deduplicated for a configurable window so a certificate with twenty SANs
produces one alert, not twenty.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from src.core.constants import PHISHING_KEYWORDS, bump_level, tld_risk
from src.core.domain_analyzer import context_signals, detect_techniques
from src.utils.domain import (
    ParsedDomain,
    brand_skeleton,
    contains_arabic,
    is_subdomain_of,
    matches_any,
    normalize_arabic,
    parse_domain,
    tokens_of,
)

logger = logging.getLogger("qacyberwatch.brand_monitor")

MIN_LABEL_LEN = 3
MIN_PHRASE_LEN = 8
SEVERITY_SCORE = {"critical": 90.0, "high": 70.0, "medium": 50.0, "low": 30.0}


@dataclass
class BrandProfile:
    """Defines a brand to protect."""

    name: str
    domains: List[str]
    keywords: List[str]
    logos: List[str] = field(default_factory=list)
    social_handles: Dict[str, str] = field(default_factory=dict)
    industry: str = ""
    priority: str = "high"  # critical, high, medium, low
    arabic_keywords: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    short_name: str = ""

    def primary_labels(self) -> Set[str]:
        """Registrable labels of the brand's own domains (typo detection applies)."""
        out: Set[str] = set()
        for d in self.domains:
            label = parse_domain(d).label
            if len(label) >= MIN_LABEL_LEN:
                out.add(label)
        return out

    def alias_labels(self) -> Set[str]:
        """Aliases and single-word keywords (exact / combo matching only)."""
        out: Set[str] = set()
        primary = self.primary_labels()
        for alias in self.aliases:
            skel = brand_skeleton(alias)
            if len(skel) >= MIN_LABEL_LEN and skel not in primary:
                out.add(skel)
        for kw in self.keywords:
            if " " not in kw.strip():
                skel = brand_skeleton(kw)
                if len(skel) >= 4 and skel not in primary:
                    out.add(skel)
        return out

    def labels(self) -> Set[str]:
        """All labels that identify this brand."""
        return self.primary_labels() | self.alias_labels()

    def phrases(self) -> List[List[str]]:
        """Multi-word keywords as token lists (``national bank qatar``)."""
        out = []
        for kw in self.keywords:
            words = [w for w in kw.lower().split() if w]
            if len(words) >= 2:
                out.append(words)
        return out

    def is_legitimate(self, hostname: str) -> bool:
        """True when ``hostname`` is one of the brand's own domains or beneath it."""
        return any(is_subdomain_of(hostname, d) for d in self.domains)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrandProfile":
        return cls(
            name=str(data.get("name", "")).strip(),
            domains=[str(d).lower() for d in data.get("domains", []) or []],
            keywords=[str(k).lower() for k in data.get("keywords", []) or []],
            logos=list(data.get("logos", []) or []),
            social_handles=dict(data.get("social_handles", {}) or {}),
            industry=str(data.get("industry", "")),
            priority=str(data.get("priority", "high")).lower(),
            arabic_keywords=list(data.get("arabic_keywords", []) or []),
            aliases=[str(a).lower() for a in data.get("aliases", []) or []],
            short_name=str(data.get("short_name", "")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "short_name": self.short_name,
            "domains": list(self.domains),
            "keywords": list(self.keywords),
            "arabic_keywords": list(self.arabic_keywords),
            "aliases": list(self.aliases),
            "industry": self.industry,
            "priority": self.priority,
        }


@dataclass
class BrandAlert:
    """Alert generated when brand impersonation is detected."""

    alert_id: str
    brand_name: str
    alert_type: str  # domain_squat, idn_homograph, combo_squat, typosquat, subdomain_abuse, ...
    severity: str
    description: str
    evidence: Dict[str, Any]
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "open"  # open, investigating, resolved, false_positive
    assignee: Optional[str] = None
    risk_score: float = 0.0
    domain: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "brand": self.brand_name,
            "brand_name": self.brand_name,
            "type": self.alert_type,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "detected_at": self.detected_at,
            "status": self.status,
            "assignee": self.assignee,
            "risk_score": self.risk_score,
            "domain": self.domain,
        }


# --------------------------------------------------------------------------- #
# Default Qatar brand profiles
# --------------------------------------------------------------------------- #

QATAR_BRANDS: List[BrandProfile] = [
    BrandProfile(
        name="Qatar National Bank (QNB)",
        short_name="QNB",
        domains=["qnb.com", "qnb.com.qa"],
        keywords=["qnb", "qatar national bank", "qnb group"],
        aliases=["qnbonline", "qnbbank", "qnbgroup"],
        arabic_keywords=["بنك قطر الوطني", "قطر الوطني"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Commercial Bank of Qatar (CBQ)",
        short_name="CBQ",
        domains=["cbq.qa"],
        keywords=["cbq", "commercial bank of qatar", "commercialbank"],
        aliases=["cbqonline", "commercialbankqatar"],
        arabic_keywords=["البنك التجاري", "البنك التجاري القطري"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Doha Bank",
        short_name="Doha Bank",
        domains=["dohabank.com", "dohabank.qa"],
        keywords=["dohabank", "doha bank"],
        aliases=["dohabankonline"],
        arabic_keywords=["بنك الدوحة"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Qatar Islamic Bank (QIB)",
        short_name="QIB",
        domains=["qib.com.qa"],
        keywords=["qib", "qatar islamic bank"],
        aliases=["qibonline", "qibbank"],
        arabic_keywords=["مصرف قطر الإسلامي", "قطر الإسلامي"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Masraf Al Rayan",
        short_name="Al Rayan",
        domains=["alrayan.com"],
        keywords=["alrayan", "al rayan", "masraf al rayan", "masrafalrayan"],
        aliases=["alrayanbank", "rayanbank"],
        arabic_keywords=["مصرف الريان", "الريان"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Dukhan Bank",
        short_name="Dukhan Bank",
        domains=["dukhanbank.com"],
        keywords=["dukhan", "dukhan bank", "dukhanbank"],
        aliases=["dukhanonline"],
        arabic_keywords=["بنك دخان", "دخان"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Ahlibank Qatar",
        short_name="Ahlibank",
        domains=["ahlibank.com.qa"],
        keywords=["ahlibank", "ahli bank qatar", "ahlibankqatar"],
        aliases=["ahlibankqa", "ahlionline"],
        arabic_keywords=["البنك الأهلي", "الأهلي القطري"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Qatar International Islamic Bank (QIIB)",
        short_name="QIIB",
        domains=["qiib.com.qa"],
        keywords=["qiib", "qatar international islamic bank", "international islamic"],
        aliases=["qiibonline"],
        arabic_keywords=["الدولي الإسلامي", "مصرف قطر الدولي الإسلامي"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Qatar Development Bank (QDB)",
        short_name="QDB",
        domains=["qdb.qa"],
        keywords=["qdb", "qatar development bank"],
        aliases=["qdbqatar"],
        arabic_keywords=["بنك قطر للتنمية"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Qatar Central Bank (QCB)",
        short_name="QCB",
        domains=["qcb.gov.qa"],
        keywords=["qcb", "qatar central bank", "central bank of qatar"],
        aliases=["qcbgov", "qcbonline"],
        arabic_keywords=["مصرف قطر المركزي", "قطر المركزي"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Qatar Financial Centre (QFC)",
        short_name="QFC",
        domains=["qfc.qa", "qfcra.com"],
        keywords=["qfc", "qatar financial centre", "qatar financial center", "qfcra"],
        aliases=["qfcqatar"],
        arabic_keywords=["مركز قطر للمال"],
        industry="finance",
        priority="medium",
    ),
    BrandProfile(
        name="Himyan card scheme and NAPS switch (QCB)",
        short_name="Himyan",
        domains=[],
        keywords=["himyan", "himyan card", "naps", "napsqatar", "national atm and pos switch"],
        aliases=["himyancard", "himyanpay"],
        arabic_keywords=["حميان", "بطاقة حميان"],
        industry="payments",
        priority="critical",
    ),
    BrandProfile(
        name="Sadad Qatar",
        short_name="Sadad",
        domains=["sadad.qa"],
        keywords=["sadad", "sadad qatar", "sadadqatar"],
        aliases=["sadadpay", "sadadqa"],
        arabic_keywords=["سداد"],
        industry="payments",
        priority="critical",
    ),
    BrandProfile(
        name="Ooredoo Qatar",
        short_name="Ooredoo",
        domains=["ooredoo.qa", "ooredoo.com"],
        keywords=["ooredoo", "ooredoo qatar", "ooredoo money", "ooredoomoney"],
        aliases=["ooredooqa", "ooredoo-qa", "myooredoo"],
        arabic_keywords=["أوريدو", "أوريدو قطر", "اوريدو"],
        industry="telecom",
        priority="critical",
    ),
    BrandProfile(
        name="Vodafone Qatar",
        short_name="Vodafone Qatar",
        domains=["vodafone.qa", "vodafone.com"],
        keywords=["vodafone qatar", "vodafoneqatar", "vodafone-qa", "vodafoneqa"],
        aliases=["myvodafoneqa"],
        arabic_keywords=["فودافون قطر", "فودافون"],
        industry="telecom",
        priority="critical",
    ),
    BrandProfile(
        name="Hukoomi (Qatar e-Government portal)",
        short_name="Hukoomi",
        domains=["hukoomi.gov.qa"],
        keywords=["hukoomi", "hukoomi portal", "qatar e-government", "qatar egov"],
        aliases=["hukoomiqatar", "hukoomi-gov"],
        arabic_keywords=["حكومي", "بوابة حكومي"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Ministry of Interior Qatar (MOI) and Metrash",
        short_name="MOI",
        domains=["moi.gov.qa"],
        keywords=[
            "moi qatar",
            "moi-qa",
            "moiqatar",
            "metrash",
            "metrash2",
            "ministry of interior qatar",
            "qatar id",
            "qatarid",
        ],
        aliases=["moigovqa", "metrash2app"],
        arabic_keywords=["وزارة الداخلية", "مطراش", "البطاقة الشخصية"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="National Cyber Security Agency (NCSA) and Q-CERT",
        short_name="NCSA",
        domains=["ncsa.gov.qa", "qcert.org"],
        keywords=["ncsa", "ncsa qatar", "qcert", "q-cert", "national cyber security agency"],
        aliases=["ncsaqatar", "qcertqatar"],
        arabic_keywords=["الوكالة الوطنية للأمن السيبراني", "الأمن السيبراني"],
        industry="government",
        priority="high",
    ),
    BrandProfile(
        name="Ministry of Public Health (MOPH)",
        short_name="MOPH",
        domains=["moph.gov.qa"],
        keywords=["moph", "moph qatar", "mophqatar", "ministry of public health"],
        aliases=["mophqa"],
        arabic_keywords=["وزارة الصحة", "وزارة الصحة العامة"],
        industry="government",
        priority="high",
    ),
    BrandProfile(
        name="Hamad Medical Corporation (HMC)",
        short_name="HMC",
        domains=["hamad.qa"],
        keywords=["hamad medical", "hamadmedical", "hmc qatar", "hmcqatar"],
        aliases=["hamadhospital", "hmcqa"],
        arabic_keywords=["مؤسسة حمد الطبية", "حمد الطبية"],
        industry="healthcare",
        priority="high",
    ),
    BrandProfile(
        name="Ministry of Communications and Information Technology (MCIT)",
        short_name="MCIT",
        domains=["mcit.gov.qa"],
        keywords=["mcit", "mcit qatar", "mcitqatar", "ministry of communications"],
        aliases=["mcitqa"],
        arabic_keywords=["وزارة الاتصالات", "وزارة الاتصالات وتكنولوجيا المعلومات"],
        industry="government",
        priority="high",
    ),
    BrandProfile(
        name="Ministry of Commerce and Industry (MOCI)",
        short_name="MOCI",
        domains=["moci.gov.qa"],
        keywords=["moci", "moci qatar", "mociqatar", "ministry of commerce"],
        aliases=["mociqa"],
        arabic_keywords=["وزارة التجارة", "وزارة التجارة والصناعة"],
        industry="government",
        priority="medium",
    ),
    BrandProfile(
        name="Kahramaa (Qatar General Electricity and Water Corporation)",
        short_name="Kahramaa",
        domains=["km.qa", "kahramaa.qa"],
        keywords=["kahramaa", "kahramaa bill", "qatar electricity and water"],
        aliases=["kahramaapay", "kahramaaqa"],
        arabic_keywords=["كهرماء", "المؤسسة العامة القطرية للكهرباء والماء"],
        industry="energy",
        priority="high",
    ),
    BrandProfile(
        name="Ashghal (Public Works Authority)",
        short_name="Ashghal",
        domains=["ashghal.gov.qa"],
        keywords=["ashghal", "public works authority qatar"],
        aliases=["ashghalqa"],
        arabic_keywords=["أشغال", "هيئة الأشغال العامة"],
        industry="government",
        priority="medium",
    ),
    BrandProfile(
        name="QatarEnergy",
        short_name="QatarEnergy",
        domains=["qatarenergy.qa", "qp.com.qa"],
        keywords=["qatarenergy", "qatar energy", "qatar petroleum", "qatarpetroleum"],
        aliases=["qatarenergyqa"],
        arabic_keywords=["قطر للطاقة", "قطر للبترول"],
        industry="energy",
        priority="high",
    ),
    BrandProfile(
        name="Qatar Airways",
        short_name="Qatar Airways",
        domains=["qatarairways.com", "qatarairways.com.qa"],
        keywords=[
            "qatar airways",
            "qatarairways",
            "qatarairway",
            "qatar-airways",
            "privilege club",
            "privilegeclub",
        ],
        aliases=["qrairways", "qatarair"],
        arabic_keywords=["القطرية", "الخطوط الجوية القطرية", "نادي الامتياز"],
        industry="aviation",
        priority="critical",
    ),
    BrandProfile(
        name="Hamad International Airport (HIA)",
        short_name="HIA",
        domains=["dohahamadairport.com"],
        keywords=[
            "hamad international airport",
            "hamadairport",
            "dohahamadairport",
            "doha airport",
        ],
        aliases=["hiaqatar", "hamad-airport"],
        arabic_keywords=["مطار حمد الدولي", "مطار حمد"],
        industry="aviation",
        priority="medium",
    ),
    BrandProfile(
        name="Qatar Post (Qpost)",
        short_name="Qatar Post",
        domains=["qpost.qa"],
        keywords=["qpost", "qatar post", "qatarpost"],
        aliases=["qpostqa", "qpostdelivery"],
        arabic_keywords=["بريد قطر", "البريد القطري"],
        industry="government",
        priority="high",
    ),
    BrandProfile(
        name="Qatar Charity",
        short_name="Qatar Charity",
        domains=["qcharity.org"],
        keywords=["qatar charity", "qatarcharity", "qcharity"],
        aliases=["qcharityqa"],
        arabic_keywords=["قطر الخيرية"],
        industry="charity",
        priority="medium",
    ),
    BrandProfile(
        name="Qatar Red Crescent Society (QRCS)",
        short_name="QRCS",
        domains=["qrcs.org.qa"],
        keywords=["qatar red crescent", "qatarredcrescent", "qrcs"],
        aliases=["qrcsqatar"],
        arabic_keywords=["الهلال الأحمر القطري"],
        industry="charity",
        priority="medium",
    ),
    BrandProfile(
        name="Snoonu",
        short_name="Snoonu",
        domains=["snoonu.com"],
        keywords=["snoonu"],
        aliases=["snoonuqa", "snoonuapp"],
        arabic_keywords=["سنونو"],
        industry="ecommerce",
        priority="medium",
    ),
    BrandProfile(
        name="Talabat Qatar",
        short_name="Talabat",
        domains=["talabat.com"],
        keywords=["talabat", "talabat qatar"],
        aliases=["talabatqa"],
        arabic_keywords=["طلبات"],
        industry="ecommerce",
        priority="medium",
    ),
    BrandProfile(
        name="Qatar University (QU)",
        short_name="QU",
        domains=["qu.edu.qa"],
        keywords=["qatar university", "qataruniversity", "qu-edu"],
        aliases=["quqatar"],
        arabic_keywords=["جامعة قطر"],
        industry="education",
        priority="medium",
    ),
    BrandProfile(
        name="Qatar Foundation (QF)",
        short_name="QF",
        domains=["qf.org.qa"],
        keywords=["qatar foundation", "qatarfoundation", "education city", "educationcity"],
        aliases=["qfqatar"],
        arabic_keywords=["مؤسسة قطر"],
        industry="education",
        priority="medium",
    ),
]


# --------------------------------------------------------------------------- #
# Monitor
# --------------------------------------------------------------------------- #

Candidate = Tuple[int, str, str, Dict[str, Any]]  # (rank, alert_type, severity, evidence)


class BrandMonitor:
    """Monitors brand assets and generates alerts on impersonation attempts."""

    def __init__(
        self,
        brands: Optional[List[BrandProfile]] = None,
        dedupe_window_seconds: int = 86400,
        allowlist: Optional[Iterable[str]] = None,
        now: Callable[[], float] = time.time,
    ):
        self.brands: List[BrandProfile] = list(brands) if brands is not None else list(QATAR_BRANDS)
        self.alerts: List[BrandAlert] = []
        self.dedupe_window = int(dedupe_window_seconds)
        self.allowlist: List[str] = [a.lower() for a in (allowlist or [])]
        self._now = now
        self._recent: Dict[Tuple[str, str], float] = {}
        self._alert_counter = 0
        self.stats = {"checked": 0, "matched": 0, "deduplicated": 0, "allowlisted": 0}

    # -- construction helpers ---------------------------------------------- #

    @classmethod
    def from_settings(cls, settings: Any) -> "BrandMonitor":
        """Build a monitor from :class:`Settings`, merging custom brand profiles."""
        custom = [BrandProfile.from_dict(b) for b in getattr(settings, "brands", []) or []]
        custom = [b for b in custom if b.name and b.domains]
        if getattr(settings, "brands_replace_defaults", False):
            brands = custom
        else:
            names = {b.name for b in QATAR_BRANDS}
            brands = list(QATAR_BRANDS) + [b for b in custom if b.name not in names]
        allowlist = getattr(getattr(settings, "domain_analysis", None), "allowlist", []) or []
        return cls(brands=brands, allowlist=allowlist)

    def add_brand(self, brand: BrandProfile) -> None:
        self.brands = [b for b in self.brands if b.name != brand.name]
        self.brands.append(brand)
        logger.info("Added brand monitor: %s", brand.name)

    def remove_brand(self, name: str) -> bool:
        before = len(self.brands)
        self.brands = [b for b in self.brands if b.name != name]
        return len(self.brands) < before

    def get_brand(self, name: str) -> Optional[BrandProfile]:
        lowered = name.lower()
        for b in self.brands:
            if b.name.lower() == lowered or (b.short_name and b.short_name.lower() == lowered):
                return b
        return None

    def find_brand_by_domain(self, domain: str) -> Optional[BrandProfile]:
        host = parse_domain(domain).hostname
        for b in self.brands:
            if b.is_legitimate(host):
                return b
        return None

    def protected_domains(self) -> List[str]:
        """Every domain owned by a monitored brand."""
        out: List[str] = []
        for b in self.brands:
            for d in b.domains:
                if d not in out:
                    out.append(d)
        return out

    def add_allowlist(self, domain: str) -> None:
        domain = domain.lower().strip()
        if domain and domain not in self.allowlist:
            self.allowlist.append(domain)

    def remove_allowlist(self, domain: str) -> None:
        self.allowlist = [d for d in self.allowlist if d != domain.lower().strip()]

    # -- detection --------------------------------------------------------- #

    def check_domain(
        self, domain: str, source: str = "scan", record: bool = True
    ) -> List[BrandAlert]:
        """
        Check a hostname against all monitored brands.

        Args:
            domain: hostname, URL or wildcard certificate name.
            source: origin tag stored in the evidence (``scan``, ``certstream`` ...).
            record: keep generated alerts in :attr:`alerts` and apply dedupe.

        Returns:
            One alert per matching brand (strongest match wins per brand). When
            one brand matches strongly (homograph, squat, combo) weaker typo or
            keyword matches against *other* brands are dropped as noise.
        """
        self.stats["checked"] += 1
        parsed = parse_domain(domain)
        if not parsed.valid or parsed.is_ip or not parsed.label:
            return []
        if matches_any(parsed.hostname, self.allowlist):
            self.stats["allowlisted"] += 1
            return []
        if any(b.is_legitimate(parsed.hostname) for b in self.brands):
            return []

        known_labels: Set[str] = set()
        for b in self.brands:
            known_labels |= b.primary_labels()

        matches: List[Tuple[BrandProfile, Candidate]] = []
        for brand in self.brands:
            candidate = self._match_brand(parsed, brand, known_labels)
            if candidate:
                matches.append((brand, candidate))
        if not matches:
            return []

        top_rank = max(c[0] for _, c in matches)
        if top_rank >= 85:
            matches = [(b, c) for b, c in matches if c[0] >= 85]

        alerts: List[BrandAlert] = []
        for brand, (_, alert_type, severity, evidence) in matches:
            if record and self._is_duplicate(brand.name, parsed.hostname):
                self.stats["deduplicated"] += 1
                continue
            alert = self._build_alert(parsed, brand, alert_type, severity, evidence, source)
            alerts.append(alert)
            if record:
                self.alerts.append(alert)
        if alerts:
            self.stats["matched"] += 1
        return alerts

    def _is_duplicate(self, brand_name: str, hostname: str) -> bool:
        if self.dedupe_window <= 0:
            return False
        key = (brand_name, hostname)
        now = self._now()
        last = self._recent.get(key)
        if last is not None and now - last < self.dedupe_window:
            return True
        self._recent[key] = now
        if len(self._recent) > 50000:
            cutoff = now - self.dedupe_window
            self._recent = {k: v for k, v in self._recent.items() if v >= cutoff}
        return False

    def _match_brand(
        self, parsed: ParsedDomain, brand: BrandProfile, known_labels: Set[str]
    ) -> Optional[Candidate]:
        """Return the strongest ``(rank, alert_type, severity, evidence)`` match."""
        candidates: List[Candidate] = []
        risky = tld_risk(parsed.suffix)
        phishing_tokens = self._phishing_tokens(parsed)
        primary = brand.primary_labels()
        # Labels that *are* other protected brands are never typos of this one.
        excluded = known_labels - primary

        # 1. Brand labels (primary labels get typo detection, aliases do not)
        for brand_label in sorted(primary, key=len, reverse=True):
            found = self._match_label(
                parsed, brand, brand_label, risky, phishing_tokens, True, excluded
            )
            if found:
                candidates.append(found)
        for brand_label in sorted(brand.alias_labels(), key=len, reverse=True):
            found = self._match_label(
                parsed, brand, brand_label, risky, phishing_tokens, False, excluded
            )
            if found:
                candidates.append(found)

        # 2. Multi-word phrases (national-bank-of-qatar.com)
        compact = brand_skeleton(parsed.searchable_text.replace(".", ""))
        tokens: Set[str] = set()
        for lbl in parsed.searchable_labels:
            tokens.update(tokens_of(lbl))
        for words in brand.phrases():
            joined = "".join(words)
            significant = [w for w in words if len(w) > 2]
            phrase_hit = len(joined) >= MIN_PHRASE_LEN and joined in compact
            token_hit = len(significant) >= 2 and all(w in tokens for w in significant)
            if phrase_hit or token_hit:
                sev = self._severity_for(brand, "medium", risky, phishing_tokens)
                candidates.append(
                    (40, "brand_keyword_abuse", sev, {"matched_keyword": " ".join(words)})
                )
                break

        # 3. Arabic-script keywords inside IDN labels
        if parsed.is_idn and brand.arabic_keywords:
            unicode_text = normalize_arabic(parsed.unicode_hostname)
            if contains_arabic(unicode_text):
                for kw in brand.arabic_keywords:
                    if normalize_arabic(kw) in unicode_text:
                        sev = self._severity_for(brand, "high", risky, phishing_tokens)
                        evidence = {
                            "matched_keyword": kw,
                            "unicode_hostname": parsed.unicode_hostname,
                        }
                        candidates.append((70, "arabic_brand_keyword", sev, evidence))
                        break

        if not candidates:
            return None
        candidates.sort(key=lambda c: c[0], reverse=True)
        rank, alert_type, severity, evidence = candidates[0]
        if risky != "none":
            evidence["tld_risk"] = risky
        if phishing_tokens:
            evidence["phishing_keywords"] = sorted(phishing_tokens)
        if parsed.hosting_platform:
            evidence["hosting_platform"] = parsed.hosting_platform
        return rank, alert_type, severity, evidence

    def _match_label(
        self,
        parsed: ParsedDomain,
        brand: BrandProfile,
        brand_label: str,
        risky: str,
        phishing_tokens: Set[str],
        allow_typo: bool,
        excluded: Optional[Set[str]] = None,
    ) -> Optional[Candidate]:
        base = brand.priority if brand.priority in SEVERITY_SCORE else "high"
        sev = self._severity_for

        # Registrable label identical to the brand label under another suffix
        if parsed.label == brand_label:
            evidence = {"technique": "tld_swap", "matched_label": parsed.label}
            return 90, "domain_squat", sev(brand, base, risky, phishing_tokens), evidence

        info = detect_techniques(
            parsed.label,
            brand_label,
            parsed.unicode_label,
            allow_typo=allow_typo,
            exclude_tokens=excluded,
        )
        techniques = list(info["techniques"])
        if techniques and info["weak"] and not context_signals(parsed, brand_label):
            techniques = []
        if techniques:
            evidence: Dict[str, Any] = {
                "technique": techniques[0],
                "techniques": techniques,
                "matched_label": parsed.label,
                "similarity": round(info["similarity"], 3),
            }
            if info["combo_keywords"]:
                evidence["combo_keywords"] = info["combo_keywords"]
            if parsed.is_idn:
                evidence["unicode_label"] = parsed.unicode_label
            if "homoglyph" in techniques:
                return 95, "idn_homograph", "critical", evidence
            if "leet_substitution" in techniques:
                return 88, "domain_squat", sev(brand, base, risky, phishing_tokens, 1), evidence
            if "combo_squat" in techniques:
                return 85, "combo_squat", sev(brand, base, risky, phishing_tokens), evidence
            if "typosquat" in techniques or "hyphenation" in techniques:
                level = "high" if base == "critical" else "medium"
                if info["weak"]:
                    level = "medium"
                kind = "domain_squat" if "hyphenation" in techniques else "typosquat"
                return 80, kind, sev(brand, level, risky, phishing_tokens), evidence
            if "addition" in techniques:
                return 60, "domain_squat", sev(brand, "medium", risky, phishing_tokens), evidence
            if "brand_embedding" in techniques:
                level = "medium" if base in ("critical", "high") else "low"
                return (
                    55,
                    "brand_keyword_abuse",
                    sev(brand, level, risky, phishing_tokens),
                    evidence,
                )

        # Subdomain labels
        for sub in parsed.subdomain_labels:
            if sub == brand_label or brand_skeleton(sub) == brand_label:
                level = "critical" if base == "critical" else "high"
                evidence = {"abused_subdomain": sub, "matched_label": brand_label}
                return 75, "subdomain_abuse", sev(brand, level, risky, phishing_tokens), evidence
            sub_info = detect_techniques(sub, brand_label, allow_typo=False)
            if "combo_squat" in sub_info["techniques"]:
                evidence = {
                    "abused_subdomain": sub,
                    "matched_label": brand_label,
                    "combo_keywords": sub_info["combo_keywords"],
                }
                return 72, "subdomain_abuse", sev(brand, "high", risky, phishing_tokens), evidence
        return None

    @staticmethod
    def _phishing_tokens(parsed: ParsedDomain) -> Set[str]:
        found: Set[str] = set()
        for lbl in parsed.searchable_labels:
            for tok in tokens_of(lbl):
                if tok in PHISHING_KEYWORDS:
                    found.add(tok)
            for kw in PHISHING_KEYWORDS:
                if len(kw) >= 5 and kw in lbl:
                    found.add(kw)
        return found

    @staticmethod
    def _severity_for(
        brand: BrandProfile,
        base: str,
        risky: str,
        phishing_tokens: Set[str],
        extra_steps: int = 0,
    ) -> str:
        level = base if base in SEVERITY_SCORE else "medium"
        steps = extra_steps
        if risky == "high":
            steps += 1
        if phishing_tokens:
            steps += 1
        return bump_level(level, steps) if steps else level

    def _build_alert(
        self,
        parsed: ParsedDomain,
        brand: BrandProfile,
        alert_type: str,
        severity: str,
        evidence: Dict[str, Any],
        source: str,
    ) -> BrandAlert:
        self._alert_counter += 1
        digest = hashlib.sha1(
            f"{brand.name}|{parsed.hostname}|{self._now():.3f}|{self._alert_counter}".encode()
        ).hexdigest()[:10]
        evidence = {
            "suspicious_domain": parsed.hostname,
            "registrable_domain": parsed.registrable,
            "protected_domains": list(brand.domains),
            "brand": brand.name,
            "source": source,
            **evidence,
        }
        descriptions = {
            "domain_squat": f"Domain squatting of {brand.name}: {parsed.hostname}",
            "idn_homograph": (
                f"IDN homograph attack impersonating {brand.name}: "
                f"{parsed.unicode_hostname} ({parsed.hostname})"
            ),
            "combo_squat": f"Combo-squat targeting {brand.name}: {parsed.hostname}",
            "typosquat": f"Typosquat of {brand.name}: {parsed.hostname}",
            "subdomain_abuse": f"{brand.name} label abused in subdomain: {parsed.hostname}",
            "brand_keyword_abuse": (
                f"Brand keyword for {brand.name} found in domain: {parsed.hostname}"
            ),
            "arabic_brand_keyword": (
                f"Arabic brand keyword for {brand.name} in IDN domain: {parsed.unicode_hostname}"
            ),
        }
        return BrandAlert(
            alert_id=f"BA-{digest}",
            brand_name=brand.name,
            alert_type=alert_type,
            severity=severity,
            description=descriptions.get(alert_type, f"Brand impersonation of {brand.name}"),
            evidence=evidence,
            risk_score=SEVERITY_SCORE.get(severity, 50.0),
            domain=parsed.hostname,
        )

    # -- alert management -------------------------------------------------- #

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        brand: Optional[str] = None,
    ) -> List[BrandAlert]:
        results = self.alerts
        if status:
            results = [a for a in results if a.status == status]
        if severity:
            results = [a for a in results if a.severity == severity]
        if brand:
            lowered = brand.lower()
            results = [a for a in results if lowered in a.brand_name.lower()]
        return list(results)

    def update_alert_status(
        self, alert_id: str, status: str, assignee: Optional[str] = None
    ) -> Optional[BrandAlert]:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = status
                if assignee is not None:
                    alert.assignee = assignee
                return alert
        return None

    def clear_alerts(self) -> None:
        self.alerts.clear()
        self._recent.clear()

    def get_stats(self) -> Dict[str, Any]:
        by_brand = self._count_by("brand_name")
        by_industry: Dict[str, int] = {}
        for b in self.brands:
            if b.name in by_brand:
                by_industry[b.industry] = by_industry.get(b.industry, 0) + by_brand[b.name]
        return {
            "total_brands": len(self.brands),
            "total_alerts": len(self.alerts),
            "open_alerts": len([a for a in self.alerts if a.status == "open"]),
            "critical_alerts": len([a for a in self.alerts if a.severity == "critical"]),
            "by_type": self._count_by("alert_type"),
            "by_severity": self._count_by("severity"),
            "by_brand": by_brand,
            "by_industry": by_industry,
            "checked": self.stats["checked"],
            "deduplicated": self.stats["deduplicated"],
            "allowlisted": self.stats["allowlisted"],
        }

    def _count_by(self, attr: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for alert in self.alerts:
            val = getattr(alert, attr)
            counts[val] = counts.get(val, 0) + 1
        return counts


__all__ = ["BrandAlert", "BrandMonitor", "BrandProfile", "QATAR_BRANDS", "MIN_LABEL_LEN"]
