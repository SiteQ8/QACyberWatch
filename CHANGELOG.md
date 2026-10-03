# Changelog

All notable changes to QACyberWatch are documented in this file. The format follows Keep a Changelog and the project adheres to Semantic Versioning.

## [1.0.0] - 2026-10-03

First release. QACyberWatch is the Qatar edition of the open-source Certificate Transparency monitoring engine that powers KWTCyberWatch 2.5.0, rebuilt for the State of Qatar's brands, suffixes, keywords and regulatory context.

### Added
- **34 Qatari brand profiles** across banking (QNB, Commercial Bank, Doha Bank, QIB, Masraf Al Rayan, Dukhan Bank, Ahlibank, QIIB, QDB, QCB, QFC), payments (Himyan and NAPS, Sadad), telecom (Ooredoo, Vodafone Qatar), government (Hukoomi, MOI and Metrash, NCSA and Q-CERT, MOPH, MCIT, MOCI, Ashghal, Qatar Post), health (HMC), energy (Kahramaa, QatarEnergy), aviation (Qatar Airways, Hamad International Airport), charity (Qatar Charity, QRCS), commerce (Snoonu, Talabat) and education (Qatar University, Qatar Foundation), each with official domains, aliases, Arabic names and a priority.
- **94 Qatar watch keywords** for the relay and the console, in Latin and Arabic script, including the 974 dialling code and Doha, plus a watch on every certificate issued for a name under the .qa ccTLD. The bare token qa is deliberately not a keyword, because it is the universal abbreviation for quality-assurance hosts, and digit-only keywords must match a whole token.
- **Qatari suffix table**: com.qa, net.qa, org.qa, gov.qa, edu.qa, mil.qa, name.qa and sch.qa are registrable-domain aware; gov.qa, edu.qa and mil.qa count as official suffixes for the fake-official check.
- **Qatar context tokens** (qa, qatar, doha, 974) and official tokens (hukoomi, metrash, moi) in both engines.
- **Qatar alignment note** (`docs/qatar-alignment.md`) describing how the tool relates to NCSA's mandate, the National Information Assurance standard and QCB's expectations, and a protected brand reference (`docs/brands.md`).
- Bilingual landing page with an Arabic summary.

### Inherited from the engine (KWTCyberWatch 2.5.0)
- Direct tailing of RFC 6962 and Static CT API logs with shard selection by certificate lifetime.
- Browser console with a JavaScript engine tested for parity with the Python engine.
- Hosting platforms scored once, a leading www ignored, short keywords anchored to label edges.
- Alert lifecycle, enrichment, STIX 2.1 and CSV exports, reports, notifications, hardened API and a scheduled relay feed.

[1.0.0]: https://github.com/SiteQ8/QACyberWatch/releases/tag/v1.0.0
