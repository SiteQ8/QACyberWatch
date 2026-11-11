# Product

## Platform

web

## Users

Primary: security analysts and fraud or abuse desks at Qatari banks, payment providers, telecom operators and government e-service operators, working at a desk or on a phone during an incident, whose job is to find a look-alike domain of their own brand before a lure reaches a customer and to hand evidence to a takedown provider or their SOC. (confirmed by the repository: brand profiles, alert lifecycle, STIX export, notifiers)

Secondary: NCSA, Q-CERT and sector CERT staff who want a national-scale feed of candidate impersonation infrastructure; students and researchers who want an auditable reference implementation of Certificate Transparency monitoring. (inferred from docs/qatar-alignment.md and the README; unconfirmed by the user)

## Product Purpose

QACyberWatch reads Certificate Transparency logs the moment certificates are issued, scores every hostname against 34 Qatari brand profiles and 94 Qatar watch keywords in Latin and Arabic script, and turns look-alikes into triaged alerts with evidence. It exists so that a phishing site imitating a Qatari bank, the national payment switch, a ministry portal or a telecom operator is seen in public data before the first message reaches a victim. The owner's stated aim: the tool should become part of the State of Qatar's cybersecurity maturity. Success is an analyst acting on a candidate domain that they would otherwise have learned about from a victim.

## Positioning

The engine reads RFC 6962 and Static CT API logs itself, with a built-in X.509 parser and shard selection by certificate lifetime, so nothing goes dark when a free aggregator does, and it runs the same detection engine in Python and in the browser, tested for identical verdicts on a shared corpus. It is the only open tool built around Qatar's own brands, suffixes (com.qa, gov.qa and the rest), the .qa ccTLD watch and Arabic lure words. Independent and open: any institution can audit, run and extend it without a paid feed.

## Operating Context

- The browser console at /demo/ tails CT logs from the analyst's own browser and keeps all data in the browser; no server, no account.
- A self-hosted backend (`python main.py monitor`, `api`, `watch-squats`, Docker) for round-the-clock monitoring, notifications (Slack, Teams, Telegram, e-mail, webhook, syslog, CEF) and a REST API with OpenAPI docs.
- A GitHub Actions relay (`ct-relay.yml`) runs the tailer on a schedule and publishes keyword matches to `demo/feed/latest.json` with a 14-day archive (`demo/feed/archive/`); real public data since 16 October 2026.
- Outputs analysts hand on: STIX 2.1 bundles, CSV, per-alert and weekly HTML reports, Prometheus metrics.
- Documents: `docs/qatar-alignment.md` (NCSA, NIA, QCB, Q-CERT mapping), `docs/brands.md` (the 34 profiles), `DISCLAIMER.md`.

## Capabilities and Constraints

- 34 brand profiles with official domains, aliases, Arabic names and priority; 94 watch keywords; the bare token `qa` is deliberately not a keyword; digit keywords match whole tokens only; every certificate under .qa is watched.
- Scores 0 to 100: critical 80+, high 60 to 79, medium 40 to 59, low 20 to 39, clean below 20.
- Detection covers typosquats, homoglyphs (Cyrillic, Greek), mixed scripts, Arabic lures, leet, combo-squats, TLD swaps, hosting platforms, lure keywords, entropy, certificate context.
- Enrichment: DNS-over-HTTPS, RDAP registration age, crt.sh history, URLhaus.
- Every finding is an automated heuristic from public data: a candidate for review, never an accusation. Legitimate services appear among results.
- Static site on GitHub Pages at https://qacyberwatch.3li.info/ (CNAME in repo); landing page is a single self-contained `index.html`, bilingual English and Arabic with an RTL toggle; the console is a separate app in `demo/`.
- Terminology: look-alike, candidate, verdict, alert, relay feed, Watchtower, Typosquat Hunter.

## Brand Commitments

- Name: QACyberWatch (owner-chosen; never renamed or re-suggested).
- Author and publisher: Ali AlEnezi (SiteQ8); commits carry his name only.
- Writing rules: no em or en dashes anywhere; Arabic sentences end with a period only at the end and join clauses with conjunctions; natural Arabic, never literal translation.
- Brand names of protected organisations are identification only and stay the property of their owners.
- The national colour maroon is the incumbent accent (from the current page); the Qatar flag's serrated band is part of the subject's world.

## Evidence on Hand

- Real relay observations: `demo/feed/latest.json` and `demo/feed/archive/2026-10-16.json` to `2026-10-30.json` (15 days, 3,613 matches, 3,558 unique hostnames; levels clean 2,274, low 924, medium 289, high 123, critical 3; top keywords qatar, .qa, gov-qa, qib, qfc, qdb, qcb, doha, qnb; issuers led by Let's Encrypt and Google Trust Services).
- Real console screenshots: `docs/screenshots/01-login.png` to `10-sightings.png`.
- The real JavaScript engine (`demo/engine-data.js`, `demo/engine.js`) that can score any typed domain in the page.
- Test suite: 455 passing tests including Python and JavaScript parity.
- No customers, testimonials, press or adoption figures exist. Do not fabricate any.

## Product Principles

1. Prove with the product's own output: real certificates, real verdicts, real counts.
2. A finding is a candidate for human review; the page never accuses a named domain.
3. Arabic is a first-class language of the product, in detection and on the page.
4. Open and auditable: anything claimed is in the repository and testable.
5. Independent: not an official product of any Qatari authority, and said so.

## Accessibility & Inclusion

Bilingual English and Arabic with correct RTL layout; keyboard-operable controls with visible focus; body contrast at least 4.5:1; motion respects prefers-reduced-motion.
