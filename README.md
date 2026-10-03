<p align="center">
  <h1 align="center">🛡️ QACyberWatch</h1>
  <p align="center"><strong>Phishing detection and brand protection for the State of Qatar</strong></p>
  <p align="center">Open-source Certificate Transparency monitoring, look-alike domain hunting and brand impersonation alerts for Qatari banks, payment services, telecoms and government services. Built as a contribution to Qatar's national cybersecurity maturity.</p>
  <p align="center">
    <a href="#features"><img src="https://img.shields.io/badge/version-1.0.0-8a1538?style=flat-square" alt="Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python"></a>
    <a href="https://github.com/SiteQ8/QACyberWatch/actions"><img src="https://img.shields.io/badge/tests-450%2B-brightgreen?style=flat-square" alt="Tests"></a>
    <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-red?style=flat-square" alt="Security"></a>
  </p>
  <p align="center"><a href="https://qacyberwatch.3li.info/">Website</a> · <a href="https://qacyberwatch.3li.info/demo/">Live console</a> · <a href="docs/qatar-alignment.md">Qatar alignment</a> · <a href="docs/brands.md">Protected brands</a> · <a href="CHANGELOG.md">Changelog</a></p>
</p>

---

## Why QACyberWatch

Every certificate that browsers trust is written to public Certificate Transparency (CT) logs the moment it is issued. A phishing site that imitates a Qatari bank, the national payment switch, a ministry portal or a telecom operator therefore becomes visible in public data before the first message reaches a victim. QACyberWatch reads those logs directly, scores every hostname against Qatari brand profiles and local keywords, and turns look-alikes into triaged alerts that analysts can act on.

The project supports Qatar's national cybersecurity maturity in three ways:

- **Early warning for the sectors NCSA, QCB and the ministries care about most**: banking, payments, telecom, government e-services, health, energy, aviation and charity.
- **Evidence that organisations can use**: STIX 2.1 bundles, CSV, reports, syslog and chat notifications feed existing SOC tooling and incident processes.
- **Full transparency**: everything is open source, runs without a paid feed, and can be audited and extended by Qatari institutions, researchers and students.

See [docs/qatar-alignment.md](docs/qatar-alignment.md) for how the tool relates to the National Cyber Security Agency's work, the National Information Assurance standard and Qatar Central Bank's expectations.

## Features

- **Direct CT log tailing.** Reads both RFC 6962 logs and Static CT API (tiled) logs with a built-in X.509 parser. No third-party aggregator, so nothing goes dark when a free feed does.
- **Correct shard selection.** Reads every shard that newly issued certificates can land in, not only the shard whose window contains today.
- **Qatar brand engine.** 34 brand profiles with official domains, aliases, Arabic names and priorities, plus 94 Qatar watch keywords in Latin and Arabic script and a watch on every certificate issued under the .qa ccTLD.
- **IDN and Arabic awareness.** Detects Cyrillic and Greek homoglyphs, mixed scripts and Arabic lures such as a brand's Arabic name combined with تحديث or تفعيل, with a character inspector and a look-alike diff.
- **Registrable-domain parsing.** Knows the Qatari second-level suffixes (com.qa, net.qa, org.qa, gov.qa, edu.qa, mil.qa, name.qa, sch.qa), 80 other regional suffixes, 165 global suffixes and 77 free hosting platforms, so `login.qnb.com.qa` and `qnb.com.qa.verify-login.example` are never confused.
- **Honest scoring.** A hosting platform counts once, a leading www is neutral, and every finding is a candidate for review, not an accusation.
- **Typosquat Hunter and Watchtower.** Generates typos, homoglyphs, leet, combos and TLD swaps for every protected brand, resolves them over DNS-over-HTTPS and sweeps on a schedule.
- **Alert lifecycle.** Open, investigating, resolved or false positive, with notes, assignee, timeline, bulk triage, allowlisting and consolidation per domain.
- **Enrichment.** DNS-over-HTTPS, RDAP registration age, crt.sh certificate history and URLhaus reputation, fetched from the browser or the backend.
- **Outputs.** STIX 2.1, CSV, per-alert and weekly HTML reports, IOC copy, JSON workspace backup, Prometheus metrics, syslog and CEF.
- **Two runtimes, one engine.** The detection engine exists in Python and JavaScript and is tested for identical verdicts on a shared corpus.

## Quick start

### Browser console, nothing to install

Open [qacyberwatch.3li.info/demo](https://qacyberwatch.3li.info/demo/). The console tails CT logs from your own browser, scores every hostname locally and keeps its data in your browser. It also loads the relay feed described below, so matches arrive even where a browser cannot read a log directly.

### Self-hosted backend

```bash
git clone https://github.com/SiteQ8/QACyberWatch.git
cd QACyberWatch && pip install -r requirements.txt

python main.py scan qnb-secure-login.xyz      # score one domain
python main.py monitor                        # tail CT logs directly
python main.py watch-squats                   # proactive typosquat watcher
python main.py api                            # REST API on http://localhost:5000
docker compose up -d                          # everything at once
```

The API ships signed bearer tokens, roles, rate limiting and OpenAPI documentation at `/api/v1/docs`. Configuration lives in `config.yaml`, with `config.local.yaml` and `QCW_*` environment variables for overrides.

### Relay feed

`.github/workflows/ct-relay.yml` runs the project's own tailer on a schedule and publishes Qatar keyword matches to `demo/feed/latest.json` with a 14-day archive. Each published observation carries a notice that it is an automated heuristic from public data.

## How detection works

1. **Discover.** Certificates arrive from the CT logs the tailer reads directly; look-alikes come from the Typosquat Hunter and the Watchtower sweep; anything else can be pasted into the scanner or the bulk scanner.
2. **Detect.** The engine parses the registrable domain, folds confusables and leetspeak, normalises Arabic, checks the 34 brand profiles and 94 keywords, scores lures, risky TLDs, entropy, structure and hosting platforms, then applies custom rules.
3. **Triage.** Alerts are enriched with DNS and registration age, consolidated per domain and worked in a drawer with evidence, diff, notes and timeline. Export STIX or a report when handing off.

Scores run from 0 to 100: 80 and above is critical, 60 to 79 high, 40 to 59 medium, 20 to 39 low and anything below 20 clean. Short keywords must sit at the edge of a label so that random strings do not match. The brand monitor scales the typo distance it tolerates to the length of the brand name, so three-letter brands such as QNB, CBQ, QIB and QCB do not swallow each other.

## Protected brands

Thirty-four Qatari organisations across banking, payments, telecom, government, health, energy, aviation, postal services, charity, commerce and education. The full list, with the keywords and Arabic names used for each, is in [docs/brands.md](docs/brands.md). Add your own under `brands:` in `config.yaml`.

Brand names are used for identification only and remain the property of their owners. The project is independent and is not affiliated with any of the organisations it protects.

## Repository layout

```
demo/            browser console (engine.js, app.js, discovery.js, feed/)
src/core/        detection engine, brand monitor, CT tailer, STIX export, reports
src/api/         Flask REST API with OpenAPI
src/notifications/  Slack, Teams, Telegram, e-mail, webhook, syslog and CEF
src/utils/       domain parsing, X.509 reader, Arabic and confusable folding
scripts/         relay snapshot, engine data export, screenshots
tests/           450+ offline tests including Python and JavaScript parity
docs/            Qatar alignment, protected brands, screenshots
```

## Responsible use

QACyberWatch produces automated heuristic findings from public data. A flagged domain is a candidate for review, not an accusation, and legitimate services will appear among the results. Verify independently before blocking, reporting or attributing. Findings that look like a live campaign are best shared with the brand owner and with NCSA before they are published. Read the full [disclaimer and terms of use](DISCLAIMER.md).

## ملخص بالعربية

QACyberWatch أداة مفتوحة المصدر لرصد التصيد وحماية العلامات التجارية في دولة قطر، فهي تقرأ سجلات شفافية الشهادات مباشرة وتفحص كل اسم نطاق جديد مقابل أسماء البنوك القطرية وخدمات الدفع وشركات الاتصالات والجهات الحكومية بحروفها اللاتينية والعربية، ثم تحوّل النطاقات المشابهة إلى تنبيهات جاهزة للمراجعة مع أدلة وتصدير بصيغة STIX. تعمل الأداة من المتصفح دون تثبيت أو تُشغَّل كخدمة ذاتية الاستضافة مع واجهة برمجية وتنبيهات فورية، وكل ما ترصده هو مؤشر يحتاج إلى تحقق بشري وليس اتهاماً لأي جهة. تُقدَّم هذه الأداة مساهمةً في نضج الأمن السيبراني الوطني لدولة قطر.

## License

MIT. Built and maintained by Ali AlEnezi (SiteQ8).
