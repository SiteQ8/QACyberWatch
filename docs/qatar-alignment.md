# QACyberWatch and Qatar's national cybersecurity maturity

QACyberWatch is an independent open-source contribution. It is not an official product of any Qatari authority. This note explains where it fits so that institutions can decide how to use it.

## Who the tool serves

| Audience | What QACyberWatch gives them |
| --- | --- |
| Banks, payment providers and QFC firms | Early sight of look-alike domains imitating their brand, with evidence they can hand to a takedown provider or their SOC |
| Ministries and e-service operators (Hukoomi, Metrash, MOPH, Kahramaa, Qatar Post) | A watch on the names that scam SMS and WhatsApp campaigns reuse, in Latin and Arabic script |
| Telecom operators | Brand monitoring plus a free signal for abuse desks that handle customer complaints |
| NCSA, Q-CERT and sector CERTs | A national-scale feed of candidate impersonation infrastructure and an open engine that can be audited and extended |
| Universities and students | A complete, tested reference implementation of CT monitoring, domain parsing, IDN handling and scoring |

## How it relates to national frameworks

The mapping below is descriptive. QACyberWatch produces evidence that supports the activities named; it does not by itself make an organisation compliant with anything.

| Framework or body | Where the tool helps |
| --- | --- |
| National Cyber Security Agency (NCSA) | Threat monitoring, information sharing and public awareness about phishing that targets Qatari brands. Findings that look like a live campaign are meant to be shared with NCSA. |
| National Information Assurance (NIA) standard | Security monitoring and logging, incident management and third-party risk: the tool supplies monitoring of a public attack surface, structured evidence (STIX 2.1, CSV, reports) for incident records, and a view of look-alike infrastructure that targets an organisation's customers. |
| Qatar Central Bank expectations for licensed financial institutions | Brand protection, customer-facing fraud awareness and timely detection of phishing infrastructure against banks and payment services, including Himyan and NAPS. |
| Q-CERT and sector CERTs | Machine-readable indicators that can be exchanged with partners and fed into blocking at DNS, mail and web gateways. |

## What the tool does not do

- It does not visit suspicious sites and does not confirm that a page is a phishing page. It reports names and certificates.
- It does not replace a takedown service, a fraud operations team or a legal process.
- It does not store data about users. The console keeps everything in the analyst's browser and the backend keeps what the operator configures.

## Suggested deployment for an institution

1. Run the backend on an internal host with `python main.py api` and `python main.py monitor`, keep the relay feed as a second source, and set the brand profiles to the institution's own domains and Arabic names in `config.yaml`.
2. Route critical and high alerts to the SOC channel with the Teams, Slack or syslog notifiers and keep medium alerts for weekly review.
3. Allowlist official infrastructure and subsidiaries early. Legitimate names otherwise fill the top of the list.
4. Export STIX bundles for anything confirmed and share them with NCSA and sector peers.
5. Keep the engine's two implementations in sync by running the test suite after any change to brand data.
