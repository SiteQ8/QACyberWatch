# QACyberWatch landing page, notes for the build (30 October 2026)

## Step 1. What is real
- Subject: an open-source engine that reads public Certificate Transparency logs the moment certificates are issued and scores every hostname against Qatar's brands and keywords. Audience: analysts and fraud desks at Qatari banks, payment providers, telecoms and ministries; NCSA, Q-CERT and sector CERTs; students.
- The one thing the page must get someone to do: look up a name (the live thing) and open the console.
- Stack: one self-contained index.html on GitHub Pages, bilingual English and Arabic with an RTL toggle; the console at demo/ is a separate app.
- Existing brand: the name QACyberWatch, the maroon of the State, the author's name. No logo beyond the wordmark.
- Imagery that truly exists: the relay's real observations (15 days, 3,613 matches), the real console (screenshots and the real JavaScript engine that can run in the page), two open-collection photographs of Doha (CC BY), credited.

### Inventory (what belongs to this subject and to no competitor)
1. The .qa ccTLD and its second-level suffixes: com.qa, net.qa, org.qa, gov.qa, edu.qa, mil.qa, name.qa, sch.qa.
2. The 974 dialling code, watched as a whole token.
3. The 34 Qatari brand profiles with their Arabic names (حكومي, مطراش, كهرماء, سداد, حميان...).
4. The State's maroon (al-adaam) and the flag's serrated white edge.
5. The Arabic lure words the engine knows: تحديث, تفعيل, تجديد.
6. The relay's real register: 41 public logs read, 158,861 entries in the last run, 3,613 matches in fifteen days, Let's Encrypt issuing 54% of them.
7. The engine's own numbers: 455 tests, two engines agreeing on one corpus, scores 0 to 100 with five levels.
8. The ritual: every certificate browsers trust is written to a public log before it is used; the tailer reads the log as it is written.
9. The printed thing of its world: Qatar's Official Gazette, the register of record where laws and licences are published, numbered and dated.
10. Doha itself: the Corniche, the Museum of Islamic Art, West Bay across the water.

## Step 2. The argument
1. A look-alike of a Qatari name is public the minute its certificate is issued. → the live register: the relay's latest real matches, with time, log and issuer; the lookup field.
2. Fifteen days of reading every public log produced 3,613 matched names. → one real figure with its caption and date; the daily series.
3. Read, score, triage: that is the whole method. → the squares diagram and three short columns.
4. One verdict explains itself. → the real verdict panel for one name with margin notes.
5. The feed is live; the same switch runs in the console. → the control at poster size.
6. Thirty-four Qatari names are under watch, each with its Arabic name. → the brand sheet.
7. Built for Qatar's institutions, open to audit. → the alignment statement with highlighted facts.
8. Open the console. → the one-word band.
9. Where to reach the maker, the licence, the credits and the notice. → the footer.

## Step 3. Direction
- Dealt: borrowed-category, seed 593137635. Borrowed category decided: an official register of record (the Gazette), because the subject is literally a public log of record and its audience reads gazettes, circulars and registers all day.
- Palette: dealt proportions kept (one field for the whole page, one ink, the accent as a sliver); colours taken from the subject: the State's maroon as the field, paper sheets with iron ink on them, the serrated edge as the one motif.
- Type: redraw, reason: the dealt face (TikTok Sans) has no Arabic coverage and the page is bilingual. Chosen: Libre Franklin (display, 800) with Source Serif 4 (text) for English; Amiri (display, 700) with Noto Naskh Arabic (text) for Arabic; tabular lining figures from Libre Franklin for numbers.
- Photographs: dealt "Architecture" set not used; two real pictures of Doha from Wikimedia Commons instead (CC BY), plus interface fragments built in HTML from the real engine.

## Step 4. The idea
On this page, the public certificate log for Qatar's names becomes an issue of an official register, printed on paper sheets whose edges are cut like the flag's. Competitor test: with Kuwait's names, Kuwait's flag and Kuwait's suffixes the sentence no longer holds.
The one live thing: look up a name in the register. The visitor types a domain; the page runs the real engine on the device and prints the verdict as a register entry (level, score, brand, what gave it away, the look-alike diff), with a link that opens the same scan in the console. Works with a thumb; without script the form opens the console's scanner.

## Step 5. Copy deck (English; Arabic in the page)
Nav: QACyberWatch · Register · Method · Brands · Console · EN/العربية · Open the console
Hero sheet: Register of certificates issued for Qatar's names. Issue 15, Friday 30 October 2026, read from 41 public logs.
H1: Seen before the first phish
Supporting: Every certificate issued for a Qatari name, read from the public logs as it is written and scored for impersonation.
Lookup: Look up a name in the register. [input] [Look up]
Stats: heading "Fifteen days of reading", figure 3,613 "names", caption: hostnames the relay matched between 16 and 30 October 2026 among certificates issued for names that carry a Qatar keyword or end in .qa; 415 of them scored medium or above. Source: the relay archive, refreshed after every run.
Method: heading "Read, score, triage". Read: RFC 6962 and Static CT API logs, every shard that can still receive a new certificate. Score: 34 Qatari brand profiles, 94 keywords in Latin and Arabic, homoglyphs, lure words, risky endings, hosting platforms. Triage: alerts with evidence, a diff against the real name, DNS and registration age, STIX and CSV when handing off.
Features: heading "One verdict, explained" with the panel for sadad-pay-qa.top and six notes.
Showcase: heading "The feed, live" / "The feed, paused"; sentence: The same switch starts the console reading the logs from your browser; here it runs the relay's latest matches.
List: heading "Thirty-four names under watch", groups by sector, each name with its official domain and Arabic name; closing lines: Brand names identify what the tool protects and remain their owners'. Add your own under brands in config.yaml.
About: heading "Built for Qatar's institutions" and the statement with highlights (NCSA, Q-CERT, the NIA standard, Qatar Central Bank, MIT, 455 tests), last sentence linking to the alignment note.
CTA: the word "Open"; sentence: The console tails the logs from your browser and keeps everything on your device, with no account.
Footer: notes (licence and author; the notice; photo credits), contact line github.com/SiteQ8, meta row.
