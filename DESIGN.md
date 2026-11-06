# QACyberWatch landing page, design record

<!-- impeccable:design-schema 1 -->

Scope: `index.html`, the public page at https://qacyberwatch.3li.info/. The console in `demo/` keeps its own interface and is not covered here.

## Thesis

The public certificate log for Qatar's names is treated as an official register of record: an issue of the register, numbered and dated, printed on paper sheets laid on the State's maroon, each sheet cut with the flag's serrated edge. The page refuses the dark cyber page with a dashboard screenshot and three feature cards. Everything it shows is the product's own output: the relay's real observations, the real engine scoring a typed name, the real console.

## Own world

- Field: maroon `#8a1538` owns the whole page; `#6b0f2b` for the feed section at rest; `#4a0a1e` for the footer.
- Paper: `#f2f1ee` sheets with `#e7e5e0` panels; iron ink `#15110f` with `#4b413c` for secondary text on paper.
- Rubric: the maroon returns on paper only for the keys, the one primary button, the verdict bar and the highlighted facts.
- On maroon, secondary text is pale rose `#e9c6d0` or `#f7e6ea`, never grey.
- Motif: the serrated edge, drawn once as a repeating SVG mask on `.sheet.top::before` and `.sheet.bottom::after`. No rules, shadows, gradients or rounded corners anywhere.
- Photographs: two real pictures of Doha from Wikimedia Commons, credited in place and in the footer (see Provenance).

## Type

- English: Libre Franklin 800 for display and headings, Source Serif 4 for text, tabular lining figures from Libre Franklin for every number (`.num`).
- Arabic: Amiri 700 for display and headings, Noto Naskh Arabic for text, with the line height raised to 1.85 for body and 1.35 for headings.
- Scale (CSS custom properties): `--t-small` 16px, `--t-body` 18px, `--t-lead` 21 to 26px, `--t-claim` 32 to 44px, `--t-head` 32 to 56px, `--t-display` 44 to 92px; the register figure and the two words (the feed switch value and the closing word) are set larger on purpose, as poster objects, not as text.

## Layout

- One frame of 1320px with a fluid gutter of 20 to 48px; every section, the navigation and the footer sit on the same margins.
- Sheets carry the paper sections (hero, method, watch list, alignment statement); the maroon field carries the figure, the verdict panel with its margin notes, the feed switch and the closing word.
- The watch list is a sheet laid on the night photograph, which stays in place while the sheet scrolls past.
- Phones: the navigation wraps to two rows with the section links on a swipe row; the register keeps time, name and verdict only; the method diagram becomes three stage marks beside their columns; the feed switch is cropped at the gutter and the bottom edge, never at the text.

## Motion

- Load: the headline rises line by line from a masked block (900ms, expo-out, 110ms apart), the supporting sentence and the lookup form follow at 420 and 480ms.
- Scroll: one reveal, used once per element and never on long blocks of text; the register rows, the figure's daily series and the diagram's squares come in staggered when they enter.
- The feed switch moves its thumb over 400ms in-out and swaps the section's field between maroon and paper; the ticker pauses with it.
- Press: 140ms scale to .97 on buttons; hover 180ms colour changes on pointers that can hover.
- `prefers-reduced-motion: reduce` removes every entrance and stops the ticker.

## Content rules

- Every number on the page is read from `demo/feed/summary.json` and `demo/feed/latest.json` after every relay run; the markup carries the values of the day it was built as the no-script state.
- Verdicts are called candidates for review. No named domain is accused.
- Arabic copy follows the project's writing rules: a period only at the end of a sentence, clauses joined with conjunctions, natural phrasing rather than literal translation.
- No em or en dashes anywhere.

## Provenance

- `assets/islamicartmuseumdohaskyline.jpg`: "IslamicArtMuseumDohaSkyline" by Mohamod Fasil, CC BY 2.0, via Wikimedia Commons (file page: https://commons.wikimedia.org/wiki/File:IslamicArtMuseumDohaSkyline.jpg).
- `assets/doha-dhow-harbour-skyline-view-at-night.jpg`: "Doha Dhow Harbour Skyline View at Night 02" by Zairon, CC BY 4.0, via Wikimedia Commons (file page: https://commons.wikimedia.org/wiki/File:Doha_Dhow_Harbour_Skyline_View_at_Night_02.jpg).
- `assets/credits.json` is the machine record of both downloads.
- Diagrams: drawn in code (`scripts` are not kept; the SVGs are inline and deterministic).
- Interface fragments: the verdict panel is the engine's real output for `sadad-pay-qa.top`; the register rows are the relay's own records.

## Open items

- No honest clip of Doha of adequate quality exists in the open collections; the moving element is the live ticker. Revisit if a CC BY clip appears.
- The page loads four Google Fonts families; self-host them if the site must work without third-party requests.
