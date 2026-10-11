# SwarmShield — Pitch Deck Content

> Source content for the SpeedHacks 2026 pitch deck. Each `## Slide` section is one slide.
> **On-slide copy** is what appears on the slide. **Visual** describes the layout.
> **Speaker notes** go in the slide's presenter notes, not on the slide.
> Text in `[BRACKETS]` is a placeholder to fill in later — render it as a clearly visible placeholder.

**One-line value prop (use consistently):**
SwarmShield is a continuous pentest for your security team of one: it safely attacks every release and tells you what to fix in minutes, not months.

**Tagline:** A security team of one gets a swarm.

---

## Slide 1 — Hook

**On-slide copy**

- Eyebrow: SWARMSHIELD
- Headline: Congrats on your Series A. 🎉
- Three short lines, revealed one at a time:
  - New office.
  - Dental insurance.
  - Your first enterprise deal.
- Punchline (larger, accent color): …and a 200-question security questionnaire.

**Visual**
Mostly empty dark slide, big type. The three lines are calm/neutral; the punchline lands in the warning accent color. Small SwarmShield wordmark in a corner.

**Speaker notes**
Congrats — you just raised your Series A. Bigger office, real benefits, and your first enterprise customer. And then their security team sends you a 200-question questionnaire. That's the moment we built SwarmShield for.

---

## Slide 2 — Problem

**On-slide copy**

- Headline: Enterprise deals come with enterprise security.
- Four stat rows (big number + short label):
  - **85–95%** of enterprise buyers require SOC 2
  - **1** — your first security hire is a team of one
  - **1×/year** — the pentest they can afford: 6–10 weeks, ~$18K
  - **45%** of AI-written code contains security flaws — and you ship daily
- Closing line (full width, bold): **Attackers move in hours. Defenders test once a year.**
- Footnote (small): Sources: industry SOC 2 surveys; Edgescan, Triaxiom, Synack (pentest timing/cost); Veracode 2025 GenAI Code Security Report.

**Visual**
Four stat rows stacked on the left or as a 2×2 grid. The closing line sits at the bottom as a banner. Numbers in the display font, large.

**Speaker notes**
Your first enterprise deal is usually the first time you have to take security seriously — 85 to 95 percent of enterprise buyers require SOC 2. So you hire one security person. Realistically, they can run one pentest a year: it takes six to ten weeks from booking to report and costs around eighteen thousand dollars. Meanwhile your engineers ship every day, increasingly with AI — and Veracode found 45% of AI-generated code has security flaws. Attackers move in hours. Defenders test once a year.

---

## Slide 3 — Solution + Time Saved

**On-slide copy**

- Headline: Turn your annual pentest into a background process.
- Subhead: SwarmShield safely attacks every release and tells you what to fix — in minutes, not months.
- Comparison table:

| | Annual pentest | SwarmShield |
|---|---|---|
| First finding | 6–10 weeks | Minutes after deploy |
| Coverage | Once a year | Every release |
| Your team's time | ~40 hrs scoping + triage* | ~1 hr setup + ~15 min per finding |

- Footnote (small): *Team estimate. Pentest timing: 4–7 week lead times + ~3 weeks to results (Edgescan, Cobalt).

**Visual**
Clean two-column comparison. "Annual pentest" column muted/grey; "SwarmShield" column highlighted with the primary accent and a subtle glow or border. The table must be a real, editable table (not an image).

**Speaker notes**
SwarmShield turns that once-a-year pentest into a background process. Every time you ship, it decides what changed, safely tests it the way an attacker would, and verifies whether the weakness is real. Your first finding arrives minutes after a deploy instead of six to ten weeks later — and your security person spends about fifteen minutes reviewing each finding instead of a week scoping and triaging a report. That includes setup and review time — we're not hiding the human part.

---

## Slide 4 — How It Works

**On-slide copy**

- Headline: How it works
- Loop diagram, five steps (left-to-right, with an arrow looping back to the start):
  1. **Code change** — a new release ships
  2. **AI plans** — picks what's most worth testing
  3. **Safe probe** — marked, sandboxed test requests
  4. **Verifier** — confirms what's actually exploitable
  5. **Learn & share** — findings to you; lessons to every customer
- Key line (bold, accent): **AI decides what to test. Code decides what's real.**

**Visual**
A circular or horizontal loop diagram built from native shapes and connector arrows (editable after export — not an image). Step 5 loops back to step 1. A small "shared intelligence" node fans out to 2–3 faint "other customer" nodes to show cross-customer learning.

**Speaker notes**
Here's the loop. A code change ships. An AI planner reads what changed and what we already know about this customer, and picks the tests most worth running. A probe engine sends safe, clearly marked requests. Then — and this is the important part — a deterministic verifier, not the AI, decides whether the weakness is real. Findings go to you, and generalized, privacy-scrubbed lessons go to every other customer. AI decides what to test. Code decides what's real.

---

## Slide 5 — How We Built It

**On-slide copy**

- Headline: How we built it
- Pipeline (horizontal, four boxes):
  **Keewano** memory & event log → **Planner** (Claude[ / Darwin]) → **Probe engine** → **Deterministic verifier** → back to **Keewano**
- Guardrails (short list, icon per item):
  - Scenario + target allowlists — the AI can't invent attacks or targets
  - Hard budgets enforced in code — 12 scenarios, 120 s, $1 per run
  - Four verdicts: confirmed · not reproduced · inconclusive · blocked — ambiguous never counts as a pass
  - Human approval before any finding is "verified"
  - Every finding replays from stored evidence
- Built with (sponsor strip):
  - **Keewano** — per-customer event store and security memory
  - [DARWIN — planner/orchestration, if integrated; otherwise remove]
  - [SPARTA — safe testing sandboxes, if integrated; otherwise remove]

**Visual**
Top half: the pipeline as connected boxes. Bottom-left: guardrails list. Bottom-right or bottom strip: sponsor logo placeholders, each with a one-line role caption. Use clear placeholder boxes for any sponsor marked conditional.

**Speaker notes**
Under the hood: Keewano stores every event and each customer's security memory. A Claude planner ranks scenarios from a fixed catalog — it returns scenario IDs, not code. A probe engine executes only allowlisted, benign requests, and a deterministic verifier compares the response against ground truth. Budgets are enforced in code, not in the prompt, and nothing becomes "verified" without a human. Every confirmed finding can be replayed from its stored evidence. [Add one sentence per sponsor actually used.]

---

## Slide 6 — What's Live + Path Forward

**On-slide copy**

- Headline: Live today. Autonomous tomorrow.
- Three-stage roadmap:
  - **TODAY (MVP)** — Finds and verifies weaknesses on every change; reports them so your team can fix.
  - **NEXT** — Auto-generated fix PRs, applied with human approval.
  - **VISION** — A fully autonomous loop: find → fix → verify → learn.
- "What's simulated" box (small, honest):
  - Probes run against our own demo sites with toggleable vulnerability flags
  - No real exploitation — every probe is marked and sandboxed
  - Single planner agent today; parallel swarm is next
  - [DEMO DETAILS FROM TEAM — what ran live, measured time from code change → verdict]

**Visual**
Horizontal three-step timeline; TODAY is solid/highlighted, NEXT is outlined, VISION is faded/dashed. The "what's simulated" box sits beneath in a subtle bordered card.

**Speaker notes**
Here's what's real today: SwarmShield finds and verifies weaknesses on every change and hands your team an evidence-backed report. To be transparent — today it runs against our own demo sites with simulated vulnerabilities, and it's a single planner agent rather than a full parallel swarm. Next, it opens fix PRs that a human approves. The vision is a fully autonomous, self-healing loop: find, fix, verify, and learn.

---

## Slide 7 — Market + Customers

**On-slide copy**

- Headline: Built for the first enterprise deal.
- Who:
  - Series A–C B2B SaaS — the moment SOC 2 and pentests become mandatory
  - Beachhead: fintech & healthtech (ship fast, handle sensitive data)
  - Buyer: the first security hire — or the CTO before one exists
- Market (three nested circles):
  - **TAM ~$3B → ~$8B by 2030** — pentesting + attack simulation
  - **SAM ~$450M** — ~15K US SaaS companies × ~$30K/yr
  - **SOM ~$9M ARR** — 300 customers in 3 years
- Why now: AI made shipping 10× faster. Security didn't keep up.
- Footnote (small): Sources: P&S Intelligence, MarketsandMarkets (pentesting); TBRC, Astute Analytica (BAS); Latka/Ascendix (SaaS counts). SAM/SOM are team estimates.

**Visual**
Left: "Who" as three short rows with icons. Right: three concentric TAM/SAM/SOM circles built from native shapes with labels. "Why now" line along the bottom.

**Speaker notes**
Our customer is a Series A to C B2B SaaS company at its first enterprise deal — starting with fintech and healthtech. The buyer is that first security hire, or the CTO before one exists. Pentesting and attack simulation together are about a three-billion-dollar market today, heading toward eight billion by 2030. Our serviceable market is roughly fifteen thousand US SaaS companies at about thirty thousand a year — around 450 million. And the timing is right: AI made shipping ten times faster, and security didn't keep up.

---

## Slide 8 — Close

**On-slide copy**

- Headline (large, centered): **A security team of one gets a swarm.**
- Subline: SwarmShield — continuous pentesting for every release.
- Small: [TEAM NAMES] · [GITHUB REPO URL] · Built at SpeedHacks, SF Tech Week 2026

**Visual**
Dark slide, centered headline, subtle swarm/particle motif behind it.

**Speaker notes**
Attackers move in hours. With SwarmShield, so do defenders. A security team of one gets a swarm. Thank you.

---

## Appendix — Sources (optional backup slide, hidden or at the end)

- Pentest market: P&S Intelligence (~$2.1B 2025 → ~$4.7B 2030); MarketsandMarkets (~$2.0B 2025 → ~$4.4B 2031)
- Breach & attack simulation: TBRC (~$0.93B 2025, ~36% CAGR); Astute Analytica (~$0.57B 2025, ~40% CAGR)
- Pentest timing/cost: Edgescan (4–7 week lead times); Triaxiom (4–6 weeks end to end); Cobalt (~3.1 weeks to results); Synack (~$18K average)
- Testing cadence: Fortra/Core Security 2024; Horizon3.ai (49% test once a year or less)
- Exploitation speed: Verizon DBIR 2025 (median time to mass exploitation: 0 days); Synack 2026 (window narrowed to hours)
- AI-generated code: Veracode 2025 GenAI Code Security Report (45%)
- SOC 2 demand: industry surveys (85–95% of enterprise buyers)
- SaaS company counts: Latka / Ascendix (~12–17K US)
