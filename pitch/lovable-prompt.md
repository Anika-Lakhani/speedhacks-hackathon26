Build a Lovable-native slide deck for **SwarmShield**, our SpeedHacks 2026 hackathon pitch. All slide content, layout notes, and speaker notes are in the attached file `swarmshield-deck-content.md` — use that copy verbatim and don't invent new claims, statistics, or features.

## Format and export
- This is a **Lovable-native slide deck** that must be **fully exportable to PowerPoint (.pptx) and Google Slides** without breaking.
- 16:9, 1920×1080.
- Build every element so it survives export as editable content:
  - Text as real text boxes.
  - Tables as native tables.
  - Diagrams, the roadmap, and the TAM/SAM/SOM circles from native shapes and connector arrows.
  - No screenshots of text and no text baked into images.
- Avoid effects that don't export cleanly: CSS blend modes, backdrop blur, gradient text, video backgrounds, and complex animations. A simple fade or appear-on-click is fine.
- Put each slide's **Speaker notes** from the content file into that slide's presenter notes.
- **Do not put visible slide numbers on any slide.** No page counters ("3 / 8") and no numbers in footers.

## Visual theme: "Night Shift"
A calm, dark security-ops look: confident, technical, uncluttered. It should feel like a modern dev-tool brand, not a hacker cliché. No hooded figures, padlocks, matrix rain, or binary code.

**Colors:**
- Background: deep navy-black `#0B0F17`. Cards and panels: `#141A26`. Hairline borders: `#232B3B`.
- Primary text: off-white `#E8ECF2`. Secondary text: slate `#8A94A6`.
- Primary accent (SwarmShield, solution, highlights): electric cyan `#22D3EE`.
- Threat accent (problem, attacker, warnings): coral red `#FF5C5C`. Use it sparingly, mainly for the slide 1 punchline and the slide 2 closing line.
- Verified/safe accent: mint green `#34D399`. Use it only for "confirmed / verified / TODAY" states.

**Fonts.** Use only Google Fonts that also exist in Google Slides:
- Headlines and big numbers: **Space Grotesk** (bold).
- Body: **Inter**.
- Technical labels, verdict names, and pipeline step names: **JetBrains Mono**.

**Motif:**
- A subtle **swarm** pattern: a sparse field of small dots or tiny hexagons, some connected by faint lines.
- Use it at low opacity in corners or behind the hook and closing slides only. Keep content slides clean.

**Layout:**
- Generous margins, at least 96px. Left-aligned headlines, with one idea per slide.
- Headlines are 56–72px and body text is at least 24px. Big stats (slide 2) are 72–96px.
- Footnotes are 14–16px in secondary slate, pinned bottom-left.
- Small SwarmShield wordmark in the top-left corner of content slides. No other header or footer furniture.

## Slide-specific direction
1. **Hook:** mostly empty space. The three short lines are neutral off-white, then the punchline lands in coral and is visibly larger. Reveal the lines one at a time on click.
2. **Problem:** four stat rows with huge numbers in Space Grotesk and short labels. The closing line "Attackers move in hours. Defenders test once a year." is a full-width banner at the bottom. This is the most important line in the deck.
3. **Solution:** an editable 3-row comparison table. The "Annual pentest" column is muted grey and the "SwarmShield" column is highlighted with a cyan border or tint. Keep the asterisk footnote visible.
4. **How it works:** a 5-step loop diagram from native shapes and arrows, where step 5 loops back to step 1. Add a small fan-out from "Learn & share" to 2–3 faint "other customer" nodes. Put the key line in cyan beneath it.
5. **How we built it:** the pipeline as connected boxes across the top, the guardrails list bottom-left, and a sponsor strip bottom-right. For any sponsor marked `[... if integrated; otherwise remove]`, render a clearly labeled dashed placeholder box so we can fill it in or delete it later.
6. **Live + roadmap:** a three-stage horizontal timeline. TODAY is solid mint, NEXT is a cyan outline, and VISION is faded and dashed. Below it, a bordered "What's simulated" card in secondary text. It must be visible and honest, not hidden.
7. **Market + customers:** "Who" rows with simple line icons on the left, three concentric TAM/SAM/SOM circles on the right, and "Why now" along the bottom.
8. **Close:** centered headline with the swarm motif behind it, and team names and the repo URL small at the bottom.
9. **Appendix (Sources):** a plain text slide at the end in a smaller font. It's fine to style it as backup.

## Placeholders
- Anything in `[BRACKETS]` in the content file is a placeholder. Render it as visible placeholder text (dashed outline or highlighted) so it's easy to find and replace. Don't fill it with made-up content.

## Tone
- Punchy and minimal. If a slide feels crowded, cut visual decoration, not content. Never shrink text below the sizes above.
- The deck backs a ~4-minute spoken pitch inside a 5-minute demo video, so slides should support the speaker, not replace them.
