# ScamShield AI

ScamShield AI is an Anna App that helps people inspect suspicious messages, links, emails, QR codes, screenshots, job offers, and investment pitches before they click, pay, or reply.

The app is built as an evidence-first fraud investigation workbench. A bundled deterministic Executa produces the risk score, findings, limitations, and recommended next actions. Anna-hosted LLM support is used only to turn that evidence into a clear investigator note when the runtime grants are available.

Current app version: `0.1.4`
Current analyzer binary release: `scamshield-analyzer-v0.1.1`

Demo video : https://youtu.be/ugw6vePwF80

## Why This Exists

Most scam checks fail in the moment when a user is pressured to act quickly. ScamShield gives the user a structured pause:

- Paste the suspicious content.
- Run a local evidence engine.
- Review risk, reasons, and recommended next steps.
- Save or export a compact report.
- Send the report context to Anna chat for follow-up guidance.

It is designed for everyday users, support teams, community safety volunteers, and anyone who needs a fast second opinion before responding to a risky message or offer.

## What It Can Investigate

- Messages: SMS, WhatsApp, DMs, and copied social posts.
- Websites: suspicious domains, shortened links, lookalike brand URLs, and non-HTTPS links.
- Emails: sender, subject, body text, attachment names, and embedded links.
- Job offers: registration fees, interview-letter pressure, fake HR language, and unrealistic salary claims.
- Investment pitches: guaranteed returns, crypto or forex signal groups, Ponzi-style language, and no-risk claims.
- QR codes: decoded payment URLs or pasted QR text.
- Screenshots: user-provided OCR text, with optional Anna image extraction when the runtime supports it.

## Product Features

- Multi-mode investigation surface with tailored labels and helper text.
- Evidence-first risk score, verdict, confidence, reasons, limitations, and actions.
- Optional public HTTPS probe with private-network and localhost blocking in the analyzer.
- Anna runtime adapter with standalone local fallback for development and browser QA.
- Anna storage history with localStorage fallback.
- Undo for clearing saved history.
- PDF report generation from the full evidence record.
- Copy recommendations and send complete report context to Anna chat.
- Responsive UI verified at `320`, `375`, `414`, `768`, and desktop widths.
- Accessible report tabs with keyboard navigation.
- Image upload guardrails for file type and size before reading image data.

## Safety Model

ScamShield is a decision-support tool. It does not claim to be a law-enforcement, banking, or financial authority.

The app is intentionally conservative:

- The deterministic analyzer is the source of truth.
- The LLM must not invent domain age, breach data, report counts, authority claims, or reputation facts.
- Missing evidence is shown as a limitation instead of being filled in.
- Network probing is opt-in and restricted to public HTTPS targets.
- The app does not ask users for provider API keys.
- Stored history is compact and limited to report summaries.

## Architecture

```text
ScamShield AI
|-- app.json
|   Anna marketplace/app metadata.
|-- manifest.json
|   Anna grants, CSP, view config, storage/chat/LLM/tool host APIs.
|-- bundle/
|   |-- index.html
|   |   Static Anna app shell.
|   |-- app.js
|   |   Runtime adapter, UI state, local fallback analyzer, PDF export.
|   |-- style.css
|   |   Hallmark-guided workbench UI.
|   |-- tokens.css
|   |   Shared OKLCH design tokens, spacing, typography, motion.
|   |-- anna-tool-ids.js
|   |   Dev/prod bundled tool id indirection.
|   `-- icon.svg
|-- executas/scamshield-analyzer/
|   |-- executa.json
|   |   Binary distribution metadata for Anna.
|   |-- pyproject.toml
|   `-- scamshield_analyzer.py
|       JSON-RPC 2.0 over stdio fraud analyzer.
|-- tests/
|   |-- bundle/static.test.js
|   |   Static contract and release metadata checks.
|   |-- plugin/test_scamshield_analyzer.py
|   |   Analyzer unit tests.
|   `-- e2e/scamshield.spec.js
|       Playwright UI, PDF, history, upload, tab, and responsive tests.
|-- fixtures/happy-path.jsonl
|   Anna fixture verification.
|-- .github/workflows/
|   CI, Anna publish, and analyzer release packaging.
`-- DEPLOY.md
    Operational release notes.
```

## Local Development

Install dependencies:

```powershell
npm install
```

Run the Anna dev harness without hosted LLM synthesis:

```powershell
npm run dev
```

Run with Anna-hosted LLM synthesis:

```powershell
npm run dev:llm
```

Open the URL printed by `anna-app dev`.

## Verification

Run the local production gate:

```powershell
npm run test
npm run fixture:verify
npm run validate
npm run test:e2e
npm audit --audit-level=moderate
```

Coverage:

- `npm run test`: static bundle contract tests plus Python analyzer unit tests.
- `npm run fixture:verify`: Anna fixture replay.
- `npm run validate`: strict Anna app schema validation.
- `npm run test:e2e`: browser investigation flow, PDF generation, saved history, keyboard tabs, upload limits, and responsive overflow checks.
- `npm audit --audit-level=moderate`: dependency vulnerability gate.

## Release And Deployment

The bundled analyzer is distributed through GitHub Release assets. The active analyzer release is:

```text
scamshield-analyzer-v0.1.1
```

It contains:

- `darwin-arm64` tarball and SHA file.
- `darwin-x86_64` tarball and SHA file.
- `linux-x86_64` tarball and SHA file.
- `windows-x86_64` zip and SHA file.
- Anna app source archive.

Push and cut the Anna app after verification:

```powershell
$ANNA_HOST = "https://anna.partners"
npm run test
npm run fixture:verify
npm run validate
npm run test:e2e
anna-app apps push --account $ANNA_HOST --json
anna-app apps cut 0.1.4 --account $ANNA_HOST --json
anna-app apps status scamshield-ai --account $ANNA_HOST --json
```

Final public promotion is intentionally separate:

```powershell
anna-app apps release 0.1.4 --account $ANNA_HOST --json
```

Use release promotion only after review approval.

## GitHub Workflows

- `.github/workflows/build-release.yml` builds analyzer binaries and attaches release assets.
- `.github/workflows/anna-app-publish.yml` runs the Anna app gate and can push, cut, or release when `ANNA_APP_PAT` is configured.

## Privacy

ScamShield does not ask for OpenAI, Anna, or provider API keys. Anna host APIs provide tools, storage, chat, and LLM calls according to `manifest.json`. In standalone local preview, the deterministic fallback analyzer runs in the browser and history is stored in localStorage.

## Status

The app is production-ready for review with version `0.1.4` cut through Anna after the final verification pass. Public release remains a separate approval step.
