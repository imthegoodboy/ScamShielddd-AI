# ScamShield AI

ScamShield AI is an Anna App for investigating suspicious messages, URLs, emails, QR codes, screenshots, job offers, and investment pitches before a user clicks, pays, or replies.

It combines a deterministic bundled Executa with Anna-hosted `llm.complete` synthesis. The deterministic analyzer is the source of truth for score, findings, evidence, and recommendations. The LLM layer is used only to summarize the evidence in user-friendly language.

## What It Does

- Multi-mode investigation for messages, websites, emails, jobs, investments, QR content, and screenshot OCR text.
- Evidence-first risk scoring with a visible score, verdict, confidence, reasons, and limitations.
- Anna tool invocation through the bundled `scamshield-analyzer` Executa.
- Optional Anna LLM narrative synthesis using only returned evidence.
- Local browser fallback so the UI can be tested outside Anna.
- Saved investigation history with Anna storage and localStorage fallback.
- Copyable recommendations, PDF report generation, and "send to Anna chat" support.
- Responsive workbench UI verified at 320, 375, 414, 768, and desktop widths.

## Architecture

```text
ScamShield AI
|-- manifest.json                         Anna app grants, view, CSP, bundled Executa wiring
|-- app.json                              Anna marketplace/app metadata
|-- bundle/
|   |-- index.html                        Static Anna view shell
|   |-- app.js                            Runtime adapter, state, UI orchestration, fallback analyzer
|   |-- style.css                         Hallmark-guided UI system
|   |-- tokens.css                        Shared design tokens
|   |-- anna-tool-ids.js                  Dev/prod tool-id indirection
|   `-- icon.svg
|-- executas/scamshield-analyzer/
|   |-- executa.json                      Bundled Python Executa manifest
|   |-- pyproject.toml
|   `-- scamshield_analyzer.py            JSON-RPC 2.0 over stdio fraud analyzer
|-- tests/
|   |-- bundle/static.test.js             Static contract tests
|   |-- plugin/test_scamshield_analyzer.py
|   `-- e2e/scamshield.spec.js            Playwright browser QA
|-- fixtures/happy-path.jsonl             anna-app fixture verification
`-- .github/workflows/                    CI and manual Anna publish workflows
```

## Local Development

Install dependencies:

```powershell
npm install
```

Run the Anna dev harness without hosted LLM:

```powershell
npm run dev
```

Run with Anna-hosted LLM synthesis:

```powershell
npm run dev:llm
```

Open the app at the URL printed by `anna-app dev`.

## Verification

Run the full local gate:

```powershell
npm run test
npm run fixture:verify
npm run validate
npm run test:e2e
```

What those cover:

- `npm run test`: bundle contract tests plus Python Executa unit tests.
- `npm run fixture:verify`: Anna fixture replay.
- `npm run validate`: strict Anna app schema validation.
- `npm run test:e2e`: browser investigation flow, PDF generation, save history, keyboard tabs, image upload limits, and responsive overflow checks.

## Anna Deployment

Production publish depends on GitHub Release binaries for the bundled Executa. The release workflow `.github/workflows/build-release.yml` builds and attaches the four assets referenced by `executas/scamshield-analyzer/executa.json` under tag `scamshield-analyzer-v0.1.1`. The current Anna app bundle version is `0.1.3`.

Push and cut through Anna only after local gates pass:

```powershell
$ANNA_HOST = "https://anna.partners"
npm run test
npm run fixture:verify
npm run validate
npm run test:e2e
anna-app apps push --account $ANNA_HOST --json
anna-app apps cut 0.1.3 --account $ANNA_HOST --json
anna-app apps status scamshield-ai --account $ANNA_HOST --json
```

Release is intentionally separate:

```powershell
anna-app apps release 0.1.3 --account $ANNA_HOST --json
```

The GitHub Actions workflow `.github/workflows/anna-app-publish.yml` can run the same gate and then perform `push`, `cut`, or `release` when `ANNA_APP_PAT` is configured as a repository secret.

## Privacy

ScamShield does not ask for provider API keys. The bundled Executa performs deterministic local analysis, and Anna-owned host APIs provide tools, storage, chat, and LLM calls according to the app manifest. The app stores only compact investigation summaries for history.

## Safety Scope

ScamShield is a decision-support tool, not a law-enforcement or financial authority. It reports evidence patterns and conservative next actions. When evidence is incomplete, it should say what is missing instead of inventing domain age, report counts, breach data, or official claims.
