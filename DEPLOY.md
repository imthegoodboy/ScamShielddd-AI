# ScamShield AI deployment

ScamShield AI is an Anna App with one bundled Python Executa.

## Local gates

```powershell
npm install
npm test
npm run validate
npm run test:e2e
```

Run the Anna harness:

```powershell
anna-app dev --port 5184 --no-llm
```

Run with Anna-hosted LLM synthesis:

```powershell
anna-app dev --port 5184 --llm-account https://anna.partners
```

## Push and cut

The bundled Executa must have public release assets before `apps push`.
The GitHub workflow `.github/workflows/build-release.yml` builds:

- `tool-test-scamshield-analyzer-12345678-darwin-arm64.tar.gz`
- `tool-test-scamshield-analyzer-12345678-darwin-x86_64.tar.gz`
- `tool-test-scamshield-analyzer-12345678-linux-x86_64.tar.gz`

Create or dispatch the release tag `scamshield-analyzer-v0.1.0` first.

Use production unless intentionally testing staging:

```powershell
$ANNA_HOST = "https://anna.partners"
npm test
npm run validate
npm run test:e2e
anna-app apps push --account $ANNA_HOST --json
anna-app apps cut 0.1.2 --account $ANNA_HOST --json
anna-app apps status scamshield-ai --account $ANNA_HOST --json
```

Release only after explicit approval:

```powershell
anna-app apps release 0.1.2 --account $ANNA_HOST --json
```

## Runtime notes

- `manifest.json` uses `bundled:scamshield-analyzer`; production tool IDs are resolved through `bundle/anna-tool-ids.js`.
- The bundled Executa uses the `binary` distribution profile with `package_name` set, so user installs do not depend on a local Python or `uv` environment.
- The UI works in standalone preview with a browser-side deterministic fallback.
- In Anna, the bundled Executa is the authoritative evidence engine and Anna `llm.complete` is an optional second-pass investigator narrative.
- History is compact and bounded to avoid Anna storage value limits.
