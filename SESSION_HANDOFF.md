# Session Handoff - Safeguard LLM Restore

Date: 2026-07-07

## Current Working App

The functional app is now in:

`/Users/nate/Documents/Safeguard LLM`

Use this folder going forward. The old folder below was left untouched after recovery work:

`/Users/nate/Documents/Counter-Spy Claude.ai`

That old folder is confusing because its checked-out Git branch is `github-example`, which is the MLSECDEVOPS migration/removal branch. It tracks almost no Counter-Spy app source, while the directory still contains ignored/untracked leftovers from older app builds. That is why the app appeared partly present but Git/npm state did not line up.

## Why This Happened

`Counter-Spy Claude.ai` was on branch `github-example` at commit `1175447`, whose purpose was to remove/migrate the MLSECDEVOPS pipeline material into its own repository.

The actual Counter-Spy application source is on GitHub remote:

`origin = https://github.com/Nate-Carroll-Cyber/Counter-Spy.ai.git`

A second remote named `github` in the old folder points to the separate MLSECDEVOPS repository:

`https://github.com/Nate-Carroll-Cyber/mlsecdevops-pipeline-example.git`

That second remote is not the app repo.

## Clean Checkout Created

A fresh clone of the app was created here:

`/Users/nate/Documents/Safeguard LLM`

Branch/state:

- Branch: `main`
- Remote: `origin/main`
- App source is present and tracked normally.

## 2026-07-07 Rebrand / Remote Update

Current authoritative repo path:

`/Users/nate/Documents/Safeguard LLM`

The application/product name has been rebranded from `Counter-Spy.ai` to `Safeguard LLM` in current user-facing source, metadata, and primary markdown documentation. Historical handoff notes may still reference old paths or repository names for provenance. A local verification search should distinguish those historical references from current product-facing docs for:

- `Counter-Spy.ai`
- `Counter-Spy`
- `Counter Spy`
- `CounterSpy`

The Git remote was updated after the GitHub repo rename:

```sh
origin  https://github.com/Nate-Carroll-Cyber/Safeguard-LLM.git (fetch)
origin  https://github.com/Nate-Carroll-Cyber/Safeguard-LLM.git (push)
```

Important caveats:

- The original shield/logo image files were intentionally left as-is at their existing paths, per user instruction.
- Lowercase/internal compatibility identifiers such as `counter-spy-backend`, `counter-spy-postgres`, `counter_spy`, `x-counter-spy-user-id`, local storage keys, CloudFormation resource names, and the `COUNTERSPY_CANARY_TOKEN` canary remain unless the user approves a deeper runtime migration.
- Rebrand changes are local and uncommitted at this handoff.
- `package.json` and `package-lock.json` also have pre-existing dependency security changes from the earlier handoff state.
- `SESSION_HANDOFF.md` is still untracked unless explicitly staged/committed later.

Current local working tree summary after the rebrand pass:

- Branch: `main`
- Tracking: `origin/main`
- Modified files: 39
- Untracked files: `SESSION_HANDOFF.md`

## 2026-07-07 Documentation Accuracy Pass

The documentation discrepancy review was completed after the rebrand pass. `CLAUDE.md` was intentionally excluded because the user said it will be deleted.

Docs updated in this pass:

- Governance/runtime claims now match code: protected execution rejects browser-supplied safeguard endpoint/model overrides, but the allowlisted `safeguardEffectivePrompt` is forwarded verbatim and the optional browser-memory `safeguardApiKey` remains available for local LM Studio testing.
- Threshold docs now use the live values: suspicious entropy floor `> 3.8`, syntactic suspicious default `65`, adversarial syntactic cutoff `90`, and chunk-embedding review threshold `> 0.72`.
- `/v1/intercept` docs now include the authenticated `tuning` object accepted by the backend.
- `Technical/LOCAL_DEVELOPMENT.md` now documents Node `22.5+`, matching `INTERCEPT_BEARER_TOKEN` / `VITE_BACKEND_BEARER_TOKEN`, current seed metadata for `core-2026-05-10-latest`, and smoke-test caveats for safeguard availability.
- `File_Structure.md` now includes the backend tree, pgvector seed corpus, CloudFormation infra, compose files, and missing `src/lib` modules.
- `Technical/SBOM.md` now includes `react-dom`, `@vitejs/plugin-react`, `@tailwindcss/vite`, and the security `overrides` block for `hono`, `protobufjs`, and `esbuild`.
- Secondary cleanup removed or corrected stale docs for `react-markdown` / `rehype-raw`, EU AI Act client-side PII wording, invalid root ATLAS IDs, `PII_LEAK`, the removed `Hide Simulated` toggle, purple review styling, and the stale Technical handoff Counter-Spy path.

Verification performed:

- `git diff --check` passed.
- A targeted `rg` scan for the known discrepancy patterns found only benign section numbers, sample entropy values, historical handoff references, and the updated `react-markdown` wording.

Important caveat: the working tree already contained unrelated source/package/doc changes before this pass. Do not treat every modified file as part of the documentation cleanup. The doc-cleanup files touched intentionally were README/docs/handoff files only; no source-code behavior was changed for this pass.

## Running Services

At handoff time, both dev servers were running from `/Users/nate/Documents/Safeguard LLM`:

- Frontend: `http://localhost:3000/`
- Backend health: `http://127.0.0.1:18080/healthz`

Backend was started with `.env.demo.local` loaded:

```sh
cd "/Users/nate/Documents/Safeguard LLM"
set -a
source .env.demo.local
set +a
APP_PORT=18080 npm run backend:dev
```

Frontend was started with `.env.demo.local` loaded and pointed at the backend:

```sh
cd "/Users/nate/Documents/Safeguard LLM"
set -a
source .env.demo.local
set +a
VITE_API_BASE_URL=http://127.0.0.1:18080 npm run dev
```

If those processes are no longer running, restart them with the commands above.

## pgvector / Instruction Monitor

The old pgvector database was recovered. It was not lost.

Docker container:

`counter-spy-postgres`

Status at handoff:

- Running
- Healthy
- Published on `127.0.0.1:15432 -> 5432`

The container uses the persisted Docker volume:

`counter-spyclaudeai_counter_spy_postgres_data`

Database tables verified:

- `app_config`
- `audit_logs`
- `instruction_chunks`
- `instruction_records`
- `instruction_seed_imports`
- `kb_policies`
- `user_profiles`

Row counts verified:

- `instruction_records`: 319
- `instruction_chunks`: 611
- `instruction_seed_imports`: 1
- `audit_logs`: 0
- `app_config`: 1
- `kb_policies`: 0
- `user_profiles`: 1

Backend health after recovery showed:

```json
"instructionMonitor": {
  "provider": "postgres_pgvector",
  "enabled": true,
  "configured": true,
  "embeddingDimensions": 768,
  "embeddings": {
    "enabled": true,
    "configured": true,
    "source": "explicit",
    "baseUrl": "http://192.168.0.183:11434/v1/embeddings",
    "modelId": "nomic-embed-text",
    "maxChunks": 4
  }
}
```

To check the database later:

```sh
docker ps --filter name=counter-spy-postgres
docker exec counter-spy-postgres pg_isready -U counter_spy -d counter_spy
```

To inspect tables without exposing the password:

```sh
docker exec counter-spy-postgres sh -lc 'PGPASSWORD="$POSTGRES_PASSWORD" psql -U counter_spy -d counter_spy -c "select schemaname, tablename from pg_tables where schemaname not in ('"'"'pg_catalog'"'"','"'"'information_schema'"'"') order by schemaname, tablename;"'
```

## Env / Credentials State

The old local demo env file was copied into the new app folder:

`/Users/nate/Documents/Safeguard LLM/.env.demo.local`

Do not commit this file. It is gitignored and contains local credentials/secrets.

Keys present, values intentionally redacted here:

- `INTERCEPT_BEARER_TOKEN`
- `VITE_BACKEND_BEARER_TOKEN`
- `POSTGRES_PASSWORD`
- `INSTRUCTION_MONITOR_DATABASE_URL`
- `INSTRUCTION_MONITOR_EMBEDDING_DIMENSIONS`
- `INSTRUCTION_MONITOR_EMBEDDINGS_ENABLED`
- `INSTRUCTION_MONITOR_EMBEDDINGS_API_BASE_URL`
- `INSTRUCTION_MONITOR_EMBEDDINGS_MODEL_ID`
- `INSTRUCTION_MONITOR_EMBEDDINGS_MAX_CHUNKS`
- `LARA_ACCESS_KEY_ID`
- `LARA_ACCESS_KEY_SECRET`
- `LARA_API_BASE_URL`
- `INSTRUCTION_MONITOR_ENABLED=true`

The last flag was added during recovery because the old Docker compose file had enabled the instruction monitor through compose environment, not through the env file.

Backend health after env migration showed:

- Lara translation: configured
- Instruction Monitor pgvector: enabled and configured
- Embeddings: configured
- Safeguard provider env defaults: not configured
- Responder provider env defaults: not configured

The user clarified that Safeguard/Responder provider settings should still be configurable through the UI/session path. Do not assume missing backend env values are a bug by themselves.

## Dependency Security Fixes

In `/Users/nate/Documents/Safeguard LLM`, npm dependency vulnerabilities were fixed.

Files modified:

- `package.json`
- `package-lock.json`

Main explicit change:

```json
"overrides": {
  "hono": "^4.12.14",
  "protobufjs": "^7.5.5",
  "esbuild": "^0.28.1"
}
```

`npm audit fix` also updated lockfile transitive dependencies including Babel, Vite, form-data, Hono, protobufjs, qs, js-yaml, brace-expansion, esbuild, and related packages.

Current Git status in the clean folder should show only:

```text
 M package-lock.json
 M package.json
```

plus `.env.demo.local` and runtime artifacts ignored by Git.

## Verification Completed

All of these passed in `/Users/nate/Documents/Safeguard LLM`:

```sh
npm audit --json
npm run lint
npm run build
npm test
```

Results:

- `npm audit --json`: 0 vulnerabilities
- `npm run lint`: passed
- `npm run build`: passed
- `npm test`: 134 passed, 0 failed
- Frontend responded on `http://localhost:3000/`
- Backend responded on `http://127.0.0.1:18080/healthz`
- Postgres/pgvector container healthy
- Instruction monitor enabled/configured

## Old Folder Cleanup Already Done

In `/Users/nate/Documents/Counter-Spy Claude.ai`, the following cleanup was completed earlier in the session:

- Deleted `docs/gaips-materials/`
- Deleted `.env.gitlab.local`
- Deleted `SESSION_HANDOFF.md`
- Removed Git remote `gitlab`
- Deleted local GAIPS branches:
  - `gaips-full-surface-scan-image-pinning`
  - `gaips-pipeline-required-fixes`

A GitLab token had been present in `.env.gitlab.local`; it was deleted locally. It should be revoked/rotated if still valid.

## Important Security Note

The user pasted a temporary GitHub token in chat. It was not used in commands. It should be revoked after the session.

Do not print secrets from `.env.demo.local` in future handoffs or logs.

## Recommended Next Steps

1. Treat `/Users/nate/Documents/Safeguard LLM` as the active app folder.
2. Keep `/Users/nate/Documents/Counter-Spy Claude.ai` around temporarily until the user confirms nothing else is needed from it.
3. Verify in the UI that provider/runtime settings are still available and wired as expected.
4. If everything looks good, consider committing the dependency security changes on a new branch from `Safeguard LLM`.
5. Do not delete old Docker volumes until the user confirms the migrated pgvector data is no longer needed.

## Quick Restart Checklist

```sh
# Start pgvector DB if it is stopped
docker start counter-spy-postgres

# Terminal 1: backend
cd "/Users/nate/Documents/Safeguard LLM"
set -a
source .env.demo.local
set +a
APP_PORT=18080 npm run backend:dev

# Terminal 2: frontend
cd "/Users/nate/Documents/Safeguard LLM"
set -a
source .env.demo.local
set +a
VITE_API_BASE_URL=http://127.0.0.1:18080 npm run dev
```

Then open:

`http://localhost:3000/`
