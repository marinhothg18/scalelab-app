# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running locally

```bash
npm install
npm run dev     # = node server.js (PORT defaults to 3001)
```

Open `http://localhost:3001/` to load the app. There's no build step, no test suite, and no linter — it's a two-file project.

Production runs on Railway. Code/comments/UI are in pt-BR; keep new work in pt-BR unless asked otherwise.

### Environment variables

- `PORT` — HTTP port (default 3001)
- `GITHUB_BACKUP_TOKEN`, `GITHUB_BACKUP_REPO` — optional, enables daily off-site backup of `db.json` to a GitHub repo (`owner/repo`, PAT with `repo` scope)
- When `/data` exists (Railway volume), `DATA_DIR = /data` and that's where `db.json` + `backups/` live. Locally they live next to `server.js`.

## Architecture

Only two source files matter:

- **`server.js`** (~2,250 lines) — single Express app. Everything is here: auth, sync endpoints, public API v1, cron jobs, WhatsApp bot, backups.
- **`public/ScaleLab.html`** (~15,000 lines) — single-file SPA (HTML + inline CSS + inline JS). Uses `localStorage` as its primary store and Chart.js from CDN. No framework, no bundler.

### Data model

`db.json` is the database. Schema:

```
{
  "store":      { <key>: <array-of-objects-with-id> | <object> },
  "timestamps": { <key>: <unix-seconds> },    // bumped on every write
  "api_tokens": [...],  "api_logs": [...],  "sessions": [...]
}
```

Keys in `store` are e.g. `tasks`, `criativos`, `sl_usuarios`, `sl_notifs`, `sl_lixeira`, `sl_auditlog`, `roi_ofertas`, etc. The full canonical list of synced keys is `SYNC_KEYS` in ScaleLab.html (~line 3420) — add new keys there if they must sync, otherwise the frontend won't pull them.

### Sync protocol (frontend ↔ server)

The SPA writes to `localStorage` first, then pushes to the server. Sync endpoints:

- `GET /api/store` — full pull (used on boot / `forceSyncAll`)
- `GET /api/updates/:since` — incremental pull, returns keys whose `timestamps[key] > since`
- `PUT /api/store/:key` — push an array or object for one key

`PUT /api/store/:key` does **conservative merge-by-id** via `_mergeArrayById`:

- Items in the server but not in incoming are **always preserved** (no delete-inference)
- Concurrent creates are union-added
- Per-item last-write-wins on `_updatedAt`

**Deletes do not go through `/api/store`.** They go through `POST /api/lixeira/soft-delete` which removes the item and puts a copy into `sl_lixeira` (the trash, 30-day TTL, cleaned by a cron). `/api/lixeira/restore/:id` and `DELETE /api/lixeira/:id` complete the cycle. When adding a delete flow, always use this path — editing `_mergeArrayById` to infer deletes will silently corrupt data for any offline/slow client.

### Auth

Two layers with different audiences:

1. **User sessions** (for the SPA) — `POST /api/auth/login` with email+password returns a Bearer token. Sessions are stored as `sha256(token)` in `db.sessions`, TTL = 30 days of inactivity (`lastActivity` bumped on every `authDiretoria` / `/api/auth/me` hit). `authDiretoria` middleware protects Diretoria-only endpoints (backup, audit log, forcing lembretes/relatórios). It also still accepts legacy `x-user-email`/`x-user-senha` headers during transition.

2. **External API tokens** (for agents / integrations) — issued via `POST /api/tokens/generate` (returned **once**, then only the `sha256` hash is kept). Used by `/api/v1/*` routes via `authAPI` middleware. Rate-limited at 60 req/min.

Passwords: bcrypt at rest. Legacy `senha` (plaintext) is migrated on first login or on server boot via `_migrarSenhasParaHash`. `_stripSenhas` strips both `senha` and `senhaHash` from every user response. Keep this — never send either field to clients.

### Roles

Stored on `sl_usuarios[].cargo`. Known values: `Diretoria`, `Gestor de Tráfego`, `Copy`, `Editor`, `Infra`, `Spy`. Only `Diretoria` passes `authDiretoria`.

### In-process cron jobs (all `setInterval` in `server.js`)

Everything runs inside the single Node process — no external scheduler. If you add a long-running task, respect this model:

- `_lembretesRodar` — every 15min. Generates notifications for demandas (24h/6h/2h/30min/vencendo, atrasadas, rituais do dia, backlog 3d/7d). Dedup-keyed per day per rule per target. Also fires WhatsApp when `_notificarViaWhatsApp` is wired.
- `_gerarRelatorioSemanal` — hourly check, fires only on configured weekday+hour (default Fri 18h). Writes to `sl_relatorios_semanais`, notifies destinatários, sends WhatsApp summary.
- `_gerarRelatorioDiario` — hourly check, fires at configured hour (default 18h). Sends daily summary via WhatsApp + internal notif.
- `criarSnapshotBackup('auto')` — every 1h, local snapshot into `backups/`.
- `_aplicarRetencaoBackup` — Time Machine retention: hourly for 48h, daily for 90d, weekly for 52w, monthly forever. `pre-restore` and `manual` snapshots are always kept.
- `_tickBackupRemoto` — hourly check, pushes gzipped `db.json` to GitHub every ~24h if configured.
- `_limparAuditoriaAntiga` — 2x/day, drops audit entries older than 90 days.
- `_pruneSessoesExpiradas` — hourly, drops expired sessions.
- `_limparLixeiraAntiga` — every 6h, purges trash items older than 30 days.

### WhatsApp + IA agent

Configured via `sl_whatsapp_config` in `db.store`: `zapi_instance`, `zapi_token`, `zapi_client_token`, `ai_provider` (`claude` | `openai`), `ai_key`, `ativo`.

Inbound: `POST /api/whatsapp/webhook` (Z-API pushes here). Looks up user by `whatsapp` field on `sl_usuarios`, then either runs Claude (tool use) or OpenAI (plain completion) or falls back to simple keyword matching (`tarefas`, `relatorio`).

The Claude agent has 4 tools defined in `_agentTools()`: `listar_tarefas`, `criar_demanda`, `resumo_roi`, `itens_em_risco`. Model is currently pinned to `claude-sonnet-4-20250514` in `_chamarClaude`. If updating model IDs, update that string. See [Anthropic messages API](https://docs.anthropic.com/en/api/messages) — the handler already implements multi-round tool_use.

Outbound: `sendWhatsAppMessage(phone, msg)` + `_notificarViaWhatsApp(destId, titulo, texto)`. Fire-and-forget; errors are logged, never thrown back into the request that triggered them.

### Backups

Two independent layers, both triggered automatically:

1. **Local** — `backups/*.json`, Time Machine retention (see above). Filename stamp format: `db-YYYYMMDD-HHMMSS-<motivo>.json`. Diretoria can list/download/restore via `/api/backup/*`.
2. **Remote GitHub** — daily push of gzipped db to configured repo under `backups/YYYY/MM/db-<stamp>.json.gz`. Uses GitHub contents API; reuses SHA when updating same-day file.

Restore is destructive but always snapshots `pre-restore` first. Require body `confirmar: "SIM_SUBSTITUIR_BANCO"`.

## Conventions to respect

- **Portuguese everywhere.** Route paths, log messages, UI strings, audit `action` keys, dedup keys, commit messages — all pt-BR. Match existing style; don't anglicize.
- **Never touch `db.json` directly from code.** Always go through `readDB()` / `writeDB(db)`. These read the *whole* file, mutate in memory, then write the whole file. There's no partial update. Hold writes to one batch per handler when possible to avoid races.
- **Never delete via `/api/store/:key` PUT.** Use the lixeira flow. See "Sync protocol" above.
- **Audit sensitive actions** via `audit(db, action, target, meta, userInfo)` — `authDiretoria` routes, deletes, restores, logins, token ops all do this. Follow the pattern when adding new admin actions. Retention is 90 days; hard cap 10k entries.
- **Rate limits are already wired** globally (`/api/` 200/min, `/api/v1/` 60/min, `/api/auth/login` 5 per 10min per IP). Don't bypass — if a legitimate use case needs more, adjust the limiter, don't work around it.
- **`cur` global** in the SPA tracks current page. `goTo(id)` handles navigation + calls the right `render<Name>()`. When adding a new page, wire it into `goTo` and add a render function; also hook the real-time path in `syncFromServer` if the page should live-update.

