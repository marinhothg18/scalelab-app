# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## REGRA Nº 1: responder sempre em português

**Toda mensagem para o Thiago é em português do Brasil. Sem exceção.**

- Isso vale para respostas curtas ("já subiu?"), passo a passo, resumos e explicações técnicas.
- Vale também depois de avisos do sistema, logs ou ferramentas em inglês: o idioma da resposta não muda.
- Antes de enviar, confira se o texto inteiro está em português.
- Ele já teve que pedir "manda em português" várias vezes em 22/10/2026.

## Sincronização entre máquinas (LEIA ANTES DE MEXER)

O projeto roda em **dois Macs** e o GitHub é a fonte de verdade:
`https://github.com/marinhothg18/scalelab-app`

**Regras, nesta ordem:**

1. **Sempre `git pull` antes de começar qualquer trabalho.** Não pergunte, apenas
   faça. A outra máquina pode ter avançado. Se houver conflito, resolva antes de
   escrever qualquer código novo.
2. **Todo commit sobe sozinho.** Existe um hook em `.githooks/post-commit` que dá
   push automático. Não é preciso lembrar de empurrar.
3. **Commit com JavaScript quebrado é recusado.** O hook `.githooks/pre-commit`
   roda `node .githooks/checar-js.js`, que valida `server.js` e o JS embutido em
   todo `public/*.html`. Foi criado depois de duas versões quebradas irem ao ar em
   14/08 (um `<style>` dentro do `<script>` e uma variável que apagou a função
   `atras`). Pra rodar à mão a qualquer momento: `node .githooks/checar-js.js`.
4. **Numa máquina nova**, rodar uma vez: `git config core.hooksPath .githooks`
   (sem isso o push automático não acontece ali).
5. `git push` sincroniza as máquinas; **`railway up` é o que publica no ar.** São
   coisas separadas — commitar não coloca em produção.

Nunca mova ou copie a pasta do projeto pelo Finder com trabalho em andamento: foi
assim que o `.git` quebrou em 14/08 e nasceu uma pasta `scalelab 2` pela metade.

## Running locally

```bash
npm install
npm run dev     # = node server.js (PORT defaults to 3001)
```

Open `http://localhost:3001/` to load the app. There's no build step and no linter. The only tests cover the AD range rules in `public/arq-faixa.js` (`npm test`); that file is shared by the SPA and `server.js`.

Production runs on Railway. Code/comments/UI are in pt-BR; keep new work in pt-BR unless asked otherwise.

### Environment variables

- `PORT` — HTTP port (default 3001)
- `GITHUB_BACKUP_TOKEN`, `GITHUB_BACKUP_REPO` — optional, enables daily off-site backup of `db.json` to a GitHub repo (`owner/repo`, PAT with `repo` scope)
- When `/data` exists (Railway volume), `DATA_DIR = /data` and that's where `db.json` + `backups/` live. Locally they live next to `server.js`.

## Architecture

Only two source files matter:

- **`server.js`** (~2,250 lines) — single Express app. Everything is here: auth, sync endpoints, public API v1, cron jobs, WhatsApp bot, backups.
- **`public/ScaleLab.html`** (~15,000 lines) — single-file SPA (HTML + inline CSS + inline JS). Uses `localStorage` as its primary store and Chart.js from CDN. No framework, no bundler.

### Multiempresa: portaria e um motor por empresa (ramo claude/multiempresa, 07/11/2026)

`server.js` roda de dois jeitos:

- **Sem `TMX_EMPRESA`**: é a TMX (empresa nº 1, dados em `/data`, código `tmx`) e também a
  **portaria**. Ela liga um processo filho (motor) por empresa e entrega a cada um os pedidos dele.
- **Com `TMX_EMPRESA=<código>`**: é o **motor** daquela empresa, com banco, SQLite, rotinas e
  memória próprios em `TMX_DATA_DIR` (`/data/empresas/<código>/`). Ouve só em 127.0.0.1.

Como a portaria (`_portaria`, registrada antes de tudo) decide de quem é o pedido: prefixo
`/e/<código>/...` (pixel, webhook, WhatsApp, quiz, links, páginas públicas) → sessão
`ses_<código>.…` → e-mail no login/esqueci (índice `contas` em `/data/plataforma.sqlite`) → senão
TMX, como antes. Sem nenhuma empresa cadastrada a portaria não faz nada. Código de empresa
inexistente é recusado, nunca cai na TMX.

Regras:
- **Nunca** ler `db.json` na portaria a cada pedido; a lista de empresas fica em memória.
- Rotina, migração ou importação que é só da TMX leva `if (!SOU_TMX) return;`.
- Link público montado no servidor usa `BASE_PUBLICA` (`''` na TMX, `/e/<código>` num motor);
  no app, `urlPublica(caminho)`.
- O motor nasce sem as chaves da TMX no Railway (`_envMotor` é uma lista branca).
- Empresa de teste: `POST /api/plataforma/empresas` (só Diretoria da TMX). Cadastro público
  continua fechado.
- O app (`_empresaDoLogin`) apaga a cópia local quando o aparelho troca de empresa.
- Fora da TMX, Meu Protocolo e os 5 módulos de `MODULOS_ARQUIVAVEIS` (IA, Educacional, Infra,
  Ajuda, Tour) não existem: `_modulosArquivados()` devolve todos, e em Configurações as seções com
  `soTmx` (Módulos arquivados, Hospedagem) somem. Páginas também fica só na TMX.
- **MCP e API v1 por empresa** (07/11): `/e/<código>/mcp?token=…` e `/e/<código>/api/v1/...` chegam ao
  motor da empresa. A Diretoria dela gera, lista e revoga os tokens (`authTokensApi`: na TMX continua
  `authDiretoriaInterna`); o token fica no `db.api_tokens` do motor, só o sha256, e não abre outra empresa
  nem a TMX. A sessão de suporte da TMX não gera nem revoga token. Ferramenta do MCP com `soTmx` fica só na
  TMX (hoje nenhuma); `MCP_TEXTOS_EMPRESA` troca os exemplos com nome de projeto da TMX. Na API v1 da
  empresa, `/dados/:chave` não devolve `CHAVES_SO_TMX` nem `KEYS_SERVIDOR`; senha não sai em lugar nenhum.
  Empresa bloqueada perde MCP e API junto com o app (`_RE_API_EMPRESA` na portaria). Configurações ›
  Conexões › Acesso por API mostra o endereço com `urlPublica('/mcp')` e o passo a passo do Claude.
  `test/mcp-empresa.test.js`.
- `test/multiempresa.test.js` sobe TMX + 2 empresas numa pasta temporária e prova o isolamento.
- **Cadastro do cliente por convite** (`/cadastro?c=cv_…`, `public/cadastro.html`): a Diretoria da TMX gera o
  link em `POST /api/plataforma/convites` (vale uma vez, vence em 7 dias, só o hash fica em `convites` no
  `plataforma.sqlite`). `POST /api/cadastro` cria a empresa e manda o motor fazer `_cadastroInicial`: conta
  Diretoria com WhatsApp, `cfg.projeto` = nome da empresa, nichos em `sl_nichos` e projetos em `sl_ofertas_v2`,
  e já devolve a sessão. Meta, checkout e pixel ficam pra aba Integrações de cada projeto. `test/cadastro.test.js`.
- **Central TMX Admin** (`/admin`, `public/admin.html`): sistema à parte, só pra Diretoria da TMX, com o mesmo
  login do TMX. Primeira parte: Clientes (registro da plataforma) e Convites (gerar, copiar, mandar no WhatsApp,
  cancelar), Suporte (chamados), bloquear/desbloquear e entrar como suporte.
- **Bloquear** (`empresas.status='bloqueada'`): a portaria recusa sessão da equipe e login com 403 +
  `X-TMX-Bloqueada` (o app mostra "conta suspensa"), mas o endereço `/e/<código>` sem sessão (pixel, webhook,
  quiz, links) continua, pra nada se perder. A sessão de suporte (`ses_<código>.sup…`) entra mesmo bloqueada.
- **Entrar como suporte**: `POST /api/plataforma/empresas/:id/suporte` (motivo obrigatório, 15/30/60 min, modo
  `olhar` ou `mexer`, avisa a Diretoria do cliente). O motor cria a sessão com a pessoa dentro dela
  (`_usuarioDaSessao`: não entra ninguém na equipe do cliente). No "só olhar" a trava em memória do motor
  recusa toda escrita (403 + `X-TMX-So-Olhar`); suporte nunca mexe em `/api/me`. A Central guarda a conta da
  TMX do aparelho (`sl_tmx_token_guardado`) e "Sair do suporte" devolve. Uma aba que vê a empresa do
  aparelho mudar (outra aba) recarrega antes de mandar qualquer coisa (`_empresaDaAba`).
- **Painel da Central (v3, 07/11)**: `GET /api/plataforma/painel` (só Diretoria da TMX) junta tudo num pedido: cada motor
  manda `_resumoDaEmpresa()` pelo comando `resumo` (só contagens: uso do plano, itens mexidos em 30 dias por módulo, vendas
  por semana, nomes dos projetos, memória, tamanho do banco, última cópia), mais receita (tabela `assinaturas`), chamados e
  saúde (memória, disco, quedas por motor em `m.quedasEm`, erros de `console.error` agrupados em `_errosRecentes`, só na
  memória e só desde que o servidor subiu). Guarda 60 s (`?novo=1` refaz). `public/admin.html` tem Painel, Clientes (com
  ficha), Uso e oportunidades, Receita, Cobrança e checkout, Pedidos, Convites, Suporte, Saúde e Auditoria.
  `test/central-painel.test.js`.
- **Chamados**: moram no `plataforma.sqlite` (`chamados`, `chamado_msgs`). O cliente abre pelo item Suporte do
  TMX dele (`/api/suporte/chamados*` no motor, que repassa com `_pedirAPortaria`; a empresa é sempre a do
  motor). A TMX responde em `/api/plataforma/chamados/:id/responder` (nota interna não vai pro cliente) e o
  cliente recebe no sininho. `test/admin-suporte.test.js`.
- **Primeiros passos** (07/11): tela `primeiros` do app, só pra Diretoria de empresa cliente. Abre sozinha só no
  primeiro login (`ppIniciar`, depois do login e do `restoreSession`) e fica no topo do menu com quantos passos faltam
  até tudo estar ligado: Meta, Utmify (opcional), checkout, produtos, contas e pixel de cada projeto, primeira venda.
  Cada passo chama as rotas que já existiam (`/api/meta/conexao`, `/api/integracoes/utmify-mcp/config`,
  `/api/integracoes/vendas/gerar-token`, `/api/produtos`). `GET/POST /api/primeiros-passos` só lê o que existe e guarda
  `vistoEm` e os passos pulados (`sl_primeiros_passos`, em `KEYS_SERVIDOR`); a sessão de suporte não marca como visto.
  Na aba Integrações do projeto, "Conectar a Meta", "Usar a Utmify" e "Ligar o checkout" abrem o passo (`ppIrPasso`;
  na TMX, a conexão em Configurações). `test/primeiros-passos.test.js`.
- **Meu plano** (Configurações › Meu plano, só Diretoria): `GET /api/meu-plano` mostra o plano da empresa (do
  registro, via `_pedirAPortaria('meu-plano')`; a TMX é `interno`) e o uso de cada limite (`_usoDoPlano`, com os
  dados da própria empresa). Os planos e limites ficam só em `PLANOS_TMX` no server.js, a lista única (preços
  da Malva, decididos em 07/11; anual = 10× o mensal). Nada trava por limite ainda. Trocar de plano: a Central muda em Clientes
  (`POST /api/plataforma/empresas/:id/plano`); o cliente pede pelo Suporte. `test/meu-plano.test.js`.

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

The trash belongs to the server (07/11/2026): `PUT /api/store/sl_lixeira` is refused with 403. Restore writes the item straight back into its key and skips the `/api/store` guards, so soft-delete, restore and purge of items from `sl_usuarios`, `sl_permissoes_roles`, `KEYS_DIRETORIA`, `KEYS_SERVIDOR` or `KEYS_PLATAFORMA` are Diretoria-only; other items follow the caller's role via `_podeChave` (`_podeLixeira`). Before this, anyone on the team could plant a Diretoria account in the trash and restore it. `sl_lixeira` reaches each client through `_lixeiraParaQuemPede`: secret keys never, other items by the caller's role, and a trashed account never with its password.

### Auth

Two layers with different audiences:

1. **User sessions** (for the SPA) — `POST /api/auth/login` with email+password returns a Bearer token. Sessions are stored as `sha256(token)` in `db.sessions`, TTL = 30 days of inactivity (`lastActivity` bumped on every `authDiretoria` / `/api/auth/me` hit). `authDiretoria` middleware protects Diretoria-only endpoints (backup, audit log, forcing lembretes/relatórios). The legacy `x-user-email`/`x-user-senha` headers were removed on 05/11/2026: only sessions authenticate. A session only works on the tenant of its own user: `validarSessao(db, token, req.tenantId)` and `authUsuario`/`authDiretoria` check it (a global middleware that re-read db.json per request made production crawl; never add one). Public signup (`/api/saas/signup`) is closed unless `CADASTRO_PUBLICO=1`. API tokens (`/api/tokens/*`) use `authTokensApi`: on the TMX it is `authDiretoriaInterna`; in a company motor it is that company's Diretoria, and the token only reads that company's MCP and `/api/v1` (see "MCP e API v1 por empresa"). Outside Diretoria, `PUT /api/store/sl_usuarios` only changes the caller's own record and never `cargo`/`senha`/`email`/`ativo`/`tenant_id`.

2. **External API tokens** (for agents / integrations) — issued via `POST /api/tokens/generate` (returned **once**, then only the `sha256` hash is kept). Used by `/api/v1/*` routes via `authAPI` middleware. Rate-limited at 60 req/min. `/api/v1/dados/:chave` never returns `KEYS_SERVIDOR`, `CHAVES_CREDENCIAL` (Z-API/IA key, Utmify token) or any password field (`CAMPOS_SENHA`), on the TMX too since 07/11/2026. The Central's `cd_*` keys are in `KEYS_DIRETORIA`.

Passwords: bcrypt at rest. Legacy `senha` (plaintext) is migrated on first login or on server boot via `_migrarSenhasParaHash`. `_stripSenhas` strips both `senha` and `senhaHash` from every user response. Keep this — never send either field to clients.

### Roles

Stored on `sl_usuarios[].cargo`. Known values: `Diretoria`, `Gestor de Tráfego`, `Copy`, `Editor`, `Infra`, `Spy`. Only `Diretoria` passes `authDiretoria`.

**O que cada cargo vê (decisão do Thiago, 07/11/2026)** — regra única em `_podeVerPagina` (ScaleLab.html), usada pelo menu e pelo `goTo`; o servidor confere as chaves restritas em `_podeChave` (server.js):
- `Diretoria` aparece como **Dono** na tela (`_nomeCargo`; por dentro continua `Diretoria`): vê tudo.
- `Sócio`: tudo menos Financeiro e Configurações; vê Gestão e RH (lê e grava as chaves `sl_rh_*` e `sl_candidatos`).
- `Gestor de Tráfego`: Demandas, Criativos, Rituais, Arquivos por projeto, Tráfego, Análise de tráfego e Projetos.
- `Copy`: Demandas, Criativos, Rituais, Arquivos por projeto e Projetos.
- `Editor`: Demandas, Criativos, Arquivos por projeto, e Rituais só se estiver em algum ritual.
- Todos: Dashboard, Chat, Ad Library e Notificações. Rituais de quem não é gestor mostram só aqueles em que a pessoa participa.
- Meu Protocolo: só a conta do Thiago (`PROTOCOLO_DONO_EMAIL`), só na TMX.
- Ainda não travado no servidor: as rotas de Tráfego/Análise (`/api/metricas/*` etc.) respondem a qualquer pessoa logada; o menu e a navegação é que escondem.

### Auditoria IA (botão na Análise de tráfego, 08/11/2026)

Entrega o relatório de fechamento do dia no padrão da skill `trafego` (metas, decisões cópia por cópia, funil, contas, anúncio por anúncio em hoje/3/7 dias, histórico, BIDCAP, testes, duplicação, prioridades). É sempre de um projeto só.

- `_audJuntarDados` (server.js) soma tudo antes: Utmify um dia por chamada nos níveis `ad` e `campaign` (vários dias costumam dar erro), vendas TMX por anúncio (`_anunciosComTmx`, dia a dia), VSLs com tráfego do projeto (ligadas pelos anúncios no `utm_content`), metas. O Claude recebe tabelas prontas, decide pelas regras em `AUD_SISTEMA` e devolve `{manchete, markdown, acoes}`. Mudou a regra de decisão da skill, muda em `AUD_SISTEMA`.
- `POST /api/ia/auditoria` devolve um id; a tela pergunta `GET /api/ia/auditoria/:id` até `pronta`. Fica em `ia_auditorias` (SQLite do motor). A próxima rodada recebe as `acoes` da anterior pra cobrar.
- Metas por projeto em `sl_auditoria_metas` (`/api/ia/auditoria-metas`). Valores em R$ das regras escalam por CPA meta ÷ 350. Sem meta, a régua é o CPA de equilíbrio de 7 dias.
- Modelo `claude-opus-5-5`, chave `_getAIKey()`. `fallbacks: 'default'` deixa a API tentar outro modelo se um filtro recusar. `test/auditoria.test.js` usa Utmify e Anthropic falsas (`TMX_UTMIFY_URL`, `ANTHROPIC_BASE_URL`).

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
- **No native `alert()`/`confirm()`/`prompt()` in the SPA.** They show up stuck at the top with "app.centraltmx.com diz". Use `await tmxConfirmar(msg)` / `await tmxPerguntar(msg, padrao)` (the function must be `async`) and `tmxAviso(msg)`; `window.alert` is routed to `tmxAviso` but doesn't block, so if something must wait for the OK (e.g. warn then log out), use `tmxAviso(msg).then(...)`. The first paragraph of the message becomes the title. Pop-ups open in the middle of the screen: an overlay that scrolls keeps `align-items:flex-start` and gives the card `margin:auto` (07/11/2026).
- **`cur` global** in the SPA tracks current page. `goTo(id)` handles navigation + calls the right `render<Name>()`. When adding a new page, wire it into `goTo` and add a render function; also hook the real-time path in `syncFromServer` if the page should live-update.

## Nomenclatura & identidade

Muitos nomes aparecem na conversa com o usuário — todos apontam para **este mesmo projeto**:

- **Axcend** — nome da marca/produto atual (o que aparece na UI)
- **ScaleLab** — nome antigo. Ainda presente em `public/ScaleLab.html` e em todas as chaves `sl_*` do storage. **Não renomear** — quebraria dados em produção. Migração é apenas visual.
- **Centralaxcend** — nome que aparece em conversas antigas. **Não é um domínio que responde.**

**Domínios que o serviço realmente atende** (confira com `railway domain` antes de usar em
integração, link de anúncio ou conector MCP — este documento já esteve errado nesse ponto e
custou uma tentativa de conexão falhada):

```
app.centraltmx.com
ir.kalebeaprovado.online
scalelab-web-production.up.railway.app
```
- **scalelab** / **scalelab-app** / **scalelab-web** — nome do repositório GitHub e do service Railway. Mesmo código.

Resumo: se o usuário mencionar qualquer um desses nomes, ele está falando deste repositório. Não é preciso clonar outro projeto nem procurar em outro lugar.

Paleta de cores (identidade visual definida — não alterar sem permissão):
- Roxo `#3E1493` · Azul `#1B9CFA` · Rosa `#C52C58` · Laranja `#FF5926` · Azul profundo `#2509E4`

## Deployment ops

Railway **não está conectado ao GitHub** para auto-deploy. `git push` NÃO dispara build. Deploys acontecem via CLI:

```bash
railway up --detach        # sobe a pasta atual como nova versão
railway status             # confirma projeto/env/service linkados (joyful-celebration / production / scalelab-web)
railway logs               # logs em tempo real
```

**Subindo de um worktree (`.claude/worktrees/...`): passe o caminho.** O `railway up` procura o projeto ligado
subindo as pastas e envia a pasta principal (`~/Projetos/scalelab`), não o worktree. Em 07/11/2026 isso pôs no ar
uma versão 25 commits atrás (sem a correção da lixeira, os cargos e o resto) achando que era a nova. No worktree:

```bash
railway up "$PWD" --path-as-root --detach
```

Depois de subir, confira no ar que o arquivo novo chegou (ex.: o `/ScaleLab.html` tem o código que você mudou);
"SUCCESS" no `railway deployment list` só diz que a versão subiu, não qual pasta foi.

O `.railwayignore` define o que sobe. O `public/ScaleLab.html` é o arquivo servido — edite-o, não duplicatas em outros lugares.

## Workflow multi-máquina

O usuário opera este projeto em 2 Macs (Mac mini + MacBook M4). Ambos têm o repo clonado em `~/Desktop/scalelab`. Regra obrigatória:

**Antes de começar a editar em qualquer sessão, rode `git pull`.** Se não fizer, o `git push` no final vai falhar com "fetch first" ou dar conflito de merge. Se você receber esse erro, é sinal de que a outra máquina commitou algo novo — faça `git pull --rebase` e repita o push.

Se houver conflito de merge em arquivos textuais (ex: `CLAUDE.md`), resolva preservando o que for mais informativo/recente. Não reverta trabalho da outra máquina sem confirmar com o usuário.

## Perguntar ao usuário antes de

- Deletar/restaurar dados em produção
- Mudar regras de cron (lembretes, relatórios, backup) — risco de spam/perda
- Alterar autenticação/permissões
- Renomear chaves do storage (`sl_*`, `roi_ofertas`, etc.)
- Mexer na paleta de cores ou no logo
- Fazer qualquer coisa que afete usuários que não sejam o Thiago

