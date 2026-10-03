const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

// ── CONSTANTES DE AUTH ──
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias de inatividade
const BCRYPT_ROUNDS = 10;

// ══════════════════════════════════════════════
// ── MULTI-TENANCY (PR 1: infraestrutura) ──
// Por enquanto TODO MUNDO é o tenant interno (axcend-interno). Nada filtra
// ainda — esse PR só cria a fundação. Os filtros vêm nos próximos PRs.
// ══════════════════════════════════════════════
const TENANT_INTERNO_ID = 'axcend-interno';
const TENANT_DEFAULT_ID = TENANT_INTERNO_ID;
// Hosts que sempre resolvem pro tenant interno (master + dev)
const HOSTS_INTERNO = new Set([
  'app.centralaxcend.com',
  'centralaxcend.com',
  'localhost:3001',
  'localhost:3000',
  '127.0.0.1:3001'
]);
// Domínio raiz do SaaS — qualquer subdomínio disso vira tenant (acme.centralaxcend.com → 'acme')
// Configurável via env SAAS_ROOT_DOMAIN — default centralaxcend.com (domínio que o usuário já tem)
const SAAS_ROOT_DOMAIN = process.env.SAAS_ROOT_DOMAIN || 'centralaxcend.com';

// Cache de tenants em memória (refresh a cada 30s). Evita ler o db.json em
// CADA request — só atualiza periodicamente. Quando um tenant é criado/editado,
// o cache simplesmente expira e na próxima request é refrescado.
let _tenantCache = { ts: 0, byHost: new Map(), bySlug: new Map() };
const _TENANT_CACHE_TTL_MS = 30 * 1000;
// Subdomínios reservados que NUNCA são tenants (são endpoints da plataforma)
const SUBDOMINIOS_RESERVADOS = new Set([
  'app', 'www', 'api', 'admin', 'painel', 'master', 'mail', 'cname',
  'static', 'cdn', 'assets', 'help', 'docs', 'blog', 'status'
]);

function _atualizarCacheTenants() {
  const agora = Date.now();
  if ((agora - _tenantCache.ts) < _TENANT_CACHE_TTL_MS) return;
  try {
    const db = readDB();
    const tenants = db.store['sl_saas_tenants'] || [];
    const byHost = new Map();
    const bySlug = new Map();
    for (const t of tenants) {
      if (!t || !t.id) continue;
      if (t.dominio) byHost.set(String(t.dominio).toLowerCase(), t.id);
      if (t.slug) bySlug.set(String(t.slug).toLowerCase(), t.id);
    }
    _tenantCache = { ts: agora, byHost, bySlug };
  } catch (e) {
    // mantém cache antigo se der erro
  }
}

/**
 * Resolve o tenant_id a partir do host da request.
 *
 * Regras:
 * 1. Host em HOSTS_INTERNO (app.centralaxcend.com, localhost...) → axcend-interno
 * 2. Host bate com tenant.dominio (domínio próprio do cliente) → tenant.id
 * 3. Host é subdomínio de axcend.com:
 *    - Subdomínio reservado (app, www, api...) → axcend-interno
 *    - Senão busca tenant com slug=subdomínio → tenant.id
 * 4. Default (host desconhecido): axcend-interno
 *
 * Defensive: hosts desconhecidos não revelam existência de outros tenants.
 */
function _resolverTenantId(req) {
  // Normaliza host: lowercase, sem porta
  const hostRaw = String(req.headers.host || '').toLowerCase();
  const host = hostRaw.split(':')[0];
  // 1. Hosts internos sempre são axcend-interno
  if (HOSTS_INTERNO.has(hostRaw) || HOSTS_INTERNO.has(host)) {
    return TENANT_INTERNO_ID;
  }
  // 2. Refresh cache + procura por domínio próprio
  _atualizarCacheTenants();
  const porDominio = _tenantCache.byHost.get(host);
  if (porDominio) return porDominio;
  // 3. Subdomínio de SAAS_ROOT_DOMAIN
  const sufixo = '.' + SAAS_ROOT_DOMAIN;
  if (host.endsWith(sufixo)) {
    const sub = host.slice(0, -sufixo.length);
    // Subdomínios reservados → interno
    if (SUBDOMINIOS_RESERVADOS.has(sub)) return TENANT_INTERNO_ID;
    // Busca tenant com esse slug
    const porSlug = _tenantCache.bySlug.get(sub);
    if (porSlug) return porSlug;
  }
  // 4. Default seguro: interno
  return TENANT_INTERNO_ID;
}

/**
 * Middleware: injeta req.tenantId em toda request.
 * Nenhum endpoint usa req.tenantId ainda — só fica disponível pra debug
 * e pros próximos PRs começarem a consumir.
 */
function _injetarTenant(req, res, next) {
  req.tenantId = _resolverTenantId(req);
  // Expose no header de resposta pra debug (será removido em prod)
  res.setHeader('X-Tenant-Id', req.tenantId);
  next();
}

/**
 * Helper: retorna o tenant_id de um item, ou o default se não tiver.
 * Backwards compat: items antigos sem tag são assumidos do tenant interno.
 * Usar nos próximos PRs ao implementar filtros.
 */
function getItemTenant(item) {
  return (item && item.tenant_id) || TENANT_DEFAULT_ID;
}

/**
 * Filtra um array por tenant_id. Items sem tag (legados) são tratados
 * como axcend-interno via getItemTenant.
 */
function _filtrarPorTenant(arr, tenantId) {
  if (!Array.isArray(arr)) return arr;
  return arr.filter(item => {
    if (!item || typeof item !== 'object') return true; // primitivos sempre passam
    return getItemTenant(item) === tenantId;
  });
}

/**
 * Aplica filtro de tenant em todo o store. Regras:
 * - Chaves da plataforma (KEYS_PLATAFORMA): só visíveis pro tenant interno;
 *   pra outros tenants são omitidas (não vazam info da plataforma).
 * - Arrays: filtra por tenant_id em cada item.
 * - Singletons (object): só aparece se for do tenant correto.
 * - Primitivos: passam direto (não fazem sentido tenant em string/número).
 */
function _aplicarFiltroTenant(store, tenantId) {
  const out = {};
  const isInterno = tenantId === TENANT_INTERNO_ID;
  for (const [k, v] of Object.entries(store || {})) {
    if (KEYS_PLATAFORMA.has(k)) {
      // Chaves da plataforma: só pro interno
      if (isInterno) out[k] = v;
      // Pra outros tenants: omite a chave (não aparece no response)
      continue;
    }
    if (Array.isArray(v)) {
      out[k] = _filtrarPorTenant(v, tenantId);
    } else if (v && typeof v === 'object') {
      // Singleton: só inclui se for do tenant certo (ou legado sem tag = interno)
      if (getItemTenant(v) === tenantId) out[k] = v;
    } else {
      out[k] = v; // primitivos passam direto (ex: rt_api_key)
    }
  }
  return out;
}

/**
 * Verifica se a request é de um super-admin (Diretoria do tenant interno).
 * Super-admin pode bypass de filtros usando ?_super=1 nas leituras —
 * útil pro painel SaaS poder ver dados de qualquer tenant.
 */
function _isSuperAdmin(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return false;
  try {
    const db = readDB();
    const sess = validarSessao(db, token);
    if (!sess) return false;
    const user = (db.store['sl_usuarios'] || []).find(u => u.id === sess.userId);
    if (!user || user.cargo !== 'Diretoria') return false;
    return getItemTenant(user) === TENANT_INTERNO_ID;
  } catch (e) {
    return false;
  }
}

// Chaves que pertencem à PLATAFORMA (master), não a tenants.
// - Na migração: não recebem tenant_id (não fazem sentido nesse contexto)
// - No filtro de leitura: só visíveis pro tenant interno (vazariam info de
//   outros clientes pra um cliente externo).
const KEYS_PLATAFORMA = new Set([
  'sl_saas_tenants',   // lista de clientes — SÓ master deve ver
  'sl_saas_config',    // config da plataforma (planos, gateways, idiomas) — SÓ master
  'sl_saas_faturas',   // faturas geradas — SÓ master por enquanto (PR futuro: cliente vê só suas próprias)
  'sl_auditlog'        // audit log da plataforma — SÓ master
]);
// Alias pra retrocompatibilidade com código que ainda usa KEYS_GLOBAIS
const KEYS_GLOBAIS = KEYS_PLATAFORMA;

const app = express();
// Atrás do proxy do Railway, sem isso req.ip é SEMPRE o IP do proxy: a empresa
// inteira dividia a mesma cota de 200 req/min e um usuário sozinho podia
// travar todo mundo. O 1 confia só no primeiro salto (o proxy do Railway) —
// confiar na cadeia toda deixaria qualquer um forjar IP e furar o limite.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const DB_FILE = path.join(DATA_DIR, 'db.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const CD_UPLOAD_DIR = path.join(DATA_DIR, 'cd_uploads');
try { if (!fs.existsSync(CD_UPLOAD_DIR)) fs.mkdirSync(CD_UPLOAD_DIR, { recursive: true }); } catch (e) {}
const BACKUP_INTERVAL_MS = 60 * 60 * 1000; // 1h (Time Machine style)
// Retenção em camadas: tudo da última 48h + 1/dia (90d) + 1/semana (12m) + 1/mês (forever)
const RET_HOURS   = 48;        // horas mantidas hora-a-hora
const RET_DAYS    = 90;        // dias mantidos (1/dia)
const RET_WEEKS   = 52;        // semanas mantidas (1/semana, até 12m)
// Snapshots mensais nunca são apagados

// Garante pasta de backups
if (!fs.existsSync(BACKUP_DIR)) {
  try { fs.mkdirSync(BACKUP_DIR, { recursive: true }); } catch {}
}

// ── SEGURANÇA ──
// CSP desabilitada temporariamente — estava quebrando o app (handlers inline,
// service worker, etc.). TODO: reabilitar com config mais permissiva ou via
// nonces nos scripts inline. Por enquanto outras protecoes (CORS, helmet defaults,
// rate limit, bcrypt, sessões hasheadas) continuam ativas.
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting global. SSE stream é pulado — é uma conexão long-lived
// (uma única request fica aberta horas; não faz sentido contar no rate limit)
// e o Authorization vai por query param, não no header
const globalLimiter = rateLimit({
  windowMs: 60*1000,
  max: 200,
  message: { error: 'Muitas requisições. Tente novamente em 1 minuto.' },
  // o pixel e o quiz tem limite proprio: um visitante dispara varios eventos por pagina
  skip: (req) => req.path === '/api/sync/stream' || req.path === '/api/funil/evento' || req.path === '/api/quiz/evento'
});
// Continua limitado, so que com folga pra trafego real (e por IP do visitante)
const pixelLimiter = rateLimit({ windowMs: 60*1000, max: 120,
  message: { error: 'limite' }, standardHeaders: false, legacyHeaders: false });
app.use('/api/funil/evento', pixelLimiter);
// Quiz: cada tela e cada resposta e um evento. 180/min por IP cobre muita gente
// atras do mesmo IP de operadora (CGNAT) sem abrir porta pra inundacao.
const quizLimiter = rateLimit({ windowMs: 60*1000, max: 180,
  message: { error: 'limite' }, standardHeaders: false, legacyHeaders: false });
app.use('/api/quiz/evento', quizLimiter);
// O MCP nao fica sob /api/, entao o limitador global nao alcanca. Uma conversa
// dispara varias chamadas seguidas; 90/min por IP cobre o uso e barra abuso.
const mcpLimiter = rateLimit({ windowMs: 60*1000, max: 90,
  message: { jsonrpc: '2.0', error: { code: -32000, message: 'Muitas chamadas. Espere um minuto.' } },
  standardHeaders: false, legacyHeaders: false });
app.use('/mcp', mcpLimiter);
app.use('/api/', globalLimiter);

// Rate limiting mais agressivo pra API v1
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 60, message: { error: 'Limite da API atingido. Máximo 60 req/min.' } });
app.use('/api/v1/', apiLimiter);

// Rate limiting crítico para login: 5 tentativas por 10min por IP
// O limite de login era 5 por IP a cada 10min. Como o time todo divide o mesmo IP
// do escritório, bastavam 5 tentativas SOMADAS pra bloquear a empresa inteira.
// Agora a proteção contra força bruta é POR CONTA (é o que importa: proteger a senha
// de alguém), e o teto por IP fica alto o bastante pra um time inteiro logar junto.
const { ipKeyGenerator } = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 10*60*1000,
  max: 5,
  keyGenerator: (req) => {
    const email = req.body && req.body.email ? String(req.body.email).trim().toLowerCase() : '';
    return email ? 'email:' + email : ipKeyGenerator(req);   // sem email informado, cai no IP
  },
  message: { error: 'Muitas tentativas nessa conta. Aguarde 10 minutos.' },
  skipSuccessfulRequests: true
});
// Teto por IP: continua barrando ataque automatizado, sem punir o escritório.
const loginLimiterIp = rateLimit({
  windowMs: 10*60*1000,
  max: 60,
  message: { error: 'Muitas tentativas de login. Aguarde alguns minutos.' },
  skipSuccessfulRequests: true
});

// CORS — restrito a domínios conhecidos (app.centralaxcend.com + dev local)
// Bloqueia qualquer outro site de chamar a API mesmo com token roubado
const ALLOWED_ORIGINS = [
  'https://app.centralaxcend.com',
  'https://centralaxcend.com',
  'http://localhost:3001',
  'http://localhost:3000',
  'http://127.0.0.1:3001'
];
// O pixel roda nas SUAS paginas de funil, em dominios de terceiros. O CORS global
// abaixo so aceita a whitelist — correto pro resto do sistema, mas bloquearia o
// pixel. Este endpoint nao le cookie, sessao nem devolve dado: so recebe
// contador. Por isso e liberado aqui, e so ele.
app.use('/api/funil/evento', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
  } else if (!origin) {
    // Same-origin requests (sem header Origin) — sempre permitidos
    res.header('Access-Control-Allow-Origin', '*');
  }
  // Se origin presente mas não está na whitelist, NÃO seta header e
  // o browser vai bloquear via mecanismo CORS natural
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-client-id, x-user-email, x-user-senha');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '20mb' }));
// Multi-tenancy PR 1: injeta req.tenantId em toda request.
// Por enquanto sempre 'axcend-interno' — não afeta nada.
app.use(_injetarTenant);
app.use(express.static(path.join(__dirname, 'public')));
// URL raiz serve o app
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'ScaleLab.html')));

// ── PÁGINA PÚBLICA DA VAGA ──
// /vaga/:slug → serve vaga.html (que faz fetch dos dados via API pública)
app.get('/vaga/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vaga.html'));
});
// /vagas → lista pública de todas as vagas ativas (ponto único pra compartilhar)
app.get('/vagas', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vagas-publico.html'));
});

// ── PAINEL SAAS (gestão de clientes externos · só Diretoria) ──
// Serve o painel; a autenticação é checada client-side via /api/auth/me
// (igual o resto do sistema). Não-Diretoria recebe tela de bloqueio.
app.get('/painel-saas', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'painel-saas.html'));
});

// ── TESTE PRÁTICO (público, sem login) ──
// Candidato acessa /teste/:slug → faz o teste → submete entrega
app.get('/teste/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'teste.html'));
});

// ── COMPARTILHAMENTO DE NOTAS (Central da Diretoria) ──
// /nota/:id → página pública read-only (busca os dados via API abaixo)
app.get('/nota/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'nota.html'));
});
// Snapshot público de uma nota compartilhada. Se for 'interno', exige sessão válida.
app.get('/api/cd/nota-publica/:id', (req, res) => {
  const db = readDB();
  const shares = db.store['cd_shares'] || [];
  const nota = shares.find(x => x.id === req.params.id);
  if (!nota) return res.status(404).json({ error: 'Nota não encontrada ou não compartilhada.' });
  if (nota.share === 'interno') {
    const authHeader = req.headers.authorization || '';
    let ok = false;
    if (authHeader.startsWith('Bearer ')) { try { if (validarSessao(db, authHeader.split(' ')[1])) ok = true; } catch {} }
    if (!ok) return res.status(403).json({ error: 'interno', msg: 'Essa nota é interna — faça login na Central pra abrir.' });
  }
  const filhas = shares.filter(x => x.parentId === nota.id).map(x => ({ id: x.id, titulo: x.titulo }));
  res.json({ id: nota.id, titulo: nota.titulo, blocks: nota.blocks || [], share: nota.share, filhas: filhas, ts: nota.ts, by: nota.by });
});
// App empurra o snapshot da nota + subpáginas ao compartilhar (só Diretoria).
app.post('/api/cd/compartilhar', authDiretoria, (req, res) => {
  const { subtree, rootId, share } = req.body || {};
  if (!Array.isArray(subtree) || !subtree.length) return res.status(400).json({ error: 'subtree vazio' });
  const db = readDB();
  if (!Array.isArray(db.store['cd_shares'])) db.store['cd_shares'] = [];
  const shares = db.store['cd_shares'];
  const ts = now();
  const sh = (share === 'externo') ? 'externo' : 'interno';
  subtree.forEach(item => {
    if (!item || !item.id) return;
    const entry = {
      id: item.id,
      titulo: item.titulo || 'Sem título',
      blocks: Array.isArray(item.blocks) ? item.blocks : [],
      parentId: item.parentId || null,
      rootId: rootId || item.id,
      share: sh, ts: ts,
      by: req.user.nome || req.user.email || ''
    };
    const idx = shares.findIndex(x => x.id === item.id);
    if (idx >= 0) shares[idx] = entry; else shares.push(entry);
  });
  db.timestamps = db.timestamps || {};
  db.timestamps['cd_shares'] = ts;
  audit(db, 'cd_compartilhar', { rootId: rootId }, { share: sh, itens: subtree.length }, { id: req.user.id, nome: req.user.nome, cargo: req.user.cargo });
  writeDB(db);
  res.json({ ok: true, url: '/nota/' + (rootId || subtree[0].id), share: sh });
});

// ── SINCRONIZAÇÃO DA CENTRAL entre aparelhos (notas/pastas/rotina/lixeira/agenda) ──
// O cliente faz a união por id e manda o resultado já mesclado; o servidor guarda.
app.get('/api/cd/data', authDiretoria, (req, res) => {
  const db = readDB();
  res.json({
    ok: true,
    cd_notas: db.store['cd_notas'] || [],
    cd_pastas: db.store['cd_pastas'] || [],
    cd_rotina: db.store['cd_rotina'] || null,
    cd_rotina_ts: (db.timestamps && db.timestamps['cd_rotina']) || 0,
    cd_del: db.store['cd_del'] || [],
    cd_gcal: db.store['cd_gcal'] || []
  });
});
app.put('/api/cd/data', authDiretoria, (req, res) => {
  const b = req.body || {}; const db = readDB();
  db.timestamps = db.timestamps || {};
  if (Array.isArray(b.cd_notas)) db.store['cd_notas'] = b.cd_notas.slice(0, 5000);
  if (Array.isArray(b.cd_pastas)) db.store['cd_pastas'] = b.cd_pastas.slice(0, 5000);
  if (Array.isArray(b.cd_del)) db.store['cd_del'] = b.cd_del.slice(0, 20000);
  if (Array.isArray(b.cd_gcal)) db.store['cd_gcal'] = b.cd_gcal.slice(0, 50);
  if (b.cd_rotina && typeof b.cd_rotina === 'object') {
    db.store['cd_rotina'] = b.cd_rotina;
    db.timestamps['cd_rotina'] = (b.cd_rotina_ts && b.cd_rotina_ts > (db.timestamps['cd_rotina'] || 0)) ? b.cd_rotina_ts : Date.now();
  }
  writeDB(db);
  res.json({ ok: true });
});

// ── ANEXOS DA CENTRAL (upload/download de arquivo dentro das notas) ──
// Arquivo guardado no volume (DATA_DIR/cd_uploads); a nota guarda só a referência.
app.post('/api/cd/upload', authDiretoria, express.raw({ type: () => true, limit: '90mb' }), (req, res) => {
  try {
    const buf = req.body;
    if (!buf || !buf.length) return res.status(400).json({ error: 'Arquivo vazio.' });
    let nome = 'arquivo';
    try { nome = decodeURIComponent(req.headers['x-nome'] || 'arquivo'); } catch (e) { nome = req.headers['x-nome'] || 'arquivo'; }
    nome = String(nome).replace(/[\r\n]/g, '').slice(0, 200);
    const mime = String(req.headers['x-mime'] || req.headers['content-type'] || 'application/octet-stream').slice(0, 120);
    const id = 'f_' + Date.now().toString(36) + Math.floor(Math.random() * 1e9).toString(36);
    fs.writeFileSync(path.join(CD_UPLOAD_DIR, id), buf);
    const db = readDB();
    if (!Array.isArray(db.store['cd_arquivos'])) db.store['cd_arquivos'] = [];
    db.store['cd_arquivos'].push({ id: id, nome: nome, mime: mime, tamanho: buf.length, por: (req.user && req.user.nome) || '', ts: now() });
    writeDB(db);
    res.json({ ok: true, id: id, nome: nome, mime: mime, tamanho: buf.length });
  } catch (e) { res.status(500).json({ error: 'Falha ao salvar o arquivo.' }); }
});
app.get('/api/cd/arquivo/:id', authDiretoria, (req, res) => {
  const db = readDB();
  const meta = (db.store['cd_arquivos'] || []).find(x => x.id === req.params.id);
  if (!meta || !/^f_[a-z0-9]+$/i.test(meta.id)) return res.status(404).json({ error: 'Arquivo não encontrado.' });
  const fp = path.join(CD_UPLOAD_DIR, meta.id);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Arquivo não está mais no servidor.' });
  res.setHeader('Content-Type', meta.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="' + encodeURIComponent(meta.nome || 'arquivo') + '"');
  fs.createReadStream(fp).on('error', () => { try { res.status(500).end(); } catch (e) {} }).pipe(res);
});
// Exibição inline de imagem (público; id aleatório = obscuro). Pra <img src>.
app.get('/api/cd/img/:id', (req, res) => {
  const db = readDB();
  const meta = (db.store['cd_arquivos'] || []).find(x => x.id === req.params.id);
  if (!meta || !/^f_[a-z0-9]+$/i.test(meta.id)) return res.status(404).end();
  const fp = path.join(CD_UPLOAD_DIR, meta.id);
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Content-Type', meta.mime || 'application/octet-stream');
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  fs.createReadStream(fp).on('error', () => { try { res.status(500).end(); } catch (e) {} }).pipe(res);
});

// ── GOOGLE AGENDA (fase 1: só leitura via link secreto iCal) ──
// Busca o .ics no Google, expande recorrências simples e devolve os eventos
// da janela pedida. Restrito a calendar.google.com (evita SSRF).
function _cdFetchICS(urlStr, depth) {
  const https = require('https');
  return new Promise((resolve, reject) => {
    if ((depth || 0) > 3) return reject(new Error('Muitos redirecionamentos'));
    let u;
    try { u = new URL(String(urlStr).replace(/^webcal:/i, 'https:')); } catch (e) { return reject(new Error('URL inválida')); }
    if (u.protocol !== 'https:') return reject(new Error('Só aceito https'));
    if (u.hostname !== 'calendar.google.com') return reject(new Error('Só aceito link do Google Agenda (calendar.google.com)'));
    https.get(u, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return _cdFetchICS(res.headers.location, (depth || 0) + 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('Google respondeu HTTP ' + res.statusCode + ' (confira o link secreto)')); }
      let data = ''; res.setEncoding('utf8');
      res.on('data', c => { data += c; if (data.length > 8 * 1024 * 1024) { res.destroy(); reject(new Error('Calendário grande demais')); } });
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}
function _cdUnescICS(s) { return String(s || '').replace(/\\n/gi, ' ').replace(/\\,/g, ',').replace(/\\;/g, ';').replace(/\\\\/g, '\\'); }
function _cdIcsDate(val) {
  const m = String(val || '').trim().match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})?(Z)?)?/);
  if (!m) return null;
  return { y: +m[1], mo: +m[2], d: +m[3], h: m[4] ? +m[4] : 0, mi: m[5] ? +m[5] : 0, s: m[6] ? +m[6] : 0, utc: !!m[7], allDay: !m[4] };
}
function _cdDtMs(dt) { return Date.UTC(dt.y, dt.mo - 1, dt.d, dt.h, dt.mi, dt.s || 0); }
function _cdParseAgenda(txt, diasJanela) {
  txt = String(txt).replace(/\r\n/g, '\n').replace(/\n[ \t]/g, ''); // desdobra linhas
  const _nm = txt.match(/^X-WR-CALNAME:(.+)$/m); const _calNome = _nm ? _cdUnescICS(_nm[1].trim()) : '';
  const linhas = txt.split('\n');
  const eventos = []; let cur = null;
  for (const ln of linhas) {
    if (ln === 'BEGIN:VEVENT') { cur = {}; continue; }
    if (ln === 'END:VEVENT') { if (cur && cur.inicio) eventos.push(cur); cur = null; continue; }
    if (!cur) continue;
    const idx = ln.indexOf(':'); if (idx < 0) continue;
    const left = ln.slice(0, idx), val = ln.slice(idx + 1), key = left.split(';')[0];
    if (key === 'SUMMARY') cur.titulo = _cdUnescICS(val);
    else if (key === 'LOCATION') cur.local = _cdUnescICS(val);
    else if (key === 'DTSTART') { cur.inicio = _cdIcsDate(val); if (cur.inicio) cur.inicio.allDay = /VALUE=DATE/i.test(left) || cur.inicio.allDay; }
    else if (key === 'DTEND') cur.fim = _cdIcsDate(val);
    else if (key === 'RRULE') cur.rrule = val;
  }
  const dias = Math.min(Math.max(diasJanela || 30, 1), 120);
  const hoje = new Date(); const janIni = Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), hoje.getUTCDate()) - 86400000;
  const janFim = janIni + (dias + 1) * 86400000;
  const WD = { SU: 0, MO: 1, TU: 2, WE: 3, TH: 4, FR: 5, SA: 6 };
  const out = [];
  function push(dt, ev) { out.push({ titulo: ev.titulo || '(sem título)', local: ev.local || '', allDay: !!dt.allDay, y: dt.y, mo: dt.mo, d: dt.d, h: dt.h, mi: dt.mi, utc: !!dt.utc }); }
  for (const ev of eventos) {
    const b = ev.inicio; if (!b) continue;
    if (!ev.rrule) { const ms = _cdDtMs(b); if (ms >= janIni && ms <= janFim) push(b, ev); continue; }
    const parts = {}; ev.rrule.split(';').forEach(p => { const kv = p.split('='); parts[kv[0]] = kv[1]; });
    const freq = parts.FREQ, interval = parts.INTERVAL ? +parts.INTERVAL : 1;
    const untilMs = parts.UNTIL ? _cdDtMs(_cdIcsDate(parts.UNTIL)) : Infinity;
    const byday = parts.BYDAY ? parts.BYDAY.split(',').map(x => WD[x.slice(-2)]).filter(x => x != null) : null;
    if (freq === 'DAILY' || freq === 'WEEKLY') {
      for (let t = Math.max(janIni, _cdDtMs(b)); t <= janFim; t += 86400000) {
        if (t > untilMs) break;
        const dd = new Date(t); const wd = dd.getUTCDay();
        let ok = false;
        if (freq === 'DAILY') ok = ((Math.round((t - _cdDtMs({ y: b.y, mo: b.mo, d: b.d, h: 0, mi: 0 })) / 86400000)) % interval === 0);
        else ok = byday ? byday.indexOf(wd) >= 0 : wd === (new Date(_cdDtMs(b))).getUTCDay();
        if (ok) push({ y: dd.getUTCFullYear(), mo: dd.getUTCMonth() + 1, d: dd.getUTCDate(), h: b.h, mi: b.mi, allDay: b.allDay, utc: b.utc }, ev);
      }
    } else { const ms = _cdDtMs(b); if (ms >= janIni && ms <= janFim) push(b, ev); }
  }
  out.sort((a, b) => (a.y - b.y) || (a.mo - b.mo) || (a.d - b.d) || (a.h - b.h) || (a.mi - b.mi));
  return { nome: _calNome, eventos: out.slice(0, 400) };
}
app.post('/api/cd/agenda', authDiretoria, async (req, res) => {
  const body = req.body || {};
  let urls = Array.isArray(body.urls) ? body.urls : (body.url ? [body.url] : []);
  urls = urls.map(u => String(u || '').trim()).filter(Boolean).slice(0, 12);
  if (!urls.length) return res.status(400).json({ error: 'Informe ao menos um link secreto (iCal) do Google Agenda.' });
  const dias = body.dias || 30;
  const todos = []; const fontes = [];
  for (let i = 0; i < urls.length; i++) {
    try {
      const ics = await _cdFetchICS(urls[i], 0);
      if (!/BEGIN:VCALENDAR/.test(ics)) throw new Error('não é um calendário válido');
      const r = _cdParseAgenda(ics, dias);
      const nome = r.nome || ('Agenda ' + (i + 1));
      r.eventos.forEach(e => { e.cal = nome; e.ci = i; });
      for (const e of r.eventos) todos.push(e);
      fontes.push({ nome: nome, ok: true, n: r.eventos.length });
    } catch (e) {
      fontes.push({ nome: 'Agenda ' + (i + 1), ok: false, erro: (e && e.message) ? e.message : 'erro' });
    }
  }
  todos.sort((a, b) => (a.y - b.y) || (a.mo - b.mo) || (a.d - b.d) || (a.h - b.h) || (a.mi - b.mi));
  res.json({ ok: true, eventos: todos.slice(0, 700), fontes: fontes });
});

// ── BANCO DE DADOS ──
function readDB() {
  // ⚠️ NUNCA devolver banco vazio quando o arquivo EXISTE mas não deu pra ler.
  // Antes, qualquer falha de leitura caía num {store:{}} silencioso — e como quase
  // todo handler faz readDB() → mexe → writeDB(), esse vazio era gravado POR CIMA
  // de tudo. Foi assim que a Central da Diretoria (270 arquivos) foi zerada.
  // Melhor a requisição falhar alto do que destruir o banco em silêncio.
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) {
    if (!fs.existsSync(DB_FILE)) {
      return { store: {}, timestamps: {}, api_tokens: [], api_logs: [] };  // 1ª execução
    }
    console.error('[DB] LEITURA FALHOU — abortando pra não sobrescrever:', e.message);
    throw new Error('Banco temporariamente ilegível. Nada foi gravado.');
  }
}

// ── ESPAÇO EM DISCO ──────────────────────────────────────────
// O volume do Railway encheu e derrubou a aplicação: writeDB falhava no boot
// (ENOSPC), o processo morria e o Railway reiniciava — em loop, site fora do ar.
// Os snapshots de hora em hora crescem pra sempre; aqui está a válvula de escape.
function _espacoLivreMB(dir) {
  try { const s = fs.statfsSync(dir); return (s.bsize * s.bavail) / (1024 * 1024); }
  catch (e) { return null; }
}

// Apaga os snapshots MAIS ANTIGOS até ter folga. Nunca toca no db.json e sempre
// preserva os 3 mais recentes — melhor perder histórico velho que ficar fora do ar.
function _liberarEspacoSeNecessario(minMB) {
  const alvo = minMB || 40;
  let livre = _espacoLivreMB(DATA_DIR);
  if (livre === null || livre >= alvo) return { livre, apagados: 0 };
  console.warn(`[DISCO] só ${Math.round(livre)}MB livres — limpando snapshots antigos.`);
  let apagados = 0;
  try {
    const arqs = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.endsWith('.json') || f.endsWith('.json.gz'))
      .map(f => { const caminho = path.join(BACKUP_DIR, f);
                  try { return { caminho, t: fs.statSync(caminho).mtimeMs }; } catch (e) { return null; } })
      .filter(Boolean)
      .sort((a, b) => a.t - b.t);        // mais antigos primeiro
    for (const a of arqs) {
      if (arqs.length - apagados <= 3) break;
      try { fs.unlinkSync(a.caminho); apagados++; } catch (e) { continue; }
      livre = _espacoLivreMB(DATA_DIR);
      if (livre !== null && livre >= alvo) break;
    }
  } catch (e) { console.error('[DISCO] limpeza falhou:', e.message); }
  console.warn(`[DISCO] ${apagados} snapshot(s) apagados — ${Math.round(livre || 0)}MB livres agora.`);
  return { livre, apagados };
}

function writeDB(db) {
  // Gravação ATÔMICA: escreve num temporário e só então troca o arquivo de lugar.
  // Antes era writeFileSync direto no db.json — isso ZERA o arquivo antes de
  // escrever, e quem lesse nesse intervalo (o backup de hora em hora, outro
  // request) pegava um arquivo vazio ou pela metade. Era a origem dos snapshots
  // de 0 KB. O rename é atômico no mesmo disco: ninguém vê estado intermediário.
  const tmp = DB_FILE + '.tmp';
  const dados = JSON.stringify(db, null, 2);
  try {
    fs.writeFileSync(tmp, dados);
  } catch (e) {
    if (!e || e.code !== 'ENOSPC') throw e;
    // Disco cheio: abre espaço e tenta de novo antes de desistir.
    _liberarEspacoSeNecessario(Math.max(60, Math.ceil(dados.length / (1024 * 1024)) * 3));
    fs.writeFileSync(tmp, dados);
  }
  fs.renameSync(tmp, DB_FILE);
}

function now() { return Math.floor(Date.now() / 1000); }

// ── MIGRAÇÃO (PR 2): tagear itens existentes com tenant_id ──
// Roda uma vez no boot. Idempotente (não roda 2x). Snapshot antes.
// Não filtra/quebra nada — só carimba os items existentes pra os próximos
// PRs poderem começar a filtrar com segurança.
function _migrarParaMultiTenant() {
  try {
    const db = readDB();
    if (db._migrated_v1_tenant) {
      // Já migrou — não faz nada
      console.log('[MULTI-TENANT] Já migrado em ' + db._migrated_v1_tenant + '. Pulando.');
      return;
    }
    // Snapshot ANTES de qualquer mudança (Time Machine + Pre-restore equivalentes)
    const snap = criarSnapshotBackup('pre-multitenancy-v1');
    if (snap && snap.ok) {
      console.log('[MULTI-TENANT] Snapshot pre-migracao criado: ' + snap.arquivo);
    } else {
      console.warn('[MULTI-TENANT] AVISO: snapshot pre-migracao falhou. Migracao prossegue.');
    }
    let itensTotais = 0;
    let itensTaggeados = 0;
    for (const key of Object.keys(db.store || {})) {
      if (KEYS_GLOBAIS.has(key)) continue;
      const valor = db.store[key];
      if (Array.isArray(valor)) {
        for (const item of valor) {
          if (item && typeof item === 'object') {
            itensTotais++;
            if (!item.tenant_id) {
              item.tenant_id = TENANT_INTERNO_ID;
              itensTaggeados++;
            }
          }
        }
      } else if (valor && typeof valor === 'object') {
        itensTotais++;
        if (!valor.tenant_id) {
          valor.tenant_id = TENANT_INTERNO_ID;
          itensTaggeados++;
        }
      }
    }
    db._migrated_v1_tenant = new Date().toISOString();
    db._migrated_v1_tenant_count = itensTaggeados;
    writeDB(db);
    console.log(`[MULTI-TENANT] Migracao concluida. ${itensTaggeados}/${itensTotais} items taggeados como '${TENANT_INTERNO_ID}'.`);
  } catch (err) {
    console.error('[MULTI-TENANT] Erro na migracao:', err.message);
  }
}

// ── MIGRAÇÃO: hash de senhas em texto puro ──
function _migrarSenhasParaHash() {
  try {
    const db = readDB();
    const usuarios = db.store['sl_usuarios'] || [];
    let migrados = 0;
    usuarios.forEach(u => {
      if (u && u.senha && !u.senhaHash) {
        // Tem senha em texto puro e nenhum hash — migra
        u.senhaHash = bcrypt.hashSync(String(u.senha), BCRYPT_ROUNDS);
        delete u.senha;
        migrados++;
      } else if (u && u.senha && u.senhaHash) {
        // Já tem hash — remove texto puro por segurança
        delete u.senha;
        migrados++;
      }
    });
    if (migrados > 0) {
      db.store['sl_usuarios'] = usuarios;
      db.timestamps['sl_usuarios'] = now();
      writeDB(db);
      console.log(`[AUTH] ${migrados} senhas migradas para bcrypt.`);
    }
  } catch (err) {
    console.error('[AUTH] Erro na migração de senhas:', err.message);
  }
}

// Migra tarefas com status legados (COPY_PENDENTE, EDICAO_PROGRESSO, etc) pro
// novo modelo: setor + status simples + aprovacao. Idempotente — quem já tem
// `setor` é pulado.
function _migrarTasksParaSetorStatus() {
  try {
    const db = readDB();
    const tasks = db.store['tasks'] || [];
    let migrados = 0;
    const MAP = {
      'BACKLOG':          { setor: 'Copy',    status: 'Pendente' },
      'COPY_PENDENTE':    { setor: 'Copy',    status: 'Pendente' },
      'COPY_PROGRESSO':   { setor: 'Copy',    status: 'Em Progresso' },
      'COPY_PARADA':      { setor: 'Copy',    status: 'Em Progresso' },
      'COPY_REVISAO':     { setor: 'Copy',    status: 'Em Revisão' },
      'COPY_APROVADA':    { setor: 'Copy',    status: 'Concluída', aprovacao: 'aprovada' },
      'EDICAO_PENDENTE':  { setor: 'Edição',  status: 'Pendente' },
      'EDICAO_PROGRESSO': { setor: 'Edição',  status: 'Em Progresso' },
      'EDICAO_REVISAO':   { setor: 'Edição',  status: 'Em Revisão' },
      'EDICAO_CONCLUIDA': { setor: 'Edição',  status: 'Concluída', aprovacao: 'aprovada' },
      'INFRA_PENDENTE':   { setor: 'Infra',   status: 'Pendente' },
      'INFRA_PROGRESSO':  { setor: 'Infra',   status: 'Em Progresso' },
      'INFRA_REVISAO':    { setor: 'Infra',   status: 'Em Revisão' },
      'INFRA':            { setor: 'Infra',   status: 'Concluída', aprovacao: 'aprovada' },
      'TRAFEGO':          { setor: 'Tráfego', status: 'Pendente' },
      'SPY':              { setor: 'Spy',     status: 'Pendente' },
      'CONCLUIDO':        { setor: null,      status: 'Concluída', aprovacao: 'aprovada' },
      'Pendente':         { setor: 'Copy',    status: 'Pendente' },
      'Em andamento':     { setor: 'Copy',    status: 'Em Progresso' },
      'Concluída':        { setor: null,      status: 'Concluída', aprovacao: 'aprovada' },
    };
    tasks.forEach(t => {
      if (!t || t.setor) return; // já migrado
      const m = MAP[t.status];
      if (m) {
        t.setor = m.setor || t.setor || 'Copy';
        t.status = m.status;
        if (m.aprovacao) t.aprovacao = m.aprovacao;
      } else {
        // Status desconhecido — default Copy/Pendente
        t.setor = 'Copy';
        t.status = 'Pendente';
      }
      migrados++;
    });
    if (migrados > 0) {
      db.store['tasks'] = tasks;
      db.timestamps['tasks'] = now();
      writeDB(db);
      console.log(`[TASKS] ${migrados} tarefa(s) migrada(s) para setor+status novo.`);
    }
  } catch (err) {
    console.error('[TASKS] Erro na migração de setor+status:', err.message);
  }
}

// Atribui gestor (1º da lista `o.gestores`) aos dias do ROI que ainda não têm
// o campo. Idempotente: rodadas seguintes não fazem nada. Ofertas sem gestor
// vinculado são puladas — o usuário precisa setar manualmente.
function _migrarGestorEmDiasAntigos() {
  try {
    const db = readDB();
    const ofertas = db.store['roi_ofertas'] || [];
    let diasMigrados = 0;
    let ofertasAfetadas = 0;
    ofertas.forEach(o => {
      if (!o || !Array.isArray(o.dias)) return;
      const gestorPadrao = Array.isArray(o.gestores) && o.gestores[0] ? String(o.gestores[0]) : '';
      if (!gestorPadrao) return;
      const antes = diasMigrados;
      o.dias.forEach(d => {
        if (d && !d.gestor) {
          d.gestor = gestorPadrao;
          diasMigrados++;
        }
      });
      if (diasMigrados > antes) ofertasAfetadas++;
    });
    if (diasMigrados > 0) {
      db.store['roi_ofertas'] = ofertas;
      db.timestamps['roi_ofertas'] = now();
      writeDB(db);
      console.log(`[ROI] ${diasMigrados} dia(s) antigo(s) migrado(s) com gestor padrão da oferta em ${ofertasAfetadas} oferta(s).`);
    }
  } catch (err) {
    console.error('[ROI] Erro na migração de gestor em dias antigos:', err.message);
  }
}

// ── SESSÕES ──
function _getSessions(db) {
  if (!db.sessions) db.sessions = [];
  return db.sessions;
}
function _pruneSessoesExpiradas(db) {
  const sess = _getSessions(db);
  const agora = Date.now();
  const antes = sess.length;
  db.sessions = sess.filter(s => (s.lastActivity || s.createdAt || 0) + SESSION_TTL_MS > agora);
  return antes - db.sessions.length;
}
function criarSessao(db, userId) {
  _pruneSessoesExpiradas(db);
  const token = 'ses_' + crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  _getSessions(db).push({
    tokenHash,
    userId,
    createdAt: Date.now(),
    lastActivity: Date.now()
  });
  return token;
}
function validarSessao(db, token) {
  if (!token) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const sess = _getSessions(db).find(s => s.tokenHash === tokenHash);
  if (!sess) return null;
  // Verifica TTL
  if ((sess.lastActivity || sess.createdAt) + SESSION_TTL_MS < Date.now()) return null;
  // Atualiza lastActivity
  sess.lastActivity = Date.now();
  return sess;
}
function invalidarSessao(db, token) {
  if (!token) return;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  db.sessions = _getSessions(db).filter(s => s.tokenHash !== tokenHash);
}

// ══════════════════════════════════════════════
// ── LOG DE AUDITORIA ──
// ══════════════════════════════════════════════
const AUDIT_RETENTION_DAYS = 90;
const AUDIT_MAX_ENTRIES = 10000; // hard cap de segurança

function audit(db, action, target, meta, userInfo) {
  try {
    if (!db.store['sl_auditlog']) db.store['sl_auditlog'] = [];
    const entry = {
      id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
      ts: Date.now(),
      iso: new Date().toISOString(),
      action: String(action || 'unknown'),
      target: target || null,
      userId: (userInfo && userInfo.id) || null,
      userNome: (userInfo && userInfo.nome) || null,
      userCargo: (userInfo && userInfo.cargo) || null,
      meta: meta || null
    };
    db.store['sl_auditlog'].unshift(entry);
    // Hard cap + retenção
    if (db.store['sl_auditlog'].length > AUDIT_MAX_ENTRIES) {
      db.store['sl_auditlog'] = db.store['sl_auditlog'].slice(0, AUDIT_MAX_ENTRIES);
    }
    if (!db.timestamps) db.timestamps = {};
    db.timestamps['sl_auditlog'] = now();
  } catch (err) {
    console.error('[AUDIT] erro:', err.message);
  }
}
function _limparAuditoriaAntiga() {
  try {
    const db = readDB();
    const lim = Date.now() - AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    const log = db.store['sl_auditlog'] || [];
    const antes = log.length;
    db.store['sl_auditlog'] = log.filter(x => (x.ts || 0) >= lim);
    const rem = antes - db.store['sl_auditlog'].length;
    if (rem > 0) {
      db.timestamps['sl_auditlog'] = now();
      writeDB(db);
      console.log(`[AUDIT] ${rem} entradas >${AUDIT_RETENTION_DAYS}d removidas.`);
    }
  } catch {}
}
setInterval(_limparAuditoriaAntiga, 12 * 60 * 60 * 1000); // 2x/dia
setTimeout(_limparAuditoriaAntiga, 2 * 60 * 1000);

// Helper — pega user info a partir de Bearer token, se tiver
function _userInfoFromReq(req, db) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const sess = validarSessao(db, token);
    if (sess) {
      const u = (db.store['sl_usuarios'] || []).find(x => x.id === sess.userId);
      if (u) return { id: u.id, nome: u.nome, cargo: u.cargo };
    }
  }
  return { id: null, nome: null, cargo: null };
}

// GET /api/auditoria/list — lista entradas (Diretoria-only)
app.get('/api/auditoria/list', authDiretoria, (req, res) => {
  const db = readDB();
  const log = (db.store['sl_auditlog'] || []).slice();
  const { user, action, target, from, to, limit } = req.query;
  let out = log;
  if (user) out = out.filter(x => x.userId === user || x.userNome === user);
  if (action) out = out.filter(x => x.action && x.action.toLowerCase().includes(String(action).toLowerCase()));
  if (target) out = out.filter(x => x.target && JSON.stringify(x.target).toLowerCase().includes(String(target).toLowerCase()));
  if (from) out = out.filter(x => x.ts >= new Date(from).getTime());
  if (to) out = out.filter(x => x.ts <= new Date(to).getTime() + 24*60*60*1000);
  const lim = parseInt(limit) || 500;
  res.json({ total: out.length, entries: out.slice(0, lim) });
});

// ── STRIP DE SENHA EM RESPOSTAS (sempre) ──
function _stripSenhas(value) {
  if (Array.isArray(value)) {
    return value.map(v => {
      if (v && typeof v === 'object' && (v.senha !== undefined || v.senhaHash !== undefined)) {
        const copy = Object.assign({}, v);
        delete copy.senha; delete copy.senhaHash;
        return copy;
      }
      return v;
    });
  }
  return value;
}

// Init
function initDB() {
  const db = readDB();
  if (!db.store['sl_usuarios']) {
    db.store['sl_usuarios'] = [
      { id:'u1', nome:'Thiago', email:'thiago@axcend.com', senha:'axcend2026', cargo:'Diretoria', ativo:true },
      { id:'u2', nome:'Rafael', email:'rafael@axcend.com', senha:'axcend2026', cargo:'Gestor de Tráfego', ativo:true },
      { id:'u3', nome:'Ana',    email:'copy@axcend.com',   senha:'axcend2026', cargo:'Copy', ativo:true },
      { id:'u4', nome:'Carlos', email:'editor@axcend.com', senha:'axcend2026', cargo:'Editor', ativo:true },
      { id:'u5', nome:'Felipe', email:'infra@axcend.com',  senha:'axcend2026', cargo:'Infra', ativo:true },
      { id:'u6', nome:'Lucas',  email:'spy@axcend.com',    senha:'axcend2026', cargo:'Spy', ativo:true }
    ];
    db.timestamps['sl_usuarios'] = now();
  }
  if (!db.api_tokens) db.api_tokens = [];
  if (!db.api_logs) db.api_logs = [];
  if (!db.sessions) db.sessions = [];
  // Nunca deixar o boot morrer por causa de disco: sem isso o processo cai e o
  // Railway reinicia em loop, deixando o site fora do ar.
  try {
    writeDB(db);
  } catch (e) {
    console.error('[BOOT] não consegui gravar o banco:', e.message);
    console.error('[BOOT] subindo assim mesmo — leitura funciona, gravação pode falhar.');
  }
}
_liberarEspacoSeNecessario(80);   // antes de qualquer gravação
initDB();
_comprimirSnapshotsAntigos();     // encolhe o acervo cru que lotou o volume
// Migra senhas existentes para bcrypt na inicialização
_migrarSenhasParaHash();
// Atribui gestor padrão (1º da oferta) a dias antigos do ROI que não têm o campo
_migrarGestorEmDiasAntigos();
// Migra tarefas com status legados (COPY_PENDENTE etc) pro novo modelo setor+status
_migrarTasksParaSetorStatus();
// Multi-tenancy PR 2: tagear items existentes com tenant_id='axcend-interno'.
// Idempotente (não roda 2x). Snapshot automático antes.
_migrarParaMultiTenant();
// Limpeza de sessões expiradas a cada 1h
setInterval(() => {
  try { const db = readDB(); const n = _pruneSessoesExpiradas(db); if (n > 0) { writeDB(db); console.log(`[AUTH] ${n} sessões expiradas removidas.`); } } catch {}
}, 60 * 60 * 1000);

// ══════════════════════════════════════════════
// ── MIDDLEWARE DE AUTENTICAÇÃO API v1 ──
// ══════════════════════════════════════════════
function authAPI(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido. Use Authorization: Bearer <token>' });
  }
  const token = authHeader.split(' ')[1];
  const db = readDB();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const found = (db.api_tokens || []).find(t => t.hash === tokenHash && t.ativo);
  if (!found) {
    return res.status(403).json({ error: 'Token inválido ou revogado.' });
  }
  // Atualiza último uso
  found.ultimoUso = new Date().toISOString();
  found.totalReqs = (found.totalReqs || 0) + 1;
  writeDB(db);
  // Log de acesso
  _logAPI(db, token.substring(0,8)+'...', req.method, req.path);
  req.apiToken = found;
  next();
}

function _logAPI(db, tokenPreview, method, path) {
  if (!db.api_logs) db.api_logs = [];
  db.api_logs.unshift({
    token: tokenPreview,
    method, path,
    timestamp: new Date().toISOString()
  });
  // Limita a 500 logs
  if (db.api_logs.length > 500) db.api_logs = db.api_logs.slice(0, 500);
  writeDB(db);
}

// ══════════════════════════════════════════════
// ── GESTÃO DE TOKENS (rotas internas) ──
// ══════════════════════════════════════════════

// POST /api/tokens/generate — gera novo token (precisa login de Diretoria)
// Esta rota nao tinha autenticacao nenhuma: qualquer um na internet podia gerar
// um token valido e ler o sistema pela /api/v1 (e agora pelo /mcp, que responde
// faturamento). Fechada pra Diretoria, como as outras rotas sensiveis. A tela ja
// manda o login em toda chamada /api/, entao nada muda pra quem usa o painel.
// Os tokens ja criados continuam valendo.
app.post('/api/tokens/generate', authDiretoria, (req, res) => {
  const { nome, userId, master, descricao } = req.body || {};
  if (!nome) return res.status(400).json({ error: 'Nome do token obrigatório.' });

  const token = 'sk_live_' + crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const db = readDB();
  const tokenMeta = {
    id: Date.now(),
    nome,
    descricao: descricao || '',
    hash: tokenHash,
    preview: token.substring(0, 16) + '...',
    criado: new Date().toISOString(),
    criadoPor: userId || 'sistema',
    ativo: true,
    master: master === true,  // flag pra habilitar broadcast no /api/spy/import
    ultimoUso: null,
    totalReqs: 0
  };
  db.api_tokens.push(tokenMeta);
  audit(db, 'api_token_criado', { tokenId: tokenMeta.id, nome }, null, _userInfoFromReq(req, db));
  writeDB(db);

  // Retorna o token APENAS NESTE MOMENTO (nunca mais será visível)
  res.json({
    token,
    aviso: 'ATENÇÃO: Copie e guarde este token agora. Ele não será exibido novamente.'
  });
});

// GET /api/tokens/list — lista tokens (sem mostrar o token real)
app.get('/api/tokens/list', (req, res) => {
  const db = readDB();
  const tokens = (db.api_tokens || []).map(t => ({
    id: t.id,
    nome: t.nome,
    preview: t.preview,
    ativo: t.ativo,
    criado: t.criado,
    criadoPor: t.criadoPor,
    ultimoUso: t.ultimoUso,
    totalReqs: t.totalReqs || 0
  }));
  res.json(tokens);
});

// POST /api/tokens/revoke/:id — revoga um token
app.post('/api/tokens/revoke/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const db = readDB();
  const token = (db.api_tokens || []).find(t => t.id === id);
  if (!token) return res.status(404).json({ error: 'Token não encontrado.' });
  token.ativo = false;
  audit(db, 'api_token_revogado', { tokenId: token.id, nome: token.nome }, null, _userInfoFromReq(req, db));
  writeDB(db);
  res.json({ ok: true, message: 'Token revogado com sucesso.' });
});

// GET /api/tokens/logs — logs de acesso
app.get('/api/tokens/logs', (req, res) => {
  const db = readDB();
  res.json((db.api_logs || []).slice(0, 100));
});

// ══════════════════════════════════════════════
// ── API v1 — ENDPOINTS PÚBLICOS (com auth) ──
// ══════════════════════════════════════════════

// ── DEMANDAS ──
app.get('/api/v1/demandas', authAPI, (req, res) => {
  const db = readDB();
  let tasks = db.store.tasks || [];
  const { status, responsavel, atrasadas, limit } = req.query;
  if (status) tasks = tasks.filter(t => t.status === status);
  if (responsavel) tasks = tasks.filter(t => t.resp === responsavel || t.respId === responsavel);
  if (atrasadas === 'true') {
    const hoje = new Date().toISOString().split('T')[0];
    tasks = tasks.filter(t => t.data && t.data < hoje && t.status !== 'Concluída');
  }
  if (limit) tasks = tasks.slice(0, parseInt(limit));
  // Remove dados sensíveis
  tasks = tasks.map(t => ({ ...t, cmts: undefined }));
  res.json({ total: tasks.length, demandas: tasks });
});

app.get('/api/v1/demandas/:id', authAPI, (req, res) => {
  const db = readDB();
  const id = parseInt(req.params.id);
  const task = (db.store.tasks || []).find(t => t.id === id);
  if (!task) return res.status(404).json({ error: 'Demanda não encontrada.' });
  res.json(task);
});

app.post('/api/v1/demandas', authAPI, (req, res) => {
  const { nome, status, resp, respId, nichoId, ofertaId, desc, data } = req.body;
  if (!nome) return res.status(400).json({ error: 'Campo "nome" obrigatório.' });
  const db = readDB();
  if (!db.store.tasks) db.store.tasks = [];
  const novaDemanda = {
    id: Date.now(),
    nome, status: status || 'BACKLOG', resp: resp || '', respId: respId || '',
    nichoId: nichoId || '', ofertaId: ofertaId || '',
    desc: desc || '', data: data || '',
    criado: new Date().toLocaleString('pt-BR'),
    arquivado: false, cmts: []
  };
  db.store.tasks.push(novaDemanda);
  db.timestamps.tasks = now();
  writeDB(db);
  res.status(201).json(novaDemanda);
});

app.patch('/api/v1/demandas/:id', authAPI, (req, res) => {
  const db = readDB();
  const id = parseInt(req.params.id);
  const tasks = db.store.tasks || [];
  const idx = tasks.findIndex(t => t.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Demanda não encontrada.' });
  Object.assign(tasks[idx], req.body);
  db.timestamps.tasks = now();
  writeDB(db);
  res.json(tasks[idx]);
});

// ── CRIATIVOS ──
app.get('/api/v1/criativos', authAPI, (req, res) => {
  const db = readDB();
  let criativos = db.store.criativos || [];
  const { nicho, oferta, status } = req.query;
  if (nicho) criativos = criativos.filter(c => c.nichoId === nicho || c.nichoNome === nicho);
  if (oferta) criativos = criativos.filter(c => c.ofertaId === oferta || c.ofertaNome === oferta);
  if (status) criativos = criativos.filter(c => c.status === status);
  res.json({ total: criativos.length, criativos });
});

app.get('/api/v1/criativos/:id', authAPI, (req, res) => {
  const db = readDB();
  const id = parseInt(req.params.id);
  const c = (db.store.criativos || []).find(x => x.id === id);
  if (!c) return res.status(404).json({ error: 'Criativo não encontrado.' });
  res.json(c);
});

// ── MÉTRICAS ──
app.get('/api/v1/metricas/resumo', authAPI, (req, res) => {
  const db = readDB();
  const tasks = db.store.tasks || [];
  const criativos = db.store.criativos || [];
  const hoje = new Date().toISOString().split('T')[0];
  const pendentes = tasks.filter(t => t.status !== 'Concluída' && !t.arquivado);
  const atrasadas = tasks.filter(t => t.data && t.data < hoje && t.status !== 'Concluída' && !t.arquivado);
  const concluidas = tasks.filter(t => t.status === 'Concluída');
  res.json({
    demandas: {
      total: tasks.length,
      pendentes: pendentes.length,
      atrasadas: atrasadas.length,
      concluidas: concluidas.length
    },
    criativos: {
      total: criativos.length,
      remessas: criativos.length,
      adsTotal: criativos.reduce((s, c) => s + (c.ads || []).length, 0),
      adsValidados: criativos.reduce((s, c) => s + (c.ads || []).filter(a => a.validado || a.adStatus === 'Validado').length, 0)
    },
    geradoEm: new Date().toISOString()
  });
});

// ── USUÁRIOS ──
app.get('/api/v1/usuarios', authAPI, (req, res) => {
  const db = readDB();
  const usuarios = (db.store['sl_usuarios'] || []).map(u => ({
    id: u.id, nome: u.nome, email: u.email, cargo: u.cargo, ativo: u.ativo
  }));
  res.json(usuarios);
});

// ── NOTIFICAÇÕES ──
app.get('/api/v1/notificacoes', authAPI, (req, res) => {
  const db = readDB();
  const { userId } = req.query;
  let notifs = db.store['sl_notifs'] || [];
  if (userId) notifs = notifs.filter(n => n.destId === userId);
  res.json({ total: notifs.length, notificacoes: notifs.slice(0, 50) });
});

// ── CHAT ──
app.get('/api/v1/chat/mensagens', authAPI, (req, res) => {
  const db = readDB();
  const msgs = db.store.msgs || [];
  const { limit } = req.query;
  const lim = parseInt(limit) || 50;
  res.json({ total: msgs.length, mensagens: msgs.slice(-lim) });
});

app.post('/api/v1/chat/enviar', authAPI, (req, res) => {
  const { nome, texto } = req.body;
  if (!texto) return res.status(400).json({ error: 'Campo "texto" obrigatório.' });
  const db = readDB();
  if (!db.store.msgs) db.store.msgs = [];
  const msg = {
    id: Date.now(),
    nome: nome || 'API',
    texto,
    hora: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
  };
  db.store.msgs.push(msg);
  db.timestamps.msgs = now();
  writeDB(db);
  res.status(201).json(msg);
});

// ── DADOS GENÉRICOS (pra agente acessar qualquer coisa) ──
app.get('/api/v1/dados/:chave', authAPI, (req, res) => {
  const db = readDB();
  const val = db.store[req.params.chave];
  if (val === undefined) return res.status(404).json({ error: 'Chave não encontrada: ' + req.params.chave });
  res.json(val);
});

// ══════════════════════════════════════════════
// ── SPY WOLF · webhook de import ──
// Recebe resultado da skill spy-wolf (Claude Cowork) e popula sl_spy_auto.
// Aceita 2 formatos: { dominios: [...] } estruturado OU { rawText: "..." } pra parser.
// ══════════════════════════════════════════════

// Blacklist global de falsos positivos (mesma do frontend)
const SPY_BLACKLIST = new Set([
  'M.READHARBOR.COM','M.BOOKPATHWAY.NET','M.CHAPTERHAVEN.COM','M.THENEURODEFENDER.COM','M.HEALTHVEXA.ONLINE','M.PUREXO.ONLINE','M.HOTBUKU.COM',
  'W2A.SHORTTV.LIVE','FB.DRAMABOX.COM','FIND.ALPHA-SPECIALS.COM','TRY.LUHXE.COM',
  'ABOUT.BUGMD.COM','SENZIO.STORE','EVELABS.STORE','VITALCURE.SHOP','LIVERCLEANSEPROTOCOL.COM','RED.TRK.ANCHORPIXEL.COM','EVERYDAYHUBONLINE.COM',
  'TRK.MRTTRCK.COM','FIND.INFO-ROADS.COM','NEW.FAST-GUIDES.COM','TRY.PRIMALS.SHOP','OFFER.NEBROO.COM','TRY.PRIMITIVELABSRESEARCH.COM','TRY.NOURIAL.COM',
  'GELIXER.COM','PILLS.MOERIE.COM','GO.KINGKONG.CO','SHOP.GETAMALAHEALTH.COM','NEUROEDGELAB.COM','OUTFIELDORGANICS.COM',
  'COLONBROOM.COM','SHOP.THEBETTYROCKER.COM','GET.METABOOSTING.COM','MEMBERS.WARRIORBABE.COM','MERAKIFITNESS.NET','GREENCHEF.COM','THESMOOTHIEBOMBS.COM','THESALADHOUSE.COM','TRIAL.HEALTHBOX.ME','FREEZERFIT.COM','PEACHFIT.COM','PROJECTSLIFESTYLE.CO',
  'EDCURE.COM','COLOPLAST.TO','LABOMBITA.COM','AQUABLATIONDALLAS.COM','INFO.UROLIFT.COM','QUIZ.PEPTONIX.COM','PEPTONIX.COM','TRYSOLUMA.COM',
  'ALEVIA.COM','PRODROME.COM','GO.VISIONCLARITYLAB.COM','BUYMAIA.COM','TRY-EDENLABS.COM','TRY.PLOISE.COM'
]);

// Detecta domínio suspeito (mesma heurística do frontend)
function _spyDominioSuspeito(host) {
  if (!host) return null;
  const H = host.toUpperCase();
  if (SPY_BLACKLIST.has(H)) return { tipo:'blacklist', motivo:'Falso positivo conhecido' };
  if (/^[0-9]/.test(H) || (/\.[A-Z]{2,4}$/.test(H) && /[0-9]{3,}/.test(H.split('.')[0]))) {
    return { tipo:'random', motivo:'Domínio com números — possível token-matching' };
  }
  return null;
}

// Parser de domínios em texto livre (mesma lógica do frontend)
function _spyParsearTexto(texto) {
  if (!texto || typeof texto !== 'string') return [];
  const dominioRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  const matches = texto.match(dominioRegex) || [];
  const dominiosMap = {};
  matches.forEach(d => {
    const H = d.toUpperCase().replace(/^WWW\./, '');
    if (/^(FACEBOOK|META|INSTAGRAM|WHATSAPP|FB|GOOGLE|YOUTUBE|AMAZON|APPLE|CDN|FBCDN|MESSENGER|HTTPS|HTTP)/.test(H)) return;
    if (H.length < 6) return;
    if (!dominiosMap[H]) {
      // Tenta extrair volume próximo
      const idx = texto.toUpperCase().indexOf(H);
      const snippet = idx >= 0 ? texto.substr(Math.max(0, idx - 100), 300) : '';
      const volMatch = snippet.match(/(\d[\d.,]*)\s*(k|K|mil|thousand|\bads\b)/);
      let volume = 0;
      if (volMatch) {
        let n = parseFloat(volMatch[1].replace(/\./g, '').replace(',', '.'));
        if (volMatch[2] && /k|K|mil|thousand/i.test(volMatch[2])) n *= 1000;
        volume = Math.round(n);
      }
      dominiosMap[H] = { host: H, volume };
    }
  });
  return Object.values(dominiosMap);
}

// POST /api/spy/import  — webhook que a skill spy-wolf chama
// Body: { nichoId: 'nic-emag', dominios?: [...], rawText?: '...', broadcast?: true }
//   broadcast:true → salva em sl_spy_master (visível pra TODOS os tenants)
//                    Só funciona se o token tiver flag master:true (token "spy-wolf-master")
app.post('/api/spy/import', authAPI, (req, res) => {
  try {
    const { nichoId, dominios, rawText, runMeta, broadcast } = req.body || {};
    if (!nichoId) return res.status(400).json({ error: 'Campo obrigatório: nichoId' });
    if (!Array.isArray(dominios) && !rawText) {
      return res.status(400).json({ error: 'Forneça `dominios` (array) ou `rawText` (string).' });
    }

    const db = readDB();
    // Master mode: salva em sl_spy_master (global, lido por todos os tenants)
    // Modo normal: salva em sl_spy_auto (privado do tenant que fez o request)
    const isMaster = broadcast === true && req.apiToken && req.apiToken.master === true;
    const storeKey = isMaster ? 'sl_spy_master' : 'sl_spy_auto';
    const bibs = db.store[storeKey] || [];
    const nichos = db.store['sl_spy_auto_nichos'] || [];
    const nicho = nichos.find(n => n.id === nichoId);
    if (!nicho) return res.status(404).json({ error: `Nicho não encontrado: ${nichoId}` });

    // Combina dominios estruturados + parse do rawText
    let candidatos = Array.isArray(dominios) ? dominios.slice() : [];
    if (rawText) {
      const parsed = _spyParsearTexto(rawText);
      parsed.forEach(p => {
        if (!candidatos.find(c => (c.host || '').toUpperCase() === p.host)) candidatos.push(p);
      });
    }

    if (!candidatos.length) return res.status(400).json({ error: 'Nenhum domínio detectado.' });

    // Map de existentes por host (uppercase)
    const existentes = {};
    bibs.forEach(b => { existentes[(b.nomePagina || '').toUpperCase()] = b; });

    let novos = 0, atualizados = 0, blacklisted = 0, suspeitos = 0;
    const detalhes = [];

    candidatos.forEach(cand => {
      const host = String(cand.host || cand.dominio || '').toUpperCase().trim();
      if (!host || host.length < 6) return;

      const suspeitoInfo = _spyDominioSuspeito(host);
      if (suspeitoInfo && suspeitoInfo.tipo === 'blacklist') {
        blacklisted++;
        detalhes.push({ host, status: 'blacklisted', motivo: suspeitoInfo.motivo });
        return;
      }

      const volume = Number(cand.volume || cand.adsAtivos || 0);
      const linkBiblioteca = cand.linkBiblioteca || `https://www.facebook.com/ads/library/?active_status=active&ad_type=all&country=ALL&q=%22${encodeURIComponent(host)}%22&search_type=keyword_exact_phrase&sort_data[mode]=total_impressions&sort_data[direction]=desc`;

      if (suspeitoInfo && suspeitoInfo.tipo === 'random') {
        suspeitos++;
        detalhes.push({ host, status: 'suspeito', motivo: suspeitoInfo.motivo });
      }

      if (existentes[host]) {
        // Atualiza — mantém histórico de ads anteriores pra calcular variação
        const b = existentes[host];
        b.adsAnteriores = b.adsAtivos || 0;
        if (volume > 0) {
          b.adsAtivos = volume;
          b.varAds24h = volume - b.adsAnteriores;
        }
        if (cand.copy) b.notas = (b.notas || '') + ` | copy: ${String(cand.copy).slice(0, 200)}`;
        if (cand.advertisers) b.notas = (b.notas || '') + ` | adv: ${String(cand.advertisers).slice(0, 200)}`;
        b.isNova = false;
        b._updatedAt = Date.now() / 1000;
        atualizados++;
      } else {
        // Cria novo
        const novoId = 'bib-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
        const novo = {
          id: novoId,
          nomePagina: host,
          handles: cand.handles || '',
          nichoId: nichoId,
          linkBiblioteca: linkBiblioteca,
          adsAtivos: volume,
          adsAnteriores: 0,
          varAds24h: 0,
          isNova: true,
          notas: `Importado via webhook Spy Wolf em ${new Date().toLocaleDateString('pt-BR')}`
            + (cand.copy ? ` | copy: ${String(cand.copy).slice(0, 200)}` : '')
            + (cand.advertisers ? ` | advertisers: ${String(cand.advertisers).slice(0, 200)}` : '')
            + (suspeitoInfo && suspeitoInfo.tipo === 'random' ? ' | ⚠️ VERIFICAR COPY (números aleatórios)' : ''),
          _criadoEm: new Date().toISOString(),
          _updatedAt: Date.now() / 1000
        };
        bibs.push(novo);
        novos++;
      }
    });

    // Salva no DB (no storeKey correto — master ou tenant)
    db.store[storeKey] = bibs;
    db.timestamps[storeKey] = Date.now() / 1000;

    // Atualiza last-run do nicho
    const nichoIdx = nichos.findIndex(n => n.id === nichoId);
    if (nichoIdx >= 0) {
      nichos[nichoIdx].ultimaBusca = new Date().toISOString();
      nichos[nichoIdx].ultimoRun = {
        timestamp: new Date().toISOString(),
        novos, atualizados, blacklisted, suspeitos,
        totalProcessados: candidatos.length,
        modo: isMaster ? 'master' : 'privado',
        meta: runMeta || null
      };
      db.store['sl_spy_auto_nichos'] = nichos;
      db.timestamps['sl_spy_auto_nichos'] = Date.now() / 1000;
    }

    writeDB(db);

    res.json({
      ok: true,
      modo: isMaster ? 'master (visível pra todos os tenants)' : 'privado (só este tenant)',
      nicho: nicho.nome,
      novos,
      atualizados,
      blacklisted,
      suspeitos,
      totalProcessados: candidatos.length,
      detalhes
    });
  } catch (err) {
    console.error('[/api/spy/import]', err);
    res.status(500).json({ error: 'Erro interno: ' + err.message });
  }
});

// ══════════════════════════════════════════════
// ── EMAIL TRANSACIONAL (Resend) ──
// Configurar RESEND_API_KEY no Railway (https://resend.com)
// Free tier: 100 emails/dia, 3000/mês
// ══════════════════════════════════════════════
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM = process.env.RESEND_FROM || 'TMX Digital <noreply@centralaxcend.com>';

async function _enviarEmail({ to, subject, html, text, replyTo }) {
  try {
    if (!RESEND_API_KEY) {
      console.warn('[email] RESEND_API_KEY não configurada, log fake:', { to, subject });
      return { ok: false, motivo: 'RESEND_API_KEY não configurada', mock: true };
    }
    const payload = {
      from: RESEND_FROM,
      to: Array.isArray(to) ? to : [to],
      subject,
      html: html || `<p>${text || ''}</p>`,
      text: text || (html ? html.replace(/<[^>]+>/g, '') : '')
    };
    if (replyTo) payload.reply_to = replyTo;
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + RESEND_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    if (!resp.ok) {
      console.error('[email] erro Resend:', data);
      return { ok: false, erro: data.message || JSON.stringify(data) };
    }
    return { ok: true, id: data.id };
  } catch (err) {
    console.error('[email]', err.message);
    return { ok: false, erro: err.message };
  }
}

// Templates de email (HTML embutido, mas pode ser extraído depois)
function _emailTemplateBase(corpo) {
  return `
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:560px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08);">
    <div style="background:linear-gradient(135deg,#5b5ef4,#3E1493);padding:24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:24px;font-weight:800;">TMX Digital</h1>
    </div>
    <div style="padding:32px 28px;color:#333;line-height:1.6;font-size:15px;">
      ${corpo}
    </div>
    <div style="background:#f9f9f9;padding:18px;text-align:center;font-size:12px;color:#999;border-top:1px solid #eee;">
      TMX Digital · Sistema de gestão pra Direct Response<br>
      <a href="https://app.centralaxcend.com" style="color:#5b5ef4;text-decoration:none;">app.centralaxcend.com</a>
    </div>
  </div>
</body></html>`;
}

function _emailTemplateResetSenha(nome, linkReset) {
  return _emailTemplateBase(`
    <h2 style="margin:0 0 16px 0;font-size:22px;">🔐 Resetar sua senha</h2>
    <p>Oi ${nome || 'tudo bem'}!</p>
    <p>Recebemos um pedido pra resetar a senha da sua conta no TMX Digital.</p>
    <p>Clica no botão abaixo pra criar uma nova senha (link válido por <b>1 hora</b>):</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${linkReset}" style="display:inline-block;background:linear-gradient(135deg,#5b5ef4,#3E1493);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;">Criar nova senha</a>
    </p>
    <p style="font-size:13px;color:#666;">Ou cole esta URL no navegador:<br><code style="background:#f0f0f0;padding:6px 10px;border-radius:4px;font-size:11px;word-break:break-all;">${linkReset}</code></p>
    <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
    <p style="font-size:13px;color:#999;">Se você não pediu isso, é só ignorar — ninguém vai alterar nada sem clicar no link.</p>
  `);
}

function _emailTemplateBoasVindas(nome, urlPainel) {
  return _emailTemplateBase(`
    <h2 style="margin:0 0 16px 0;font-size:22px;">🎉 Bem-vindo ao TMX Digital, ${nome || 'tudo bem'}!</h2>
    <p>Sua conta foi criada com sucesso. Você tem <b>14 dias grátis</b> pra testar tudo.</p>
    <p>Acesse seu painel:</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${urlPainel}" style="display:inline-block;background:linear-gradient(135deg,#5b5ef4,#3E1493);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;">Abrir meu painel</a>
    </p>
    <h3 style="font-size:16px;margin:24px 0 10px;">🚀 Primeiros passos:</h3>
    <ul style="padding-left:20px;color:#555;">
      <li>Adicione sua equipe em Configurações → Usuários</li>
      <li>Personalize as cores em Configurações → Branding</li>
      <li>Conecte WhatsApp em Configurações → WhatsApp (opcional)</li>
      <li>Crie sua primeira demanda</li>
    </ul>
    <p style="font-size:13px;color:#999;margin-top:24px;">Dúvidas? Responde esse email ou fala com <a href="mailto:suporte@centralaxcend.com" style="color:#5b5ef4;">suporte@centralaxcend.com</a></p>
  `);
}

function _emailTemplatePagamentoConfirmado(nome, plano, valor) {
  return _emailTemplateBase(`
    <h2 style="margin:0 0 16px 0;font-size:22px;">✅ Pagamento confirmado!</h2>
    <p>Oi ${nome || ''}, recebemos seu pagamento. Plano <b>${plano}</b> ativado.</p>
    <div style="background:#f9f9f9;padding:16px;border-radius:8px;margin:20px 0;">
      <div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span>Plano:</span><b>${plano}</b></div>
      <div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span>Valor:</span><b>R$ ${valor.toFixed(2).replace('.', ',')}</b></div>
      <div style="display:flex;justify-content:space-between;"><span>Próxima cobrança:</span><b>${new Date(Date.now() + 30*24*60*60*1000).toLocaleDateString('pt-BR')}</b></div>
    </div>
    <p>A nota fiscal será emitida em até 24h e enviada por email.</p>
    <p style="font-size:13px;color:#999;">Pra cancelar ou trocar de plano, acesse Configurações → Meu Plano.</p>
  `);
}

function _emailTemplatePagamentoFalhado(nome, plano, tentativa, max) {
  return _emailTemplateBase(`
    <h2 style="margin:0 0 16px 0;font-size:22px;color:#DC2626;">⚠️ Não conseguimos cobrar seu cartão</h2>
    <p>Oi ${nome || ''}, a renovação do plano <b>${plano}</b> falhou.</p>
    <p style="background:rgba(220,38,38,.1);color:#DC2626;padding:12px;border-radius:8px;font-weight:700;">Tentativa ${tentativa} de ${max}.</p>
    <p>Verifique seu cartão e atualize os dados em Configurações → Meu Plano antes que a conta seja suspensa.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="https://app.centralaxcend.com/" style="display:inline-block;background:linear-gradient(135deg,#5b5ef4,#3E1493);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;">Atualizar pagamento</a>
    </p>
  `);
}

// POST /api/email/test — envia email de teste (Diretoria)
app.post('/api/email/test', authDiretoria, async (req, res) => {
  try {
    const { to } = req.body || {};
    if (!to || !to.includes('@')) return res.status(400).json({ error: 'email destinatário inválido' });
    const r = await _enviarEmail({
      to,
      subject: '🧪 Teste do TMX Digital',
      html: _emailTemplateBase(`<h2>Funcionou!</h2><p>Esse é um email de teste enviado do TMX Digital. Se você recebeu, a integração com Resend está OK.</p><p style="font-size:13px;color:#999;">Enviado em ${new Date().toLocaleString('pt-BR')}</p>`)
    });
    res.json(r);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── RESET DE SENHA + 2FA ──
// Fluxo: usuário esquece → digita email → recebe link único → cria nova senha
// ══════════════════════════════════════════════

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hora

// POST /api/auth/forgot — usuário pede reset
app.post('/api/auth/forgot', loginLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email inválido' });
    const db = readDB();
    const usuarios = db.store['sl_usuarios'] || [];
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    // Filtra por tenant do host atual + email
    const user = usuarios.find(u =>
      u && u.email && u.email.toLowerCase() === email.toLowerCase() &&
      u.ativo !== false &&
      getItemTenant(u) === tenantId
    );
    // Sempre responde sucesso (não vaza info de email existente)
    if (!user) {
      audit(db, 'reset_senha_solicitado_invalido', { email, tenantId }, { ip: req.ip }, null);
      writeDB(db);
      return res.json({ ok: true, mensagem: 'Se o email existir, você vai receber um link de reset em alguns segundos.' });
    }

    // Gera token de reset
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    user.resetSenha = {
      hash: tokenHash,
      criadoEm: new Date().toISOString(),
      expira: new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString()
    };
    user._updatedAt = Date.now();
    db.timestamps['sl_usuarios'] = now();
    audit(db, 'reset_senha_solicitado', { userId: user.id, email }, { ip: req.ip }, { id: user.id, nome: user.nome, cargo: user.cargo });
    writeDB(db);

    // Monta URL baseada no host
    const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
    const baseUrl = tenant && tenant.slug && tenantId !== TENANT_INTERNO_ID
      ? `https://${tenant.slug}.${SAAS_ROOT_DOMAIN}`
      : 'https://app.centralaxcend.com';
    const linkReset = `${baseUrl}/reset-senha?token=${token}`;

    // Envia email
    const emailResult = await _enviarEmail({
      to: user.email,
      subject: '🔐 Resetar senha · TMX Digital',
      html: _emailTemplateResetSenha(user.nome, linkReset)
    });

    res.json({
      ok: true,
      mensagem: 'Se o email existir, você vai receber um link de reset em alguns segundos.',
      emailEnviado: emailResult.ok,
      // Em modo dev (sem RESEND_API_KEY), retorna o link pra debug:
      _dev: !RESEND_API_KEY ? { linkReset, motivo: 'RESEND_API_KEY não configurada' } : undefined
    });
  } catch (err) {
    console.error('[auth/forgot]', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/reset — confirma novo password
app.post('/api/auth/reset', loginLimiter, (req, res) => {
  try {
    const { token, novaSenha } = req.body || {};
    if (!token || !novaSenha) return res.status(400).json({ error: 'Token e nova senha obrigatórios' });
    if (novaSenha.length < 6) return res.status(400).json({ error: 'Senha precisa ter no mínimo 6 caracteres' });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const db = readDB();
    const usuarios = db.store['sl_usuarios'] || [];
    const user = usuarios.find(u => u.resetSenha && u.resetSenha.hash === tokenHash);
    if (!user) return res.status(401).json({ error: 'Link inválido ou já usado' });
    if (new Date(user.resetSenha.expira) < new Date()) return res.status(401).json({ error: 'Link expirou. Solicite um novo reset.' });

    // Atualiza senha
    user.senhaHash = bcrypt.hashSync(String(novaSenha), BCRYPT_ROUNDS);
    delete user.senha; // remove campo legado se existir
    delete user.resetSenha;
    user._updatedAt = Date.now();
    db.timestamps['sl_usuarios'] = now();
    audit(db, 'reset_senha_concluido', { userId: user.id, email: user.email }, { ip: req.ip }, { id: user.id, nome: user.nome, cargo: user.cargo });
    writeDB(db);

    res.json({ ok: true, mensagem: 'Senha alterada com sucesso! Faça login com a nova senha.' });
  } catch (err) {
    console.error('[auth/reset]', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /reset-senha — serve a página de reset
app.get('/reset-senha', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-senha.html'));
});

// ══════════════════════════════════════════════
// ── MINHA CONTA (usuário edita dados próprios) ──
// ══════════════════════════════════════════════
function _authUser(req, db) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return null;
  const sess = validarSessao(db, token);
  if (!sess) return null;
  const user = (db.store['sl_usuarios'] || []).find(u => u.id === sess.userId);
  return user || null;
}

// POST /api/me/trocar-senha — usuário troca a própria senha (precisa senha atual)
app.post('/api/me/trocar-senha', (req, res) => {
  try {
    const db = readDB();
    const user = _authUser(req, db);
    if (!user) return res.status(401).json({ error: 'Não autenticado' });
    const { senhaAtual, novaSenha } = req.body || {};
    if (!senhaAtual || !novaSenha) return res.status(400).json({ error: 'Senha atual e nova senha obrigatórios' });
    if (novaSenha.length < 6) return res.status(400).json({ error: 'Nova senha precisa ter no mínimo 6 caracteres' });

    // Valida senha atual
    let ok = false;
    if (user.senhaHash) {
      try { ok = bcrypt.compareSync(String(senhaAtual), user.senhaHash); } catch { ok = false; }
    } else if (user.senha) {
      ok = (user.senha === senhaAtual);
    }
    if (!ok) {
      audit(db, 'me_trocar_senha_falhou', { userId: user.id }, null, { id: user.id, nome: user.nome, cargo: user.cargo });
      writeDB(db);
      return res.status(401).json({ error: 'Senha atual incorreta' });
    }

    user.senhaHash = bcrypt.hashSync(String(novaSenha), BCRYPT_ROUNDS);
    delete user.senha;
    user._updatedAt = Date.now();
    db.timestamps['sl_usuarios'] = now();
    audit(db, 'me_trocar_senha', { userId: user.id }, null, { id: user.id, nome: user.nome, cargo: user.cargo });
    writeDB(db);
    res.json({ ok: true, mensagem: 'Senha alterada com sucesso!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/me — atualiza dados do próprio usuário (nome, telefone, foto)
app.put('/api/me', (req, res) => {
  try {
    const db = readDB();
    const user = _authUser(req, db);
    if (!user) return res.status(401).json({ error: 'Não autenticado' });
    const body = req.body || {};
    if (body.nome) user.nome = String(body.nome).trim().slice(0, 100);
    if (body.whatsapp !== undefined) user.whatsapp = String(body.whatsapp).trim().slice(0, 30);
    if (body.fotoUrl !== undefined) user.fotoUrl = String(body.fotoUrl).trim().slice(0, 500);
    user._updatedAt = Date.now();
    db.timestamps['sl_usuarios'] = now();
    audit(db, 'me_editar', { userId: user.id, campos: Object.keys(body) }, null, { id: user.id, nome: user.nome, cargo: user.cargo });
    writeDB(db);
    const { senha, senhaHash, resetSenha, ...safeUser } = user;
    res.json({ ok: true, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/me/sessoes — lista sessões ativas do usuário
app.get('/api/me/sessoes', (req, res) => {
  try {
    const db = readDB();
    const user = _authUser(req, db);
    if (!user) return res.status(401).json({ error: 'Não autenticado' });
    const sessoes = (db.sessions || []).filter(s => s.userId === user.id).map(s => ({
      id: s.tokenHash.slice(0, 12) + '...',
      criadaEm: s.criadaEm,
      ultimaAtividade: s.lastActivity,
      atual: s.tokenHash === crypto.createHash('sha256').update((req.headers.authorization||'').split(' ')[1]||'').digest('hex')
    }));
    res.json({ ok: true, sessoes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── IA REAL DE COPY (Direct Response) ──
// Geração + análise de copy especializada em DR usando Claude.
// 5 endpoints: headlines, anúncio completo, variações, análise, advertorial.
// ══════════════════════════════════════════════

const IA_COPY_MODEL = 'claude-sonnet-4-5-20250929';

// Helper genérico pra chamar Claude com prompt do sistema + user
async function _chamarClaudeCopy(systemPrompt, userPrompt, maxTokens = 2000) {
  const aiKey = _getAIKey();
  if (!aiKey) throw new Error('Configure ANTHROPIC_API_KEY no Railway pra usar IA de copy');
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': aiKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: IA_COPY_MODEL,
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }]
    })
  });
  if (!r.ok) { const err = await r.text(); throw new Error(`Claude ${r.status}: ${err.slice(0,300)}`); }
  const data = await r.json();
  return data.content[0]?.text || '';
}

// System prompt base — define a expertise do agente
const SYSTEM_PROMPT_DR = `Você é um copywriter expert em Direct Response Marketing (DR), especializado em copy brasileiro pra Meta Ads, Google Ads, advertoriais e VSLs.

Seu estilo:
- Direto e emocional, não corporativo
- Usa gatilhos comprovados de DR (curiosidade, urgência, prova social, autoridade, contraste)
- PT-BR coloquial, sem jargão técnico
- Hooks em até 8 palavras, com tensão narrativa
- Promessas específicas (números, prazos) > genéricas
- Adapta tom ao nicho (mais médico em saúde, mais agressivo em emagrecimento, etc.)

NUNCA faça:
- Promessas absurdas que infringem políticas Meta (curas milagrosas, garantias de renda)
- Copy genérico sem ângulo claro
- Linguagem corporativa ("solução inovadora", "tecnologia de ponta")
- Listas grandes sem priorizar

SEMPRE responda em formato JSON quando solicitado, sem markdown extra.`;

// POST /api/ia/copy/headlines — gera 10 headlines pra um produto
app.post('/api/ia/copy/headlines', async (req, res) => {
  try {
    const { nicho, produto, dor, promessa, prova, angulo } = req.body || {};
    if (!produto && !nicho) return res.status(400).json({ error: 'Informe ao menos produto ou nicho' });

    const userPrompt = `Gere 10 HEADLINES de Direct Response pra:

Nicho: ${nicho || 'não especificado'}
Produto: ${produto || '—'}
Dor que resolve: ${dor || '—'}
Promessa principal: ${promessa || '—'}
Prova/diferencial: ${prova || '—'}
Ângulo desejado: ${angulo || 'variar entre curiosidade, prova social, contraste, urgência'}

Cada headline deve ter no MÁXIMO 12 palavras, em PT-BR coloquial. Varie os gatilhos.

Responda APENAS com JSON neste formato exato (sem markdown):
{
  "headlines": [
    {"texto": "...", "gatilho": "curiosidade|prova-social|urgencia|contraste|autoridade", "tom": "..."},
    ...
  ]
}`;
    const txt = await _chamarClaudeCopy(SYSTEM_PROMPT_DR, userPrompt, 1500);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, ...parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ia/copy/anuncio — gera anúncio completo pronto pra Meta
app.post('/api/ia/copy/anuncio', async (req, res) => {
  try {
    const { nicho, produto, dor, promessa, prova, formato, plataforma } = req.body || {};
    if (!produto) return res.status(400).json({ error: 'Produto obrigatório' });
    const fmt = formato || 'feed_image';
    const plat = plataforma || 'meta';

    const userPrompt = `Gere um ANÚNCIO COMPLETO de Direct Response pra ${plat.toUpperCase()} (formato: ${fmt}):

Nicho: ${nicho || '—'}
Produto: ${produto}
Dor: ${dor || '—'}
Promessa: ${promessa || '—'}
Prova: ${prova || '—'}

Responda APENAS com JSON neste formato (sem markdown):
{
  "headline": "máx 8 palavras",
  "subheadline": "máx 15 palavras (opcional, pra reforço)",
  "primary_text": "texto principal que aparece acima do criativo, 3-5 parágrafos curtos, com hooks, dor amplificada, promessa e CTA",
  "description": "máx 20 palavras (aparece embaixo da imagem)",
  "cta_button": "Saiba mais | Comprar agora | Inscrever-se | Baixar | Cadastrar",
  "angulo": "qual gatilho/ângulo usado",
  "observacoes": "dicas de teste A/B"
}`;
    const txt = await _chamarClaudeCopy(SYSTEM_PROMPT_DR, userPrompt, 2000);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, anuncio: parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ia/copy/variacoes — varia uma copy existente em N versões
app.post('/api/ia/copy/variacoes', async (req, res) => {
  try {
    const { copyOriginal, quantidade, tipoVariacao } = req.body || {};
    if (!copyOriginal) return res.status(400).json({ error: 'copyOriginal obrigatório' });
    const qtd = Math.min(10, Math.max(3, parseInt(quantidade) || 5));
    const tipo = tipoVariacao || 'estrutura';

    const userPrompt = `Crie ${qtd} VARIAÇÕES dessa copy mudando o ${tipo}:

COPY ORIGINAL:
"""
${copyOriginal}
"""

Tipos possíveis:
- estrutura: muda como a copy é montada (ordem dos elementos)
- angulo: muda o ângulo de venda (de curiosidade pra prova, etc)
- tom: muda o tom (mais agressivo, mais médico, mais informal, etc)
- comprimento: faz versões mais curtas e mais longas
- gancho: testa novos hooks de abertura

Mantenha a essência da promessa mas varie a abordagem. Responda APENAS com JSON:
{
  "variacoes": [
    {"id": 1, "texto": "...", "mudancaPrincipal": "..."},
    ...
  ]
}`;
    const txt = await _chamarClaudeCopy(SYSTEM_PROMPT_DR, userPrompt, 3000);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, ...parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ia/copy/analise — analisa copy existente (forças, fraquezas, sugestões)
app.post('/api/ia/copy/analise', async (req, res) => {
  try {
    const { copy, contexto } = req.body || {};
    if (!copy) return res.status(400).json({ error: 'copy obrigatório' });

    const userPrompt = `Analise essa copy de Direct Response criticamente:

COPY:
"""
${copy}
"""

Contexto adicional: ${contexto || 'não informado'}

Dê uma análise estruturada como expert em DR. Responda APENAS com JSON:
{
  "nota": "0-100 (avaliação geral)",
  "veredito": "1 frase resumo",
  "forcas": ["3-5 pontos fortes específicos da copy"],
  "fraquezas": ["3-5 pontos fracos específicos"],
  "sugestoes": ["5-7 sugestões CONCRETAS de melhoria"],
  "elementos": {
    "hook": "avaliação do hook (1-10) + comentário",
    "promessa": "avaliação da promessa + comentário",
    "prova": "avaliação da prova social/autoridade",
    "cta": "avaliação do CTA"
  },
  "publico_alvo_provavel": "quem essa copy mira",
  "riscos_compliance": "alertas sobre políticas Meta (se houver)"
}`;
    const txt = await _chamarClaudeCopy(SYSTEM_PROMPT_DR, userPrompt, 2500);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, analise: parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ia/analise-ads — análise preditiva de criativo (escalar/pausar/manter)
app.post('/api/ia/analise-ads', async (req, res) => {
  try {
    const { nome, formato, ctr, cpm, cpc, roas, hookRate, holdRate, convCheckout, diasRodando, investido, faturado, tendenciaCpm, tendenciaCtr, comentarios } = req.body || {};
    if (!nome) return res.status(400).json({ error: 'Nome do anúncio obrigatório' });

    const systemPrompt = `Você é um analista expert em tráfego pago de Direct Response. Analisa métricas de criativos e prevê se devem ESCALAR, PAUSAR ou MANTER, baseado em padrões de performance de DR.

Critérios de decisão:
- ESCALAR: CTR crescendo, CPM estável/caindo, ROAS > 2x e subindo, hook rate alto (>25%), comentários positivos
- PAUSAR: CPM subindo forte, CTR/hook caindo 3+ dias, ROAS < 1.5x, saturação de audiência
- MANTER: métricas estáveis, ainda dentro do CPA alvo, sem sinais claros de escala ou queda

Seja DIRETO e ACIONÁVEL. Use a experiência de DR brasileiro. Responda APENAS JSON.`;

    const userPrompt = `Analise esse criativo e preveja a ação:

Anúncio: ${nome}
Formato: ${formato || '—'}
Dias rodando: ${diasRodando || '—'}

MÉTRICAS:
- CTR: ${ctr != null ? ctr + '%' : '—'}
- CPM: ${cpm != null ? 'R$ ' + cpm : '—'}
- CPC: ${cpc != null ? 'R$ ' + cpc : '—'}
- ROAS: ${roas != null ? roas + 'x' : '—'}
- Hook Rate: ${hookRate != null ? hookRate + '%' : '—'}
- Hold Rate: ${holdRate != null ? holdRate + '%' : '—'}
- Conv. Checkout: ${convCheckout != null ? convCheckout + '%' : '—'}
- Investido: ${investido != null ? 'R$ ' + investido : '—'}
- Faturado: ${faturado != null ? 'R$ ' + faturado : '—'}

TENDÊNCIAS:
- CPM: ${tendenciaCpm || 'não informado'}
- CTR/Hook: ${tendenciaCtr || 'não informado'}
- Comentários: ${comentarios || 'não informado'}

Responda APENAS com JSON:
{
  "previsao": "ESCALAR | PAUSAR | MANTER",
  "confianca": "0-100 (quão confiante você está)",
  "recomendacao": "1-2 frases acionáveis (ex: 'Aumentar budget 40% nas próximas 48h')",
  "janela": "prazo da ação (ex: 'próximas 48h', 'imediato', 'monitorar 3 dias')",
  "sinais_positivos": ["sinais que apoiam escalar/manter"],
  "sinais_negativos": ["red flags / sinais de alerta"],
  "diagnostico": "análise técnica em 2-3 frases do que está acontecendo com esse criativo",
  "proximo_passo": "ação concreta sugerida"
}`;
    const txt = await _chamarClaudeCopy(systemPrompt, userPrompt, 1500);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, analise: parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ia/analise-ads-lote — analisa VÁRIOS anúncios de uma vez (do RedTrack)
// e retorna ranking: quais escalar, manter, pausar
app.post('/api/ia/analise-ads-lote', async (req, res) => {
  try {
    const { ads } = req.body || {};
    if (!Array.isArray(ads) || !ads.length) return res.status(400).json({ error: 'Envie array de ads' });
    // Limita a 30 ads por análise pra não estourar tokens
    const lista = ads.slice(0, 30);

    const systemPrompt = `Você é um analista expert em tráfego pago de Direct Response. Recebe uma lista de criativos com métricas reais e classifica CADA UM como ESCALAR, MANTER ou PAUSAR, com base em ROAS, CPA, volume de vendas e investimento.

Critérios:
- ESCALAR: ROAS alto (>2.5x), CPA saudável, volume relevante de vendas, lucro positivo forte
- PAUSAR: ROAS < 1.5x, CPA alto demais, queimando dinheiro sem retorno
- MANTER: ROAS ok (1.5-2.5x), ainda lucrativo mas sem espaço claro pra escala agressiva

Seja DIRETO. Priorize lucro real (revenue - cost). Responda APENAS JSON.`;

    const adsResumo = lista.map((a, i) => {
      const roas = a.cost > 0 ? (a.revenue / a.cost) : 0;
      return `${i+1}. "${a.nome}" — Investido: R$${(a.cost||0).toFixed(0)} | Faturado: R$${(a.revenue||0).toFixed(0)} | Vendas: ${a.vendas||0} | ROAS: ${roas.toFixed(2)}x | CPA: R$${(a.cpa||0).toFixed(0)}`;
    }).join('\n');

    const userPrompt = `Analise esses ${lista.length} criativos e classifique cada um:

${adsResumo}

Responda APENAS com JSON neste formato:
{
  "resumo": "1-2 frases sobre o conjunto (quantos escalar, quanto lucro total, etc)",
  "ads": [
    {
      "nome": "nome exato do ad",
      "veredito": "ESCALAR | MANTER | PAUSAR",
      "roas": número,
      "lucro": número (revenue - cost),
      "motivo": "1 frase curta justificando",
      "acao": "ação concreta (ex: 'aumentar budget 40%', 'pausar já', 'manter e monitorar')"
    }
  ]
}

Ordene o array: ESCALAR primeiro, depois MANTER, depois PAUSAR.`;
    const txt = await _chamarClaudeCopy(systemPrompt, userPrompt, 3000);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, ...parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ia/copy/advertorial — gera advertorial completo
app.post('/api/ia/copy/advertorial', async (req, res) => {
  try {
    const { nicho, produto, persona, dor, promessa, prova } = req.body || {};
    if (!produto) return res.status(400).json({ error: 'Produto obrigatório' });

    const userPrompt = `Crie um ADVERTORIAL completo (formato matéria-jornalística) pra Direct Response:

Nicho: ${nicho || '—'}
Produto: ${produto}
Persona principal: ${persona || 'pessoa comum sofrendo da dor'}
Dor: ${dor || '—'}
Promessa: ${promessa || '—'}
Prova: ${prova || '—'}

Estrutura clássica de advertorial DR:
1. Headline + lead intrigante (dor amplificada + curiosidade)
2. Identificação com a persona (1-2 parágrafos)
3. Causa raiz do problema (educação que muda perspectiva)
4. Descoberta/solução (introdução do mecanismo)
5. Prova/case stories (1-2 histórias específicas)
6. Como funciona (explicação simples)
7. CTA com urgência

Tom: matéria de portal/blog, NÃO comercial óbvio. 600-900 palavras.

Responda APENAS com JSON:
{
  "headline": "...",
  "lead": "primeiro parágrafo intrigante",
  "secoes": [
    {"titulo": "...", "texto": "..."},
    ...
  ],
  "cta_final": "...",
  "observacoes": "dicas pra teste"
}`;
    const txt = await _chamarClaudeCopy(SYSTEM_PROMPT_DR, userPrompt, 4000);
    try {
      const parsed = JSON.parse(txt.replace(/^```json\s*|\s*```$/g, ''));
      res.json({ ok: true, advertorial: parsed });
    } catch (e) {
      res.json({ ok: true, raw: txt, _parseErr: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── DOMÍNIO PRÓPRIO DO CLIENTE (8/8) ──
// Cliente Pro+ pode configurar app.suaempresa.com em vez de
// acme.centralaxcend.com. Sistema mostra instruções DNS, verifica
// que o CNAME aponta certo e armazena o domínio em tenant.dominio
// (que já é lido em _resolverTenantId).
// ══════════════════════════════════════════════

// POST /api/me/dominio — define domínio próprio do tenant
// Body: { dominio: 'app.acme.com' }
app.post('/api/me/dominio', authDiretoria, (req, res) => {
  try {
    const { dominio } = req.body || {};
    if (!dominio) return res.status(400).json({ error: 'dominio obrigatório' });
    const d = String(dominio).toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    // Valida formato básico
    if (!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return res.status(400).json({ error: 'Formato de domínio inválido' });
    // Bloqueia tentativas óbvias
    if (d.endsWith('.' + SAAS_ROOT_DOMAIN) || d === SAAS_ROOT_DOMAIN) return res.status(400).json({ error: 'Use um domínio próprio diferente de centralaxcend.com' });

    const db = readDB();
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const tenants = db.store['sl_saas_tenants'] || [];
    const tenant = tenants.find(t => t.id === tenantId);
    if (!tenant) return res.status(404).json({ error: 'Tenant não encontrado' });

    // Verifica plano (precisa Enterprise)
    const plano = SAAS_PLANOS[tenant.plano];
    if (!plano || !plano.features.dominioProprio) {
      return res.status(403).json({ error: 'Domínio próprio disponível apenas no plano Enterprise. Faça upgrade pra ativar.', codigo: 'PLANO_INSUFICIENTE' });
    }

    // Verifica que ninguém mais usa esse dominio
    const conflito = tenants.find(t => t.id !== tenantId && t.dominio && String(t.dominio).toLowerCase() === d);
    if (conflito) return res.status(409).json({ error: 'Esse domínio já está em uso por outro cliente.' });

    tenant.dominio = d;
    tenant.dominioVerificado = false; // precisa ser verificado depois
    tenant._updatedAt = Date.now();
    db.timestamps['sl_saas_tenants'] = now();
    writeDB(db);
    // Invalida cache
    _tenantCache = { ts: 0, byHost: new Map(), bySlug: new Map() };

    res.json({
      ok: true,
      dominio: d,
      instrucoes: {
        passo1: 'Vá no painel DNS do registrador do seu domínio (GoDaddy, Cloudflare, etc.)',
        passo2: 'Adicione um registro CNAME:',
        cname: { tipo: 'CNAME', nome: d.split('.')[0], valor: 'cname.centralaxcend.com' },
        passo3: 'Aguarde 5-30 min de propagação',
        passo4: 'Volte aqui e clique em "Verificar DNS"',
        passo5: 'SSL é emitido automaticamente via Let\'s Encrypt'
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/me/dominio/verificar — verifica DNS apontando certo
app.post('/api/me/dominio/verificar', authDiretoria, async (req, res) => {
  try {
    const db = readDB();
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
    if (!tenant || !tenant.dominio) return res.status(400).json({ error: 'Configure o domínio primeiro' });

    // Tenta resolver via DNS
    const dns = require('dns').promises;
    try {
      const cnames = await dns.resolveCname(tenant.dominio);
      // Aceita qualquer CNAME que termine em railway.app ou centralaxcend.com
      const ok = cnames.some(c => /\.railway\.app$|centralaxcend\.com$/.test(c.toLowerCase()));
      if (ok) {
        tenant.dominioVerificado = true;
        tenant._updatedAt = Date.now();
        db.timestamps['sl_saas_tenants'] = now();
        writeDB(db);
        _tenantCache = { ts: 0, byHost: new Map(), bySlug: new Map() };
        return res.json({ ok: true, verificado: true, cnames, mensagem: 'DNS verificado! Acesse https://' + tenant.dominio + ' em 5-15 min (tempo do SSL).' });
      }
      return res.json({ ok: true, verificado: false, cnames, mensagem: 'CNAME encontrado mas não aponta pro TMX Digital. Esperado: cname.centralaxcend.com' });
    } catch (e) {
      return res.json({ ok: true, verificado: false, mensagem: 'DNS não propagou ainda. Tente novamente em 5-30 min.', erro: e.message });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/me/dominio — remove domínio próprio
app.delete('/api/me/dominio', authDiretoria, (req, res) => {
  try {
    const db = readDB();
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
    if (!tenant) return res.status(404).json({ error: 'Tenant não encontrado' });
    delete tenant.dominio;
    delete tenant.dominioVerificado;
    tenant._updatedAt = Date.now();
    db.timestamps['sl_saas_tenants'] = now();
    writeDB(db);
    _tenantCache = { ts: 0, byHost: new Map(), bySlug: new Map() };
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── PERMISSÕES CUSTOMIZÁVEIS (7/8) ──
// Diretoria pode criar roles custom além dos 6 cargos default
// (Diretoria, Copy, Editor, Gestor de Tráfego, Spy, Infra).
// Cada role tem set de permissões por módulo.
// ══════════════════════════════════════════════

const MODULOS_PERMISSAO = [
  { id:'demandas', label:'Demandas' },
  { id:'criativos', label:'Criativos' },
  { id:'rh', label:'RH' },
  { id:'financeiro', label:'Financeiro' },
  { id:'vagas', label:'Vagas' },
  { id:'spy', label:'Spy + AdLib' },
  { id:'roi', label:'ROI / Métricas' },
  { id:'config', label:'Configurações' },
  { id:'usuarios', label:'Usuários' },
  { id:'billing', label:'Plano e cobrança' }
];

// GET /api/permissoes/roles — lista roles do tenant atual
app.get('/api/permissoes/roles', (req, res) => {
  try {
    const db = readDB();
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const roles = (db.store['sl_permissoes_roles'] || []).filter(r => getItemTenant(r) === tenantId);
    res.json({ ok: true, roles, modulos: MODULOS_PERMISSAO });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/permissoes/roles — cria/edita role custom (só Diretoria)
app.post('/api/permissoes/roles', authDiretoria, (req, res) => {
  try {
    const { id, nome, descricao, permissoes } = req.body || {};
    if (!nome) return res.status(400).json({ error: 'Nome obrigatório' });
    const db = readDB();
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const roles = db.store['sl_permissoes_roles'] || [];
    let role = id ? roles.find(r => r.id === id) : null;
    if (!role) {
      role = { id: 'role-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,5), tenant_id: tenantId, criadoEm: new Date().toISOString() };
      roles.push(role);
    }
    role.nome = String(nome).trim().slice(0, 50);
    role.descricao = String(descricao || '').trim().slice(0, 200);
    role.permissoes = permissoes || {};
    role._updatedAt = Date.now();
    db.store['sl_permissoes_roles'] = roles;
    db.timestamps['sl_permissoes_roles'] = now();
    writeDB(db);
    res.json({ ok: true, role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/permissoes/roles/:id
app.delete('/api/permissoes/roles/:id', authDiretoria, (req, res) => {
  try {
    const db = readDB();
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const roles = (db.store['sl_permissoes_roles'] || []).filter(r => !(r.id === req.params.id && getItemTenant(r) === tenantId));
    db.store['sl_permissoes_roles'] = roles;
    db.timestamps['sl_permissoes_roles'] = now();
    writeDB(db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/me/logout-all — invalida todas as sessões do usuário
app.post('/api/me/logout-all', (req, res) => {
  try {
    const db = readDB();
    const user = _authUser(req, db);
    if (!user) return res.status(401).json({ error: 'Não autenticado' });
    db.sessions = (db.sessions || []).filter(s => s.userId !== user.id);
    audit(db, 'me_logout_all', { userId: user.id }, null, { id: user.id, nome: user.nome, cargo: user.cargo });
    writeDB(db);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── INTEGRAÇÃO UTMIFY (por tenant) ──
// Cada cliente conecta SUA conta Utmify pelo painel.
// TMX Digital dispara eventos de conversão automaticamente (lead, qualified, opportunity, conversion).
// Docs: https://docs.utmify.com.br/
// ══════════════════════════════════════════════

const UTMIFY_API_BASE = 'https://api.utmify.com.br/api-credentials';

// Helper: pega config Utmify do tenant
function _getUtmifyConfig(tenantId, db) {
  if (!db) db = readDB();
  const configs = db.store['sl_integracoes_utmify'] || [];
  return configs.find(c => c.tenant_id === tenantId) || null;
}

// Função reutilizável: envia evento de conversão pra Utmify
// Outros endpoints chamam essa função quando algo importante acontece
async function _enviarEventoUtmify(tenantId, tipoEvento, dadosEvento) {
  try {
    const db = readDB();
    const cfg = _getUtmifyConfig(tenantId, db);
    if (!cfg || !cfg.ativo || !cfg.apiToken) return { ok: false, motivo: 'Integração não configurada' };

    // Filtra: evento deve estar habilitado nessa config
    if (cfg.eventosHabilitados && !cfg.eventosHabilitados.includes(tipoEvento)) {
      return { ok: false, motivo: 'Evento não habilitado pra esse tenant' };
    }

    // Monta payload pro Utmify
    const payload = {
      orderId: dadosEvento.orderId || ('axcend-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7)),
      platform: 'TMX Digital',
      paymentMethod: dadosEvento.paymentMethod || 'other',
      status: tipoEvento === 'conversion' ? 'paid' : 'pending',
      createdAt: new Date().toISOString(),
      approvedDate: tipoEvento === 'conversion' ? new Date().toISOString() : null,
      refundedAt: null,
      customer: {
        name: dadosEvento.customerName || '',
        email: dadosEvento.customerEmail || '',
        phone: dadosEvento.customerPhone || '',
        document: dadosEvento.customerDoc || '',
        country: 'BR',
        ip: dadosEvento.ip || ''
      },
      products: dadosEvento.products || [{
        id: tipoEvento,
        name: dadosEvento.productName || tipoEvento,
        planId: dadosEvento.planId || tipoEvento,
        planName: dadosEvento.planName || tipoEvento,
        quantity: 1,
        priceInCents: Math.round((dadosEvento.value || 0) * 100)
      }],
      trackingParameters: dadosEvento.utm || {
        src: null, sck: null,
        utm_source: dadosEvento.utm_source || null,
        utm_campaign: dadosEvento.utm_campaign || null,
        utm_medium: dadosEvento.utm_medium || null,
        utm_content: dadosEvento.utm_content || null,
        utm_term: dadosEvento.utm_term || null
      },
      commission: {
        totalPriceInCents: Math.round((dadosEvento.value || 0) * 100),
        gatewayFeeInCents: 0,
        userCommissionInCents: Math.round((dadosEvento.value || 0) * 100),
        currency: 'BRL'
      },
      isTest: false
    };

    // Faz a chamada
    const resp = await fetch(UTMIFY_API_BASE + '/orders', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-token': cfg.apiToken
      },
      body: JSON.stringify(payload)
    });

    const txt = await resp.text();
    let result;
    try { result = JSON.parse(txt); } catch { result = { raw: txt }; }

    // Loga no histórico
    const historico = db.store['sl_integracoes_utmify_historico'] || [];
    historico.unshift({
      id: 'log-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6),
      tenant_id: tenantId,
      tipoEvento,
      payload,
      response: result,
      status: resp.ok ? 'sucesso' : 'erro',
      httpStatus: resp.status,
      timestamp: new Date().toISOString(),
      _updatedAt: Date.now() / 1000
    });
    // Limita a 200 logs por tenant
    const logsDessetenant = historico.filter(h => h.tenant_id === tenantId).slice(0, 200);
    const outrosLogs = historico.filter(h => h.tenant_id !== tenantId);
    db.store['sl_integracoes_utmify_historico'] = [...logsDessetenant, ...outrosLogs];
    db.timestamps['sl_integracoes_utmify_historico'] = now();
    writeDB(db);

    return { ok: resp.ok, status: resp.status, response: result };
  } catch (err) {
    console.error('[utmify-evento]', err.message);
    return { ok: false, erro: err.message };
  }
}

// POST /api/integracoes/utmify/config — salva config Utmify do tenant atual
// Body: { apiToken, ativo, eventosHabilitados: ['lead','qualified','opportunity','conversion'] }
app.post('/api/integracoes/utmify/config', authDiretoria, (req, res) => {
  try {
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const { apiToken, ativo, eventosHabilitados } = req.body || {};
    if (!apiToken) return res.status(400).json({ error: 'apiToken obrigatório' });

    const db = readDB();
    const configs = db.store['sl_integracoes_utmify'] || [];
    let cfg = configs.find(c => c.tenant_id === tenantId);
    if (!cfg) {
      cfg = { id: 'utm-' + Date.now().toString(36), tenant_id: tenantId, criadoEm: new Date().toISOString() };
      configs.push(cfg);
    }
    cfg.apiToken = String(apiToken).trim();
    cfg.ativo = ativo === true;
    cfg.eventosHabilitados = Array.isArray(eventosHabilitados) ? eventosHabilitados : ['lead', 'qualified', 'opportunity', 'conversion'];
    cfg._updatedAt = Date.now();

    db.store['sl_integracoes_utmify'] = configs;
    db.timestamps['sl_integracoes_utmify'] = now();
    writeDB(db);
    res.json({ ok: true, config: { ...cfg, apiToken: cfg.apiToken.slice(0, 8) + '...' } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/integracoes/utmify/me — retorna config do tenant + último log
app.get('/api/integracoes/utmify/me', authDiretoria, (req, res) => {
  try {
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const db = readDB();
    const cfg = _getUtmifyConfig(tenantId, db);
    const logs = (db.store['sl_integracoes_utmify_historico'] || []).filter(l => l.tenant_id === tenantId).slice(0, 50);
    const stats = {
      total: logs.length,
      sucesso: logs.filter(l => l.status === 'sucesso').length,
      erro: logs.filter(l => l.status === 'erro').length,
      ultimoEvento: logs[0] ? logs[0].timestamp : null
    };
    res.json({
      ok: true,
      configurado: !!cfg,
      ativo: cfg ? cfg.ativo : false,
      eventosHabilitados: cfg ? cfg.eventosHabilitados : [],
      apiTokenPreview: cfg ? cfg.apiToken.slice(0, 8) + '...' : null,
      stats,
      ultimosLogs: logs.slice(0, 20).map(l => ({
        timestamp: l.timestamp,
        tipoEvento: l.tipoEvento,
        status: l.status,
        httpStatus: l.httpStatus,
        productName: l.payload?.products?.[0]?.name || '—'
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/integracoes/utmify/test — envia evento de teste
app.post('/api/integracoes/utmify/test', authDiretoria, async (req, res) => {
  try {
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const r = await _enviarEventoUtmify(tenantId, 'lead', {
      orderId: 'test-' + Date.now(),
      customerName: 'Teste TMX Digital',
      customerEmail: 'teste@axcend.com',
      productName: 'Evento de teste',
      value: 0
    });
    res.json(r);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── TRACKING PRÓPRIO: META ADS + VENDAS ──
// ══════════════════════════════════════════════
// A Utmify não tem API de leitura (só POST /orders), então não dá pra "puxar" o
// painel dela. A saída é montar o número na fonte, que é o que ela mesma faz:
//   INVESTIMENTO ← API do Meta Ads (Graph API)
//   FATURAMENTO  ← postback do checkout/gateway (mesmo que já alimenta a Utmify)
//   ROAS         = faturamento / investimento, calculado aqui.
// Os tokens ficam em chaves FORA do SYNC_KEYS: nunca são enviados pro browser.

const META_API_VER  = 'v25.0';
const META_API_BASE = `https://graph.facebook.com/${META_API_VER}`;
const KEY_META      = 'sl_integracoes_meta';     // server-only (token)
const KEY_VENDAS    = 'sl_vendas';
const KEY_METRICAS  = 'sl_metricas_ads';   // métricas importadas (Utmify, Meta…)               // vendas normalizadas
const KEY_VENDAS_RAW= 'sl_vendas_raw';           // últimos payloads crus (debug/mapeamento)
const KEY_PLANOS    = 'sl_planos';               // preço de cada plano, pra classificar venda por valor
const KEY_CUSTOS    = 'sl_custos';               // imposto, taxa do gateway e custo — pra margem real

// ── Margem de contribuição ──────────────────────────────────────────────────
// ROAS nao desconta nada: nem imposto, nem taxa do gateway, nem o custo de
// entregar o produto. Uma campanha com ROAS 1,6 pode estar empatando ou dando
// prejuizo depois que tudo isso sai. Este e o numero que sobra de verdade.
const CUSTOS_PADRAO = {
  imposto: 0,        // % sobre o faturamento (Simples, presumido…)
  gateway: 0,        // % que a plataforma de checkout retem
  custoVenda: 0,     // R$ fixo por venda entregue (suporte, plataforma, comissao)
  impostoAds: 0      // % sobre o investimento (IOF do cartao internacional)
};
function _custosCfg(db) {
  const c = (db || readDB()).store[KEY_CUSTOS];
  const out = Object.assign({}, CUSTOS_PADRAO);
  if (c && typeof c === 'object') {
    for (const k of Object.keys(CUSTOS_PADRAO)) {
      const v = Number(c[k]);
      if (Number.isFinite(v) && v >= 0) out[k] = v;
    }
  }
  return out;
}
// Devolve as parcelas separadas, nao so o total: ver que o imposto sozinho comeu
// R$ 4 mil e diferente de ver "margem menor que o ROAS".
function _margem(receita, investimento, vendas, cfg) {
  const imposto = receita * (cfg.imposto / 100);
  const gateway = receita * (cfg.gateway / 100);
  const produto = vendas * cfg.custoVenda;
  const iof     = investimento * (cfg.impostoAds / 100);
  const liquido = receita - imposto - gateway - produto;
  const margem  = liquido - investimento - iof;
  return {
    receita, investimento, imposto, gateway, produto, iof, liquido, margem,
    pct: receita > 0 ? (margem / receita) * 100 : 0,
    // quanto voce ganha por real investido, ja limpo
    retorno: investimento > 0 ? liquido / (investimento + iof) : 0,
    configurado: cfg.imposto > 0 || cfg.gateway > 0 || cfg.custoVenda > 0 || cfg.impostoAds > 0
  };
}
const VENDAS_RAW_MAX = 50;
const VENDAS_RETENCAO_DIAS = 365;

function _metaCfg(db) {
  const c = (db || readDB()).store[KEY_META];
  return (c && typeof c === 'object') ? c : null;
}
// act_123 e 123 são aceitos; a Graph API exige o prefixo act_
function _metaActId(id) {
  const s = String(id || '').trim();
  if (!s) return '';
  return s.startsWith('act_') ? s : ('act_' + s.replace(/^act/, ''));
}

// ── Planos: classificar a venda pelo VALOR ──────────────────────────────────
// O ideal seria o nome do produto dizer o plano, mas o gateway dele manda um
// nome so ("Apostilai") pras quatro assinaturas. Entao o preco e a unica coisa
// que separa. Funciona, com duas ressalvas que a tela precisa dizer em voz alta:
// desconto/cupom tira a venda da faixa, e dois planos com o mesmo preco sao
// indistinguiveis. Por isso a faixa tem tolerancia e sobra um balde "fora das
// faixas" em vez de empurrar pro mais proximo a qualquer custo.
const PLANOS_PADRAO = [
  { chave: 'mensal',     rotulo: 'Mensal',     meses: 1,  preco: 0 },
  { chave: 'trimestral', rotulo: 'Trimestral', meses: 3,  preco: 0 },
  { chave: 'semestral',  rotulo: 'Semestral',  meses: 6,  preco: 0 },
  { chave: 'anual',      rotulo: 'Anual',      meses: 12, preco: 0 }
];
function _planosCfg(db) {
  const c = (db || readDB()).store[KEY_PLANOS];
  const lista = Array.isArray(c && c.planos) ? c.planos : null;
  return {
    planos: lista && lista.length ? lista : PLANOS_PADRAO,
    tolerancia: Number(c && c.tolerancia) > 0 ? Number(c.tolerancia) : 10   // %
  };
}
// Devolve o plano cujo preco mais se aproxima, dentro da tolerancia. Fora dela
// devolve null — chutar o mais proximo transformaria um order bump de R$ 47
// num "mensal" e sujaria a conta toda.
// O plano dito no nome do produto. Mais confiavel que o preco: o nome nao muda
// com cupom, promocao ou order bump, e dois planos de mesmo preco continuam
// distinguiveis. So cai no preco quando o nome nao disser nada.
const PLANO_NO_NOME = [
  { chave: 'anual',      re: /anual|(?:12)\s*mes|(?:1|um)\s*ano/i },
  { chave: 'semestral',  re: /semestral|(?:6|seis)\s*mes/i },
  { chave: 'trimestral', re: /trimestral|(?:3|tres|três)\s*mes/i },
  { chave: 'mensal',     re: /mensal|(?:1|um)\s*mes(?!\s*es\b)/i }
];
function _planoPorNome(nome) {
  const n = String(nome || '');
  if (!n) return null;
  for (const p of PLANO_NO_NOME) if (p.re.test(n)) return p;
  return null;
}

function _planoPorValor(valor, cfg) {
  const v = Number(valor);
  if (!Number.isFinite(v) || v <= 0) return null;
  let melhor = null, menorDist = Infinity;
  for (const p of cfg.planos) {
    const preco = Number(p.preco) || 0;
    if (preco <= 0) continue;
    const dist = Math.abs(v - preco) / preco * 100;
    if (dist <= cfg.tolerancia && dist < menorDist) { menorDist = dist; melhor = p; }
  }
  return melhor;
}

// ── Config ──
app.get('/api/integracoes/meta/me', authDiretoria, (req, res) => {
  try {
    const cfg = _metaCfg();
    res.json({
      ok: true,
      configurado: !!(cfg && cfg.accessToken),
      ativo: !!(cfg && cfg.ativo),
      adAccountId: cfg ? (cfg.adAccountId || '') : '',
      tokenPreview: (cfg && cfg.accessToken) ? String(cfg.accessToken).slice(0, 10) + '…' : null,
      ultimoTeste: cfg ? (cfg.ultimoTeste || null) : null,
      ultimoErro: cfg ? (cfg.ultimoErro || null) : null,
      versaoApi: META_API_VER
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/integracoes/meta/config', authDiretoria, (req, res) => {
  try {
    const { accessToken, adAccountId, ativo } = req.body || {};
    const db = readDB();
    const cfg = _metaCfg(db) || { criadoEm: new Date().toISOString() };
    // token em branco = manter o que já está salvo (o campo vem vazio na tela)
    if (accessToken && String(accessToken).trim()) cfg.accessToken = String(accessToken).trim();
    if (adAccountId !== undefined) cfg.adAccountId = _metaActId(adAccountId);
    cfg.ativo = ativo === true;
    cfg._updatedAt = Date.now();
    if (!cfg.accessToken) return res.status(400).json({ error: 'Cole o token de acesso do Meta.' });
    db.store[KEY_META] = cfg;
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_META] = now();
    audit(db, 'integracao.meta.config', KEY_META, { adAccountId: cfg.adAccountId, ativo: cfg.ativo }, req.user);
    writeDB(db);   // depois do audit, senão o registro fica só na memória
    res.json({ ok: true, adAccountId: cfg.adAccountId, ativo: cfg.ativo });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Chamada crua na Graph API, com erro legível (o do Meta vem aninhado)
async function _metaGet(pathRel, params, cfg) {
  const qs = new URLSearchParams(Object.assign({ access_token: cfg.accessToken }, params || {}));
  const url = `${META_API_BASE}/${pathRel}?${qs}`;
  const r = await fetch(url);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) {
    const e = j.error || {};
    const msg = e.error_user_msg || e.message || `HTTP ${r.status}`;
    const err = new Error(msg);
    err.metaCode = e.code;
    err.httpStatus = r.status;
    throw err;
  }
  return j;
}

app.post('/api/integracoes/meta/test', authDiretoria, async (req, res) => {
  const db = readDB();
  const cfg = _metaCfg(db);
  if (!cfg || !cfg.accessToken) return res.status(400).json({ error: 'Configure o token primeiro.' });
  if (!cfg.adAccountId) return res.status(400).json({ error: 'Informe o ID da conta de anúncios.' });
  try {
    const j = await _metaGet(cfg.adAccountId, { fields: 'name,account_status,currency,timezone_name' }, cfg);
    cfg.ultimoTeste = new Date().toISOString();
    cfg.ultimoErro = null;
    db.store[KEY_META] = cfg; writeDB(db);
    res.json({ ok: true, conta: { nome: j.name, moeda: j.currency, fuso: j.timezone_name, status: j.account_status } });
  } catch (err) {
    cfg.ultimoErro = err.message;
    db.store[KEY_META] = cfg; writeDB(db);
    res.status(400).json({ error: err.message, metaCode: err.metaCode });
  }
});

// ── Investimento por campanha ──
// level: campaign | adset | ad
app.get('/api/integracoes/meta/insights', authDiretoria, async (req, res) => {
  const cfg = _metaCfg();
  if (!cfg || !cfg.accessToken || !cfg.adAccountId) {
    return res.status(400).json({ error: 'Integração do Meta não configurada.' });
  }
  const from = String(req.query.from || '').slice(0, 10);
  const to   = String(req.query.to   || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to)) {
    return res.status(400).json({ error: 'Use from e to no formato AAAA-MM-DD.' });
  }
  const level = ['campaign', 'adset', 'ad'].includes(req.query.level) ? req.query.level : 'campaign';
  try {
    const j = await _metaGet(`${cfg.adAccountId}/insights`, {
      level,
      fields: 'campaign_id,campaign_name,adset_name,ad_name,spend,impressions,clicks,ctr,cpc,cpm,date_start,date_stop',
      time_range: JSON.stringify({ since: from, until: to }),
      time_increment: '1',
      limit: '500'
    }, cfg);
    const linhas = (j.data || []).map(d => ({
      data: d.date_start,
      campanhaId: d.campaign_id || '',
      campanha: d.campaign_name || '',
      adset: d.adset_name || '',
      anuncio: d.ad_name || '',
      investimento: Number(d.spend || 0),
      impressoes: Number(d.impressions || 0),
      cliques: Number(d.clicks || 0),
      ctr: Number(d.ctr || 0),
      cpc: Number(d.cpc || 0),
      cpm: Number(d.cpm || 0)
    }));
    res.json({ ok: true, level, de: from, ate: to, linhas });
  } catch (err) {
    res.status(400).json({ error: err.message, metaCode: err.metaCode });
  }
});

// ── Vendas via postback do checkout ──
// O gateway que hoje alimenta a Utmify passa a mandar a mesma venda pra cá também.
// A URL carrega um token secreto (gateways não mandam header Authorization).
function _vendasCfg(db) {
  const c = (db || readDB()).store['sl_integracoes_vendas'];
  return (c && typeof c === 'object') ? c : null;
}
app.get('/api/integracoes/vendas/me', authDiretoria, (req, res) => {
  try {
    const db = readDB();
    const cfg = _vendasCfg(db);
    const vendas = db.store[KEY_VENDAS] || [];
    const raw = db.store[KEY_VENDAS_RAW] || [];
    // "Vendas recebidas: 1.218" fazia parecer que tinham entrado 1.218 vendas.
    // Sao EVENTOS do checkout: o mesmo pedido chega como pix gerado, depois
    // pago (ou cancelado), e carrinho perdido tambem vem. So 'paid' e venda.
    const porStatus = {};
    vendas.forEach(v => { const st = String(v.status || '(sem status)'); porStatus[st] = (porStatus[st] || 0) + 1; });
    const pagas = vendas.filter(_vendaPaga);
    const hoje = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
    const pagasHoje = pagas.filter(v => String(v.recebidoEm || '').slice(0, 10) === hoje);
    res.json({
      ok: true,
      configurado: !!(cfg && cfg.token),
      urlWebhook: cfg && cfg.token ? `/api/webhook/vendas/${cfg.token}` : null,
      eventos: vendas.length,
      totalVendas: pagas.length,                       // pagas, que e o que a tela chama de venda
      pagasHoje: pagasHoje.length,
      receitaHoje: pagasHoje.reduce((a, v) => a + (Number(v.valor) || 0), 0),
      pedidos: new Set(vendas.map(v => v.pedidoId).filter(Boolean)).size,
      porStatus,
      comVid: vendas.filter(v => v.vid).length,
      semValor: pagas.filter(v => !(Number(v.valor) > 0)).length,
      ultimaVenda: pagas.length ? pagas[pagas.length - 1].recebidoEm : null,
      ultimosBrutos: raw.slice(-10).reverse()
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/integracoes/vendas/gerar-token', authDiretoria, (req, res) => {
  try {
    const db = readDB();
    const cfg = _vendasCfg(db) || {};
    cfg.token = crypto.randomBytes(24).toString('hex');
    cfg._updatedAt = Date.now();
    db.store['sl_integracoes_vendas'] = cfg;
    if (!db.timestamps) db.timestamps = {};
    db.timestamps['sl_integracoes_vendas'] = now();
    audit(db, 'integracao.vendas.token', 'sl_integracoes_vendas', {}, req.user);
    writeDB(db);   // depois do audit
    res.json({ ok: true, urlWebhook: `/api/webhook/vendas/${cfg.token}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Extrai os campos que interessam de payloads de gateways diferentes.
// Cada gateway nomeia do seu jeito; aqui a gente tenta os nomes mais comuns e
// guarda o payload cru pra ajustar depois vendo o formato real.
function _num(v) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v === 'number') return v;
  const s = String(v).replace(/[^\d,.-]/g, '').replace(/\.(?=\d{3}\b)/g, '').replace(',', '.');
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}
// devolve {valor, caminho} — o caminho importa pra saber se o número veio em centavos
function _pegaCom(obj, caminhos) {
  for (const c of caminhos) {
    const v = c.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), obj);
    if (v !== undefined && v !== null && v !== '') return { valor: v, caminho: c };
  }
  return { valor: undefined, caminho: '' };
}
function _pega(obj, caminhos) { return _pegaCom(obj, caminhos).valor; }

// A Payt nao manda utm e sck soltos no corpo: ela junta tudo em 'link'
// ('link.sources' com as utm, 'link.query_params' com o resto da query, e a
// propria 'link.url'). Enquanto isso nao era lido, TODA venda chegava orfa —
// 146 em 7 dias, nenhuma com origem. Aqui a gente achata esses tres num objeto
// so, que entra como mais um lugar onde procurar cada campo.
function _doLink(p) {
  const l = (p && p.link) || {};
  const out = {};
  const por = o => { if (o && typeof o === 'object' && !Array.isArray(o)) Object.keys(o).forEach(k => { if (o[k] !== null && o[k] !== '') out[k] = o[k]; }); };
  por(l.sources); por(l.query_params); por(l.tracking); por(p && p.query_params);
  // a query da propria URL do checkout: e onde o sck viaja quando o gateway
  // guarda o link inteiro em vez dos campos separados
  [l.url, p && p.url, p && p.checkout_url].forEach(u => {
    if (!u || typeof u !== 'string' || u.indexOf('?') < 0) return;
    try {
      new URL(u, 'https://x').searchParams.forEach((v, k) => { if (v && out[k] === undefined) out[k] = v; });
    } catch (e) {}
  });
  return out;
}
// Valor que o checkout crava sozinho e que nao diz de onde a pessoa veio.
const _ORIGEM_VAZIA = /^(organic|organico|orgânico|direct|direto|none|null|undefined|nao-informado|n\/a|sem|)$/i;
function _origemVale(v) { return !!String(v || '').trim() && !_ORIGEM_VAZIA.test(String(v).trim()); }

// Procura o id do visitante em todos os campos que um gateway pode devolver.
// O pixel esconde 'tmx_<id>' dentro do sck (e do src, quando existe) porque
// parametro proprio nao sobrevive ao postback.
function _vidDaVenda(p) {
  const doLink = _doLink(p);
  const direto = _pega(p, ['tmx_vid', 'trackingParameters.tmx_vid', 'tracking.tmx_vid',
                           'metadata.tmx_vid', 'custom.tmx_vid']) || doLink.tmx_vid;
  if (direto) return String(direto).slice(0, 40);
  const campos = ['sck', 'src', 'utm_content', 'xcod',
                  'trackingParameters.sck', 'trackingParameters.src',
                  'trackingParameters.utm_content', 'tracking.sck', 'tracking.src'];
  for (const c of campos.concat(['__link.sck', '__link.src', '__link.utm_content', '__link.xcod'])) {
    const v = String((c.indexOf('__link.') === 0 ? doLink[c.slice(7)] : _pega(p, [c])) || '');
    const m = v.match(/tmx_([A-Za-z0-9]{6,40})/);
    if (m) return m[1];
  }
  return '';
}

function _normalizarVenda(p) {
  const achado = _pegaCom(p, [
    'commission.totalPriceInCents','totalPriceInCents','amount_in_cents','price_in_cents',
    // Payt: o que a pessoa pagou de verdade (em centavos). Sem esta linha TODA
    // venda da Payt ficava guardada com valor nulo.
    'transaction.total_price',
    'valor','value','amount','total','price','transaction.amount','data.amount','order.total',
    'product.price'
  ]);
  let valor = _num(achado.valor);
  // Gateways que mandam em centavos: ou dizem no nome do campo, ou são estes
  if (valor !== null && /cents|transaction\.total_price|^product\.price$/i.test(achado.caminho)) valor = valor / 100;
  const doLink = _doLink(p);
  return {
    id: 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    pedidoId: String(_pega(p, ['orderId','order_id','id','transaction_id','codigo','code']) || ''),
    status: String(_pega(p, ['status','order_status','payment_status','situacao']) || '').toLowerCase(),
    valor: valor,
    moeda: String(_pega(p, ['currency','moeda']) || 'BRL'),
    produto: String(_pega(p, ['products.0.name','product.name','produto','product_name','plan_name']) || ''),
    cliente: String(_pega(p, ['customer.name','cliente.nome','customer_name','buyer.name']) || ''),
    email: String(_pega(p, ['customer.email','cliente.email','customer_email','buyer.email']) || ''),
    utmSource:   String(_pega(p, ['trackingParameters.utm_source','utm_source','tracking.utm_source','src']) || doLink.utm_source || doLink.src || ''),
    utmMedium:   String(_pega(p, ['trackingParameters.utm_medium','utm_medium','tracking.utm_medium']) || doLink.utm_medium || ''),
    utmCampaign: String(_pega(p, ['trackingParameters.utm_campaign','utm_campaign','tracking.utm_campaign','campaign']) || doLink.utm_campaign || ''),
    utmContent:  String(_pega(p, ['trackingParameters.utm_content','utm_content','tracking.utm_content']) || doLink.utm_content || ''),
    utmTerm:     String(_pega(p, ['trackingParameters.utm_term','utm_term','tracking.utm_term']) || doLink.utm_term || ''),
    // assinatura que se renova sozinha nao teve clique nenhum: contar como
    // "venda sem origem" fazia a conta de orfas parecer defeito de rastreio
    renovacao: Number((p && p.subscription && p.subscription.charges) || 0) > 1,
    // O que Recuperacao, Assinaturas e a ficha do lead precisam. Guardado a
    // partir de 29/09: venda anterior nao tem, e a tela diz isso.
    metodo:       String(_pega(p, ['transaction.payment_method','payment_method','payment.method','metodo']) || '').toLowerCase().slice(0, 30),
    telefone:     String(_pega(p, ['customer.phone','cliente.telefone','customer_phone','buyer.phone']) || '').replace(/[^\d+]/g, '').slice(0, 20),
    plano:        String(_pega(p, ['subscription.plan_name','plan_name','link.title']) || '').slice(0, 80),
    assinatura:   String(_pega(p, ['subscription.code','subscription.id','subscription_id']) || '').slice(0, 40),
    cobrancas:    Number(_pega(p, ['subscription.charges']) || 0) || 0,
    periodicidade:String(_pega(p, ['subscription.periodicity']) || '').toLowerCase().slice(0, 20),
    assinaturaStatus: String(_pega(p, ['subscription.status']) || '').toLowerCase().slice(0, 20),
    assinaturaDesde:  String(_pega(p, ['subscription.started_at']) || '').slice(0, 30),
    pedidoCriado: String(_pega(p, ['transaction.created_at','created_at','started_at']) || '').slice(0, 30),
    pagoEm:       String(_pega(p, ['transaction.paid_at','paid_at']) || '').slice(0, 30),
    expiraEm:     String(_pega(p, ['transaction.expires_at','expires_at']) || '').slice(0, 30),
    // o visitante que o pixel anexou no link do checkout — e o que liga a venda
    // a jornada inteira, mesmo quando a UTM se perdeu no caminho
    // O vid pode voltar em tres lugares, em ordem de confianca:
    //   tmx_vid  — se o gateway repassou o parametro cru (poucos repassam)
    //   sck/src  — onde o pixel o esconde justamente porque esses SAO repassados
    //   utm_content — ultimo recurso, quando o checkout so devolve utm_*
    vid: _vidDaVenda(p),
    recebidoEm: new Date().toISOString()
  };
}

// Como esta venda foi ligada a uma origem. Sem isso voce troca um numero ruim
// por outro numero ruim sem saber qual e qual: 'vid' e confianca dura (o proprio
// visitante), 'utm' e o parametro que sobreviveu, 'nenhum' e venda orfa.
// So entra na conta o que foi pago. A Payt manda o mesmo pedido em varios
// estados (waiting_payment, lost_cart, canceled) e contar todos como venda
// inflava faturamento e conversao sem ninguem perceber. Venda antiga sem
// status continua valendo: quando ela foi guardada, tudo contava.
const _PAGO = /^(paid|approved|aprovad|pago|completed|complete|authorized|captured|confirmed|confirmad|active|ativo|success|settled)/i;
function _vendaPaga(v) {
  const st = String((v && v.status) || '').trim();
  return !st || _PAGO.test(st);
}

function _comoCasou(v) {
  if (v.vid)       return 'vid';
  // utm_source fixo em "organic" e o padrao do checkout, nao a origem da venda:
  // aceitar isso como atribuicao enchia o relatorio de venda "organica" que na
  // verdade veio de anuncio.
  if (_origemVale(v.utmContent) || _origemVale(v.utmCampaign) || _origemVale(v.utmSource)) return 'utm';
  if (v.renovacao) return 'renovacao';
  return 'nenhum';
}

app.post('/api/webhook/vendas/:token', (req, res) => {   // body já vem parseado pelo express.json global
  try {
    const db = readDB();
    const cfg = _vendasCfg(db);
    if (!cfg || !cfg.token) return res.status(404).json({ error: 'Webhook não configurado.' });
    // comparação em tempo constante — o token vem na URL
    const a = Buffer.from(String(req.params.token || ''));
    const b = Buffer.from(String(cfg.token));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'Token inválido.' });
    }
    const payload = req.body || {};
    // guarda o cru (limitado) pra conseguir mapear os campos do gateway real
    const raw = db.store[KEY_VENDAS_RAW] || [];
    raw.push({ em: new Date().toISOString(), payload });
    db.store[KEY_VENDAS_RAW] = raw.slice(-VENDAS_RAW_MAX);

    const venda = _normalizarVenda(payload);
    venda.casadaPor = _comoCasou(venda);
    const vendas = db.store[KEY_VENDAS] || [];
    // dedupe por pedidoId (gateways reenviam o mesmo evento)
    const jaTem = venda.pedidoId && vendas.some(v => v.pedidoId === venda.pedidoId && v.status === venda.status);
    if (!jaTem) {
      // liga a venda à pessoa (sck, e-mail, telefone, documento) e guarda na
      // base que não esquece; uma falha aqui nunca pode derrubar o webhook
      try { _pedidoRegistrar(venda, payload); } catch (e) { console.error('[PESSOAS] casamento falhou:', e.message); }
      vendas.push(venda);
    }
    // retenção
    const corte = Date.now() - VENDAS_RETENCAO_DIAS * 86400000;
    db.store[KEY_VENDAS] = vendas.filter(v => new Date(v.recebidoEm).getTime() >= corte);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_VENDAS] = now();
    writeDB(db);
    res.json({ ok: true, duplicada: !!jaTem });
  } catch (err) {
    // nunca devolve 500 pro gateway sem contexto — muitos desativam o webhook após erros
    res.status(200).json({ ok: false, erro: err.message });
  }
});

// ── CLIENTE MCP DA UTMIFY (servidor -> servidor) ──
// A API publica da Utmify so RECEBE pedidos (POST /orders). Mas o servidor MCP
// deles (https://mcp.utmify.com.br/mcp) EXPOE LEITURA e pede so um token de
// acesso, sem OAuth. Entao da pra puxar as metricas direto daqui.
// Protocolo: JSON-RPC sobre HTTP -> initialize, depois tools/call.
// resources=gs,gm,gu libera get_utms_ad_objects (agrupamento por UTM), que sem
// esse parametro nem aparece no tools/list. Mantem get_dashboards,
// get_dashboard_summary e get_meta_ad_objects; so tira google/kwai/tiktok,
// que nao usamos. Conferido em tools/list nos dois modos.
const UTMIFY_MCP_URL = 'https://mcp.utmify.com.br/mcp?resources=gs,gm,gu';
const KEY_UTMIFY_MCP = 'sl_integracoes_utmify_mcp';   // server-only: guarda o token

function _utmifyMcpCfg(db) {
  const c = (db || readDB()).store[KEY_UTMIFY_MCP];
  const cfg = (c && typeof c === 'object') ? c : null;
  // Alternativa ao token salvo pela tela: variavel de ambiente no Railway.
  // Util pra quem prefere guardar credencial fora do banco (estilo .env).
  const doEnv = process.env.UTMIFY_MCP_TOKEN;
  if (doEnv && String(doEnv).trim()) {
    const base = cfg || { criadoEm: new Date().toISOString() };
    // o do ambiente tem prioridade: e o mais explicito
    const c2 = Object.assign({}, base, { token: String(doEnv).trim(), origemToken: 'env' });
    // Botar o token no ambiente e dizer "quero puxando sozinho". Antes isso valia
    // so como padrao, e um false salvo na tela mantinha tudo parado em silencio —
    // foi assim que a sincronizacao ficou horas sem rodar sem ninguem perceber.
    // Com o token no ambiente, o automatico fica ligado; pra desligar de vez,
    // basta remover a variavel UTMIFY_MCP_TOKEN do Railway.
    if (!c2.autoSync) c2.autoSync = true;
    return c2;
  }
  return cfg;
}

// A Utmify fica atras da Cloudflare, que corta com 429 (erro 1015) quando as
// requisicoes chegam muito juntas. Sem tratar isso, sincronizar um mes voltava
// com o periodo inteiro vazio e a tela dizia so "Utmify recusou: ERRO".
let _utmifyUltimaChamada = 0;
// O espaco entre chamadas se ajusta sozinho: comeca curto (puxar "hoje" leva 2s)
// e vai abrindo a cada recusa. Fixo nao serve — curto derruba periodo longo,
// longo faria o uso do dia a dia esperar a toa.
let _utmifyEspaco = 260;
const UTMIFY_ESPACO_MIN = 260, UTMIFY_ESPACO_MAX = 1600;

function _dormir(ms) { return new Promise(r => setTimeout(r, ms)); }

function _utmifyPisarNoFreio() {
  _utmifyEspaco = Math.min(UTMIFY_ESPACO_MAX, Math.round(_utmifyEspaco * 1.9) + 100);
}
function _utmifyAliviar() {
  if (_utmifyEspaco > UTMIFY_ESPACO_MIN) _utmifyEspaco = Math.max(UTMIFY_ESPACO_MIN, _utmifyEspaco - 25);
}

async function _utmifyVezDeFalar() {
  const desde = Date.now() - _utmifyUltimaChamada;
  if (desde < _utmifyEspaco) await _dormir(_utmifyEspaco - desde);
  _utmifyUltimaChamada = Date.now();
}

async function _utmifyRpc(token, metodo, params, sessionId) {
  // ate 3 tentativas quando levar 429; a espera cresce, e respeita o Retry-After
  for (let tentativa = 0; ; tentativa++) {
    try {
      return await _utmifyRpcUma(token, metodo, params, sessionId);
    } catch (e) {
      if (e.httpStatus !== 429 || tentativa >= 3) throw e;
      _utmifyPisarNoFreio();
      const espera = e.retryAfter ? (e.retryAfter * 1000) : [1500, 4000, 9000][tentativa];
      console.log('[utmify] 429 — esperando ' + Math.round(espera / 1000) + 's e tentando de novo');
      await _dormir(espera);
    }
  }
}

async function _utmifyRpcUma(token, metodo, params, sessionId) {
  await _utmifyVezDeFalar();
  // O token vai na QUERY STRING — testei todos os formatos de header
  // (Authorization Bearer, x-api-token, x-api-key...) e todos devolvem
  // "O token de acesso é obrigatório". Só ?token= funciona.
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
    'User-Agent': 'CentralTMX/1.0'
  };
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;
  const url = UTMIFY_MCP_URL + '&token=' + encodeURIComponent(token);
  const r = await fetch(url, {
    method: 'POST', headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method: metodo, params: params || {} })
  });
  const sid = r.headers.get('mcp-session-id') || sessionId || null;
  const texto = await r.text();
  if (!r.ok) {
    const e = r.status === 429
      ? new Error('A Utmify limitou as requisições (429). Tentando mais devagar.')
      : new Error('Utmify MCP ' + r.status + ': ' + texto.slice(0, 180));
    e.httpStatus = r.status;
    const ra = Number(r.headers.get('retry-after'));
    if (ra > 0 && ra < 120) e.retryAfter = ra;
    throw e;
  }
  let corpo = null;
  if (texto.trim().startsWith('{')) {
    corpo = JSON.parse(texto);
  } else {
    // resposta em SSE: linhas "data: {...}"
    texto.split('\n').forEach(l => {
      const t = l.trim();
      if (t.startsWith('data:')) { try { corpo = JSON.parse(t.slice(5).trim()); } catch (e) {} }
    });
  }
  if (!corpo) throw new Error('Resposta do MCP em formato inesperado.');
  if (corpo.error) throw new Error(corpo.error.message || JSON.stringify(corpo.error));
  return { resultado: corpo.result, sessionId: sid };
}

// Abre sessao e chama uma tool, devolvendo o JSON ja desembrulhado.
// Sessao reaproveitada: antes cada pergunta abria uma sessao nova (initialize +
// initialized + tools/call = 3 requisicoes). Numa sincronizacao de 2 dias x 3
// dashboards x 2 niveis isso virava ~36 requisicoes, e a tela ficava eterna.
let _utmifySessao = null;   // { token, sid, quando }
const UTMIFY_SESSAO_MS = 4 * 60 * 1000;

async function _utmifyAbrirSessao(token) {
  const ini = await _utmifyRpc(token, 'initialize', {
    protocolVersion: '2024-11-05', capabilities: {},
    clientInfo: { name: 'central-tmx', version: '1.0' }
  });
  const sid = ini.sessionId;
  try { await _utmifyRpc(token, 'notifications/initialized', {}, sid); } catch (e) {}
  _utmifySessao = { token, sid, quando: Date.now() };
  return sid;
}

async function _utmifyChamarTool(token, tool, args, _repetindo) {
  let sid;
  const viva = _utmifySessao && _utmifySessao.token === token &&
               (Date.now() - _utmifySessao.quando) < UTMIFY_SESSAO_MS;
  if (viva) sid = _utmifySessao.sid;
  else sid = await _utmifyAbrirSessao(token);

  let r;
  try {
    r = await _utmifyRpc(token, 'tools/call', { name: tool, arguments: args || {} }, sid);
  } catch (e) {
    // Sessao reaproveitada pode ter morrido do outro lado: abre uma nova e repete.
    if (!viva) throw e;
    _utmifySessao = null;
    sid = await _utmifyAbrirSessao(token);
    r = await _utmifyRpc(token, 'tools/call', { name: tool, arguments: args || {} }, sid);
  }
  const res = r.resultado || {};
  const bloco = (res.content || []).find(c => c && c.type === 'text');
  if (!bloco) return res.structuredContent || res;
  let dados;
  try { dados = JSON.parse(bloco.text); } catch (e) { dados = bloco.text; }
  // Atenção: erro da Utmify vem com HTTP 200 e isError:true no corpo.
  // Sem tratar isso, token inválido passaria como "conectado".
  const falhou = res.isError === true ||
                 (dados && typeof dados === 'object' && dados.result === 'ERROR');
  if (falhou) {
    const motivo = (dados && dados.reason) || 'ERRO';
    const amigavel = {
      MCP_INTEGRATION_NOT_FOUND: 'Token não reconhecido pela Utmify — provavelmente foi revogado. Gere um novo token de MCP no painel da Utmify (Integrações › MCP) e cole aqui. Atenção: não é o token de API de envio de vendas.',
      UNAUTHORIZED: 'Token sem permissão para essa consulta.'
    }[motivo];
    if (amigavel) throw new Error(amigavel);       // problema de token: insistir nao resolve
    // 'ERRO' seco quase sempre e aperto de limite disfarcado de HTTP 200.
    // Freia e tenta mais uma vez antes de dar o dia por perdido.
    if (!_repetindo) {
      _utmifyPisarNoFreio();
      await _dormir(1200);
      try { return await _utmifyChamarTool(token, tool, args, true); } catch (e) { throw e; }
    }
    throw new Error('Utmify recusou: ' + motivo);
  }
  _utmifyAliviar();
  return dados;
}

// ══════════════════════════════════════════════
// ── INGESTÃO DE MÉTRICAS (Utmify e outras fontes) ──
// ══════════════════════════════════════════════
// A Utmify não deixa o servidor consultar direto (o MCP dela é autenticado na
// conta do Claude, e o endpoint fica atrás de Cloudflare). Então a ponte é ao
// contrário: quem tem acesso à Utmify EMPURRA os números pra cá, com um token
// de API. Serve tanto pra importação manual quanto pra rotina automática.
//
// POST /api/v1/metricas/importar
// body: { fonte:'utmify', periodo:{de,ate}, dashboard:'CONCURSO', linhas:[...] }
// cada linha: { data, campanhaId, campanha, adsetId, adset, adId, anuncio,
//               investimento, faturamento, faturamentoLiquido, lucro, vendas,
//               impressoes, cliques, ctr, cpc, cpm, roas }
app.post('/api/v1/metricas/importar', authAPI, (req, res) => {
  try {
    const { fonte, periodo, dashboard, linhas } = req.body || {};
    if (!Array.isArray(linhas)) return res.status(400).json({ error: 'Envie "linhas" como lista.' });
    if (linhas.length > 20000) return res.status(400).json({ error: 'Lote grande demais (máx 20000 linhas).' });

    const num = v => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
    const norm = linhas.map(l => ({
      data:        String(l.data || '').slice(0, 10),
      fonte:       String(fonte || 'utmify'),
      dashboard:   String(dashboard || ''),
      campanhaId:  String(l.campanhaId || ''),
      campanha:    String(l.campanha || ''),
      adsetId:     String(l.adsetId || ''),
      adset:       String(l.adset || ''),
      adId:        String(l.adId || ''),
      anuncio:     String(l.anuncio || ''),
      investimento: num(l.investimento),
      faturamento:  num(l.faturamento),
      faturamentoLiquido: num(l.faturamentoLiquido),
      lucro:        num(l.lucro),
      vendas:       num(l.vendas),
      impressoes:   num(l.impressoes),
      cliques:      num(l.cliques),
      ctr:          num(l.ctr),
      cpc:          num(l.cpc),
      cpm:          num(l.cpm),
      roas:         num(l.roas)
    })).filter(l => /^\d{4}-\d{2}-\d{2}$/.test(l.data));

    const db = readDB();
    const atual = Array.isArray(db.store[KEY_METRICAS]) ? db.store[KEY_METRICAS] : [];
    // Substitui o que já existe do MESMO período/fonte/dashboard — reimportar não duplica
    const de  = (periodo && periodo.de)  ? String(periodo.de).slice(0,10)  : null;
    const ate = (periodo && periodo.ate) ? String(periodo.ate).slice(0,10) : null;
    const mantidos = atual.filter(l => {
      if (l.fonte !== (fonte || 'utmify')) return true;
      if (dashboard && l.dashboard !== dashboard) return true;
      if (de && ate) return !(l.data >= de && l.data <= ate);
      return true;
    });
    db.store[KEY_METRICAS] = mantidos.concat(norm);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_METRICAS] = now();
    writeDB(db);
    res.json({ ok: true, recebidas: norm.length, substituidas: atual.length - mantidos.length,
               total: db.store[KEY_METRICAS].length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Consulta consolidada — é daqui que a tela de Métricas de Ads vai ler
// ── CONSULTAS AO VIVO NA UTMIFY (nao passam pelo banco) ──────────────
// Nivel de anuncio gera ~320 linhas por dia por dashboard. Gravar isso no
// db.json incharia o banco (foi disco cheio que derrubou a aplicacao hoje).
// Essas telas sao "de agora", entao consultam direto e guardam so em memoria.
const _utmifyCacheVivo = new Map();
function _vivoGet(chave, ms) {
  const c = _utmifyCacheVivo.get(chave);
  if (c && (Date.now() - c.quando) < ms) return c.dados;
  return null;
}
function _vivoSet(chave, dados) {
  _utmifyCacheVivo.set(chave, { quando: Date.now(), dados });
  if (_utmifyCacheVivo.size > 40) _utmifyCacheVivo.delete(_utmifyCacheVivo.keys().next().value);
}

async function _utmifyDashboardsAtivos() {
  const cfg = _utmifyMcpCfg();
  if (!cfg || !cfg.token) throw new Error('Utmify não configurada.');
  if (!cfg.modo) cfg.modo = String(cfg.token).startsWith('ey') ? 'api' : 'mcp';
  if (cfg.modo !== 'mcp') throw new Error('Essa tela precisa do token de MCP da Utmify (o token de sessão não serve).');
  let lista = cfg.dashboards || [];
  if (!lista.length) lista = await _utmifyListarDashboards(cfg);
  return { cfg, lista };
}

// Lista os projetos (dashboards) da Utmify — alimenta o filtro da tela
app.get('/api/metricas/utmify/projetos', authUsuario, async (req, res) => {
  const pronto = _vivoGet('projetos', 10 * 60 * 1000);
  if (pronto) return res.json(Object.assign({ doCache: true }, pronto));
  try {
    const { lista } = await _utmifyDashboardsAtivos();
    const saida = { ok: true, projetos: lista.map(d => ({ id: d.id, nome: (d.nome || '').trim() || d.id })) };
    _vivoSet('projetos', saida);
    res.json(saida);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Reduz a lista de dashboards ao projeto pedido (vazio = todos)
function _filtrarProjeto(lista, projeto) {
  if (!projeto) return lista;
  const alvo = lista.filter(d => String(d.id) === String(projeto));
  return alvo.length ? alvo : lista;
}

// Anuncios do periodo, agregados entre os dashboards
app.get('/api/metricas/utmify/anuncios', authUsuario, (req, res) => _rotaAnuncios(req, res));
async function _rotaAnuncios(req, res) {
  const de  = String(req.query.de  || '').slice(0, 10);
  const ate = String(req.query.ate || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) {
    return res.status(400).json({ error: 'Informe de/ate no formato AAAA-MM-DD.' });
  }
  const projeto = String(req.query.projeto || '').slice(0, 40);
  const chave = 'anuncios|' + de + '|' + ate + '|' + projeto;
  const pronto = _vivoGet(chave, 60 * 1000);
  if (pronto) return res.json(Object.assign({ doCache: true }, pronto));
  try {
    const achado = await _utmifyDashboardsAtivos();
    const cfg = achado.cfg, lista = _filtrarProjeto(achado.lista, projeto);
    const cent = v => (Number(v) || 0) / 100;
    const mapa = {};
    const erros = [];
    // Contagem pra tela: sem isso, "nenhum anuncio" nao diferencia entre
    // a Utmify nao ter devolvido nada e a gente ter descartado tudo.
    const diag = { dashboards: lista.length, linhas: 0, semGasto: 0 };
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      try {
        const r = await _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', {
          dashboardId: d.id, level: 'ad',
          dateRange: { from: de + 'T00:00:00' + off, to: ate + 'T23:59:59' + off }
        });
        const linhas = (r && r.results) || [];
        diag.linhas += linhas.length;
        linhas.forEach(a => {
          const inv = cent(a.spend), rec = cent(a.grossRevenue);
          if (!inv && !rec) { diag.semGasto++; return; }
          // Agrupa pela NOMENCLATURA, nao pelo id: o mesmo criativo roda em varios
          // adsets/campanhas e aparecia repetido, sem mostrar o resultado real dele.
          const nome = String(a.name || '(sem nome)').trim();
          const k = nome.toLowerCase().replace(/\s+/g, ' ') + '|' + d.id;
          if (!mapa[k]) mapa[k] = {
            nome: nome || '(sem nome)', dashboard: d.nome || d.id, veiculacoes: 0,
            investimento: 0, receita: 0, lucro: 0, vendas: 0, ics: 0, cliques: 0, impressoes: 0
          };
          const m = mapa[k];
          m.veiculacoes += 1;
          m.investimento += inv; m.receita += rec; m.lucro += cent(a.profit);
          m.vendas   += Number(a.approvedOrdersCount) || 0;
          m.ics      += Number(a.initiateCheckout) || 0;
          m.cliques  += Number(a.inlineLinkClicks) || 0;
          m.impressoes += Number(a.impressions) || 0;
          // o id do anúncio é o que chega no utm_content quando a UTM segue o padrão por id
          const aid = String(a.id || a.adId || a.ad_id || '').trim();
          if (aid) { m.ids = m.ids || []; if (m.ids.indexOf(aid) < 0 && m.ids.length < 30) m.ids.push(aid); }
        });
      } catch (e) { erros.push((d.nome || d.id) + ': ' + e.message); }
    }
    // Metricas calculadas em cima da SOMA, nao pela media das veiculacoes:
    // media de medias distorce quando uma veiculacao gasta muito mais que a outra.
    const anuncios = Object.values(mapa).map(m => Object.assign(m, {
      roas:      m.investimento > 0 ? m.receita / m.investimento : 0,
      cpa:       m.vendas   > 0 ? m.investimento / m.vendas : 0,
      cpc:       m.cliques  > 0 ? m.investimento / m.cliques : 0,
      cpm:       m.impressoes > 0 ? (m.investimento / m.impressoes) * 1000 : 0,
      ctr:       m.impressoes > 0 ? (m.cliques / m.impressoes) * 100 : 0,
      custoPorIc: m.ics    > 0 ? m.investimento / m.ics : 0,
      lucro:     m.receita - m.investimento
    })).sort((a, b) => b.investimento - a.investimento);
    // A conta sempre vende mais do que a soma dos anuncios: venda direta, organica
    // ou com link sem UTM a Meta nao tem como reivindicar. Sem mostrar os dois
    // lados, a tela parecia estar perdendo venda.
    let contaVendas = null, contaReceita = null;
    try {
      const pano = await _utmifyPanorama(de, ate, projeto);
      contaVendas  = Number(((pano.kpis || {}).pedidos || {}).aprovadas) || 0;
      contaReceita = Number((pano.kpis || {}).receita) || 0;
    } catch (e) { erros.push('total da conta: ' + e.message); }
    const somaVendas  = anuncios.reduce((a, x) => a + (Number(x.vendas) || 0), 0);
    const somaReceita = anuncios.reduce((a, x) => a + (Number(x.receita) || 0), 0);
    const saida = { ok: true, de, ate, anuncios, erros, diag,
      conciliacao: {
        vendasAnuncios: somaVendas, vendasConta: contaVendas,
        receitaAnuncios: somaReceita, receitaConta: contaReceita,
        vendasSemAnuncio: (contaVendas === null) ? null : Math.max(0, contaVendas - somaVendas),
        receitaSemAnuncio: (contaReceita === null) ? null : Math.max(0, contaReceita - somaReceita)
      } };
    // Resultado vazio nao entra em cache: se foi tropeço momentaneo, o proximo
    // clique tem que tentar de novo em vez de repetir o vazio por um minuto.
    if (anuncios.length) _vivoSet(chave, saida);
    // Guarda o que veio. A partir daqui o dia existe aqui dentro, mesmo que a
    // Utmify caia ou pare de devolver aquele periodo.
    if (anuncios.length) _adsGuardar(de, ate, projeto, saida);

    // ── A Utmify respondeu, mas veio vazia ─────────────────────────────────
    // Nao e erro: e ela nao ter mais aquele dia na janela dela. Se aqui dentro
    // existe o arquivo daquele periodo, ele vale mais que uma tela em branco —
    // era exatamente o caso de pedir uma data de tres dias atras e nao aparecer
    // nada, mesmo depois de o dia ter sido guardado.
    if (!anuncios.length) {
      const salvo = _adsLer(de, ate, projeto);
      if (salvo && salvo.anuncios.length) return res.json(Object.assign({}, salvo, {
        doArquivo: true,
        avisoArquivo: 'A Utmify não tem mais este período na janela dela. ' +
                      'Estes números são os que ficaram guardados aqui.' }));
    }
    res.json(saida);
  } catch (e) {
    // ── A Utmify falhou: entrega o que ficou guardado ────────────────────────
    // Dado de ads e historico: uma vez lido, tem de continuar existindo. Antes,
    // qualquer tropeço da API apagava o dia inteiro da tela.
    const salvo = _adsLer(de, ate, projeto);
    if (salvo) return res.json(Object.assign({}, salvo, {
      doArquivo: true, avisoArquivo: 'A Utmify não respondeu agora (' + e.message +
        '). Estes números são a última leitura guardada aqui.' }));
    res.status(400).json({ error: e.message });
  }
}

// ══════════════════════════════════════════════════════
// ── HISTÓRICO DE ADS ──
// A Utmify e a fonte, mas nao pode ser a unica memoria: ela e uma API de fora,
// com limite de uso e janela propria. O que foi lido uma vez fica aqui.
// Guardado por DIA, nao por periodo: assim "ontem", "7 dias" e "este mes"
// remontam do mesmo acervo, em vez de cada recorte ter a sua copia.
// ══════════════════════════════════════════════════════
const KEY_ADS_HIST = 'sl_ads_hist';       // { 'dia|projeto': { anuncios, conciliacao, em } }
const ADS_HIST_DIAS = 400;                // pouco mais de um ano

function _adsGuardar(de, ate, projeto, saida) {
  // So guarda recorte de UM dia: periodo maior e soma de dias, e somar somas
  // duplicaria tudo na hora de remontar.
  if (de !== ate) return;
  try {
    const db = readDB();
    const h = (db.store[KEY_ADS_HIST] && typeof db.store[KEY_ADS_HIST] === 'object')
      ? db.store[KEY_ADS_HIST] : {};
    h[de + '|' + (projeto || '')] = {
      em: new Date().toISOString(),
      anuncios: saida.anuncios,
      conciliacao: saida.conciliacao
    };
    // retencao por data, nao por quantidade: o que importa e ate quando lembra
    const corte = new Date(Date.now() - ADS_HIST_DIAS * 86400000).toISOString().slice(0, 10);
    Object.keys(h).forEach(k => { if (k.slice(0, 10) < corte) delete h[k]; });
    db.store[KEY_ADS_HIST] = h;
    db.timestamps[KEY_ADS_HIST] = now();
    writeDB(db);
  } catch (e) { console.error('[ADS] não consegui guardar o histórico:', e.message); }
}

function _adsLer(de, ate, projeto) {
  try {
    const h = readDB().store[KEY_ADS_HIST];
    if (!h || typeof h !== 'object') return null;
    // remonta o periodo somando os dias que existirem
    const dias = [];
    for (let d = new Date(de + 'T12:00:00Z'); d.toISOString().slice(0,10) <= ate;
         d.setUTCDate(d.getUTCDate() + 1)) {
      const k = d.toISOString().slice(0, 10) + '|' + (projeto || '');
      if (h[k]) dias.push(h[k]);
      if (dias.length > ADS_HIST_DIAS) break;   // trava de seguranca
    }
    if (!dias.length) return null;

    const mapa = {};
    dias.forEach(dia => (dia.anuncios || []).forEach(a => {
      const k = a.id || a.nome;
      if (!mapa[k]) mapa[k] = Object.assign({}, a, { investimento:0, receita:0, vendas:0,
                                                     cliques:0, impressoes:0, ics:0 });
      ['investimento','receita','vendas','cliques','impressoes','ics'].forEach(c => {
        mapa[k][c] = (Number(mapa[k][c]) || 0) + (Number(a[c]) || 0);
      });
    }));
    // recalcula as taxas em cima da soma, igual o caminho ao vivo faz
    const anuncios = Object.values(mapa).map(m => Object.assign(m, {
      roas:      m.investimento > 0 ? m.receita / m.investimento : 0,
      cpa:       m.vendas   > 0 ? m.investimento / m.vendas : 0,
      cpc:       m.cliques  > 0 ? m.investimento / m.cliques : 0,
      cpm:       m.impressoes > 0 ? (m.investimento / m.impressoes) * 1000 : 0,
      ctr:       m.impressoes > 0 ? (m.cliques / m.impressoes) * 100 : 0,
      custoPorIc: m.ics    > 0 ? m.investimento / m.ics : 0,
      lucro:     m.receita - m.investimento
    })).sort((a, b) => b.investimento - a.investimento);

    const soma = c => dias.reduce((t, d) => t + (Number((d.conciliacao || {})[c]) || 0), 0);
    return { ok: true, de, ate, anuncios, erros: [], diag: { doArquivo: dias.length },
      conciliacao: {
        vendasAnuncios: anuncios.reduce((t,a)=>t+(Number(a.vendas)||0),0),
        vendasConta: soma('vendasConta'),
        receitaAnuncios: anuncios.reduce((t,a)=>t+(Number(a.receita)||0),0),
        receitaConta: soma('receitaConta'),
        vendasSemAnuncio: soma('vendasSemAnuncio'),
        receitaSemAnuncio: soma('receitaSemAnuncio')
      } };
  } catch (e) { return null; }
}

// Guarda ontem e hoje sozinho, sem depender de alguem abrir a tela. Sem isto so
// ficaria registrado o dia que por acaso foi olhado — e o pedido era que o
// numero exista "independentemente do que aconteça".
async function _adsArquivarDia() {
  try {
    const cfg = readDB().store[KEY_UTMIFY_MCP];
    if (!cfg || !cfg.token) return;                    // sem integracao, nada a fazer
    const hoje  = new Date(Date.now() - 3*3600000).toISOString().slice(0, 10);
    const ontem = new Date(Date.now() - 3*3600000 - 86400000).toISOString().slice(0, 10);
    for (const dia of [ontem, hoje]) {
      // dia fechado e ja guardado nao precisa ser lido de novo
      const h = readDB().store[KEY_ADS_HIST] || {};
      if (dia === ontem && h[dia + '|']) continue;
      await new Promise(resolve => _rotaAnuncios(
        { query: { de: dia, ate: dia, projeto: '' } },
        { json: () => resolve(), status: () => ({ json: () => resolve() }) }
      ));
    }
  } catch (e) { console.error('[ADS] arquivamento falhou:', e.message); }
}
setInterval(_adsArquivarDia, 30 * 60 * 1000);
setTimeout(_adsArquivarDia, 90 * 1000);      // uma vez logo depois do boot

// No boot, corre atras dos dias que faltam. Sem isto o arquivo so comeca a
// existir do dia seguinte, e o historico que a Utmify ainda tem se perde na
// primeira vez que ela mudar a janela dela.
// Dia ja guardado e pulado, entao restart nao custa chamada nenhuma — depois da
// primeira rodada bem-sucedida isto vira quase de graca.
setTimeout(async () => {
  try {
    const h = readDB().store[KEY_ADS_HIST] || {};
    const faltam = [];
    for (let i = 1; i <= 14; i++) {
      const d = new Date(Date.now() - 3*3600000 - i*86400000).toISOString().slice(0, 10);
      if (!h[d + '|']) faltam.push(d);
    }
    if (!faltam.length) return;
    console.log('[ADS] faltam ' + faltam.length + ' dia(s) no arquivo; buscando na Utmify...');
    const r = await _adsPreencher(14);
    console.log('[ADS] arquivo: ' + r.feitos.length + ' dia(s) novo(s)' +
                (r.falhos.length ? ', ' + r.falhos.length + ' sem dado' : '') + '.');
  } catch (e) { console.error('[ADS] preenchimento do boot falhou:', e.message); }
}, 150 * 1000);

// ── Preencher o passado ─────────────────────────────────────────────────────
// O arquivo comeca vazio: sem isto, so existiria de hoje em diante e todo o
// historico que a Utmify ainda tem se perderia na primeira vez que ela mudasse
// a janela. Aqui a gente busca os dias que faltam, um por vez.
// Dia ja guardado nao e rebuscado — a segunda rodada nao custa nada.
async function _adsPreencher(dias) {
  // 0, vazio ou texto caem no padrao de 7: pedir "zero dias" nao quer dizer
  // nada, e e mais util assumir a semana do que nao fazer coisa nenhuma.
  const quantos = Math.max(1, Math.min(60, Number(dias) || 7));
  const feitos = [], pulados = [], falhos = [];
  for (let i = 1; i <= quantos; i++) {
    const d = new Date(Date.now() - 3*3600000 - i*86400000).toISOString().slice(0, 10);
    const h = readDB().store[KEY_ADS_HIST] || {};
    if (h[d + '|']) { pulados.push(d); continue; }
    try {
      const r = await new Promise(resolve => _rotaAnuncios(
        { query: { de: d, ate: d, projeto: '' } },
        { json: x => resolve(x), status: () => ({ json: x => resolve(null) }) }
      ));
      if (r && r.anuncios && r.anuncios.length) feitos.push(d + ' (' + r.anuncios.length + ')');
      else falhos.push(d + ' (sem dado)');
    } catch (e) { falhos.push(d + ': ' + e.message); }
    // respiro entre chamadas: a Utmify tem limite de uso e nao vale a pena
    // queimar a cota pra ganhar dois segundos
    await new Promise(r => setTimeout(r, 1200));
  }
  return { feitos, pulados, falhos };
}

// Diretoria dispara pela tela; nao roda sozinho pra nao consumir a cota da
// Utmify sem alguem ter pedido.
app.post('/api/metricas/utmify/preencher', authDiretoria, async (req, res) => {
  try {
    const r = await _adsPreencher(req.body && req.body.dias);
    audit(readDB(), 'ads_preencher_historico', {}, r.feitos.length + ' dia(s)', req.user);
    res.json(Object.assign({ ok: true }, r));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── FEED DE EVENTOS (venda / checkout iniciado) ───────────────────
// A Utmify nao expoe pedido a pedido. Mas ela atualiza os contadores por anuncio,
// entao comparamos leituras seguidas: quando o contador de um anuncio sobe, isso
// E o evento. Da o mesmo que o RedTrack mostrava: o que aconteceu e em qual criativo.
let _evFoto = null;              // ultima leitura { chave: {vendas, ics, receita} }
let _evFeed = [];                // eventos mais recentes primeiro
let _evUltimoInteresse = 0;      // quando alguem olhou a tela pela ultima vez
let _evRodando = false;
let _evSujo = false;
const KEY_EVENTOS = 'sl_funil_eventos';

// O feed precisa sobreviver a quem fecha a tela e ao restart do servidor: sem
// isso as vendas e checkouts que acontecem de madrugada simplesmente sumiam.
const KEY_EV_FOTO = 'sl_funil_evfoto';
// A foto anterior tambem precisa sobreviver ao restart. Sem isso, cada deploy
// zerava a base de comparacao: a primeira leitura virava marco zero e tudo que
// aconteceu no intervalo sumia do feed — foi assim que uma venda se perdeu.
function _evCarregar() {
  try {
    const db = readDB();
    const l = db.store[KEY_EVENTOS];
    if (Array.isArray(l)) _evFeed = l.slice(0, 400);
    const f = db.store[KEY_EV_FOTO];
    // contador zera na virada do dia: foto de ontem nao serve de comparacao
    if (f && f.dia === _hojeBR() && f.foto && typeof f.foto === 'object') {
      _evFoto = f.foto;
      console.log('[FUNIL] base de comparação recuperada (' + Object.keys(_evFoto).length + ' anúncios).');
    }
  } catch (e) {}
}
function _evGravar() {
  if (!_evSujo) return;
  _evSujo = false;
  try {
    const db = readDB();
    const corte = Date.now() - 5 * 86400000;         // 5 dias de historico
    db.store[KEY_EVENTOS] = _evFeed
      .filter(e => new Date(e.momento).getTime() >= corte)
      .slice(0, 400);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_EVENTOS] = now();
    writeDB(db);
  } catch (e) { console.error('[FUNIL] não consegui gravar o feed:', e.message); }
}
setTimeout(_evCarregar, 2500);
setInterval(_evGravar, 60 * 1000);

function _evRegistrar(ev) {
  _evFeed.unshift(ev);
  if (_evFeed.length > 400) _evFeed.length = 400;
  _evSujo = true;
}

let _evUltimaColeta = 0;
async function _tickEventosUtmify() {
  if (_evRodando) return;
  // Antes so coletava com alguem olhando — e as vendas de quando ninguem estava
  // na tela nunca eram registradas. Agora nao para nunca: so fica mais espacada
  // quando ninguem esta olhando, o que muda a precisao do horario, nao o registro.
  const olhando = (Date.now() - _evUltimoInteresse) < 5 * 60 * 1000;
  const intervalo = olhando ? 45 * 1000 : 3 * 60 * 1000;
  if (Date.now() - _evUltimaColeta < intervalo) return;
  _evUltimaColeta = Date.now();
  _evRodando = true;
  try {
    const { cfg, lista } = await _utmifyDashboardsAtivos();
    const cent = v => (Number(v) || 0) / 100;
    const foto = {}, faltou = {};
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      const hoje = new Date(Date.now() + tz * 3600000).toISOString().slice(0, 10);
      const ontem = new Date(Date.now() + tz * 3600000 - 86400000).toISOString().slice(0, 10);
      // ONTEM tambem: a Utmify prende o pedido na data em que ele foi CRIADO.
      // Pix gerado ontem e pago hoje vira aprovado na data de ontem — olhando so
      // hoje, essa venda nunca aparecia no feed.
      for (const dia of [hoje, ontem]) {
        let r;
        try {
          r = await _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', {
            dashboardId: d.id, level: 'ad',
            dateRange: { from: dia + 'T00:00:00' + off, to: dia + 'T23:59:59' + off }
          });
        } catch (e) {
          // ── Leitura falhou: PRESERVA a base daquele dia ──────────────────
          // Antes era 'continue', e a foto nova (sem as chaves desse dia)
          // substituia a anterior inteira. Na leitura seguinte o dia voltava do
          // zero e o feed re-anunciava o DIA TODO como se tivesse acabado de
          // acontecer. Foi o que aconteceu em 25/09: as 9 vendas do dia 24
          // reapareceram juntas as 07:52, sem nenhuma venda nova ter entrado.
          console.warn('[EVENTOS] Utmify falhou em ' + (d.nome || d.id) + ' ' + dia +
                       ' (' + e.message + '). Base preservada; nada re-anunciado.');
          if (_evFoto) Object.keys(_evFoto).forEach(k => {
            if (k.indexOf(d.id + '|' + dia + '|') === 0) foto[k] = _evFoto[k];
          });
          faltou[d.id + '|' + dia] = true;
          continue;
        }
        const porNome = {};
        ((r && r.results) || []).forEach(a => {
          const nome = String(a.name || '(sem nome)').trim();
          const k = d.id + '|' + dia + '|' + nome.toLowerCase().replace(/\s+/g, ' ');
          if (!porNome[k]) porNome[k] = { nome, dashboard: d.nome || d.id, dashboardId: d.id, dia,
                                          atrasada: dia !== hoje, vendas: 0, ics: 0, receita: 0 };
          porNome[k].vendas  += Number(a.approvedOrdersCount) || 0;
          porNome[k].ics     += Number(a.initiateCheckout) || 0;
          porNome[k].receita += cent(a.grossRevenue);
        });
        Object.assign(foto, porNome);
      }
    }
    if (_evFoto) {
      const agora = new Date().toISOString();
      Object.keys(foto).forEach(k => {
        const novo = foto[k];
        // Anuncio que ainda nao estava na foto anterior: se ja aparece com venda,
        // e venda de verdade que aconteceu no intervalo. Ignorar tudo dele fazia a
        // primeira venda de um criativo novo nunca chegar no feed.
        const conhecida = Object.prototype.hasOwnProperty.call(_evFoto, k);
        // Chave de ONTEM aparecendo pela primeira vez nao e venda nova: e base
        // perdida. Venda de ontem so entra no feed se a gente ja acompanhava
        // aquele anuncio e o contador subiu. Pra HOJE o primeiro contato vale,
        // senao a primeira venda de um criativo novo nunca chegaria no feed.
        if (!conhecida && novo.atrasada) return;
        if (faltou[novo.dashboardId + '|' + novo.dia]) return;
        const velho = _evFoto[k] || { vendas: 0, ics: 0, receita: 0 };
        const dv = novo.vendas - velho.vendas;
        const di = novo.ics    - velho.ics;
        const dr = novo.receita - velho.receita;
        // venda de dia anterior aprovada agora = Pix/boleto que caiu depois
        const atras = !!novo.atrasada, diaOrig = novo.dia || '';
        if (dv > 0) _evRegistrar({ momento: agora, tipo: 'venda', anuncio: novo.nome,
                                   dashboard: novo.dashboard, qtd: dv, valor: dr > 0 ? dr : 0,
                                   atrasada: atras, diaOriginal: diaOrig });
        else if (dr > 0.009) _evRegistrar({ momento: agora, tipo: 'receita', anuncio: novo.nome,
                                   dashboard: novo.dashboard, qtd: 0, valor: dr,
                                   atrasada: atras, diaOriginal: diaOrig });
        // checkout iniciado de ontem nao interessa: o que importa e a aprovacao
        if (di > 0 && !atras) _evRegistrar({ momento: agora, tipo: 'ic', anuncio: novo.nome,
                                   dashboard: novo.dashboard, qtd: di, valor: 0 });
      });
    }
    _evFoto = foto;
    // grava junto com o dia, pra saber se ainda vale depois de um restart
    try {
      const db = readDB();
      db.store[KEY_EV_FOTO] = { dia: _hojeBR(), foto: foto, em: new Date().toISOString() };
      if (!db.timestamps) db.timestamps = {};
      db.timestamps[KEY_EV_FOTO] = now();
      writeDB(db);
    } catch (e) {}
  } catch (e) {
    // silencioso: e rotina de fundo, o erro real aparece na tela pelo endpoint
  } finally { _evRodando = false; }
}
setInterval(_tickEventosUtmify, 20 * 1000);   // confere de perto; o ritmo real e decidido dentro
setTimeout(_tickEventosUtmify, 40 * 1000);   // no boot ja monta a base de comparacao

// Panorama de hoje, somando os dashboards (funil, pedidos, lucro por hora)
// Panorama de um periodo (sem data = hoje). Serve o Resumo e o Tempo Real.
async function _utmifyPanorama(deQuery, ateQuery, projeto) {
  {
    const achado = await _utmifyDashboardsAtivos();
    const cfg = achado.cfg, lista = _filtrarProjeto(achado.lista, projeto);
    const cent = v => (Number(v) || 0) / 100;
    const tot = {
      investimento: 0, receita: 0, lucro: 0,
      cliques: 0, visitas: 0, ics: 0,
      pedidos: { total: 0, aprovadas: 0, pendentes: 0, reembolsadas: 0, recusadas: 0 }
    };
    const porHora = Array.from({ length: 24 }, (_, h) => ({ hora: h, lucro: 0 }));
    const porUtm = {}, porDash = [], porProduto = {};
    const erros = [];
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      const hoje = new Date(Date.now() + tz * 3600000).toISOString().slice(0, 10);
      const ini = deQuery || hoje, fim = ateQuery || hoje;
      try {
        const s = await _utmifyChamarTool(cfg.token, 'get_dashboard_summary', {
          dashboardId: d.id,
          dateRange: { from: ini + 'T00:00:00' + off, to: fim + 'T23:59:59' + off }
        });
        const ads = s.ads || {}, an = s.analytics || {}, oc = s.ordersCount || {};
        const inv = cent(ads.spent), luc = cent(an.profit);
        // receita pelo ROAS e exata; gasto+lucro erra quando ha taxa ou custo de produto
        const rec = Number(an.roas) > 0 ? inv * Number(an.roas) : (inv + luc);
        tot.investimento += inv; tot.lucro += luc; tot.receita += rec;
        tot.cliques += Number(ads.clicks) || 0;
        tot.visitas += Number(ads.pageViews) || 0;
        tot.ics     += Number(ads.initiateCheckouts) || 0;
        tot.pedidos.total        += Number(oc.total) || 0;
        tot.pedidos.aprovadas    += Number(oc.approved) || 0;
        tot.pedidos.pendentes    += Number(oc.pending) || 0;
        tot.pedidos.reembolsadas += Number(oc.refunded) || 0;
        tot.pedidos.recusadas    += Number(oc.refusedCreditCard) || 0;
        (s.profitByHourNet || []).forEach(h => {
          const i = Number(h.hour);
          if (i >= 0 && i < 24) porHora[i].lucro += cent(h.cents);
        });
        (oc.byUtmTerm || []).forEach(u => {
          const k = u.utmTerm || '(sem origem)';
          porUtm[k] = (porUtm[k] || 0) + (Number(u.count) || 0);
        });
        // Vendas por produto: a Utmify ja mandava isso e a gente ignorava.
        // E o que permite separar mensal/trimestral/semestral/anual sem
        // adivinhar plano pelo valor — o nome do produto vem do gateway.
        (oc.byProductName || []).forEach(pn => {
          const k = String(pn.productName || '(sem nome)').trim() || '(sem nome)';
          if (!porProduto[k]) porProduto[k] = { produto: k, vendas: 0, receita: 0 };
          porProduto[k].vendas  += Number(pn.count) || 0;
          porProduto[k].receita += cent(pn.revenue);
        });
        porDash.push({ nome: d.nome || d.id, investimento: inv, lucro: luc,
                       receita: rec, vendas: Number(oc.approved) || 0,
                       roas: inv > 0 ? rec / inv : 0 });
      } catch (e) { erros.push((d.nome || d.id) + ': ' + e.message); }
    }
    // ── Vendas por plano ────────────────────────────────────────────────────
    // Preferencia: as vendas individuais do webhook, classificadas por VALOR —
    // e o unico caminho quando o gateway manda um nome de produto so pras
    // quatro assinaturas. Sem webhook, cai no nome do produto, que ao menos
    // separa quando os nomes ajudam.
    // _utmifyPanorama nao lia o banco — eu usei `db` aqui sem ele existir e
    // derrubei a aba Tempo Real inteira com "db is not defined".
    const dbPl = readDB();
    const cfgPl = _planosCfg(dbPl);
    const vendasInd = (Array.isArray(dbPl.store[KEY_VENDAS]) ? dbPl.store[KEY_VENDAS] : [])
      .filter(v => {
        const dia = String(v.recebidoEm || '').slice(0, 10);
        if (deQuery && dia < deQuery) return false;
        if (ateQuery && dia > ateQuery) return false;
        // so venda que entrou de fato; pendente, carrinho perdido e reembolso nao sao faturamento
        return _vendaPaga(v);
      });
    const temPrecos = cfgPl.planos.some(p => Number(p.preco) > 0);
    // basta ter venda individual: o nome ja classifica sozinho na maioria dos casos
    let porValor = null;
    if (vendasInd.length) {
      const acc = {};
      cfgPl.planos.forEach(p => { acc[p.chave] = {
        chave: p.chave, rotulo: p.rotulo, meses: p.meses, preco: Number(p.preco) || 0,
        vendas: 0, receita: 0, produtos: [] }; });
      acc['fora'] = { chave: 'fora', rotulo: 'Fora das faixas', meses: null, preco: 0,
                      vendas: 0, receita: 0, produtos: [], valores: [] };
      vendasInd.forEach(v => {
        // O nome do produto manda: na Payt ele vem "Apostilai - mensal", e nome
        // nao muda com cupom nem promocao. O preco entra so quando o nome cala.
        const porNome = _planoPorNome(v.produto);
        const pl = porNome || _planoPorValor(v.valor, cfgPl);
        const alvo = (pl && acc[pl.chave]) ? acc[pl.chave] : acc['fora'];
        alvo.vendas += 1;
        alvo.receita += Number(v.valor) || 0;
        if (!pl && Number(v.valor) > 0 && alvo.valores.length < 12) alvo.valores.push(Number(v.valor));
      });
      porValor = Object.values(acc).filter(p => p.vendas > 0);
    }

    // O nome do produto e quem diz o plano. Adivinhar pelo VALOR quebra no dia
    // que voce roda promocao, cupom ou order bump — dois planos com o mesmo
    // preco viram um so. Se o nome nao disser, fica "outros" em vez de chutar.
    // Alternancia solta com \b no fim so aplicava a fronteira na ULTIMA opcao —
    // "tres meses" passava e "três meses" nao, porque "mes\b" nao casa dentro de
    // "meses". Agrupado, cada numero vale pra todas as escritas.
    // A ordem tambem importa: "12 meses" tem que virar anual antes de bater em mensal.
    const PLANOS = [
      { chave: 'anual',      re: /anual|(?:12)\s*mes|(?:1|um)\s*ano/i,          rotulo: 'Anual',      meses: 12 },
      { chave: 'semestral',  re: /semestral|(?:6|seis)\s*mes/i,                  rotulo: 'Semestral',  meses: 6 },
      { chave: 'trimestral', re: /trimestral|(?:3|tres|três)\s*mes/i,            rotulo: 'Trimestral', meses: 3 },
      { chave: 'mensal',     re: /mensal|(?:1|um)\s*mes(?!\s*es\b)/i,            rotulo: 'Mensal',     meses: 1 }
    ];
    function _planoDe(nome) {
      for (const p of PLANOS) if (p.re.test(nome)) return p;
      return null;
    }
    const porPlano = {};
    Object.values(porProduto).forEach(pr => {
      const pl = _planoDe(pr.produto);
      const k = pl ? pl.chave : 'outros';
      if (!porPlano[k]) porPlano[k] = {
        chave: k, rotulo: pl ? pl.rotulo : 'Não identificado',
        meses: pl ? pl.meses : null, vendas: 0, receita: 0, produtos: []
      };
      porPlano[k].vendas  += pr.vendas;
      porPlano[k].receita += pr.receita;
      porPlano[k].produtos.push(pr.produto);
    });
    const ordem = { anual: 1, semestral: 2, trimestral: 3, mensal: 4, outros: 5, fora: 6 };
    const planos = (porValor || Object.values(porPlano))
      .map(p => Object.assign(p, {
        ticket: p.vendas > 0 ? p.receita / p.vendas : 0,
        // quanto essa venda vale por mes de contrato — compara plano com plano
        porMes: (p.meses && p.vendas > 0) ? (p.receita / p.vendas / p.meses) : null
      }))
      .sort((a, b) => (ordem[a.chave] || 9) - (ordem[b.chave] || 9));

    const saida = {
      ok: true, momento: new Date().toISOString(),
      kpis: Object.assign({}, tot, {
        roas: tot.investimento > 0 ? tot.receita / tot.investimento : 0,
        ticket: tot.pedidos.aprovadas > 0 ? tot.receita / tot.pedidos.aprovadas : 0,
        cpa: tot.pedidos.aprovadas > 0 ? tot.investimento / tot.pedidos.aprovadas : 0
      }),
      margem: _margem(tot.receita, tot.investimento, tot.pedidos.aprovadas, _custosCfg(dbPl)),
      custos: _custosCfg(dbPl),
      porHora,
      planos,
      // a tela precisa saber DE ONDE veio a classificacao pra nao mentir
      planosFonte: porValor ? 'valor' : 'nome',
      planosCfg: { tolerancia: cfgPl.tolerancia,
                   precos: cfgPl.planos.map(p => ({ chave: p.chave, rotulo: p.rotulo,
                                                    meses: p.meses, preco: Number(p.preco) || 0 })) },
      vendasIndividuais: vendasInd.length,
      produtos: Object.values(porProduto).sort((a, b) => b.receita - a.receita),
      porUtm: Object.entries(porUtm).map(([nome, qtd]) => ({ nome, qtd })).sort((a, b) => b.qtd - a.qtd),
      porDashboard: porDash.sort((a, b) => b.investimento - a.investimento),
      erros
    };
    return saida;
  }
}

app.get('/api/metricas/utmify/tempo-real', authUsuario, async (req, res) => {
  _evUltimoInteresse = Date.now();     // liga a coleta de eventos em segundo plano
  const projeto = String(req.query.projeto || '').slice(0, 40);
  // o feed guarda o nome do projeto; converte o id pedido pra nome pra filtrar
  let nomeProj = '';
  try {
    const { lista } = await _utmifyDashboardsAtivos();
    const d = lista.find(x => String(x.id) === projeto);
    if (d) nomeProj = (d.nome || '').trim();
  } catch (e) {}
  const eventos = (nomeProj
    ? _evFeed.filter(e => String(e.dashboard).trim() === nomeProj)
    : _evFeed).slice(0, 60);
  const chave = 'tempo-real|' + projeto;
  const pronto = _vivoGet(chave, 25 * 1000);
  if (pronto) return res.json(Object.assign({ doCache: true, eventos }, pronto));
  try {
    const saida = await _utmifyPanorama(null, null, projeto);
    _vivoSet(chave, saida);
    if (!_evFoto) _tickEventosUtmify();          // primeira leitura: comeca a base de comparacao
    res.json(Object.assign({ eventos }, saida));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Mesmo panorama, mas do periodo escolhido na tela (alimenta o Resumo)
app.get('/api/metricas/utmify/panorama', authUsuario, async (req, res) => {
  const de  = String(req.query.de  || '').slice(0, 10);
  const ate = String(req.query.ate || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) {
    return res.status(400).json({ error: 'Informe de/ate no formato AAAA-MM-DD.' });
  }
  const projeto = String(req.query.projeto || '').slice(0, 40);
  const chave = 'panorama|' + de + '|' + ate + '|' + projeto;
  const pronto = _vivoGet(chave, 60 * 1000);
  if (pronto) return res.json(Object.assign({ doCache: true }, pronto));
  try {
    const saida = await _utmifyPanorama(de, ate, projeto);
    _vivoSet(chave, saida);
    res.json(saida);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Cliques pro mapa de funil. O total sai do mesmo lugar que a tela de Metricas
// de Ads usa (get_dashboard_summary), pra nao ter dois numeros diferentes de
// clique no sistema. A quebra por campanha vem do nivel 'campaign' e serve pra
// amarrar cada origem de trafego numa campanha especifica.
app.get('/api/funil/cliques', authUsuario, async (req, res) => {
  const de  = String(req.query.de  || '').slice(0, 10);
  const ate = String(req.query.ate || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) {
    return res.status(400).json({ error: 'Informe de/ate no formato AAAA-MM-DD.' });
  }
  const projeto = String(req.query.projeto || '').slice(0, 40);
  const chave = 'funilcliques|' + de + '|' + ate + '|' + projeto;
  const pronto = _vivoGet(chave, 60 * 1000);
  if (pronto) return res.json(Object.assign({ doCache: true }, pronto));
  try {
    const pano = await _utmifyPanorama(de, ate, projeto);
    const achado = await _utmifyDashboardsAtivos();
    const cfg = achado.cfg, lista = _filtrarProjeto(achado.lista, projeto);
    const mapa = {};
    const erros = (pano.erros || []).slice();
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      try {
        const r = await _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', {
          dashboardId: d.id, level: 'campaign',
          dateRange: { from: de + 'T00:00:00' + off, to: ate + 'T23:59:59' + off }
        });
        // A mesma campanha aparece mais de uma vez (uma linha por conta de
        // anuncio), entao junta pelo nome — senao o seletor enche de repetido.
        ((r && r.results) || []).forEach(c => {
          const nome = String(c.name || '(sem nome)').trim();
          const k = nome.toLowerCase().replace(/\s+/g, ' ');
          if (!mapa[k]) mapa[k] = { nome, cliques: 0, investimento: 0 };
          mapa[k].cliques += Number(c.inlineLinkClicks) || 0;
          mapa[k].investimento += (Number(c.spend) || 0) / 100;
        });
      } catch (e) { erros.push((d.nome || d.id) + ': ' + e.message); }
    }
    const k = pano.kpis || {};
    const saida = {
      ok: true, de, ate,
      total: Number(k.cliques) || 0,
      visitas: Number(k.visitas) || 0,
      ics: Number(k.ics) || 0,
      // vendas aprovadas: usadas como rede de seguranca no mapa quando a pagina
      // de obrigado nao tem pixel (checkout hospedado que nao volta pro site)
      vendas: Number((k.pedidos || {}).aprovadas) || 0,
      campanhas: Object.values(mapa).filter(c => c.cliques > 0)
                       .sort((a, b) => b.cliques - a.cliques),
      erros
    };
    if (saida.total || saida.campanhas.length) _vivoSet(chave, saida);
    res.json(saida);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Quanto do gasto chega na pagina com utm_content. Sem essa UTM a VTurb nao
// consegue separar retencao por criativo, o pixel nao sabe quem trouxe a pessoa,
// e ate a Utmify enxerga o gasto como '__unattributed__'. A tela precisava dizer
// QUAIS anuncios estao sem, nao so 'confira se as UTMs estao chegando'.
app.get('/api/metricas/utmify/cobertura-utm', authUsuario, async (req, res) => {
  const de  = String(req.query.de  || '').slice(0, 10);
  const ate = String(req.query.ate || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) {
    return res.status(400).json({ error: 'Informe de/ate no formato AAAA-MM-DD.' });
  }
  const projeto = String(req.query.projeto || '').slice(0, 40);
  const chave = 'coberturautm|' + de + '|' + ate + '|' + projeto;
  const pronto = _vivoGet(chave, 5 * 60 * 1000);
  if (pronto) return res.json(Object.assign({ doCache: true }, pronto));
  try {
    const achado = await _utmifyDashboardsAtivos();
    const cfg = achado.cfg, lista = _filtrarProjeto(achado.lista, projeto);
    const cent = v => (Number(v) || 0) / 100;
    let gastoTotal = 0, gastoComUtm = 0;
    const semUtm = {}, erros = [];
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      const faixa = { from: de + 'T00:00:00' + off, to: ate + 'T23:59:59' + off };
      try {
        const [anun, porUtm] = await Promise.all([
          _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', {
            dashboardId: d.id, level: 'ad', dateRange: faixa }),
          _utmifyChamarTool(cfg.token, 'get_utms_ad_objects', {
            dashboardId: d.id, groupBy: 'utmContent', dateRange: faixa })
        ]);
        // quem TEM utm_content aparece no agrupamento com o adId preenchido
        const temUtm = new Set(((porUtm && porUtm.results) || [])
          .filter(u => u.adId).map(u => String(u.adId)));
        ((anun && anun.results) || []).forEach(a => {
          const gasto = cent(a.spend);
          if (!gasto) return;
          gastoTotal += gasto;
          if (temUtm.has(String(a.adId || a.id))) { gastoComUtm += gasto; return; }
          // junta pelo nome: o mesmo criativo roda em varias contas/campanhas
          const nome = String(a.name || '(sem nome)').trim();
          const k = nome.toLowerCase() + '|' + d.id;
          if (!semUtm[k]) semUtm[k] = {
            nome, dashboard: d.nome || d.id, conta: a.ca || '—',
            gasto: 0, cliques: 0, veiculacoes: 0
          };
          semUtm[k].gasto += gasto;
          semUtm[k].cliques += Number(a.inlineLinkClicks) || 0;
          semUtm[k].veiculacoes += 1;
        });
      } catch (e) { erros.push((d.nome || d.id) + ': ' + e.message); }
    }
    const saida = {
      ok: true, de, ate,
      gastoTotal, gastoComUtm, gastoSemUtm: gastoTotal - gastoComUtm,
      cobertura: gastoTotal > 0 ? (gastoComUtm / gastoTotal) * 100 : 0,
      semUtm: Object.values(semUtm).sort((a, b) => b.gasto - a.gasto),
      erros
    };
    if (gastoTotal) _vivoSet(chave, saida);
    res.json(saida);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/metricas/consolidado', authUsuario, (req, res) => {
  try {
    const de  = String(req.query.de  || '').slice(0,10);
    const ate = String(req.query.ate || '').slice(0,10);
    const db = readDB();
    let linhas = Array.isArray(db.store[KEY_METRICAS]) ? db.store[KEY_METRICAS] : [];
    if (de)  linhas = linhas.filter(l => l.data >= de);
    if (ate) linhas = linhas.filter(l => l.data <= ate);
    // filtro por projeto: as linhas gravadas guardam o NOME do dashboard
    const projeto = String(req.query.projeto || '').slice(0, 40);
    if (projeto) {
      const cfgP = _utmifyMcpCfg(db) || {};
      const dP = (cfgP.dashboards || []).find(x => String(x.id) === projeto);
      const nomeP = dP ? String(dP.nome || '').trim() : '';
      if (nomeP) linhas = linhas.filter(l => String(l.dashboard || '').trim() === nomeP);
    }
    // Duas camadas: linhas de CONTA dao o total exato (igual a tela da Utmify,
    // que inclui gasto nao atribuido a campanha); linhas de CAMPANHA dao o detalhe.
    // Sem linha de conta (dados antigos ou modo api), cai no detalhe.
    const deConta   = linhas.filter(l => l.nivel === 'conta');
    const deCampanha= linhas.filter(l => l.nivel !== 'conta');
    const baseKpi   = deConta.length ? deConta : deCampanha;
    const soma  = c => baseKpi.reduce((s, l) => s + (Number(l[c]) || 0), 0);
    // vendas aprovadas: e o que a Utmify chama de "Vendas Apr.". O total inclui
    // pendente/recusada, e usar ele inflava a contagem e derrubava o CPA.
    const aprov = baseKpi.reduce((s, l) => s + (Number(
      l.vendasAprovadas !== undefined ? l.vendasAprovadas : l.vendas) || 0), 0);
    const inv = soma('investimento'), fat = soma('faturamento');
    const agrupar = (campo, fonte) => {
      const m = {};
      (fonte || deCampanha).forEach(l => {
        const k = l[campo] || '—';
        if (!m[k]) m[k] = { nome:k, investimento:0, faturamento:0, lucro:0, vendas:0, cliques:0, impressoes:0 };
        m[k].investimento += Number(l.investimento)||0;
        m[k].faturamento  += Number(l.faturamento)||0;
        m[k].lucro        += Number(l.lucro)||0;
        m[k].vendas       += Number(l.vendas)||0;
        m[k].cliques      += Number(l.cliques)||0;
        m[k].impressoes   += Number(l.impressoes)||0;
      });
      return Object.values(m).map(x => Object.assign(x, {
        roas: x.investimento > 0 ? x.faturamento / x.investimento : 0
      })).sort((a,b) => b.investimento - a.investimento);
    };
    res.json({
      ok: true, de, ate, linhas: linhas.length,
      kpis: {
        investimento: inv, faturamento: fat,
        lucro: soma('lucro'), vendas: aprov, vendasTotais: soma('vendas'),
        cliques: soma('cliques'), impressoes: soma('impressoes'),
        roas: inv > 0 ? fat / inv : 0,
        cpc: soma('cliques') > 0 ? inv / soma('cliques') : 0,
        cpm: soma('impressoes') > 0 ? (inv / soma('impressoes')) * 1000 : 0,
        cpa: aprov > 0 ? inv / aprov : 0
      },
      atualizadoEm: (_utmifyMcpCfg(db) || {}).ultimaSync || null,
      porCampanha:  agrupar('campanha'),
      porAnuncio:   agrupar('anuncio'),
      porDia:       agrupar('data', baseKpi).sort((a, b) => String(a.nome).localeCompare(String(b.nome))),
      porDashboard: agrupar('dashboard', baseKpi),
      // conta de anuncio: so as linhas de nivel conta tem esse dado. As gravadas
      // antes do campo 'conta' existir caem no 'campanha', que guardava o nome.
      porConta: agrupar('conta', deConta.map(l => Object.assign({}, l, {
        conta: l.conta || l.campanha || '—'
      })))
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── API INTERNA DA UTMIFY (a mesma que o painel deles usa) ──
// Descoberta inspecionando o painel: POST server.utmify.com.br/orders/search-objects
// com Authorization: Bearer <JWT da sessao>. E a mesma API que o MCP embrulha —
// mesmo dashboardId, mesmo formato de dateRange e level.
// Vantagem: funciona com o token que voce ja tem, sem depender de integracao MCP.
// Custo: o JWT expira, entao a tela avisa quando precisar renovar.
const UTMIFY_API_URL = 'https://server.utmify.com.br';

async function _utmifyApi(jwt, caminho, corpo) {
  const r = await fetch(UTMIFY_API_URL + caminho, {
    method: corpo ? 'POST' : 'GET',
    headers: {
      'Authorization': 'Bearer ' + jwt,
      'Content-Type': 'application/json; charset=UTF-8',
      'Accept': 'application/json',
      'User-Agent': 'CentralTMX/1.0'
    },
    body: corpo ? JSON.stringify(corpo) : undefined
  });
  const texto = await r.text();
  if (r.status === 401 || r.status === 403) {
    const e = new Error('Sessão da Utmify expirou. Pegue o token novo no painel (F12 > Network > qualquer chamada > Authorization) e cole aqui de novo.');
    e.expirou = true; throw e;
  }
  if (!r.ok) throw new Error('Utmify ' + r.status + ': ' + texto.slice(0, 160));
  try { return JSON.parse(texto); } catch (e) { return texto; }
}

// Lista os dashboards — serve tambem pra validar o token
async function _utmifyApiDashboards(jwt) {
  const d = await _utmifyApi(jwt, '/dashboards/actives', null);
  // a resposta vem aninhada: { actives: [ { dashboard: {...} } ] }
  const lista = (d && Array.isArray(d.actives))
    ? d.actives.map(a => (a && a.dashboard) ? a.dashboard : a).filter(Boolean)
    : (Array.isArray(d) ? d : (d && (d.dashboards || d.results || d.data)) || []);
  return lista.map(x => ({
    id: x.id || x._id, nome: x.name || x.nome || '(sem nome)',
    moeda: x.currency || 'BRL',
    tz: (x.timeZone !== undefined && x.timeZone !== null) ? x.timeZone : -3
  })).filter(x => x.id);
}

// Campanhas com gasto/faturamento/lucro de um periodo
async function _utmifyApiCampanhas(jwt, dashboardId, deIso, ateIso) {
  const d = await _utmifyApi(jwt, '/orders/search-objects', {
    accountStatuses: null, adObjectStatuses: null, adsetIds: null, campaignIds: null,
    dashboardId: dashboardId,
    dateRange: { from: deIso, to: ateIso },
    level: 'campaign',
    metaAdAccountIds: null, nameContains: null,
    orderBy: 'greater_profit', productNames: null
  });
  return (d && (d.results || d.data || d.objects)) || (Array.isArray(d) ? d : []);
}

// ── Configuracao e sincronizacao da Utmify ──
app.get('/api/integracoes/utmify-mcp/me', authDiretoria, (req, res) => {
  try {
    const cfg = _utmifyMcpCfg();
    const db = readDB();
    const linhas = Array.isArray(db.store[KEY_METRICAS]) ? db.store[KEY_METRICAS] : [];
    const daUtmify = linhas.filter(l => l.fonte === 'utmify');
    res.json({
      ok: true,
      // 'configurado' exige token E dashboards: token salvo com validacao falha
      // aparecia como CONECTADO e confundia
      configurado: !!(cfg && cfg.token && (cfg.dashboards || []).length),
      tokenSalvo: !!(cfg && cfg.token),
      origemToken: (cfg && cfg.origemToken) || null,
      modo: (cfg && cfg.modo) || null,
      tokenPreview: (cfg && cfg.token) ? String(cfg.token).slice(0, 8) + '...' : null,
      dashboards: (cfg && cfg.dashboards) || [],
      ultimaSync: (cfg && cfg.ultimaSync) || null,
      ultimoErro: (cfg && cfg.ultimoErro) || null,
      linhasImportadas: daUtmify.length
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/integracoes/utmify-mcp/config', authDiretoria, async (req, res) => {
  try {
    const { token } = req.body || {};
    const db = readDB();
    const cfg = _utmifyMcpCfg(db) || { criadoEm: new Date().toISOString() };
    if (token && String(token).trim()) cfg.token = String(token).trim();
    // Se nao veio token e ainda nao ha um salvo, tenta o da integracao de ENVIO
    // que ja existe. A Utmify nao documenta token separado pra MCP — pode ser o
    // mesmo, e assim voce nao precisa sair procurando outro.
    if (!cfg.token) {
      const antigo = (db.store['sl_integracoes_utmify'] || [])
        .map(c => c && c.apiToken).filter(Boolean)[0];
      if (antigo) { cfg.token = String(antigo).trim(); cfg.origemToken = 'reaproveitado'; }
    }
    if (!cfg.token) return res.status(400).json({ error: 'Cole o token de acesso da Utmify.' });
    // Dois caminhos: JWT da sessao (começa com "ey", API interna) ou token de
    // integracao MCP. Detecta sozinho pra você não precisar escolher.
    cfg.modo = String(cfg.token).startsWith('ey') ? 'api' : 'mcp';
    let dashboards = [];
    try {
      dashboards = await _utmifyListarDashboards(cfg);
      cfg.ultimoErro = null;
    } catch (e) {
      cfg.ultimoErro = e.message;
      cfg.dashboards = [];          // falhou: nao mantem lista antiga
      db.store[KEY_UTMIFY_MCP] = cfg; writeDB(db);
      return res.status(400).json({ error: e.message });
    }
    cfg.dashboards = dashboards;
    cfg._updatedAt = Date.now();
    db.store[KEY_UTMIFY_MCP] = cfg;
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_UTMIFY_MCP] = now();
    audit(db, 'integracao.utmify_mcp.config', KEY_UTMIFY_MCP, { dashboards: dashboards.length }, req.user);
    writeDB(db);
    res.json({ ok: true, dashboards, reaproveitado: cfg.origemToken === 'reaproveitado' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Puxa as metricas da Utmify e grava em sl_metricas_ads (a mesma base que a tela le)
// Sincroniza um periodo e grava em sl_metricas_ads. Usada tanto pelo botao
// quanto pela rotina automatica.
async function _utmifyListarDashboards(cfg) {
  if (cfg.modo === 'api') return await _utmifyApiDashboards(cfg.token);
  const d = await _utmifyChamarTool(cfg.token, 'get_dashboards', {});
  return (Array.isArray(d) ? d : []).map(x => ({ id: x.id, nome: x.name, moeda: x.currency, tz: x.timeZone }));
}

function _diasEntre(de, ate) {
  const out = [];
  let d = new Date(de + 'T12:00:00Z');
  const fim = new Date(ate + 'T12:00:00Z');
  while (d <= fim && out.length < 92) {   // teto de ~3 meses por chamada
    out.push(d.toISOString().slice(0, 10));
    d = new Date(d.getTime() + 86400000);
  }
  return out.length ? out : [ate];
}

async function _utmifySincronizar(de, ate, dashboardsPedidos) {
  const cfg = _utmifyMcpCfg();
  if (!cfg || !cfg.token) throw new Error('Utmify não configurada.');
  if (!cfg.modo) cfg.modo = String(cfg.token).startsWith('ey') ? 'api' : 'mcp';
  let dashboards = (dashboardsPedidos && dashboardsPedidos.length)
    ? dashboardsPedidos : (cfg.dashboards || []).map(d => d.id);
  // Sem lista salva (token vindo do ambiente, por exemplo): descobre sozinho,
  // pra nao depender de alguem ter clicado em "Salvar e conectar" antes.
  if (!dashboards.length) {
    const achados = await _utmifyListarDashboards(cfg);
    if (achados.length) {
      cfg.dashboards = achados;
      dashboards = achados.map(d => d.id);
    }
  }
  if (!dashboards.length) throw new Error('Nenhum dashboard encontrado na Utmify com esse token.');

  const cent = v => (Number(v) || 0) / 100;   // a Utmify devolve em centavos
  const linhas = [];
  const erros = [];
  const dias = _diasEntre(de, ate);
  // dia a dia: numa busca de periodo a Utmify devolve o total somado, e todas as
  // linhas acabariam carimbadas com a data final (perdendo a quebra por dia).
  // Em fila isso eram 2 chamadas x cada dia x cada dashboard, uma esperando a
  // outra — um mes passava de 2 minutos com o botao travado.
  // Lotes de DOIS, medido contra a Utmify com 18 tarefas: 2 -> 6,3s e zero erro;
  // 3 -> 5,1s e 2 erros; 4 -> 2,1s e 15 erros ("Utmify recusou: ERRO"). Ela
  // rejeita rapido quando aperta, entao ir mais alto so parece mais rapido.
  const tarefas = [];
  for (const dashId of dashboards) {
    for (const dia of dias) tarefas.push({ dashId, dia });
  }
  async function _umDia(t) {
    const dashId = t.dashId, dia = t.dia;
    const meta = (cfg.dashboards || []).find(d => d.id === dashId) || {};
    const tz = (meta.tz === undefined || meta.tz === null) ? -3 : meta.tz;
    const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
    try {
      let campanhas, contas = [];
      if (cfg.modo === 'api') {
        // a API interna espera UTC (o painel manda assim)
        const dIni = new Date(dia + 'T00:00:00' + off).toISOString();
        const dFim = new Date(dia + 'T23:59:59' + off).toISOString();
        campanhas = await _utmifyApiCampanhas(cfg.token, dashId, dIni, dFim);
      } else {
        const faixa = { from: dia + 'T00:00:00' + off, to: dia + 'T23:59:59' + off };
        const r = await _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', {
          dashboardId: dashId, level: 'campaign', dateRange: faixa
        });
        campanhas = (r && r.results) ? r.results : [];
        // Nivel conta tambem: parte do gasto nao cai em campanha nenhuma, e e o
        // total da conta que a tela da Utmify exibe. Sem isso os KPIs ficam menores.
        try {
          const rc = await _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', {
            dashboardId: dashId, level: 'account', dateRange: faixa
          });
          contas = (rc && rc.results) ? rc.results : [];
        } catch (e) { contas = []; }
      }
      (contas || []).forEach(c => {
        const inv = cent(c.spend), fat = cent(c.grossRevenue);
        if (!inv && !fat) return;
        linhas.push({
          data: dia, fonte: 'utmify', nivel: 'conta', dashboard: meta.nome || dashId,
          conta: String(c.name || ''),
          campanhaId: '', campanha: String(c.name || ''),
          adsetId: '', adset: '', adId: '', anuncio: '',
          investimento: inv, faturamento: fat,
          faturamentoLiquido: cent(c.revenue), lucro: cent(c.profit),
          vendas: Number(c.totalOrdersCount) || 0,
          vendasAprovadas: Number(c.approvedOrdersCount) || 0,
          impressoes: Number(c.impressions) || 0,
          cliques: Number(c.inlineLinkClicks) || 0,
          ctr: Number(c.inlineLinkClickCtr) || 0,
          cpc: cent(c.costPerInlineLinkClick), cpm: cent(c.cpm),
          roas: Number(c.roas) || 0
        });
      });
      (campanhas || []).forEach(c => {
        const inv = cent(c.spend), fat = cent(c.grossRevenue);
        if (!inv && !fat) return;
        linhas.push({
          data: dia, fonte: 'utmify', nivel: 'campanha', dashboard: meta.nome || dashId,
          campanhaId: String(c.campaignId || c.id || ''), campanha: String(c.name || ''),
          adsetId: '', adset: '', adId: '', anuncio: '',
          investimento: inv, faturamento: fat,
          faturamentoLiquido: cent(c.revenue), lucro: cent(c.profit),
          vendas: Number(c.totalOrdersCount) || 0,
          vendasAprovadas: Number(c.approvedOrdersCount) || 0,
          impressoes: Number(c.impressions) || 0,
          cliques: Number(c.inlineLinkClicks) || 0,
          ctr: Number(c.inlineLinkClickCtr) || 0,
          cpc: cent(c.costPerInlineLinkClick), cpm: cent(c.cpm),
          roas: Number(c.roas) || 0
        });
      });
    } catch (e) { erros.push((meta.nome || dashId) + ' ' + dia + ': ' + e.message); }
  }
  // a primeira sozinha: ela abre a sessao MCP, e as demais ja reaproveitam
  if (tarefas.length) await _umDia(tarefas[0]);
  const resto = tarefas.slice(1);
  for (let i = 0; i < resto.length; i += 2) {
    await Promise.all(resto.slice(i, i + 2).map(_umDia));
  }
  // Repescagem: o que falhou volta uma vez, em fila. Recusa por aperto passa
  // na segunda, e assim um tropeco nao deixa buraco de um dia inteiro no banco.
  if (erros.length) {
    const falhou = erros.slice();
    erros.length = 0;
    // A recusa quase sempre e aperto de limite disfarçado. Esperar alguns
    // segundos antes de insistir resolve mais do que tentar na hora.
    await _dormir(6000);
    for (const t of tarefas) {
      const meta = (cfg.dashboards || []).find(d => d.id === t.dashId) || {};
      const marca = (meta.nome || t.dashId) + ' ' + t.dia + ':';
      if (falhou.some(m => m.indexOf(marca) === 0)) await _umDia(t);
    }
  }

  const db = readDB();
  const atual = Array.isArray(db.store[KEY_METRICAS]) ? db.store[KEY_METRICAS] : [];
  const mantidos = atual.filter(l => !(l.fonte === 'utmify' && l.data >= de && l.data <= ate));
  db.store[KEY_METRICAS] = mantidos.concat(linhas);
  const c2 = _utmifyMcpCfg(db) || cfg;
  if (!(c2.dashboards || []).length && (cfg.dashboards || []).length) c2.dashboards = cfg.dashboards;
  if (!c2.modo) c2.modo = cfg.modo;
  c2.ultimaSync = new Date().toISOString();
  c2.ultimoErro = erros.length ? erros.join(' | ') : null;
  db.store[KEY_UTMIFY_MCP] = c2;
  if (!db.timestamps) db.timestamps = {};
  db.timestamps[KEY_METRICAS] = now();
  writeDB(db);
  return { importadas: linhas.length, substituidas: atual.length - mantidos.length, erros };
}

app.post('/api/integracoes/utmify-mcp/sync', authDiretoria, async (req, res) => {
  const de  = String((req.body && req.body.de)  || '').slice(0, 10);
  const ate = String((req.body && req.body.ate) || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) {
    return res.status(400).json({ error: 'Informe de/ate no formato AAAA-MM-DD.' });
  }
  try {
    const r = await _utmifySincronizar(de, ate, (req.body && req.body.dashboards) || null);
    res.json(Object.assign({ ok: true }, r));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Liga/desliga a atualizacao automatica
app.post('/api/integracoes/utmify-mcp/auto', authDiretoria, (req, res) => {
  try {
    const db = readDB();
    const cfg = _utmifyMcpCfg(db);
    if (!cfg || !cfg.token) return res.status(400).json({ error: 'Configure o token primeiro.' });
    cfg.autoSync = (req.body && req.body.ativo) === true;
    const min = Number(req.body && req.body.minutos);
    cfg.autoMin = (min >= 15 && min <= 720) ? min : 30;   // piso de 15min: a Utmify pede pra não abusar
    db.store[KEY_UTMIFY_MCP] = cfg;
    writeDB(db);
    res.json({ ok: true, autoSync: cfg.autoSync, minutos: cfg.autoMin });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── ROTINA AUTOMÁTICA ──
// Roda de tempos em tempos e atualiza HOJE + ONTEM (ontem porque venda de fim
// de dia costuma ser atribuída depois). Reimportar substitui, não duplica.
let _utmifyRodando = false;
let _avisouDesligado = false;
async function _tickUtmifyAuto() {
  if (_utmifyRodando) return;                       // evita rodadas sobrepostas
  let cfg;
  try { cfg = _utmifyMcpCfg(); } catch (e) { return; }
  if (!cfg || !cfg.token) return;
  if (!cfg.autoSync) {
    // Silencio aqui foi o que escondeu o problema por horas: a sincronizacao
    // estava desligada e nada dizia isso em lugar nenhum.
    if (!_avisouDesligado) {
      console.warn('[UTMIFY] sincronização automática DESLIGADA — nada será atualizado sozinho.');
      _avisouDesligado = true;
    }
    return;
  }
  const min = Number(cfg.autoMin) || 15;   // o gasto sobe o dia todo: 30min defasava demais
  const ultima = cfg.ultimaSyncAuto ? new Date(cfg.ultimaSyncAuto).getTime() : 0;
  const faltam = min * 60 * 1000 - (Date.now() - ultima);
  if (faltam > 0) return;                             // ainda não deu a hora
  if (ultima) {
    const atraso = Math.round((Date.now() - ultima) / 60000);
    if (atraso > min * 2) console.warn('[UTMIFY] ficou ' + atraso + 'min sem sincronizar.');
  }
  _utmifyRodando = true;
  try {
    const tz = -3;
    const agora = new Date(Date.now() + tz * 3600000);
    const iso = d => d.toISOString().slice(0, 10);
    const ontem = new Date(agora.getTime() - 86400000);
    const r = await _utmifySincronizar(iso(ontem), iso(agora), null);
    const db = readDB();
    const c = _utmifyMcpCfg(db);
    if (c) { c.ultimaSyncAuto = new Date().toISOString(); db.store[KEY_UTMIFY_MCP] = c; writeDB(db); }
    console.log(`[UTMIFY] auto-sync: ${r.importadas} campanha(s).`);
  } catch (e) {
    console.error('[UTMIFY] auto-sync falhou:', e.message);
    try {
      const db = readDB(); const c = _utmifyMcpCfg(db);
      if (c) { c.ultimoErro = e.message; c.ultimaSyncAuto = new Date().toISOString();
               db.store[KEY_UTMIFY_MCP] = c; writeDB(db); }
    } catch (e2) {}
  } finally { _utmifyRodando = false; }
}
// Conferir de 5 em 5 minutos parecia suficiente, mas cada deploy reinicia o
// servidor e zera o cronometro: numa sequencia de deploys curtos o timer nunca
// chegava na primeira execucao e a sincronizacao simplesmente parava.
// Agora confere logo depois de subir e com mais frequencia.
setTimeout(_tickUtmifyAuto, 45 * 1000);        // pouco depois do boot
setInterval(_tickUtmifyAuto, 2 * 60 * 1000);   // confere a cada 2min; só roda quando dá a hora


// ══════════════════════════════════════════════
// ── SAAS · PLANOS E LIMITES (Bloqueador 3/7) ──
// Define os 3 planos comerciais com limites e features.
// ══════════════════════════════════════════════

const SAAS_PLANOS = {
  trial: {
    id: 'trial',
    nome: 'Trial Grátis',
    precoBRL: 0,
    duracao: '14 dias',
    limites: {
      maxUsuarios: 5,
      maxDemandas: 100,
      maxClientes: 1,
      maxNichos: 3,
      maxArquivosMB: 200,
      historicoMeses: 1
    },
    features: {
      demandas: true,
      criativos: true,
      rh: true,
      financeiro: true,
      spy: true,
      spyWolfMaster: false,
      iaWhatsapp: false,
      ofx: false,
      apiTokens: false,
      brandingCustom: false,
      dominioProprio: false,
      multiUsuario: true,
      relatoriosCustom: false
    }
  },
  basic: {
    id: 'basic',
    nome: 'Basic',
    precoBRL: 97,
    duracao: 'mensal',
    limites: {
      maxUsuarios: 5,
      maxDemandas: 500,
      maxClientes: 3,
      maxNichos: 5,
      maxArquivosMB: 1000,
      historicoMeses: 3
    },
    features: {
      demandas: true,
      criativos: true,
      rh: true,
      financeiro: true,
      spy: true,
      spyWolfMaster: true,
      iaWhatsapp: false,
      ofx: false,
      apiTokens: false,
      brandingCustom: false,
      dominioProprio: false,
      multiUsuario: true,
      relatoriosCustom: false
    }
  },
  pro: {
    id: 'pro',
    nome: 'Pro',
    precoBRL: 297,
    duracao: 'mensal',
    limites: {
      maxUsuarios: 20,
      maxDemandas: 5000,
      maxClientes: 10,
      maxNichos: 20,
      maxArquivosMB: 10000,
      historicoMeses: 12
    },
    features: {
      demandas: true,
      criativos: true,
      rh: true,
      financeiro: true,
      spy: true,
      spyWolfMaster: true,
      iaWhatsapp: true,
      ofx: true,
      apiTokens: true,
      brandingCustom: true,
      dominioProprio: false,
      multiUsuario: true,
      relatoriosCustom: true
    }
  },
  enterprise: {
    id: 'enterprise',
    nome: 'Enterprise',
    precoBRL: 997,
    duracao: 'mensal',
    limites: {
      maxUsuarios: -1, // ilimitado
      maxDemandas: -1,
      maxClientes: -1,
      maxNichos: -1,
      maxArquivosMB: -1,
      historicoMeses: -1
    },
    features: {
      demandas: true,
      criativos: true,
      rh: true,
      financeiro: true,
      spy: true,
      spyWolfMaster: true,
      iaWhatsapp: true,
      ofx: true,
      apiTokens: true,
      brandingCustom: true,
      dominioProprio: true,
      multiUsuario: true,
      relatoriosCustom: true,
      suportePrioritario: true,
      nichosCustom: true
    }
  }
};

// Retorna o plano efetivo de um tenant (com fallback pra trial)
function _getPlanoTenant(tenantId, db) {
  if (!db) db = readDB();
  if (tenantId === TENANT_INTERNO_ID) return SAAS_PLANOS.enterprise; // axcend-interno tem tudo
  const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
  if (!tenant || !tenant.plano) return SAAS_PLANOS.trial;
  return SAAS_PLANOS[tenant.plano] || SAAS_PLANOS.trial;
}

// Verifica se o tenant pode usar uma feature
function _podeUsarFeature(tenantId, feature, db) {
  const plano = _getPlanoTenant(tenantId, db);
  return plano.features[feature] === true;
}

// Verifica se o tenant ainda tem espaço pra criar mais um item de tipo X
// returns: { ok: bool, usado: N, limite: N, plano: 'basic' }
function _checarLimite(tenantId, tipo, db) {
  if (!db) db = readDB();
  const plano = _getPlanoTenant(tenantId, db);
  const limiteKey = 'max' + tipo.charAt(0).toUpperCase() + tipo.slice(1);
  const limite = plano.limites[limiteKey];
  if (limite === -1) return { ok: true, usado: -1, limite: -1, plano: plano.id, ilimitado: true };

  // Conta uso atual
  let usado = 0;
  const tenantTag = u => getItemTenant(u) === tenantId;
  if (tipo === 'usuarios') usado = (db.store['sl_usuarios'] || []).filter(tenantTag).filter(u => u.ativo !== false).length;
  else if (tipo === 'demandas') usado = (db.store.tasks || []).filter(tenantTag).filter(t => !t.arquivado).length;
  else if (tipo === 'clientes') usado = (db.store['roi_nichos'] || []).filter(tenantTag).length;
  else if (tipo === 'nichos') usado = (db.store['sl_nichos'] || []).filter(tenantTag).length;

  return {
    ok: usado < limite,
    usado,
    limite,
    plano: plano.id,
    ilimitado: false,
    pct: Math.round(usado / limite * 100)
  };
}

// GET /api/saas/planos — lista planos disponíveis
app.get('/api/saas/planos', (req, res) => {
  res.json({ ok: true, planos: Object.values(SAAS_PLANOS) });
});

// ══════════════════════════════════════════════
// ── BILLING · Pagar.me (Bloqueador 4/7) ──
// Cobrança recorrente mensal via Pagar.me v5.
// Configure PAGARME_API_KEY no Railway pra ativar.
// ══════════════════════════════════════════════

const PAGARME_API_KEY = process.env.PAGARME_API_KEY || '';
const PAGARME_API_BASE = 'https://api.pagar.me/core/v5';

// POST /api/billing/checkout — cria checkout de assinatura pro tenant logado
// Body: { planoId: 'basic'|'pro'|'enterprise' }
app.post('/api/billing/checkout', async (req, res) => {
  try {
    const { planoId } = req.body || {};
    if (!planoId || !['basic','pro','enterprise'].includes(planoId)) {
      return res.status(400).json({ error: 'planoId inválido' });
    }
    if (!PAGARME_API_KEY) {
      // Modo de desenvolvimento — retorna link mock
      return res.json({
        ok: false,
        modo: 'mock',
        message: 'Billing não está configurado. Defina PAGARME_API_KEY no Railway. Por enquanto, contate suporte@axcend.com pra fazer upgrade.',
        suporteUrl: 'mailto:suporte@axcend.com?subject=Upgrade%20pra%20'+planoId
      });
    }

    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const db = readDB();
    const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
    if (!tenant) return res.status(404).json({ error: 'Tenant não encontrado' });

    const plano = SAAS_PLANOS[planoId];

    // Cria/recupera customer no Pagar.me
    let customerId = tenant.pagarmeCustomerId;
    if (!customerId) {
      const cust = await fetch(PAGARME_API_BASE + '/customers', {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(PAGARME_API_KEY + ':').toString('base64'),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: tenant.contato?.nomeAdmin || tenant.nome,
          email: tenant.contato?.email || '',
          type: 'individual',
          country: 'BR',
          metadata: { tenantId: tenant.id, slug: tenant.slug }
        })
      });
      if (!cust.ok) {
        const err = await cust.text();
        return res.status(500).json({ error: 'Erro Pagar.me: ' + err.slice(0,200) });
      }
      const custData = await cust.json();
      customerId = custData.id;
      tenant.pagarmeCustomerId = customerId;
      tenant._updatedAt = Date.now();
      db.timestamps['sl_saas_tenants'] = now();
      writeDB(db);
    }

    // Cria checkout link
    const cents = Math.round(plano.precoBRL * 100);
    const orderRes = await fetch(PAGARME_API_BASE + '/orders', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(PAGARME_API_KEY + ':').toString('base64'),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        customer_id: customerId,
        items: [{
          amount: cents,
          description: 'TMX Digital ' + plano.nome + ' — Assinatura mensal',
          quantity: 1
        }],
        payments: [{
          payment_method: 'checkout',
          checkout: {
            expires_in: 120, // minutos
            accepted_payment_methods: ['credit_card', 'pix', 'boleto'],
            success_url: `https://${tenant.slug}.${SAAS_ROOT_DOMAIN}/?billing=success&plano=${planoId}`,
            billing_address_editable: true,
            customer_editable: true
          }
        }],
        metadata: { tenantId: tenant.id, slug: tenant.slug, planoId }
      })
    });
    if (!orderRes.ok) {
      const err = await orderRes.text();
      return res.status(500).json({ error: 'Erro ao criar order Pagar.me: ' + err.slice(0,200) });
    }
    const orderData = await orderRes.json();
    const checkoutUrl = orderData.checkouts?.[0]?.payment_url || orderData.checkout_url;

    res.json({
      ok: true,
      checkoutUrl,
      orderId: orderData.id,
      plano: plano.nome,
      valor: plano.precoBRL
    });
  } catch (err) {
    console.error('[billing/checkout]', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/billing/webhook — Pagar.me chama quando pagamento muda de status
// Configurar URL no painel Pagar.me: https://app.centralaxcend.com/api/billing/webhook
app.post('/api/billing/webhook', async (req, res) => {
  try {
    const evento = req.body || {};
    console.log('[Pagar.me webhook]', evento.type, evento.id);

    // Tipos relevantes: order.paid, subscription.canceled, charge.paid, charge.refused
    if (evento.type === 'order.paid' || evento.type === 'charge.paid') {
      const meta = evento.data?.metadata || evento.data?.order?.metadata || {};
      const tenantId = meta.tenantId;
      const planoId = meta.planoId;
      if (tenantId && planoId) {
        const db = readDB();
        const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
        if (tenant) {
          // 📧 Hook email: confirma pagamento
          _enviarEmail({
            to: tenant.contato?.email,
            subject: '✅ Pagamento confirmado · TMX Digital',
            html: _emailTemplatePagamentoConfirmado(tenant.contato?.nomeAdmin || tenant.nome, SAAS_PLANOS[planoId]?.nome, SAAS_PLANOS[planoId]?.precoBRL || 0)
          }).catch(()=>{});

          // 🚀 Hook Utmify: cliente PAGOU → evento 'conversion' (venda fechada!)
          // Envia pra Diretoria TMX Digital (você é o owner do funil) + pro próprio tenant (auto-conversão)
          const valorPago = SAAS_PLANOS[planoId]?.precoBRL || 0;
          _enviarEventoUtmify(TENANT_INTERNO_ID, 'conversion', {
            orderId: 'pay-' + tenantId + '-' + Date.now(),
            customerName: tenant.contato?.nomeAdmin || tenant.nome,
            customerEmail: tenant.contato?.email || '',
            customerPhone: tenant.contato?.telefone || '',
            productName: 'Plano TMX Digital ' + SAAS_PLANOS[planoId]?.nome,
            planId: planoId,
            planName: SAAS_PLANOS[planoId]?.nome,
            value: valorPago,
            paymentMethod: 'credit_card'
          }).catch(()=>{});

          tenant.plano = planoId;
          tenant.status = 'ativo';
          tenant.assinatura = {
            ativa: true,
            ativadaEm: new Date().toISOString(),
            ultimoPagamento: new Date().toISOString(),
            proximoPagamento: new Date(Date.now() + 30*24*60*60*1000).toISOString(),
            valorMensal: SAAS_PLANOS[planoId].precoBRL,
            tentativasFalhadas: 0
          };
          tenant._updatedAt = Date.now();
          db.timestamps['sl_saas_tenants'] = now();
          audit(db, 'billing_pagamento_aprovado', { tenantId, planoId, eventoId: evento.id }, null, { id: 'sistema', nome: 'Sistema', cargo: 'sistema' });
          writeDB(db);
          // Invalida cache
          _tenantCache = { ts: 0, byHost: new Map(), bySlug: new Map() };
        }
      }
    } else if (evento.type === 'charge.refused' || evento.type === 'charge.payment_failed') {
      const meta = evento.data?.metadata || {};
      const tenantId = meta.tenantId;
      if (tenantId) {
        const db = readDB();
        const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
        if (tenant) {
          tenant.assinatura = tenant.assinatura || {};
          tenant.assinatura.tentativasFalhadas = (tenant.assinatura.tentativasFalhadas || 0) + 1;
          // 📧 Hook email: avisa cliente que cobrança falhou
          _enviarEmail({
            to: tenant.contato?.email,
            subject: '⚠️ Pagamento falhou · TMX Digital',
            html: _emailTemplatePagamentoFalhado(tenant.contato?.nomeAdmin || tenant.nome, SAAS_PLANOS[tenant.plano]?.nome || tenant.plano, tenant.assinatura.tentativasFalhadas, 3)
          }).catch(()=>{});
          if (tenant.assinatura.tentativasFalhadas >= 3) {
            tenant.status = 'suspenso';
            audit(db, 'billing_tenant_suspenso', { tenantId, tentativas: 3 }, null, { id: 'sistema', nome: 'Sistema', cargo: 'sistema' });
          }
          tenant._updatedAt = Date.now();
          db.timestamps['sl_saas_tenants'] = now();
          writeDB(db);
        }
      }
    }

    res.json({ ok: true, received: true });
  } catch (err) {
    console.error('[billing/webhook]', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/billing/me — info da assinatura do tenant
app.get('/api/billing/me', (req, res) => {
  try {
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const db = readDB();
    const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
    if (!tenant) return res.json({ ok: true, assinatura: null });
    res.json({
      ok: true,
      plano: tenant.plano,
      status: tenant.status,
      trial: tenant.trial,
      assinatura: tenant.assinatura || null,
      pagarmeConfigurado: !!PAGARME_API_KEY
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/saas/meu-plano — retorna plano atual + uso vs limite
app.get('/api/saas/meu-plano', (req, res) => {
  try {
    const tenantId = req.tenantId || TENANT_DEFAULT_ID;
    const db = readDB();
    const plano = _getPlanoTenant(tenantId, db);
    const tenant = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);

    // Uso atual em cada limite
    const uso = {
      usuarios: _checarLimite(tenantId, 'usuarios', db),
      demandas: _checarLimite(tenantId, 'demandas', db),
      clientes: _checarLimite(tenantId, 'clientes', db),
      nichos: _checarLimite(tenantId, 'nichos', db)
    };

    res.json({
      ok: true,
      tenantId,
      tenantNome: tenant ? tenant.nome : 'Interno',
      plano,
      uso,
      tenant: tenant ? {
        plano: tenant.plano,
        status: tenant.status,
        trial: tenant.trial || null
      } : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════
// ── SAAS · SIGNUP PÚBLICO (Bloqueador 1/7) ──
// Permite que qualquer pessoa se cadastre como cliente novo:
// cria tenant + usuário admin + trial de 14d.
// ══════════════════════════════════════════════

// Slugs reservados que ninguém pode usar (conflitam com subdomínios da plataforma)
const SLUGS_RESERVADOS_SIGNUP = new Set([
  ...SUBDOMINIOS_RESERVADOS,
  'axcend', 'central', 'centralaxcend', 'painel', 'master', 'root', 'sys', 'system',
  'support', 'suporte', 'contato', 'ajuda', 'pricing', 'precos', 'planos', 'signup',
  'login', 'logout', 'register', 'registro', 'cadastro', 'home', 'index'
]);

// GET /api/saas/signup/check-slug?slug=acme — verifica se slug está disponível
app.get('/api/saas/signup/check-slug', (req, res) => {
  const slugRaw = String(req.query.slug || '').toLowerCase().trim();
  // Sanitiza: só letras, números e hífen
  const slug = slugRaw.replace(/[^a-z0-9-]/g, '').replace(/^-+|-+$/g, '');
  if (!slug || slug.length < 3) return res.json({ ok: false, disponivel: false, motivo: 'Slug muito curto (mínimo 3 caracteres)' });
  if (slug.length > 30) return res.json({ ok: false, disponivel: false, motivo: 'Slug muito longo (máximo 30)' });
  if (SLUGS_RESERVADOS_SIGNUP.has(slug)) return res.json({ ok: false, disponivel: false, motivo: 'Slug reservado pela plataforma' });
  const db = readDB();
  const tenants = db.store['sl_saas_tenants'] || [];
  const existe = tenants.find(t => t && t.slug && String(t.slug).toLowerCase() === slug);
  if (existe) return res.json({ ok: false, disponivel: false, motivo: 'Slug já em uso por outra empresa' });
  res.json({ ok: true, disponivel: true, slug, url: `https://${slug}.${SAAS_ROOT_DOMAIN}` });
});

// POST /api/saas/signup — cria novo cliente (tenant + admin + trial)
// Body: { empresa, slug, nomeAdmin, email, senha, telefone?, aceitouTermos: true }
app.post('/api/saas/signup', async (req, res) => {
  try {
    const { empresa, slug: slugRaw, nomeAdmin, email, senha, telefone, aceitouTermos } = req.body || {};

    // Validações
    if (!empresa || empresa.length < 2) return res.status(400).json({ error: 'Nome da empresa obrigatório' });
    if (!nomeAdmin || nomeAdmin.length < 2) return res.status(400).json({ error: 'Nome do admin obrigatório' });
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email inválido' });
    if (!senha || senha.length < 6) return res.status(400).json({ error: 'Senha precisa ter no mínimo 6 caracteres' });
    if (!aceitouTermos) return res.status(400).json({ error: 'É obrigatório aceitar os Termos de Uso e Política de Privacidade' });

    // Sanitiza e valida slug
    const slug = String(slugRaw || '').toLowerCase().trim().replace(/[^a-z0-9-]/g, '').replace(/^-+|-+$/g, '');
    if (!slug || slug.length < 3) return res.status(400).json({ error: 'Slug do subdomínio inválido (mínimo 3 caracteres)' });
    if (slug.length > 30) return res.status(400).json({ error: 'Slug muito longo (máximo 30)' });
    if (SLUGS_RESERVADOS_SIGNUP.has(slug)) return res.status(400).json({ error: 'Slug reservado, escolha outro' });

    const db = readDB();
    const tenants = db.store['sl_saas_tenants'] || [];
    const usuarios = db.store['sl_usuarios'] || [];

    // Verifica unicidade de slug
    if (tenants.find(t => t && t.slug && String(t.slug).toLowerCase() === slug)) {
      return res.status(409).json({ error: 'Esse subdomínio já está em uso por outra empresa' });
    }
    // Verifica unicidade de email
    if (usuarios.find(u => u && u.email && u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email já cadastrado. Faça login em vez de criar nova conta.' });
    }

    // Cria tenant
    const tenantId = 'tenant-' + Date.now().toString(36) + '-' + crypto.randomBytes(3).toString('hex');
    const trialDias = 14;
    const agora = new Date();
    const trialFim = new Date(agora.getTime() + trialDias * 24 * 60 * 60 * 1000);

    const novoTenant = {
      id: tenantId,
      slug: slug,
      nome: empresa,
      criado: agora.toISOString(),
      criadoPor: 'signup_publico',
      plano: 'trial',
      status: 'ativo',
      trial: {
        iniciado: agora.toISOString(),
        expira: trialFim.toISOString(),
        diasTotais: trialDias
      },
      contato: {
        email: email.toLowerCase(),
        telefone: telefone || '',
        nomeAdmin: nomeAdmin
      },
      termosAceitos: {
        versao: '1.0',
        aceitoEm: agora.toISOString(),
        ip: req.ip || req.headers['x-forwarded-for'] || '',
        userAgent: req.headers['user-agent'] || ''
      },
      branding: {
        nome: empresa,
        primary: '#5b5ef4',
        secondary: '#3E1493',
        bgDark: '#0F0F0F',
        logoUrl: '',
        faviconUrl: ''
      },
      _updatedAt: Date.now()
    };

    // Cria usuário admin (Diretoria)
    const adminId = 'u-' + Date.now().toString(36) + '-' + crypto.randomBytes(3).toString('hex');
    const senhaHash = bcrypt.hashSync(String(senha), BCRYPT_ROUNDS);
    const novoAdmin = {
      id: adminId,
      nome: nomeAdmin,
      email: email.toLowerCase(),
      senhaHash: senhaHash,
      cargo: 'Diretoria',
      whatsapp: telefone || '',
      ativo: true,
      tenant_id: tenantId,
      criadoEm: agora.toISOString(),
      criadoPor: 'signup_publico',
      _updatedAt: Date.now()
    };

    // Salva
    tenants.push(novoTenant);
    usuarios.push(novoAdmin);
    db.store['sl_saas_tenants'] = tenants;
    db.store['sl_usuarios'] = usuarios;
    if (!db.timestamps) db.timestamps = {};
    db.timestamps['sl_saas_tenants'] = now();
    db.timestamps['sl_usuarios'] = now();

    // Audit log
    audit(db, 'saas_signup', { tenantId, slug, empresa, email: email.toLowerCase() }, { ip: req.ip }, { id: adminId, nome: nomeAdmin, cargo: 'Diretoria' });

    // Cria sessão automaticamente (login direto)
    const token = criarSessao(db, adminId);

    writeDB(db);

    // Invalida cache de tenants pra resolução por host funcionar imediatamente
    _tenantCache = { ts: 0, byHost: new Map(), bySlug: new Map() };

    // Notifica admin do TMX Digital via WhatsApp (se configurado)
    try {
      const cfg = db.store['sl_whatsapp_config'] || {};
      const adminInterno = (db.store['sl_usuarios'] || []).find(u => u.cargo === 'Diretoria' && u.tenant_id === TENANT_INTERNO_ID && u.whatsapp);
      if (cfg.ativo && adminInterno && adminInterno.whatsapp) {
        sendWhatsAppMessage(adminInterno.whatsapp,
          `🎉 *Novo cliente no TMX Digital!*\n\n*Empresa:* ${empresa}\n*Admin:* ${nomeAdmin}\n*Email:* ${email}\n*Subdomínio:* ${slug}.${SAAS_ROOT_DOMAIN}\n*Plano:* Trial 14 dias\n\n_via signup público_`
        ).catch(()=>{});
      }
    } catch(e) { console.error('[signup notif WA]', e.message); }

    // 📧 Hook email: envia boas-vindas pro novo admin
    _enviarEmail({
      to: email.toLowerCase(),
      subject: `🎉 Bem-vindo ao TMX Digital, ${nomeAdmin}!`,
      html: _emailTemplateBoasVindas(nomeAdmin, `https://${slug}.${SAAS_ROOT_DOMAIN}/?token=${token}`)
    }).catch(()=>{});

    // 🚀 Hook Utmify: envia evento 'lead' pra Diretoria TMX Digital (qualifica como lead)
    // Esse signup conta como LEAD QUALIFICADO no funil do TMX Digital (você é o owner)
    const utmSignup = req.body.utm || {};
    _enviarEventoUtmify(TENANT_INTERNO_ID, 'qualified', {
      orderId: 'signup-' + tenantId,
      customerName: nomeAdmin,
      customerEmail: email.toLowerCase(),
      customerPhone: telefone || '',
      productName: 'Trial TMX Digital · ' + empresa,
      value: 0,
      planId: 'trial',
      planName: 'Trial 14 dias',
      ip: req.ip || '',
      utm_source: utmSignup.utm_source,
      utm_campaign: utmSignup.utm_campaign,
      utm_medium: utmSignup.utm_medium,
      utm_content: utmSignup.utm_content,
      utm_term: utmSignup.utm_term
    }).catch(()=>{});

    res.json({
      ok: true,
      tenant: {
        id: tenantId,
        slug,
        nome: empresa,
        url: `https://${slug}.${SAAS_ROOT_DOMAIN}`,
        trial: { dias: trialDias, expira: trialFim.toISOString() }
      },
      user: {
        id: adminId,
        nome: nomeAdmin,
        email: email.toLowerCase(),
        cargo: 'Diretoria'
      },
      token: token,
      mensagem: `Conta criada! Seu painel está em https://${slug}.${SAAS_ROOT_DOMAIN}`
    });
  } catch (err) {
    console.error('[/api/saas/signup]', err);
    res.status(500).json({ error: 'Erro ao criar conta: ' + err.message });
  }
});

// GET /signup — serve a página pública de signup
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// GET /termos — serve Termos de Uso + Política de Privacidade (LGPD)
app.get('/termos', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'termos.html'));
});

// GET /ajuda — serve Central de Ajuda (Help Center)
app.get('/ajuda', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ajuda.html'));
});

// GET /preview-menu — 4 conceitos de layout de menu pra escolher
app.get('/preview-menu', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'preview-menu.html'));
});
app.get('/help', (req, res) => res.redirect('/ajuda'));
app.get('/docs', (req, res) => res.redirect('/ajuda'));

// GET /landing — landing page pública pra vendas
app.get('/landing', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});
// GET /site e /vendas — página de vendas institucional TMX Digital
app.get(['/site', '/vendas'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'site.html'));
});
// /pricing e /planos viram alias pra /landing#pricing
app.get('/pricing', (req, res) => res.redirect('/landing#pricing'));
app.get('/planos', (req, res) => res.redirect('/landing#pricing'));
app.get('/privacidade', (req, res) => res.redirect('/termos#privacidade'));
app.get('/lgpd', (req, res) => res.redirect('/termos#privacidade'));

// GET /api/spy/master — bibliotecas mestre (qualquer usuário autenticado pode ler)
// Mostra o banco master que VOCÊ alimenta — clientes veem como "Inteligência TMX Digital"
app.get('/api/spy/master', (req, res) => {
  try {
    const db = readDB();
    const masterBibs = db.store['sl_spy_master'] || [];
    const nichos = db.store['sl_spy_auto_nichos'] || [];
    const lastUpdate = db.timestamps['sl_spy_master'] || 0;
    res.json({
      ok: true,
      bibliotecas: masterBibs,
      nichos: nichos,
      totalBibliotecas: masterBibs.length,
      ultimaAtualizacao: lastUpdate ? new Date(lastUpdate * 1000).toISOString() : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/spy/nichos — lista nichos disponíveis (pra skill saber pra qual mandar)
app.get('/api/spy/nichos', authAPI, (req, res) => {
  const db = readDB();
  const nichos = (db.store['sl_spy_auto_nichos'] || []).map(n => ({
    id: n.id,
    nome: n.nome,
    icone: n.icone,
    termos: n.termos,
    ultimaBusca: n.ultimaBusca || null,
    ultimoRun: n.ultimoRun || null
  }));
  res.json({ ok: true, nichos });
});

// ══════════════════════════════════════════════
// ── ROTAS INTERNAS (frontend sync) ──
// ══════════════════════════════════════════════

// ══════════════════════════════════════════════
// ── BRANDING DO TENANT (multi-tenancy PR 6) ──
// Endpoints pra o cliente buscar/editar o branding DELE.
// O branding mora em sl_saas_tenants[].branding — esse endpoint expõe só o
// branding (não toda a info do tenant), pra qualquer um logado.
// ══════════════════════════════════════════════
const BRANDING_DEFAULT = {
  nome: 'TMX Digital',
  primary: '#5b5ef4',
  secondary: '#3E1493',
  bgDark: '#0F0F0F',
  logoUrl: '',
  faviconUrl: ''
};

app.get('/api/tenant/branding', (req, res) => {
  try {
    const db = readDB();
    const tenants = db.store['sl_saas_tenants'] || [];
    const t = tenants.find(x => x && x.id === req.tenantId);
    const branding = (t && t.branding) ? t.branding : {};
    res.json({
      tenantId: req.tenantId,
      tenantNome: (t && t.nome) || 'TMX Digital',
      branding: Object.assign({}, BRANDING_DEFAULT, branding)
    });
  } catch (e) {
    console.error('[BRANDING get]', e.message);
    res.status(500).json({ error: 'Erro ao buscar branding' });
  }
});

app.put('/api/tenant/branding', (req, res) => {
  try {
    // Só Diretoria do tenant pode editar o branding dele
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ error: 'Não autenticado' });
    const db = readDB();
    const sess = validarSessao(db, token);
    if (!sess) return res.status(401).json({ error: 'Sessão expirada' });
    const user = (db.store['sl_usuarios'] || []).find(u => u.id === sess.userId);
    if (!user || user.cargo !== 'Diretoria') return res.status(403).json({ error: 'Só Diretoria pode editar branding' });
    if (getItemTenant(user) !== req.tenantId) return res.status(403).json({ error: 'Usuário não pertence a esse tenant' });

    const body = req.body || {};
    // Sanitiza: só campos esperados, valores curtos
    const novo = {
      primary: String(body.primary || BRANDING_DEFAULT.primary).slice(0, 20),
      secondary: String(body.secondary || BRANDING_DEFAULT.secondary).slice(0, 20),
      bgDark: String(body.bgDark || BRANDING_DEFAULT.bgDark).slice(0, 20),
      logoUrl: String(body.logoUrl || '').slice(0, 500),
      faviconUrl: String(body.faviconUrl || '').slice(0, 500)
    };
    // Atualiza no tenant
    let tenants = db.store['sl_saas_tenants'] || [];
    const idx = tenants.findIndex(t => t && t.id === req.tenantId);
    if (idx < 0) {
      // Tenant não existe na tabela (pode ser tenant interno que ainda não foi criado)
      // Cria entrada mínima
      tenants.push({ id: req.tenantId, nome: 'TMX Digital', branding: novo, _updatedAt: Date.now() });
    } else {
      tenants[idx].branding = novo;
      tenants[idx]._updatedAt = Date.now();
    }
    db.store['sl_saas_tenants'] = tenants;
    if (!db.timestamps) db.timestamps = {};
    db.timestamps['sl_saas_tenants'] = now();
    writeDB(db);
    _broadcastSync('sl_saas_tenants', req.headers['x-client-id']);
    res.json({ ok: true, branding: novo });
  } catch (e) {
    console.error('[BRANDING put]', e.message);
    res.status(500).json({ error: 'Erro ao salvar branding' });
  }
});

app.get('/api/store', authUsuario, (req, res) => {
  const db = readDB();
  // Multi-tenancy: filtra o store pelo tenant da request.
  // Super-admin com ?_super=1 vê tudo (pro painel SaaS poder consultar
  // dados de qualquer tenant quando precisar).
  const bypass = req.query._super === '1' && _isSuperAdmin(req);
  const baseStore = bypass ? db.store : _aplicarFiltroTenant(db.store, req.tenantId);
  const safe = _filtrarKeysPorCargo(Object.assign({}, baseStore), req);
  if (safe['sl_usuarios']) safe['sl_usuarios'] = _stripSenhas(safe['sl_usuarios']);
  res.json(safe);
});

app.get('/api/updates/:since', authUsuario, (req, res) => {
  const since = parseInt(req.params.since) || 0;
  const db = readDB();
  const bypass = req.query._super === '1' && _isSuperAdmin(req);
  const isInterno = req.tenantId === TENANT_INTERNO_ID;
  const soDiretoria = _ehDiretoria(req);
  const data = {};
  Object.entries(db.timestamps || {}).forEach(([k, ts]) => {
    if (ts > since) {
      // Mesma regra do GET /api/store: segredo nunca sai; sensível só pra Diretoria.
      if (KEYS_SERVIDOR.has(k)) return;
      if (KEYS_DIRETORIA.has(k) && !soDiretoria) return;
      let valor = db.store[k];
      if (!bypass) {
        // Chaves da plataforma: só pro interno
        if (KEYS_PLATAFORMA.has(k)) {
          if (!isInterno) return; // omite pra outros tenants
        } else if (Array.isArray(valor)) {
          valor = _filtrarPorTenant(valor, req.tenantId);
        } else if (valor && typeof valor === 'object') {
          valor = (getItemTenant(valor) === req.tenantId) ? valor : undefined;
        }
      }
      if (valor === undefined) return;
      data[k] = (k === 'sl_usuarios') ? _stripSenhas(valor) : valor;
    }
  });
  res.json({ data, timestamp: now() });
});

// ── MERGE INTELIGENTE POR ID (SAFE: union-only, sem delete-inference) ──
// Regras conservadoras:
// - Items novos do incoming são adicionados (concurrent create = add-wins)
// - Items editados: maior _updatedAt vence (last-write-wins per-item)
// - Items no server ausentes no incoming: SEMPRE PRESERVADOS (evita perda)
// - Deletes são feitos EXPLICITAMENTE via /api/lixeira/soft-delete (fora desse merge)
function _mergeArrayById(existing, incoming) {
  if (!Array.isArray(existing)) return incoming;
  if (!Array.isArray(incoming)) return incoming;
  const hasIdAndObj = (arr) => arr.length === 0 || (typeof arr[0] === 'object' && arr[0] !== null && 'id' in arr[0]);
  if (!hasIdAndObj(existing) || !hasIdAndObj(incoming)) return incoming;

  const map = new Map();
  // Preserva TODOS os items existentes do servidor
  existing.forEach(item => {
    if (!item || item.id === undefined || item.id === null) return;
    map.set(String(item.id), item);
  });
  // Aplica incoming: adiciona novos, sobrepõe existentes se _updatedAt for mais novo
  incoming.forEach(item => {
    if (!item || item.id === undefined || item.id === null) return;
    const id = String(item.id);
    const cur = map.get(id);
    if (!cur) { map.set(id, item); return; }
    const curTs = Number(cur._updatedAt) || 0;
    const incTs = Number(item._updatedAt) || 0;
    // Se incoming tem timestamp mais recente OU não há timestamps, incoming vence
    if (incTs >= curTs || (curTs === 0 && incTs === 0)) map.set(id, item);
  });
  return Array.from(map.values());
}

app.put('/api/store/:key', authUsuario, (req, res) => {
  const db = readDB();
  const key = req.params.key;
  // mudou o desenho do funil (ex.: o minuto do pitch): o retrato em memória
  // e as visitas já marcadas se refazem logo, sem esperar os 15 min
  if (key === 'sl_funis') { clearTimeout(_pitchTimer); _pitchTimer = setTimeout(() => { try { _fcCache.em = 0; _pitchRecalcular(); } catch (e) {} }, 3000); }
  let incoming = req.body;
  const existing = db.store[key];

  // Chave restrita: só Diretoria escreve. Bloquear a escrita é tão importante
  // quanto a leitura — sem isso um cliente com cópia velha em cache poderia
  // sobrescrever RH/financeiro/protocolo com dados desatualizados.
  if (KEYS_DIRETORIA.has(key) && !_ehDiretoria(req)) {
    return res.status(403).json({ error: 'Acesso restrito à Diretoria.' });
  }

  // ── MULTI-TENANCY PR 5: protege escritas ──
  // 1. Chaves da plataforma: só super-admin (Diretoria do tenant interno) escreve.
  // 2. Items novos: força tenant_id = req.tenantId (cliente nao escolhe).
  // 3. Items existentes: força tenant_id do existente (impede roubo cross-tenant).
  // Super-admin pode mexer em qualquer item — pro master conseguir corrigir dados.
  const isSuper = _isSuperAdmin(req);
  if (KEYS_PLATAFORMA.has(key) && !isSuper) {
    return res.status(403).json({ error: 'Apenas o tenant interno pode editar essa chave.' });
  }
  if (!KEYS_PLATAFORMA.has(key)) {
    if (Array.isArray(incoming)) {
      // Mapeia tenant_id dos items existentes
      const existingTenantMap = new Map();
      if (Array.isArray(existing)) {
        existing.forEach(it => { if (it && it.id !== undefined) existingTenantMap.set(String(it.id), getItemTenant(it)); });
      }
      incoming = incoming.map(item => {
        if (!item || typeof item !== 'object') return item;
        const idStr = item.id !== undefined ? String(item.id) : null;
        const tenantExistente = idStr ? existingTenantMap.get(idStr) : null;
        const copy = Object.assign({}, item);
        if (tenantExistente) {
          // Item já existe: preserva tenant_id original (super pode trocar)
          copy.tenant_id = isSuper && item.tenant_id ? item.tenant_id : tenantExistente;
        } else {
          // Item novo: força tenant_id da request (super pode escolher outro)
          copy.tenant_id = isSuper && item.tenant_id ? item.tenant_id : req.tenantId;
        }
        return copy;
      });
    } else if (incoming && typeof incoming === 'object') {
      // Singleton object: força tenant_id
      const tenantExistente = (existing && typeof existing === 'object') ? getItemTenant(existing) : null;
      incoming = Object.assign({}, incoming, {
        tenant_id: tenantExistente || (isSuper && incoming.tenant_id) || req.tenantId
      });
    }
  }

  // Tratamento especial para sl_usuarios: preserva senhaHash existente + hash qualquer senha nova
  if (key === 'sl_usuarios' && Array.isArray(incoming)) {
    const existingMap = new Map();
    if (Array.isArray(existing)) existing.forEach(u => { if (u && u.id) existingMap.set(String(u.id), u); });
    incoming = incoming.map(u => {
      if (!u || !u.id) return u;
      const cur = existingMap.get(String(u.id));
      const copy = Object.assign({}, u);
      if (copy.senha) {
        // Nova senha em texto puro (alteração via UI) — hash agora
        copy.senhaHash = bcrypt.hashSync(String(copy.senha), BCRYPT_ROUNDS);
        delete copy.senha;
      } else if (!copy.senhaHash && cur && cur.senhaHash) {
        // Usuário existente sem senha nova — preserva hash atual
        copy.senhaHash = cur.senhaHash;
      } else if (!copy.senhaHash && cur && cur.senha) {
        // Migração — existia senha em texto, hash agora
        copy.senhaHash = bcrypt.hashSync(String(cur.senha), BCRYPT_ROUNDS);
      }
      return copy;
    });
  }

  // Detecta tarefas novas ANTES do merge (pra disparar notificação WhatsApp)
  let novasTasks = [];
  if (key === 'tasks' && Array.isArray(incoming)) {
    const existingIds = new Set((Array.isArray(existing) ? existing : []).map(t => String(t && t.id)));
    novasTasks = incoming.filter(t => t && t.id && !existingIds.has(String(t.id)) && !t.arquivado);
  }

  // Aplica merge inteligente por ID quando faz sentido
  db.store[key] = _mergeArrayById(existing, incoming);

  if (!db.timestamps) db.timestamps = {};
  db.timestamps[key] = now();
  writeDB(db);
  _broadcastSync(key, req.headers['x-client-id']);

  // Dispara notificação WhatsApp para tarefas novas (fire-and-forget)
  if (novasTasks.length) {
    setImmediate(() => {
      try {
        const db2 = readDB();
        const usuarios = db2.store['sl_usuarios'] || [];
        const cfgLemb = db2.store['sl_lembretes_config'] || {};
        if (cfgLemb.novaDemanda === false) return; // explicitamente desligado
        novasTasks.forEach(t => {
          const respIds = Array.isArray(t.respIds) && t.respIds.length ? t.respIds : (t.respId ? [t.respId] : []);
          respIds.forEach(rid => {
            const u = usuarios.find(x => x.id === rid);
            if (!u || u.ativo === false || !u.whatsapp) return;
            const prazo = t.data ? ` — prazo *${t.data.split('-').reverse().join('/')}*` : '';
            const prio = t.prio || t.prioridade ? ` — prioridade *${t.prio || t.prioridade}*` : '';
            const titulo = '📌 Nova demanda para você';
            const texto = `*${t.nome || 'Sem título'}*${prazo}${prio}\n\nStatus: ${t.status || 'BACKLOG'}`;
            _notificarViaWhatsApp(rid, titulo, texto).catch(()=>{});
          });
        });
      } catch (e) { console.error('[WA nova demanda]', e.message); }
    });
  }

  res.json({ ok: true, merged: Array.isArray(db.store[key]) ? db.store[key].length : undefined, novas: novasTasks.length });
});

// ── LIXEIRA GLOBAL (30 dias) ──
const LIXEIRA_MAX_DIAS = 30;

// Remove item de uma key e joga na lixeira global
// Body: { itemId, tipo, deletedBy, deletedByNome }
app.post('/api/lixeira/soft-delete', authUsuario, (req, res) => {
  const { key, itemId, tipo, deletedBy, deletedByNome } = req.body || {};
  if (!key || itemId === undefined) return res.status(400).json({ error: 'key e itemId obrigatórios' });

  const db = readDB();
  const arr = db.store[key];
  if (!Array.isArray(arr)) return res.status(400).json({ error: `${key} não é array` });

  const idx = arr.findIndex(x => String(x && x.id) === String(itemId));
  if (idx === -1) return res.status(404).json({ error: 'Item não encontrado' });

  const item = arr[idx];
  arr.splice(idx, 1);

  // Adiciona à lixeira global
  if (!db.store['sl_lixeira']) db.store['sl_lixeira'] = [];
  db.store['sl_lixeira'].push({
    id: Date.now() + '-' + Math.random().toString(36).slice(2,8),
    sourceKey: key,
    tipo: tipo || key,
    deletedAt: new Date().toISOString(),
    deletedBy: deletedBy || null,
    deletedByNome: deletedByNome || null,
    originalId: item.id,
    data: item
  });

  if (!db.timestamps) db.timestamps = {};
  db.timestamps[key] = now();
  db.timestamps['sl_lixeira'] = now();
  audit(db, 'soft_delete', { sourceKey: key, itemId, tipo }, { itemNome: (item && (item.nome || item.titulo)) || null }, { id: deletedBy, nome: deletedByNome });
  writeDB(db);
  _broadcastSync(key, req.headers['x-client-id']);
  _broadcastSync('sl_lixeira', req.headers['x-client-id']);
  res.json({ ok: true });
});

// Restaura item da lixeira de volta ao array original
app.post('/api/lixeira/restore/:lixeiraId', authUsuario, (req, res) => {
  const db = readDB();
  const lix = db.store['sl_lixeira'] || [];
  const idx = lix.findIndex(x => String(x.id) === String(req.params.lixeiraId));
  if (idx === -1) return res.status(404).json({ error: 'Item da lixeira não encontrado' });

  const entry = lix[idx];
  if (!db.store[entry.sourceKey]) db.store[entry.sourceKey] = [];
  // Evita duplicar caso já exista
  const sourceArr = db.store[entry.sourceKey];
  if (Array.isArray(sourceArr) && !sourceArr.find(x => String(x && x.id) === String(entry.data.id))) {
    sourceArr.push(entry.data);
  }
  lix.splice(idx, 1);

  if (!db.timestamps) db.timestamps = {};
  db.timestamps[entry.sourceKey] = now();
  db.timestamps['sl_lixeira'] = now();
  audit(db, 'restore_lixeira', { sourceKey: entry.sourceKey, itemId: entry.originalId, tipo: entry.tipo }, null, _userInfoFromReq(req, db));
  writeDB(db);
  _broadcastSync(entry.sourceKey, req.headers['x-client-id']);
  _broadcastSync('sl_lixeira', req.headers['x-client-id']);
  res.json({ ok: true, restaurado: entry.data });
});

// Apaga permanentemente da lixeira
app.delete('/api/lixeira/:lixeiraId', authUsuario, (req, res) => {
  const db = readDB();
  const lix = db.store['sl_lixeira'] || [];
  const entry = lix.find(x => String(x.id) === String(req.params.lixeiraId));
  db.store['sl_lixeira'] = lix.filter(x => String(x.id) !== String(req.params.lixeiraId));
  if (!entry) return res.status(404).json({ error: 'Não encontrado' });

  if (!db.timestamps) db.timestamps = {};
  db.timestamps['sl_lixeira'] = now();
  audit(db, 'purge_lixeira', { sourceKey: entry.sourceKey, itemId: entry.originalId, tipo: entry.tipo }, null, _userInfoFromReq(req, db));
  writeDB(db);
  _broadcastSync('sl_lixeira', req.headers['x-client-id']);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════
// VAGAS — endpoints públicos (sem auth)
// Substituem o fluxo Notion + Google Forms.
// ══════════════════════════════════════════════

// Rate limit específico pra aplicação em vaga: 10 candidaturas por hora por IP
const aplicarLimiter = rateLimit({
  windowMs: 60*60*1000,
  max: 10,
  message: { error: 'Muitas candidaturas. Aguarde 1 hora antes de tentar novamente.' }
});

// ══════════════════════════════════════════════
// IA · RANKEAR CANDIDATO (Claude)
// Lê briefing da vaga + portfolio + respostas + teste e dá score 0-100.
// ══════════════════════════════════════════════
app.post('/api/ia/rankear-candidato', async (req, res) => {
  try {
    const { candidatoId } = req.body || {};
    if (!candidatoId) return res.status(400).json({ error: 'candidatoId obrigatório' });
    const db = readDB();
    const cands = db.store['sl_candidatos'] || [];
    const c = cands.find(x => String(x.id) === String(candidatoId));
    if (!c) return res.status(404).json({ error: 'Candidato não encontrado' });
    const vagas = db.store['sl_vagas'] || [];
    const v = vagas.find(x => String(x.id) === String(c.vagaId));
    if (!v) return res.status(404).json({ error: 'Vaga não encontrada' });
    const aiKey = _getAIKey();
    if (!aiKey) return res.status(500).json({ error: 'IA não configurada (defina ANTHROPIC_API_KEY ou ai_key)' });

    // Coleta entrega(s) de teste se houver
    const emailNorm = String(c.email||'').toLowerCase().trim();
    const entregas = (db.store['sl_teste_entregas'] || []).filter(e => String(e.email||'').toLowerCase().trim() === emailNorm && e.vagaId === v.id);

    // Monta prompt
    const respostas = c.respostasCustom || {};
    const perguntas = v.perguntasCustom || [];
    const respostasFmt = perguntas.map(p => {
      const r = respostas[p.id];
      const valor = Array.isArray(r) ? r.join(', ') : (r||'(sem resposta)');
      return `[${p.label}]\n${valor}`;
    }).join('\n\n');

    const entregasFmt = entregas.map(e => {
      return `Entrega em ${e.recebidoEm}, tempo ${Math.round((e.tempoGasto||0)/60)}min:\n${e.entregaTexto||'(sem texto)'}\n${e.entregaLink?'Link: '+e.entregaLink:''}`;
    }).join('\n\n---\n\n') || '(candidato ainda não fez teste prático)';

    const systemPrompt = `Você é um avaliador sênior de candidatos pra vagas de operação de direct response (Brasil). Avalia candidatos com rigor e foco em RESULTADOS práticos, não em formação acadêmica. Você responde APENAS com JSON válido, sem markdown:
{
  "score": <0-100>,
  "motivo": "<1-2 frases curtas explicando a nota: forças e fraquezas críticas>",
  "analise": "<análise mais longa: 3-5 parágrafos cobrindo: aderência ao briefing/requisitos, qualidade do portfólio/teste, sinais de risco, recomendação final>"
}

REGRAS de scoring:
- 90-100: excepcional, contrata sem entrevista
- 80-89: forte match, entrevista é só formalidade
- 70-79: bom, entrevistar pra validar
- 60-69: mediano, talvez banco de talentos
- 40-59: fraco, raras chances
- 0-39: descartar

CRITÉRIOS:
- Experiência REAL no nicho (não decorada)
- Provas concretas (cases, números, prints)
- Português correto
- Pensamento estruturado nas respostas
- Se tem teste prático: qualidade do que entregou pesa MUITO mais que o currículo`;

    const userPrompt = `VAGA:
Título: ${v.titulo||'-'}
Área: ${v.area||'-'}
Descrição: ${v.descricao||'-'}
Requisitos: ${(v.requisitos||[]).join('; ')}
Expectativas: ${(v.expectativas||[]).join('; ')}
Diferenciais: ${(v.diferenciais||[]).join('; ')}
Por que única: ${v.porqueUnica||'-'}
${v.teste && v.teste.briefing ? '\nBRIEFING DO TESTE PRÁTICO:\n'+v.teste.briefing : ''}
${v.teste && v.teste.criterios ? '\nCRITÉRIOS DE AVALIAÇÃO:\n'+v.teste.criterios : ''}

CANDIDATO:
Nome: ${c.nome||'-'}
Email: ${c.email||'-'}
Portfolio: ${c.portfolio||'(não enviou)'}
Instagram: ${c.instagram||'-'}

RESPOSTAS CUSTOM:
${respostasFmt || '(sem respostas custom)'}

ENTREGAS DO TESTE PRÁTICO:
${entregasFmt}

Avalia e responde com o JSON.`;

    const body = {
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: 1500,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }]
    };

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': aiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!r.ok) {
      const err = await r.text();
      // Mensagens amigáveis pros erros mais comuns
      const errLower = err.toLowerCase();
      let msg = `Claude ${r.status}: ${err.slice(0, 200)}`;
      if (errLower.includes('credit balance') || errLower.includes('credit_balance')) {
        msg = 'Sem créditos na conta Anthropic. Adicione créditos em https://console.anthropic.com/settings/billing (custo ~$0.02 por análise).';
      } else if (errLower.includes('invalid_api_key') || errLower.includes('authentication')) {
        msg = 'Chave da Anthropic inválida ou expirada. Verifique em Configurações → WhatsApp/IA.';
      } else if (errLower.includes('rate_limit') || r.status === 429) {
        msg = 'Limite de requisições da Anthropic atingido. Aguarde 1 minuto e tente de novo.';
      } else if (errLower.includes('overloaded') || r.status === 529) {
        msg = 'API da Anthropic sobrecarregada. Tente em alguns segundos.';
      }
      return res.status(500).json({ error: msg });
    }
    const data = await r.json();
    const textRaw = (data.content || []).filter(x => x.type === 'text').map(x => x.text).join('').trim();
    const cleaned = textRaw.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
    let parsed;
    try { parsed = JSON.parse(cleaned); }
    catch (e) {
      const match = cleaned.match(/\{[\s\S]*\}/);
      if (match) { try { parsed = JSON.parse(match[0]); } catch (e2) { return res.status(500).json({ error: 'IA retornou JSON inválido', raw: cleaned.slice(0,500) }); } }
      else return res.status(500).json({ error: 'IA não retornou JSON', raw: cleaned.slice(0,500) });
    }

    // Salva no candidato
    const idx = cands.findIndex(x => String(x.id) === String(candidatoId));
    if (idx >= 0) {
      cands[idx].scoreIA = Number(parsed.score) || 0;
      cands[idx].motivoIA = String(parsed.motivo||'').slice(0, 1000);
      cands[idx].analiseIA = String(parsed.analise||'').slice(0, 5000);
      cands[idx].dataIA = new Date().toISOString();
      cands[idx]._updatedAt = Date.now();
      db.store['sl_candidatos'] = cands;
      if (!db.timestamps) db.timestamps = {};
      db.timestamps['sl_candidatos'] = now();
      writeDB(db);
      _broadcastSync('sl_candidatos', req.headers['x-client-id']);
    }

    res.json({ score: parsed.score, motivo: parsed.motivo, analise: parsed.analise });
  } catch (e) {
    console.error('[IA rankear]', e.message);
    res.status(500).json({ error: e.message || 'Erro IA' });
  }
});

// ══════════════════════════════════════════════
// TESTE PRÁTICO — endpoints públicos (sem auth)
// ══════════════════════════════════════════════

// Rate limit pra envio de teste: 5 entregas por hora por IP
const testeLimiter = rateLimit({
  windowMs: 60*60*1000,
  max: 5,
  message: { error: 'Muitas entregas. Aguarde 1h antes de tentar novamente.' }
});

// GET /api/teste/publica/:slug — retorna briefing público do teste
app.get('/api/teste/publica/:slug', (req, res) => {
  try {
    const db = readDB();
    const vagas = db.store['sl_vagas'] || [];
    const v = vagas.find(x => x && x.teste && x.teste.slug === req.params.slug && x.teste.ativo);
    if (!v) return res.status(404).json({ error: 'Teste não encontrado ou desativado' });
    res.json({
      vagaTitulo: v.titulo || '',
      vagaArea: v.area || '',
      briefing: v.teste.briefing || '',
      links: Array.isArray(v.teste.links) ? v.teste.links : [],
      tipoEntrega: v.teste.tipoEntrega || 'ambos',
      tempoEstimado: v.teste.tempoEstimado || 'Sem limite'
      // critérios NÃO retornados — só o admin vê
    });
  } catch (e) {
    console.error('[TESTE publica GET]', e.message);
    res.status(500).json({ error: 'Erro ao buscar teste' });
  }
});

// POST /api/teste/publica/:slug/enviar — recebe entrega do candidato
app.post('/api/teste/publica/:slug/enviar', testeLimiter, (req, res) => {
  try {
    const db = readDB();
    const vagas = db.store['sl_vagas'] || [];
    const v = vagas.find(x => x && x.teste && x.teste.slug === req.params.slug && x.teste.ativo);
    if (!v) return res.status(404).json({ error: 'Teste não encontrado' });

    const body = req.body || {};
    const nome = String(body.nome || '').trim().slice(0, 200);
    const email = String(body.email || '').trim().slice(0, 200);
    const entregaTexto = String(body.entregaTexto || '').slice(0, 20000);
    const entregaLink = String(body.entregaLink || '').trim().slice(0, 500);
    const tempoGasto = Number(body.tempoGastoSegundos) || 0;

    if (!nome || !email) return res.status(400).json({ error: 'Nome e email são obrigatórios' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Email inválido' });
    if (!entregaTexto && !entregaLink) return res.status(400).json({ error: 'Entrega vazia' });

    const entrega = {
      id: 'tst-' + Date.now() + '-' + Math.random().toString(36).slice(2,8),
      testeSlug: req.params.slug,
      vagaId: v.id,
      vagaTitulo: v.titulo,
      nome,
      email,
      entregaTexto,
      entregaLink,
      tempoGasto,
      recebidoEm: new Date().toISOString(),
      _updatedAt: Date.now(),
      tenant_id: getItemTenant(v),
      ipOrigem: (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim().slice(0, 60),
      status: 'novo'  // 'novo' | 'avaliado' | 'rejeitado'
    };

    if (!db.store['sl_teste_entregas']) db.store['sl_teste_entregas'] = [];
    db.store['sl_teste_entregas'].push(entrega);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps['sl_teste_entregas'] = now();
    writeDB(db);
    _broadcastSync('sl_teste_entregas', null);

    // Tenta notificar via WhatsApp a Diretoria
    setImmediate(() => {
      try {
        const db2 = readDB();
        const usuarios = db2.store['sl_usuarios'] || [];
        const diretoria = usuarios.filter(u => u && u.cargo === 'Diretoria' && u.ativo !== false);
        diretoria.forEach(d => {
          if (!d.whatsapp) return;
          const titulo = '📝 Teste prático recebido!';
          const texto = `*${nome}* enviou entrega da vaga *${v.titulo}*\n\nEmail: ${email}\nTempo: ${Math.round(tempoGasto/60)}min\n${entregaLink ? 'Link: '+entregaLink : ''}\n\n👁️ Veja no TMX Digital.`;
          _notificarViaWhatsApp(d.id, titulo, texto).catch(()=>{});
        });
      } catch (e) { console.error('[WA teste]', e.message); }
    });

    res.json({ ok: true, mensagem: 'Entrega recebida! Vamos avaliar e responder em breve.' });
  } catch (e) {
    console.error('[TESTE enviar]', e.message);
    res.status(500).json({ error: 'Erro ao enviar entrega' });
  }
});

// GET /api/vagas/publicas — lista pública de TODAS as vagas ativas+publicadas
// (usada pela página /vagas; só campos públicos)
app.get('/api/vagas/publicas', (req, res) => {
  try {
    const db = readDB();
    // Multi-tenancy: só lista vagas do tenant que o host resolveu.
    const todas = (db.store['sl_vagas'] || []).filter(v => getItemTenant(v) === req.tenantId);
    const visiveis = todas
      .filter(v => v && v.publicada && v.status !== 'Encerrada')
      .map(v => ({
        id: v.id,
        titulo: v.titulo || '',
        area: v.area || '',
        modelo: v.modelo || '',
        salario: v.salario || '',
        slug: v.slug,
        descricao: (v.descricao || '').slice(0, 280) // preview curto
      }))
      .sort((a, b) => String(a.titulo).localeCompare(String(b.titulo), 'pt-BR'));
    res.json(visiveis);
  } catch (e) {
    console.error('[VAGAS publicas list]', e.message);
    res.status(500).json({ error: 'Erro ao listar vagas' });
  }
});

// GET /api/vagas/publica/:slug — retorna dados públicos da vaga (sem auth)
// Só vagas com publicada=true e status !=='Encerrada'. Strip de campos internos.
// Multi-tenancy: também filtra por tenant do host (acme.axcend.com só vê vagas do Acme).
app.get('/api/vagas/publica/:slug', (req, res) => {
  try {
    const db = readDB();
    const todas = (db.store['sl_vagas'] || []).filter(v => getItemTenant(v) === req.tenantId);
    const v = todas.find(x => x && x.slug === req.params.slug);
    if (!v) return res.status(404).json({ error: 'Vaga não encontrada' });
    if (!v.publicada) return res.status(404).json({ error: 'Vaga não disponível' });
    if (v.status === 'Encerrada') return res.status(404).json({ error: 'Vaga encerrada' });

    res.json({
      id: v.id,
      titulo: v.titulo || '',
      area: v.area || '',
      modelo: v.modelo || '',
      salario: v.salario || '',
      descricao: v.descricao || '',
      requisitos: Array.isArray(v.requisitos) ? v.requisitos : [],
      expectativas: Array.isArray(v.expectativas) ? v.expectativas : [],
      diferenciais: Array.isArray(v.diferenciais) ? v.diferenciais : [],
      porqueUnica: v.porqueUnica || '',
      perguntasCustom: Array.isArray(v.perguntasCustom) ? v.perguntasCustom : [],
      slug: v.slug
    });
  } catch (e) {
    console.error('[VAGAS publica GET]', e.message);
    res.status(500).json({ error: 'Erro ao buscar vaga' });
  }
});

// POST /api/vagas/publica/:slug/aplicar — recebe candidatura (sem auth, rate-limited)
// Multi-tenancy: a candidatura é taggeada com o tenant_id resolvido pelo host.
app.post('/api/vagas/publica/:slug/aplicar', aplicarLimiter, (req, res) => {
  try {
    const db = readDB();
    const todas = (db.store['sl_vagas'] || []).filter(v => getItemTenant(v) === req.tenantId);
    const v = todas.find(x => x && x.slug === req.params.slug);
    if (!v) return res.status(404).json({ error: 'Vaga não encontrada' });
    if (!v.publicada || v.status === 'Encerrada') return res.status(400).json({ error: 'Vaga não está aceitando candidaturas' });

    const body = req.body || {};
    const nome = String(body.nome || '').trim().slice(0, 200);
    const email = String(body.email || '').trim().slice(0, 200);
    const instagram = String(body.instagram || '').trim().slice(0, 100);
    const whatsapp = String(body.whatsapp || '').trim().slice(0, 60);
    const portfolio = String(body.portfolio || '').trim().slice(0, 500);
    const respostasCustom = (body.respostasCustom && typeof body.respostasCustom === 'object') ? body.respostasCustom : {};

    if (!nome || !email) return res.status(400).json({ error: 'Nome e email são obrigatórios' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Email inválido' });

    // Sanitiza respostas custom — só perguntas conhecidas. String OU array (checkbox).
    // String: max 2000 chars. Array: max 50 itens, cada item max 500 chars.
    const perguntasMap = {};
    (v.perguntasCustom || []).forEach(p => { perguntasMap[p.id] = p; });
    const respClean = {};
    for (const k of Object.keys(respostasCustom)) {
      if (!perguntasMap[k]) continue;
      const raw = respostasCustom[k];
      if (Array.isArray(raw)) {
        respClean[k] = raw.slice(0, 50).map(v => String(v == null ? '' : v).slice(0, 500));
      } else {
        respClean[k] = String(raw == null ? '' : raw).slice(0, 2000);
      }
    }

    // Valida obrigatórias do servidor (defesa em profundidade — frontend já valida)
    for (const p of (v.perguntasCustom || [])) {
      if (!p.obrigatoria) continue;
      const r = respClean[p.id];
      const vazio = (r == null) || (typeof r === 'string' && !r.trim()) || (Array.isArray(r) && !r.length);
      if (vazio) {
        return res.status(400).json({ error: 'Pergunta obrigatória sem resposta: ' + p.label });
      }
    }

    const cand = {
      id: 'cand-' + Date.now() + '-' + Math.random().toString(36).slice(2,8),
      vagaId: v.id,
      vagaSlug: v.slug,
      vagaTitulo: v.titulo,
      nome,
      email,
      instagram,
      whatsapp,
      portfolio,
      respostasCustom: respClean,
      status: 'Novo',
      criadoEm: new Date().toISOString(),
      _updatedAt: Date.now(),
      ipOrigem: (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim().slice(0, 60)
    };

    if (!db.store['sl_candidatos']) db.store['sl_candidatos'] = [];
    db.store['sl_candidatos'].push(cand);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps['sl_candidatos'] = now();
    writeDB(db);
    _broadcastSync('sl_candidatos', null);

    // 🚀 Hook Utmify: envia evento 'lead' quando candidato se aplica
    // Captura UTMs do body (se o form mandar) ou do referer
    const utmData = body.utm || {};
    _enviarEventoUtmify(req.tenantId, 'lead', {
      orderId: 'cand-' + cand.id,
      customerName: nome,
      customerEmail: email,
      customerPhone: whatsapp,
      productName: 'Candidatura: ' + (v.titulo || v.slug),
      value: 0,
      ip: cand.ipOrigem,
      utm_source: utmData.utm_source,
      utm_campaign: utmData.utm_campaign,
      utm_medium: utmData.utm_medium,
      utm_content: utmData.utm_content,
      utm_term: utmData.utm_term
    }).catch(()=>{});

    res.json({ ok: true, mensagem: 'Candidatura recebida com sucesso!' });
  } catch (e) {
    console.error('[VAGAS aplicar]', e.message);
    res.status(500).json({ error: 'Erro ao enviar candidatura' });
  }
});

// Limpa itens da lixeira >30 dias (chamado via cron)
function _limparLixeiraAntiga() {
  try {
    const db = readDB();
    const lix = db.store['sl_lixeira'] || [];
    const limiteMs = Date.now() - (LIXEIRA_MAX_DIAS * 24 * 60 * 60 * 1000);
    const antes = lix.length;
    db.store['sl_lixeira'] = lix.filter(entry => {
      const ts = new Date(entry.deletedAt).getTime();
      return ts >= limiteMs;
    });
    const removidos = antes - db.store['sl_lixeira'].length;
    if (removidos > 0) {
      db.timestamps['sl_lixeira'] = now();
      writeDB(db);
      console.log(`[LIXEIRA] Limpeza automática: ${removidos} itens >30 dias removidos`);
    }
  } catch (err) {
    console.error('[LIXEIRA] Erro na limpeza:', err.message);
  }
}
// Roda limpeza a cada 6h
setInterval(_limparLixeiraAntiga, 6 * 60 * 60 * 1000);
setTimeout(_limparLixeiraAntiga, 60 * 1000); // primeira execução 1min após boot

app.post('/api/auth/login', loginLimiterIp, loginLimiter, (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) return res.status(400).json({ error: 'Email e senha obrigatórios' });
  const db = readDB();
  const usuarios = db.store['sl_usuarios'] || [];
  // ── MULTI-TENANT: filtra usuários pelo tenant do host ──
  // O middleware injetou req.tenantId baseado no subdomínio acessado.
  // Se você abrir cliente1.axcend.com, req.tenantId === id-do-cliente1
  // Aí só users desse tenant podem logar.
  const tenantId = req.tenantId || TENANT_DEFAULT_ID;
  const usuariosDoTenant = usuarios.filter(u => getItemTenant(u) === tenantId);

  const user = usuariosDoTenant.find(u => u.email && u.email.toLowerCase() === String(email).toLowerCase() && u.ativo !== false);
  if (!user) {
    // Pra evitar leak: verifica se existe esse email em OUTRO tenant pra dar mensagem útil
    const emailOutroTenant = usuarios.find(u => u.email && u.email.toLowerCase() === String(email).toLowerCase() && u.ativo !== false);
    audit(db, 'login_falhou', { email, tenantId, motivoTenant: emailOutroTenant ? 'email_em_outro_tenant' : 'email_nao_existe' }, { ip: req.ip }, null);
    writeDB(db);
    if (emailOutroTenant) {
      // Encontra o slug do tenant correto pra orientar o user
      const tenantCorreto = (db.store['sl_saas_tenants'] || []).find(t => t.id === emailOutroTenant.tenant_id);
      const dicaSlug = tenantCorreto && tenantCorreto.slug ? `https://${tenantCorreto.slug}.${SAAS_ROOT_DOMAIN}` : null;
      return res.status(401).json({
        error: 'Esse email está cadastrado em outra empresa.' + (dicaSlug ? ` Acesse ${dicaSlug} pra logar.` : ''),
        codigo: 'WRONG_TENANT',
        urlCorreta: dicaSlug
      });
    }
    return res.status(401).json({ error: 'Email ou senha inválidos' });
  }

  // Tenta bcrypt primeiro, senão senha em texto (legado — migra on-the-fly)
  let match = false;
  if (user.senhaHash) {
    try { match = bcrypt.compareSync(String(senha), user.senhaHash); } catch { match = false; }
  } else if (user.senha) {
    match = (user.senha === senha);
    if (match) {
      // Migra agora
      user.senhaHash = bcrypt.hashSync(String(senha), BCRYPT_ROUNDS);
      delete user.senha;
      db.timestamps['sl_usuarios'] = now();
    }
  }
  if (!match) {
    audit(db, 'login_falhou', { email, userId: user.id, tenantId }, { motivo: 'senha_incorreta', ip: req.ip }, null);
    writeDB(db);
    return res.status(401).json({ error: 'Email ou senha inválidos' });
  }

  // ── Verificações pós-auth ──
  // Se o tenant está suspenso/cancelado, bloqueia
  const tenantInfo = (db.store['sl_saas_tenants'] || []).find(t => t.id === tenantId);
  if (tenantInfo && tenantInfo.status === 'suspenso') {
    audit(db, 'login_bloqueado', { userId: user.id, tenantId, motivo: 'tenant_suspenso' }, { ip: req.ip }, null);
    writeDB(db);
    return res.status(403).json({ error: 'Conta suspensa. Entre em contato com suporte ou regularize o pagamento.', codigo: 'TENANT_SUSPENSO' });
  }

  // Se trial expirou, alerta mas não bloqueia (deixa o frontend decidir)
  let trialExpirado = false;
  if (tenantInfo && tenantInfo.plano === 'trial' && tenantInfo.trial && tenantInfo.trial.expira) {
    trialExpirado = new Date(tenantInfo.trial.expira) < new Date();
  }

  const token = criarSessao(db, user.id);
  audit(db, 'login', { userId: user.id, email: user.email, tenantId }, { ip: req.ip }, { id: user.id, nome: user.nome, cargo: user.cargo });
  writeDB(db);

  const { senha: _s, senhaHash: _h, ...safeUser } = user;
  res.json({
    user: safeUser,
    token,
    expiraEm: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    tenant: tenantInfo ? {
      id: tenantInfo.id,
      slug: tenantInfo.slug,
      nome: tenantInfo.nome,
      plano: tenantInfo.plano,
      status: tenantInfo.status,
      trial: tenantInfo.trial || null,
      trialExpirado
    } : null
  });
});

// POST /api/auth/logout — invalida sessão
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (token) {
    const db = readDB();
    const u = _userInfoFromReq(req, db);
    invalidarSessao(db, token);
    audit(db, 'logout', { userId: u.id }, null, u);
    writeDB(db);
  }
  res.json({ ok: true });
});

// GET /api/auth/me — valida token e retorna usuário atual
app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  const db = readDB();
  const sess = validarSessao(db, token);
  if (!sess) return res.status(401).json({ error: 'Sessão inválida ou expirada' });
  writeDB(db); // salvar lastActivity atualizado
  const user = (db.store['sl_usuarios'] || []).find(u => u.id === sess.userId);
  if (!user || user.ativo === false) return res.status(401).json({ error: 'Usuário inexistente ou inativo' });
  const { senha: _s, senhaHash: _h, ...safeUser } = user;
  res.json({ user: safeUser, expiraEm: new Date((sess.lastActivity || sess.createdAt) + SESSION_TTL_MS).toISOString() });
});

app.get('/api/ping', (req, res) => res.json({ ok: true, version: '2.0', api: true }));

// ══════════════════════════════════════════════
// ── IA: CATEGORIZAÇÃO AUTOMÁTICA DE DEMANDA ──
// ══════════════════════════════════════════════
// Recebe texto livre, devolve JSON estruturado com sugestões para o modal Nova Demanda.
// Usa Claude API (mesma chave do agente WhatsApp em sl_whatsapp_config).
// Resolve a chave da IA: prefere ENV var (mais seguro — não vai pro backup),
// fallback pra cfg.ai_key salva em db (legado, ainda funciona)
function _getAIKey() {
  const db = readDB();
  const cfg = (db.store['sl_whatsapp_config']) || {};
  return process.env.ANTHROPIC_API_KEY || process.env.AI_KEY || cfg.ai_key || '';
}

async function _iaAnalisarDemanda(texto, db) {
  const cfg = (db.store['sl_whatsapp_config']) || {};
  const aiKey = _getAIKey();
  if (!aiKey) throw new Error('IA não configurada (defina ANTHROPIC_API_KEY no Railway ou em Configurações → WhatsApp/IA)');

  const usuarios = (db.store['sl_usuarios'] || []).filter(u => u && u.ativo !== false).map(u => ({ id: u.id, nome: u.nome, cargo: u.cargo }));
  const nichos = (db.store['sl_nichos'] || []).map(n => ({ id: n.id, nome: n.nome }));
  const ofertas = (db.store['sl_ofertas_v2'] || []).map(o => ({ id: o.id, nome: o.nome, nichoId: o.nichoId }));
  const setores = ['Copy', 'Edição', 'Infra', 'Tráfego', 'Spy'];
  // Histórico recente (últimas 30 demandas) — pra IA ver padrões
  const tasksRecentes = (db.store['tasks'] || [])
    .filter(t => t && !t.arquivado)
    .slice(-30)
    .map(t => ({
      nome: t.nome || '',
      setor: t.setor || '',
      respIds: t.respIds || (t.respId ? [t.respId] : []),
      ofertaId: t.ofertaId || null,
      data: t.data || null
    }));

  const systemPrompt = `Você é um assistente que analisa descrições de tarefas e sugere campos estruturados para criação no sistema TMX Digital (gestão de tráfego pago).

IMPORTANTE: responda APENAS com JSON válido, sem markdown, sem explicação. Use exatamente esta estrutura:
{
  "titulo": "string curto e claro",
  "setor": "Copy" | "Edição" | "Infra" | "Tráfego" | "Spy",
  "status": "Pendente",
  "respId": "id_do_usuario_ou_null",
  "nichoId": "id_do_nicho_ou_null",
  "ofertaId": "id_da_oferta_ou_null",
  "prazoData": "YYYY-MM-DD ou null",
  "checklist": ["item 1", "item 2"] ou [],
  "raciocinio": "1 frase curta explicando suas escolhas"
}

REGRAS:
- "setor": Copy=textos/roteiros/headlines/CTA. Edição=videos/UGC/cortes/legenda. Infra=cloaker/dominio/server/PV/teste A/B. Tráfego=campanhas/ads/budget/cbo. Spy=concorrentes/análise.
- "respId": pegue o usuario com o cargo certo do setor — se varios, escolha o que aparece mais em demandas recentes do mesmo setor.
- "ofertaId": detecte por palavras (TGLV10, Detox, Gelatina, Memória etc) — match contra a lista.
- "nichoId": derive do match da oferta (ofertas tem nichoId).
- "prazoData": demandas de Copy tipicamente 2 dias, Edição 3 dias, Infra 1 dia, Tráfego 1 dia. Calcule a partir de hoje (${new Date().toISOString().slice(0,10)}).
- "checklist": só se a descrição menciona passos claros. Caso contrário, [].
- Se algo for ambíguo, escolha o mais provável e mencione no raciocinio.`;

  const userPrompt = `DESCRIÇÃO DO USUÁRIO:
"${texto}"

USUÁRIOS DISPONÍVEIS:
${JSON.stringify(usuarios)}

NICHOS:
${JSON.stringify(nichos)}

OFERTAS:
${JSON.stringify(ofertas)}

DEMANDAS RECENTES (pra você ver padrão de quem faz o quê):
${JSON.stringify(tasksRecentes)}

Responda agora com o JSON.`;

  const body = {
    model: 'claude-sonnet-4-5-20250929',
    max_tokens: 800,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }]
  };

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': aiKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`Claude ${r.status}: ${err.slice(0, 200)}`);
  }
  const data = await r.json();
  const textRaw = (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('').trim();
  // Remove possíveis cercas markdown
  const cleaned = textRaw.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
  let parsed;
  try { parsed = JSON.parse(cleaned); }
  catch (e) {
    // Tenta extrair primeiro objeto JSON válido
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) { try { parsed = JSON.parse(m[0]); } catch (e2) { throw new Error('Resposta da IA não foi JSON válido'); } }
    else throw new Error('Resposta da IA não foi JSON válido');
  }
  return parsed;
}

// POST /api/ia/analisar-demanda — body: { texto }
app.post('/api/ia/analisar-demanda', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ error: 'Não autenticado' });
    const db = readDB();
    const sess = validarSessao(db, token);
    if (!sess) return res.status(401).json({ error: 'Sessão inválida' });
    const texto = (req.body && req.body.texto) || '';
    if (!texto.trim()) return res.status(400).json({ error: 'Texto vazio' });
    const resultado = await _iaAnalisarDemanda(texto.trim(), db);
    res.json({ ok: true, resultado });
  } catch (err) {
    console.error('[IA analisar-demanda]', err.message);
    res.status(500).json({ error: err.message || 'Erro na IA' });
  }
});

// ══════════════════════════════════════════════
// ── SSE: SINCRONIZAÇÃO EM TEMPO REAL ──
// ══════════════════════════════════════════════
// Clientes conectados mantêm uma conexão HTTP aberta. Quando alguma chave
// do db é mutada (PUT /api/store, lixeira), o server emite um evento com
// {key, ts, originator} pra todos. O cliente filtra eventos próprios via
// `originator` (clientId enviado no PUT) e re-puxa só as chaves alteradas.
const _sseClients = new Set();

function _broadcastSync(key, originator) {
  if (!_sseClients.size) return;
  const payload = JSON.stringify({ key, ts: now(), originator: originator || null });
  for (const client of _sseClients) {
    try { client.res.write(`data: ${payload}\n\n`); } catch (e) { /* desconectado */ }
  }
}

// EventSource não suporta headers customizados — auth via ?token=...
app.get('/api/sync/stream', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();
  const db = readDB();
  const sess = validarSessao(db, String(token));
  if (!sess) return res.status(401).end();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const client = { res, userId: sess.userId, connectedAt: Date.now() };
  _sseClients.add(client);

  // Hello inicial — cliente confirma conexão e pode sincronizar com /api/updates/:since
  res.write(`event: hello\ndata: ${JSON.stringify({ ts: now() })}\n\n`);

  // Heartbeat a cada 30s — mantém conexão viva em proxies/CDN do Railway
  const heartbeat = setInterval(() => {
    try { res.write(`: ping\n\n`); } catch (e) { clearInterval(heartbeat); }
  }, 30 * 1000);

  req.on('close', () => {
    clearInterval(heartbeat);
    _sseClients.delete(client);
  });
});

// ── DOCUMENTAÇÃO DA API ──
app.get('/api/v1/docs', (req, res) => {
  res.json({
    nome: 'ScaleLab API v1',
    versao: '1.0.0',
    autenticacao: 'Bearer Token no header Authorization',
    endpoints: [
      { method: 'GET',   path: '/api/v1/demandas',           desc: 'Listar demandas (query: status, responsavel, atrasadas, limit)' },
      { method: 'GET',   path: '/api/v1/demandas/:id',       desc: 'Detalhe de uma demanda' },
      { method: 'POST',  path: '/api/v1/demandas',           desc: 'Criar demanda (body: nome, status, resp, respId, desc, data)' },
      { method: 'PATCH', path: '/api/v1/demandas/:id',       desc: 'Atualizar demanda' },
      { method: 'GET',   path: '/api/v1/criativos',          desc: 'Listar criativos (query: nicho, oferta, status)' },
      { method: 'GET',   path: '/api/v1/criativos/:id',      desc: 'Detalhe de um criativo' },
      { method: 'GET',   path: '/api/v1/metricas/resumo',    desc: 'Resumo geral (demandas pendentes, atrasadas, criativos)' },
      { method: 'GET',   path: '/api/v1/usuarios',           desc: 'Listar equipe' },
      { method: 'GET',   path: '/api/v1/notificacoes',       desc: 'Notificações (query: userId)' },
      { method: 'GET',   path: '/api/v1/chat/mensagens',     desc: 'Mensagens do chat (query: limit)' },
      { method: 'POST',  path: '/api/v1/chat/enviar',        desc: 'Enviar mensagem (body: nome, texto)' },
      { method: 'GET',   path: '/api/v1/dados/:chave',       desc: 'Ler qualquer chave do banco' },
      { method: 'GET',   path: '/api/v1/docs',               desc: 'Esta documentação' }
    ],
    limites: { global: '200 req/min', api_v1: '60 req/min' }
  });
});

// ══════════════════════════════════════════════
// ── SISTEMA DE BACKUP ──
// ══════════════════════════════════════════════

// Middleware: só Diretoria pode acessar backup. Aceita Bearer token (preferido) ou email+senha (legado).
// Chaves que só a Diretoria lê/escreve pelo /api/store.
// São os módulos que vivem dentro de Gestão (RH, Financeiro, Vagas) e o painel pessoal.
// Sem isso, estar logado como Editor já daria acesso a folha de pagamento e afins.
const KEYS_DIRETORIA = new Set([
  'sl_protocolo',
  'sl_rh_colaboradores','sl_rh_feedbacks','sl_rh_ferias','sl_rh_onboarding',
  'sl_rh_offboarding','sl_rh_folha','sl_rh_treinamentos','sl_rh_enps',
  'sl_fin_contas','sl_fin_categorias','sl_fin_lancamentos','sl_fin_recorrentes',
  'sl_fin_nfs','sl_fin_ofx','sl_fin_impostos',
  'sl_candidatos',
  // guarda o API token da Utmify — não pode sincronizar pro browser do time
  'sl_integracoes_utmify','sl_integracoes_utmify_historico',
  'sl_vendas'
]);
// Chaves que guardam SEGREDO (tokens de API) e nunca devem sair pro navegador —
// nem pra Diretoria. Ficam só no servidor; a tela conversa com elas por rotas
// dedicadas, que devolvem no máximo um preview do token.
const KEYS_SERVIDOR = new Set([
  'sl_integracoes_meta',    // access token do Meta Ads
  'sl_integracoes_vendas',  // token secreto da URL de webhook
  'sl_vendas_raw',          // payloads crus dos gateways (dados de cliente)
  'sl_integracoes_utmify_mcp', // token de acesso do MCP da Utmify
  'sl_vturb',               // token da API de analytics da VTurb
  'sl_funil_evfoto',        // foto interna dos contadores; nao serve pra tela
  'sl_ab_vistos',           // ids de quem ja foi contado no teste; interno
  'sl_quiz_resp',           // caminho de cada visitante no quiz; a tela le por /api/quiz/stats
  'sl_quiz_dia',            // contagem agregada do quiz; idem
  'sl_ab_stats',            // contagem do teste A/B; a tela le por /api/ab/stats
  'sl_funil_jornada',       // caminho por visitante; a tela le por /api/funil/jornadas
  'sl_funil_atencao',       // rolagem e cliques; a tela le por /api/funil/atencao
  'sl_funil_adocoes',       // so o servidor decide; o navegador sobrescreveria
  'sl_ads_hist',            // historico de ads por dia; a tela le pelo endpoint
  'sl_desenhos',            // quadros de rascunho; carregam prints, a tela le por /api/desenhos
  'sl_produtos',            // catalogo de produtos; a tela le por /api/produtos
  'sl_canais',              // canais de trafego; a tela le por /api/canais
  'sl_regras',              // regras automaticas; a tela le por /api/regras
  'sl_regras_log',          // log das regras; idem
  'sl_funis_versoes',       // fotos das versoes do funil; a tela le por /api/funis/versoes
  'sl_funil_notas'          // anotacoes do grafico por dia; a tela le por /api/funil/resultado
]);
function _ehDiretoria(req) { return !!(req.user && req.user.cargo === 'Diretoria'); }
// Remove do payload as chaves restritas quando quem pede não é Diretoria.
function _filtrarKeysPorCargo(obj, req) {
  const soDir = _ehDiretoria(req);
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (KEYS_SERVIDOR.has(k)) continue;              // segredo: nunca sai, nem pra Diretoria
    if (!soDir && KEYS_DIRETORIA.has(k)) continue;   // dado sensível: só Diretoria
    out[k] = v;
  }
  return out;
}

// Só persiste lastActivity de hora em hora: as rotas de sync são chamadas o tempo
// todo e reescrever o db.json inteiro a cada poll seria caro demais.
const SESSAO_BUMP_MS = 60 * 60 * 1000;

// Qualquer usuário logado e ativo (não só Diretoria).
// Usado nas rotas de sync, que antes eram abertas — o banco inteiro era legível
// por qualquer um que soubesse a URL, sem login nenhum.
function authUsuario(req, res, next) {
  const db = readDB();

  // 1) Bearer token (preferido)
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const sess = _getSessions(db).find(s => s.tokenHash === tokenHash);
    if (sess && (sess.lastActivity || sess.createdAt) + SESSION_TTL_MS >= Date.now()) {
      const user = (db.store['sl_usuarios'] || []).find(u => u.id === sess.userId);
      if (user && user.ativo !== false) {
        // ⚠️ NUNCA gravar o banco aqui.
        // writeDB grava o arquivo INTEIRO a partir do snapshot lido no começo desta
        // requisição. Como isto roda em toda sincronização, qualquer dado salvo por
        // outra pessoa entre o readDB() acima e a gravação seria APAGADO.
        // O lastActivity da sessão é renovado no /api/auth/me (a cada abertura do app),
        // o que é suficiente pro TTL de 30 dias.
        req.user = user;
        return next();
      }
    }
  }

  // 2) Legado: email+senha nos headers (mesma transição aceita por authDiretoria)
  const email = req.headers['x-user-email'];
  const senha = req.headers['x-user-senha'];
  if (email && senha) {
    const user = (db.store['sl_usuarios'] || []).find(u =>
      u.email && u.email.toLowerCase() === String(email).toLowerCase() && u.ativo !== false);
    if (user) {
      let match = false;
      if (user.senhaHash) { try { match = bcrypt.compareSync(String(senha), user.senhaHash); } catch {} }
      else if (user.senha) { match = (user.senha === senha); }
      if (match) { req.user = user; return next(); }
    }
  }

  return res.status(401).json({ error: 'Não autenticado. Faça login novamente.' });
}

function authDiretoria(req, res, next) {
  const db = readDB();

  // 1) Bearer token (preferido)
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const sess = validarSessao(db, token);
    if (sess) {
      const user = (db.store['sl_usuarios'] || []).find(u => u.id === sess.userId);
      if (user && user.ativo !== false && user.cargo === 'Diretoria') {
        // Mesmo motivo do authUsuario: gravar o banco inteiro aqui, a partir de um
        // snapshot já lido, apagaria o que outra pessoa salvou nesse meio-tempo.
        // O lastActivity é renovado no /api/auth/me.
        req.user = user;
        return next();
      }
      if (user && user.cargo !== 'Diretoria') return res.status(403).json({ error: 'Acesso restrito à Diretoria.' });
    }
  }

  // 2) Legado: email+senha (ainda aceito durante transição — migra hash on-the-fly)
  const email = req.headers['x-user-email'] || (req.body && req.body.email);
  const senha = req.headers['x-user-senha'] || (req.body && req.body.senha);
  if (email && senha) {
    const user = (db.store['sl_usuarios'] || []).find(u =>
      u.email && u.email.toLowerCase() === String(email).toLowerCase() && u.ativo !== false);
    if (user) {
      let match = false;
      if (user.senhaHash) { try { match = bcrypt.compareSync(String(senha), user.senhaHash); } catch {} }
      else if (user.senha) { match = (user.senha === senha); if (match) { user.senhaHash = bcrypt.hashSync(String(senha), BCRYPT_ROUNDS); delete user.senha; writeDB(db); } }
      if (match) {
        if (user.cargo !== 'Diretoria') return res.status(403).json({ error: 'Acesso restrito à Diretoria.' });
        req.user = user;
        return next();
      }
    }
  }

  return res.status(401).json({ error: 'Não autenticado. Use Authorization: Bearer <token>.' });
}

// ── Helpers de data ──
function _parseStamp(fname) {
  // Ex: db-20260419-143012-auto.json → Date
  const m = fname.match(/^db-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6]));
}
function _dayKey(d)   { return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`; }
function _weekKey(d)  {
  // ISO week: ano-semana
  const tmp = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dow = tmp.getUTCDay() || 7;
  tmp.setUTCDate(tmp.getUTCDate() + 4 - dow);
  const yearStart = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 1));
  const weekNum = Math.ceil(((tmp - yearStart) / 86400000 + 1) / 7);
  return `${tmp.getUTCFullYear()}-W${String(weekNum).padStart(2,'0')}`;
}
function _monthKey(d) { return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`; }

// ── Retenção Time Machine: decide quais backups manter ──
function _aplicarRetencaoBackup() {
  try {
    const agora = new Date();
    const lista = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.endsWith('.json') || f.endsWith('.json.gz'))
      .map(f => ({ nome: f, data: _parseStamp(f) }))
      .filter(x => x.data)
      .sort((a,b) => b.data - a.data); // mais novo primeiro

    const manter = new Set();

    // Marca "pre-restore" e "manual" pra manter sempre (são importantes)
    lista.forEach(x => {
      if (/-pre-restore|-manual/.test(x.nome)) manter.add(x.nome);
    });

    // Camada 1: tudo das últimas RET_HOURS horas
    const limiteHoras = new Date(agora.getTime() - RET_HOURS*60*60*1000);
    lista.forEach(x => { if (x.data >= limiteHoras) manter.add(x.nome); });

    // Camada 2: 1 por dia nos últimos RET_DAYS dias (mais antigo do dia)
    const limiteDias = new Date(agora.getTime() - RET_DAYS*24*60*60*1000);
    const porDia = {};
    lista.forEach(x => {
      if (x.data < limiteDias || x.data >= limiteHoras) return;
      const k = _dayKey(x.data);
      // fica com o mais velho do dia (mais representativo)
      if (!porDia[k] || x.data < porDia[k].data) porDia[k] = x;
    });
    Object.values(porDia).forEach(x => manter.add(x.nome));

    // Camada 3: 1 por semana nas últimas RET_WEEKS semanas (>90d < 1ano)
    const limiteSem = new Date(agora.getTime() - RET_WEEKS*7*24*60*60*1000);
    const porSemana = {};
    lista.forEach(x => {
      if (x.data < limiteSem || x.data >= limiteDias) return;
      const k = _weekKey(x.data);
      if (!porSemana[k] || x.data < porSemana[k].data) porSemana[k] = x;
    });
    Object.values(porSemana).forEach(x => manter.add(x.nome));

    // Camada 4: 1 por mês (para sempre) pros mais antigos que 1 ano
    const porMes = {};
    lista.forEach(x => {
      if (x.data >= limiteSem) return;
      const k = _monthKey(x.data);
      if (!porMes[k] || x.data < porMes[k].data) porMes[k] = x;
    });
    Object.values(porMes).forEach(x => manter.add(x.nome));

    // Apaga o que não foi marcado
    let apagados = 0;
    lista.forEach(x => {
      if (!manter.has(x.nome)) {
        try { fs.unlinkSync(path.join(BACKUP_DIR, x.nome)); apagados++; } catch {}
      }
    });
    return { mantidos: manter.size, apagados, total: lista.length };
  } catch (err) {
    console.error('[BACKUP] erro na retenção:', err.message);
    return { erro: err.message };
  }
}

// Migracao unica: comprime os snapshots crus que ja estao no volume. Sao eles
// que ocupam o disco hoje (~1,9MB cada); comprimidos ficam ~400KB. Conservador:
// so apaga o original depois de reler o .gz e confirmar que o JSON esta intacto.
function _comprimirSnapshotsAntigos() {
  const zlib = require('zlib');
  let convertidos = 0, liberadoMB = 0, falhas = 0;
  let arqs;
  try { arqs = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.json')); }
  catch (e) { return; }
  if (!arqs.length) return;
  for (const f of arqs) {
    const cru = path.join(BACKUP_DIR, f);
    const alvo = cru + '.gz';
    try {
      if (fs.existsSync(alvo)) { fs.unlinkSync(cru); continue; }   // ja convertido antes
      const texto = fs.readFileSync(cru, 'utf8');
      JSON.parse(texto);                                  // original precisa estar sao
      const tam = fs.statSync(cru).size;
      fs.writeFileSync(alvo, zlib.gzipSync(texto));
      const volta = zlib.gunzipSync(fs.readFileSync(alvo)).toString('utf8');
      if (volta !== texto) { fs.unlinkSync(alvo); falhas++; continue; }
      fs.unlinkSync(cru);                                 // so agora o original sai
      convertidos++; liberadoMB += (tam - fs.statSync(alvo).size) / (1024 * 1024);
    } catch (e) { falhas++; try { if (fs.existsSync(alvo)) fs.unlinkSync(alvo); } catch (e2) {} }
  }
  if (convertidos || falhas) {
    console.log(`[BACKUP] compressao do acervo: ${convertidos} convertido(s), ` +
                `${Math.round(liberadoMB)}MB liberados` + (falhas ? `, ${falhas} pulado(s)` : '') + '.');
  }
}

// Le um snapshot, seja .json ou .json.gz. Os antigos continuam funcionando.
function _lerSnapshot(fpath) {
  const bruto = fs.readFileSync(fpath);
  if (fpath.endsWith('.gz')) return require('zlib').gunzipSync(bruto).toString('utf8');
  return bruto.toString('utf8');
}

// Grava o db.json de forma ATOMICA a partir de texto ja pronto (mesma razao do
// writeDB: escrever direto zera o arquivo e quem ler no meio pega lixo).
function _gravarDbTexto(txt) {
  const tmp = DB_FILE + '.tmp';
  try {
    fs.writeFileSync(tmp, txt);
  } catch (e) {
    if (!e || e.code !== 'ENOSPC') throw e;
    _liberarEspacoSeNecessario(Math.max(60, Math.ceil(txt.length / (1024 * 1024)) * 3));
    fs.writeFileSync(tmp, txt);
  }
  fs.renameSync(tmp, DB_FILE);
}

// Grava snapshot e aplica retenção
function criarSnapshotBackup(motivo) {
  try {
    const agora = new Date();
    const pad = n => String(n).padStart(2,'0');
    const stamp = `${agora.getUTCFullYear()}${pad(agora.getUTCMonth()+1)}${pad(agora.getUTCDate())}-${pad(agora.getUTCHours())}${pad(agora.getUTCMinutes())}${pad(agora.getUTCSeconds())}`;
    // Comprimido: os dados encolhem ~4,6x e a retencao inteira passa a caber no
    // volume. Foi o acumulo de snapshots crus que lotou o disco e derrubou o site.
    const fname = `db-${stamp}${motivo ? '-' + motivo : ''}.json.gz`;
    const fpath = path.join(BACKUP_DIR, fname);
    const conteudo = fs.readFileSync(DB_FILE, 'utf8');
    // Abre espaço ANTES de gravar: foi o acúmulo de snapshots que lotou o volume
    // e derrubou a aplicação. O banco em si tem prioridade sobre o histórico.
    _liberarEspacoSeNecessario(Math.max(80, Math.ceil(conteudo.length / (1024 * 1024)) * 4));
    // Nunca gravar snapshot vazio/quebrado: um backup inválido dá falsa sensação
    // de segurança — só se descobre que não presta na hora de precisar dele.
    if (!conteudo || !conteudo.trim()) {
      console.error('[BACKUP] abortado: db.json veio vazio.');
      return { ok: false, erro: 'db vazio' };
    }
    try { JSON.parse(conteudo); }
    catch (e) {
      console.error('[BACKUP] abortado: db.json não é JSON válido.');
      return { ok: false, erro: 'db inválido' };
    }
    fs.writeFileSync(fpath, require('zlib').gzipSync(conteudo));
    const ret = _aplicarRetencaoBackup();
    console.log(`[BACKUP] ${fname} criado. Retenção: ${ret.mantidos} mantidos, ${ret.apagados||0} apagados.`);
    return { ok: true, arquivo: fname, mantidos: ret.mantidos };
  } catch (err) {
    console.error('[BACKUP] erro ao criar snapshot:', err.message);
    return { ok: false, erro: err.message };
  }
}

// Auto-snapshot a cada 6h
setInterval(() => criarSnapshotBackup('auto'), BACKUP_INTERVAL_MS);
// Snapshot inicial 30s após startup (evita acumulação se reiniciar muito)
setTimeout(() => criarSnapshotBackup('boot'), 30000);

// ══════════════════════════════════════════════
// ── BACKUP EXTERNO (GitHub) ──
// ══════════════════════════════════════════════
// Variáveis de ambiente necessárias no Railway:
//   GITHUB_BACKUP_TOKEN = PAT com scope "repo"
//   GITHUB_BACKUP_REPO  = "owner/repo" (ex: marinhothg18/scalelab-backups)

const REMOTE_BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h
const REMOTE_BACKUP_MARKER = path.join(DATA_DIR, '.last-remote-backup');

async function pushBackupToGitHub(motivo) {
  const token = process.env.GITHUB_BACKUP_TOKEN;
  const repo  = process.env.GITHUB_BACKUP_REPO;
  if (!token || !repo) {
    return { ok: false, erro: 'GITHUB_BACKUP_TOKEN / GITHUB_BACKUP_REPO não configurados no Railway.' };
  }
  try {
    const zlib = require('zlib');
    const conteudo = fs.readFileSync(DB_FILE, 'utf8');
    const gz = zlib.gzipSync(conteudo);
    const base64 = gz.toString('base64');

    const agora = new Date();
    const pad = n => String(n).padStart(2,'0');
    const stamp = `${agora.getUTCFullYear()}-${pad(agora.getUTCMonth()+1)}-${pad(agora.getUTCDate())}_${pad(agora.getUTCHours())}${pad(agora.getUTCMinutes())}`;
    const filepath = `backups/${agora.getUTCFullYear()}/${pad(agora.getUTCMonth()+1)}/db-${stamp}${motivo ? '-' + motivo : ''}.json.gz`;

    // Verifica se arquivo já existe (pra pegar SHA)
    let sha;
    try {
      const r0 = await fetch(`https://api.github.com/repos/${repo}/contents/${encodeURI(filepath)}`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/vnd.github+json' }
      });
      if (r0.ok) { const d = await r0.json(); sha = d.sha; }
    } catch {}

    const res = await fetch(`https://api.github.com/repos/${repo}/contents/${encodeURI(filepath)}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: `Backup ${stamp}${motivo ? ' (' + motivo + ')' : ''}`,
        content: base64,
        ...(sha ? { sha } : {})
      })
    });
    if (!res.ok) {
      const err = await res.text();
      return { ok: false, erro: `GitHub ${res.status}: ${err.slice(0,300)}` };
    }
    // Grava marker com timestamp
    try { fs.writeFileSync(REMOTE_BACKUP_MARKER, JSON.stringify({ ts: Date.now(), arquivo: filepath })); } catch {}
    console.log(`[REMOTE-BACKUP] Enviado ao GitHub: ${filepath} (${(gz.length/1024).toFixed(1)}KB)`);
    return { ok: true, arquivo: filepath, tamanho: gz.length, repo };
  } catch (err) {
    console.error('[REMOTE-BACKUP] erro:', err.message);
    return { ok: false, erro: err.message };
  }
}

// Auto-push a cada 24h (se configurado)
async function _tickBackupRemoto() {
  try {
    // Só se configurado
    if (!process.env.GITHUB_BACKUP_TOKEN || !process.env.GITHUB_BACKUP_REPO) return;
    // Só se última vez foi >20h atrás
    try {
      const marker = JSON.parse(fs.readFileSync(REMOTE_BACKUP_MARKER, 'utf8'));
      if (marker && marker.ts && Date.now() - marker.ts < 20*60*60*1000) return;
    } catch {}
    await pushBackupToGitHub('daily');
  } catch (e) { console.error('[REMOTE-BACKUP] tick erro:', e.message); }
}
setInterval(_tickBackupRemoto, 60*60*1000); // verifica a cada 1h

// ══════════════════════════════════════════════
// LEMBRETES AUTOMÁTICOS (cron)
// ══════════════════════════════════════════════
function _lembretesRodar() {
  try {
    const db = readDB();
    const cfgLemb = db.store['sl_lembretes_config'] || {};
    // Regras padrão = ativas, exceto explicitamente false. prazo6h/2h/30min padrão = false (economia).
    const regras = {
      prazo24h:     cfgLemb.prazo24h     !== false,
      prazo6h:      cfgLemb.prazo6h      === true,
      prazo2h:      cfgLemb.prazo2h      === true,
      prazo30min:   cfgLemb.prazo30min   === true,
      vencendoHoje: cfgLemb.vencendoHoje === true,
      atrasada1d:   cfgLemb.atrasada1d   !== false,
      atrasada3d:   cfgLemb.atrasada3d   !== false,
      alertaDir2d:  cfgLemb.alertaDir2d  !== false,
      ritualHoje:   cfgLemb.ritualHoje   !== false,
      backlog3d:    cfgLemb.backlog3d    !== false,
    };
    // Hora configurada como "fim do prazo" quando não há hora explícita na demanda (padrão 18h)
    const prazoHoraFim = typeof cfgLemb.prazoHoraFim === 'number' ? cfgLemb.prazoHoraFim : 18;
    const tasks = (db.store.tasks || []).filter(t => t && !t.arquivado);
    const rituais = db.store.rituais || [];
    const usuarios = db.store['sl_usuarios'] || [];
    const notifs = db.store['sl_notifs'] || [];

    const today = new Date();
    const todayStr = today.toISOString().slice(0,10);
    const amanha = new Date(today); amanha.setDate(today.getDate()+1);
    const amanhaStr = amanha.toISOString().slice(0,10);

    const dedupKey = (rule, extra) => `${todayStr}:${rule}:${extra}`;
    const jaNotificado = (k) => notifs.some(n => n && n.dedupKey === k);
    const addLembrete = (destId, destNome, titulo, texto, key, refId) => {
      if (!destId) return;
      if (jaNotificado(key)) return;
      notifs.unshift({
        id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
        destId, destNome: destNome || '',
        tipo: 'lembrete',
        titulo: titulo || '', texto: texto || '',
        refId: refId || null,
        lida: false,
        criado: Date.now(),
        dedupKey: key
      });
      // Best-effort WhatsApp (fire-and-forget)
      try { _notificarViaWhatsApp(destId, titulo, texto); } catch(e){}
    };
    const respsOf = (t) => {
      if (Array.isArray(t.respIds) && t.respIds.length) return t.respIds;
      if (t.respId) return [t.respId];
      return [];
    };

    let criados = 0;
    const initialLen = notifs.length;

    // ── Regra: prazo em 24h ──
    if (regras.prazo24h) {
      tasks.forEach(t => {
        if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return;
        if (t.data !== amanhaStr) return;
        respsOf(t).forEach(rid => {
          const u = usuarios.find(x => x.id === rid);
          if (!u || u.ativo === false) return;
          addLembrete(rid, u.nome, '⏰ Prazo amanhã', `A demanda "${t.nome}" vence amanhã.`, dedupKey('prazo24h', rid+'-'+t.id), t.id);
        });
      });
    }

    // ── Regras por janela de horas até o vencimento (6h / 2h / 30min / vencendo hoje) ──
    // Deadline = t.data + (t.prazoHora || prazoHoraFim:00)
    const agoraMs = today.getTime();
    const janelas = [
      { ativa: regras.prazo6h,    min: 5*60,  max: 6*60 + 14, rule: 'prazo6h',    emoji: '⏳', titulo: 'Prazo em 6h' },
      { ativa: regras.prazo2h,    min: 1*60 + 45, max: 2*60 + 14, rule: 'prazo2h',    emoji: '⚡', titulo: 'Prazo em 2h' },
      { ativa: regras.prazo30min, min: 15,    max: 44,        rule: 'prazo30min', emoji: '🚨', titulo: 'Prazo em 30min' },
      { ativa: regras.vencendoHoje, min: -14, max: 14,        rule: 'vencendoHoje', emoji: '🔔', titulo: 'Vencendo agora' },
    ];
    if (janelas.some(j => j.ativa)) {
      tasks.forEach(t => {
        if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return;
        if (!t.data) return;
        // Monta timestamp do vencimento
        let hora = prazoHoraFim, min = 0;
        if (typeof t.prazoHora === 'string' && /^\d{1,2}:\d{2}$/.test(t.prazoHora)) {
          const p = t.prazoHora.split(':'); hora = +p[0]; min = +p[1];
        }
        const deadline = new Date(t.data + 'T00:00:00');
        deadline.setHours(hora, min, 0, 0);
        const minutosAteVencer = Math.round((deadline.getTime() - agoraMs) / 60000);
        janelas.forEach(j => {
          if (!j.ativa) return;
          if (minutosAteVencer < j.min || minutosAteVencer > j.max) return;
          respsOf(t).forEach(rid => {
            const u = usuarios.find(x => x.id === rid);
            if (!u || u.ativo === false) return;
            addLembrete(rid, u.nome, `${j.emoji} ${j.titulo}`, `"${t.nome}" vence ${minutosAteVencer <= 15 ? 'agora' : 'em breve'} (${t.data.split('-').reverse().join('/')} ${String(hora).padStart(2,'0')}:${String(min).padStart(2,'0')}).`, dedupKey(j.rule, rid+'-'+t.id), t.id);
          });
        });
      });
    }

    // ── Regra: atrasada 1 dia ──
    if (regras.atrasada1d) {
      tasks.forEach(t => {
        if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return;
        if (!t.data || t.data >= todayStr) return;
        const dias = Math.floor((new Date(todayStr).getTime() - new Date(t.data).getTime()) / (24*60*60*1000));
        if (dias !== 1) return;
        respsOf(t).forEach(rid => {
          const u = usuarios.find(x => x.id === rid);
          if (!u || u.ativo === false) return;
          addLembrete(rid, u.nome, '⚠️ Demanda atrasada', `"${t.nome}" está atrasada há 1 dia.`, dedupKey('atrasada1d', rid+'-'+t.id), t.id);
        });
      });
    }

    // ── Regra: alerta Diretoria (atrasada 2 dias) ──
    if (regras.alertaDir2d) {
      const diretoria = usuarios.filter(u => u.cargo === 'Diretoria' && u.ativo !== false);
      tasks.forEach(t => {
        if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return;
        if (!t.data || t.data >= todayStr) return;
        const dias = Math.floor((new Date(todayStr).getTime() - new Date(t.data).getTime()) / (24*60*60*1000));
        if (dias !== 2) return;
        diretoria.forEach(u => {
          addLembrete(u.id, u.nome, '🚨 Item em risco', `"${t.nome}" (${t.resp||'sem resp.'}) atrasada há 2 dias.`, dedupKey('alertaDir2d', u.id+'-'+t.id), t.id);
        });
      });
    }

    // ── Regra: atrasada 3+ dias (cobrança firme) ──
    if (regras.atrasada3d) {
      tasks.forEach(t => {
        if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return;
        if (!t.data || t.data >= todayStr) return;
        const dias = Math.floor((new Date(todayStr).getTime() - new Date(t.data).getTime()) / (24*60*60*1000));
        if (dias !== 3) return; // só dispara no dia 3
        respsOf(t).forEach(rid => {
          const u = usuarios.find(x => x.id === rid);
          if (!u || u.ativo === false) return;
          addLembrete(rid, u.nome, '🔥 Demanda paralisada (3 dias)', `"${t.nome}" está paralisada há 3 dias. Precisa de ação urgente.`, dedupKey('atrasada3d', rid+'-'+t.id), t.id);
        });
      });
    }

    // ── Regra: ritual hoje (dispara só pela manhã, 8h-11h) ──
    const hora = today.getHours();
    if (regras.ritualHoje && hora >= 8 && hora <= 11) {
      rituais.forEach(r => {
        if (!r || !r.id) return;
        const rDate = new Date(Number(r.id));
        if (!isNaN(rDate.getTime()) && rDate.toISOString().slice(0,10) === todayStr) {
          (r.participantes || []).forEach(nome => {
            const u = usuarios.find(x => x.nome === nome && x.ativo !== false);
            if (!u) return;
            addLembrete(u.id, u.nome, '⭐ Ritual hoje', `Ritual "${r.nome}" acontece hoje.`, dedupKey('ritualHoje', u.id+'-'+r.id), r.id);
          });
        }
      });
    }

    // ── Regra: demanda em Backlog 3+ dias ──
    if (regras.backlog3d) {
      tasks.forEach(t => {
        if (t.status !== 'BACKLOG') return;
        const ts = Number(t.id);
        if (!ts) return;
        const dias = Math.floor((today.getTime() - ts) / (24*60*60*1000));
        if (dias !== 3 && dias !== 7) return; // dispara só nos dias 3 e 7
        respsOf(t).forEach(rid => {
          const u = usuarios.find(x => x.id === rid);
          if (!u || u.ativo === false) return;
          addLembrete(rid, u.nome, '💤 Demanda parada no Backlog', `"${t.nome}" está no Backlog há ${dias} dias.`, dedupKey('backlog3d-'+dias, rid+'-'+t.id), t.id);
        });
      });
    }

    criados = notifs.length - initialLen;
    if (criados > 0) {
      db.store['sl_notifs'] = notifs.slice(0, 1000); // limita a 1000 notifs
      db.timestamps['sl_notifs'] = now();
      writeDB(db);
      console.log(`[LEMBRETES] ${criados} notificações criadas.`);
    }
  } catch (err) {
    console.error('[LEMBRETES] erro:', err.message);
  }
}
// Roda a cada 15min + primeira em 30s após boot (granularidade para lembretes de 30min/2h/6h)
setInterval(_lembretesRodar, 15 * 60 * 1000);
setTimeout(_lembretesRodar, 30 * 1000);

// Endpoint pra forçar execução manual (só Diretoria)
app.post('/api/lembretes/rodar', authDiretoria, (req, res) => {
  _lembretesRodar();
  res.json({ ok: true, message: 'Lembretes executados.' });
});

// ══════════════════════════════════════════════
// RELATÓRIO SEMANAL AUTOMÁTICO
// ══════════════════════════════════════════════
function _gerarRelatorioSemanal(forcado) {
  try {
    const db = readDB();
    const cfg = db.store['sl_relatorio_config'] || {};
    const ativo = cfg.ativo !== false;
    const diaSemana = typeof cfg.diaSemana === 'number' ? cfg.diaSemana : 5; // 5 = sexta
    const hora = typeof cfg.hora === 'number' ? cfg.hora : 18;

    if (!forcado) {
      if (!ativo) return { ok: false, motivo: 'desativado' };
      const agora = new Date();
      if (agora.getDay() !== diaSemana) return { ok: false, motivo: 'dia_errado' };
      if (agora.getHours() !== hora) return { ok: false, motivo: 'hora_errada' };
      // Evita duplicar: se já rodou hoje, pula
      const hojeStr = agora.toISOString().slice(0,10);
      const existentes = db.store['sl_relatorios_semanais'] || [];
      if (existentes.some(r => r.geradoEm && r.geradoEm.slice(0,10) === hojeStr)) {
        return { ok: false, motivo: 'ja_rodou_hoje' };
      }
    }

    const agora = new Date();
    const iniSem = new Date(agora.getTime() - 7*24*60*60*1000);
    const fmt = d => d.toISOString().slice(0,10);
    const periodo_ini = fmt(iniSem), periodo_fim = fmt(agora);

    // Dados: tasks, criativos, rituais, roi, alertas
    const tasks = (db.store.tasks || []).filter(t => t && !t.arquivado);
    const rituais = db.store.rituais || [];
    const roiOfertas = db.store['roi_ofertas'] || [];
    const auditLog = db.store['sl_auditlog'] || [];

    // KPIs ROI (soma dias na semana)
    let inv = 0, ret = 0, leads = 0, vendas = 0;
    const ofertasSemana = {};
    roiOfertas.forEach(o => {
      (o.dias || []).forEach(d => {
        if (!d || !d.data) return;
        if (d.data < periodo_ini || d.data > periodo_fim) return;
        const dInv = Number(d.investido) || 0;
        const dRet = Number(d.retorno) || 0;
        inv += dInv; ret += dRet;
        leads += Number(d.leads) || 0;
        vendas += Number(d.vendas) || 0;
        if (!ofertasSemana[o.id]) ofertasSemana[o.id] = { nome: o.nome, inv: 0, ret: 0, lucro: 0 };
        ofertasSemana[o.id].inv += dInv;
        ofertasSemana[o.id].ret += dRet;
        ofertasSemana[o.id].lucro = ofertasSemana[o.id].ret - ofertasSemana[o.id].inv;
      });
    });
    const lucro = ret - inv;
    const roas = inv > 0 ? ret / inv : 0;
    const cpa = leads > 0 ? inv / leads : 0;

    // Top 5 ofertas por lucro
    const topOfertas = Object.values(ofertasSemana)
      .sort((a, b) => b.lucro - a.lucro)
      .slice(0, 5);

    // Helpers pra resolver nomes de responsáveis
    const respNome = (t) => {
      if (Array.isArray(t.respIds) && t.respIds.length) {
        return t.respIds.map(rid => {
          const u = (db.store['sl_usuarios']||[]).find(x => x.id === rid);
          return u ? u.nome : '—';
        }).join(', ');
      }
      return t.resp || '—';
    };

    // Demandas concluídas na semana
    const demandas_concluidas = tasks.filter(t => {
      if (t.status !== 'CONCLUIDO' && t.status !== 'Concluída') return false;
      const ts = Number(t._updatedAt) || Number(t.id);
      if (!ts) return false;
      return ts >= iniSem.getTime();
    }).map(t => ({ id: t.id, nome: t.nome||'(sem nome)', resp: respNome(t), ofertaNome: t.ofertaNome||'' }));

    // Demandas atrasadas (prazo < hoje, não concluídas)
    const demandas_atrasadas = tasks.filter(t => {
      if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return false;
      return t.data && t.data < periodo_fim;
    }).map(t => {
      const diasAtraso = Math.floor((new Date(periodo_fim).getTime() - new Date(t.data).getTime()) / (24*60*60*1000));
      return { id: t.id, nome: t.nome||'(sem nome)', resp: respNome(t), ofertaNome: t.ofertaNome||'', diasAtraso };
    });

    // Demandas pendentes (não concluídas + não atrasadas)
    const demandas_pendentes = tasks.filter(t => {
      if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return false;
      if (t.data && t.data < periodo_fim) return false; // já conta como atrasada
      return true;
    }).map(t => ({ id: t.id, nome: t.nome||'(sem nome)', resp: respNome(t), status: t.status||'', ofertaNome: t.ofertaNome||'' }));

    const concluidasSemana = demandas_concluidas.length;
    const atrasadas = demandas_atrasadas.length;
    const pendentes = demandas_pendentes.length;

    // Rituais na semana (detalhado)
    const rituais_detalhes = rituais.filter(r => {
      const ts = Number(r.id);
      return ts && ts >= iniSem.getTime();
    }).map(r => ({
      id: r.id, nome: r.nome||'(sem nome)', tipo: r.tipo||'—',
      participantes: Array.isArray(r.participantes) ? r.participantes : []
    }));

    // Alertas da semana (audit events)
    const alertas_detalhes = auditLog.filter(a => {
      if (!a || !a.ts) return false;
      if (a.ts < iniSem.getTime()) return false;
      return /login_falhou|kpi|alerta|soft_delete|purge|backup_restore/i.test(a.action || '');
    }).slice(0, 30).map(a => ({
      ts: a.ts, iso: a.iso || new Date(a.ts).toISOString(),
      action: a.action || '—', userNome: a.userNome||'—',
      target: a.target || null
    }));

    const relatorio = {
      id: 'rel-' + Date.now(),
      geradoEm: agora.toISOString(),
      periodo_ini,
      periodo_fim,
      kpis: { investimento: inv, retorno: ret, lucro, roas, cpa, leads, vendas },
      ofertas_top: topOfertas,
      demandas: { concluidas: concluidasSemana, pendentes, atrasadas },
      demandas_concluidas,
      demandas_pendentes: demandas_pendentes.slice(0, 50),
      demandas_atrasadas,
      rituais_realizados: rituais_detalhes.length,
      rituais_detalhes,
      alertas: alertas_detalhes.length,
      alertas_detalhes
    };

    if (!db.store['sl_relatorios_semanais']) db.store['sl_relatorios_semanais'] = [];
    db.store['sl_relatorios_semanais'].unshift(relatorio);
    // Mantém últimos 52 (1 ano)
    if (db.store['sl_relatorios_semanais'].length > 52) {
      db.store['sl_relatorios_semanais'] = db.store['sl_relatorios_semanais'].slice(0, 52);
    }

    // Notifica destinatários
    const destinos = Array.isArray(cfg.destinatariosIds) && cfg.destinatariosIds.length
      ? cfg.destinatariosIds
      : (db.store['sl_usuarios'] || []).filter(u => u.cargo === 'Diretoria' && u.ativo !== false).map(u => u.id);

    if (!db.store['sl_notifs']) db.store['sl_notifs'] = [];
    destinos.forEach(uid => {
      const u = (db.store['sl_usuarios'] || []).find(x => x.id === uid);
      if (!u) return;
      const dedupKey = `rel-semanal:${periodo_fim}:${uid}`;
      if (db.store['sl_notifs'].some(n => n.dedupKey === dedupKey)) return;
      db.store['sl_notifs'].unshift({
        id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
        destId: uid, destNome: u.nome,
        tipo: 'relatorio_semanal',
        titulo: '📤 Relatório Semanal pronto',
        texto: `Relatório ${periodo_ini} a ${periodo_fim} · ROAS ${roas.toFixed(2).replace('.',',')}x · Lucro R$ ${Math.round(lucro).toLocaleString('pt-BR')}`,
        refId: relatorio.id,
        lida: false,
        criado: Date.now(),
        dedupKey
      });
    });

    // ── Envia resumo via WhatsApp para destinatários com número cadastrado ──
    if (cfg.enviarWhatsApp !== false) {
      const fmtBR = n => 'R$ ' + Math.round(n).toLocaleString('pt-BR');
      const linhas = [];
      linhas.push('📊 *Relatório Semanal TMX Digital*');
      linhas.push(`_${periodo_ini.split('-').reverse().join('/')} a ${periodo_fim.split('-').reverse().join('/')}_`);
      linhas.push('');
      linhas.push('*💰 KPIs*');
      linhas.push(`• Investimento: ${fmtBR(inv)}`);
      linhas.push(`• Faturamento: ${fmtBR(ret)}`);
      linhas.push(`• Lucro: ${fmtBR(lucro)}`);
      linhas.push(`• ROAS: ${roas.toFixed(2).replace('.',',')}x`);
      if (vendas) linhas.push(`• Vendas: ${vendas} · Leads: ${leads}`);
      linhas.push('');
      linhas.push('*✅ Demandas*');
      linhas.push(`• Concluídas: ${concluidasSemana}`);
      linhas.push(`• Pendentes: ${pendentes}`);
      linhas.push(`• Atrasadas: ${atrasadas}`);
      if (topOfertas.length) {
        linhas.push('');
        linhas.push('*🏆 Top Ofertas*');
        topOfertas.slice(0, 3).forEach((o, i) => {
          linhas.push(`${i+1}. ${o.nome} · ${fmtBR(o.lucro)}`);
        });
      }
      linhas.push('');
      linhas.push('_Abra o app pra ver detalhes._');
      const msg = linhas.join('\n');
      destinos.forEach(uid => {
        const u = (db.store['sl_usuarios'] || []).find(x => x.id === uid);
        if (!u || !u.whatsapp) return;
        sendWhatsAppMessage(u.whatsapp, msg).catch(()=>{});
      });
    }

    db.timestamps['sl_relatorios_semanais'] = now();
    db.timestamps['sl_notifs'] = now();
    writeDB(db);

    console.log(`[RELATÓRIO-SEMANAL] Gerado: ${periodo_ini} a ${periodo_fim} · ROAS ${roas.toFixed(2)}x · Lucro R$ ${Math.round(lucro)}`);
    return { ok: true, relatorio };
  } catch (err) {
    console.error('[RELATÓRIO-SEMANAL] erro:', err.message);
    return { ok: false, erro: err.message };
  }
}

// Cron roda a cada 1h
setInterval(_gerarRelatorioSemanal, 60 * 60 * 1000);

// Endpoint forçar (Diretoria)
app.post('/api/relatorio-semanal/rodar', authDiretoria, (req, res) => {
  const r = _gerarRelatorioSemanal(true);
  if (!r.ok) return res.status(400).json(r);
  res.json({ ok: true, relatorio: r.relatorio });
});

// ══════════════════════════════════════════════
// RELATÓRIO DIÁRIO VIA WHATSAPP (Diretoria)
// ══════════════════════════════════════════════
function _gerarRelatorioDiario(forcado) {
  try {
    const db = readDB();
    const cfg = db.store['sl_relatorio_diario_config'] || {};
    const ativo = cfg.ativo !== false;
    const hora = typeof cfg.hora === 'number' ? cfg.hora : 18;

    const agora = new Date();
    const hojeStr = agora.toISOString().slice(0,10);

    if (!forcado) {
      if (!ativo) return { ok: false, motivo: 'desativado' };
      if (agora.getHours() !== hora) return { ok: false, motivo: 'hora_errada' };
      // Evita mandar 2x no mesmo dia
      const notifs = db.store['sl_notifs'] || [];
      if (notifs.some(n => n.dedupKey && n.dedupKey.startsWith(`rel-diario:${hojeStr}:`))) {
        return { ok: false, motivo: 'ja_rodou_hoje' };
      }
    }

    const tasks = (db.store.tasks || []).filter(t => t && !t.arquivado);
    const usuarios = db.store['sl_usuarios'] || [];
    const roiOfertas = db.store['roi_ofertas'] || [];

    const respNome = (t) => {
      if (Array.isArray(t.respIds) && t.respIds.length) {
        return t.respIds.map(rid => {
          const u = usuarios.find(x => x.id === rid);
          return u ? u.nome : '—';
        }).join(', ');
      }
      return t.resp || '—';
    };
    const respIdsOf = (t) => {
      if (Array.isArray(t.respIds) && t.respIds.length) return t.respIds;
      if (t.respId) return [t.respId];
      return [];
    };

    // Concluídas hoje (usando _updatedAt)
    const inicioDoDia = new Date(hojeStr + 'T00:00:00').getTime();
    const fimDoDia = inicioDoDia + 24*60*60*1000 - 1;
    const concluidasHoje = tasks.filter(t => {
      if (t.status !== 'CONCLUIDO' && t.status !== 'Concluída') return false;
      const ts = Number(t._updatedAt) || Number(t.id);
      return ts >= inicioDoDia && ts <= fimDoDia;
    });

    // Vencendo hoje (não concluídas, prazo == hoje)
    const vencendoHoje = tasks.filter(t => {
      if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return false;
      return t.data === hojeStr;
    });

    // Atrasadas (prazo < hoje, não concluídas)
    const atrasadas = tasks.filter(t => {
      if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return false;
      return t.data && t.data < hojeStr;
    });

    // Em andamento / backlog (não concluídas, sem prazo ou prazo futuro)
    const emAberto = tasks.filter(t => {
      if (t.status === 'CONCLUIDO' || t.status === 'Concluída') return false;
      return !t.data || t.data > hojeStr;
    });

    // ROI do dia (somando dias com data == hoje)
    let invHoje = 0, retHoje = 0;
    roiOfertas.forEach(o => {
      (o.dias || []).forEach(d => {
        if (d && d.data === hojeStr) {
          invHoje += Number(d.investido) || 0;
          retHoje += Number(d.retorno) || 0;
        }
      });
    });
    const lucroHoje = retHoje - invHoje;
    const roasHoje = invHoje > 0 ? retHoje / invHoje : 0;

    // Produtividade por pessoa (ativos com WhatsApp OU Diretoria)
    const porPessoa = {};
    tasks.forEach(t => {
      respIdsOf(t).forEach(rid => {
        const u = usuarios.find(x => x.id === rid);
        if (!u || u.ativo === false) return;
        if (!porPessoa[rid]) porPessoa[rid] = { nome: u.nome, concluidas: 0, atrasadas: 0, vencendoHoje: 0, abertas: 0 };
        if (t.status === 'CONCLUIDO' || t.status === 'Concluída') {
          const ts = Number(t._updatedAt) || Number(t.id);
          if (ts >= inicioDoDia && ts <= fimDoDia) porPessoa[rid].concluidas++;
        } else if (t.data && t.data < hojeStr) {
          porPessoa[rid].atrasadas++;
        } else if (t.data === hojeStr) {
          porPessoa[rid].vencendoHoje++;
        } else {
          porPessoa[rid].abertas++;
        }
      });
    });

    // Destinatários: IDs configurados OU Diretoria com WhatsApp
    const destinos = Array.isArray(cfg.destinatariosIds) && cfg.destinatariosIds.length
      ? cfg.destinatariosIds
      : usuarios.filter(u => u.cargo === 'Diretoria' && u.ativo !== false).map(u => u.id);

    // Monta mensagem
    const fmtBR = n => 'R$ ' + Math.round(n).toLocaleString('pt-BR');
    const dataBR = hojeStr.split('-').reverse().join('/');
    const linhas = [];
    linhas.push(`📋 *Relatório Diário TMX Digital — ${dataBR}*`);
    linhas.push('');
    linhas.push('*✅ Demandas hoje*');
    linhas.push(`• Concluídas hoje: ${concluidasHoje.length}`);
    linhas.push(`• Vencendo hoje: ${vencendoHoje.length}`);
    linhas.push(`• Atrasadas: ${atrasadas.length}`);
    linhas.push(`• Em aberto: ${emAberto.length}`);

    if (invHoje > 0 || retHoje > 0) {
      linhas.push('');
      linhas.push('*💰 ROI hoje*');
      linhas.push(`• Investido: ${fmtBR(invHoje)}`);
      linhas.push(`• Faturamento: ${fmtBR(retHoje)}`);
      linhas.push(`• Lucro: ${fmtBR(lucroHoje)}`);
      linhas.push(`• ROAS: ${roasHoje.toFixed(2).replace('.',',')}x`);
    }

    const pessoasArr = Object.values(porPessoa).sort((a,b) => b.concluidas - a.concluidas || b.atrasadas - a.atrasadas);
    if (pessoasArr.length) {
      linhas.push('');
      linhas.push('*👥 Por pessoa*');
      pessoasArr.slice(0, 10).forEach(p => {
        const partes = [];
        if (p.concluidas) partes.push(`✅ ${p.concluidas}`);
        if (p.vencendoHoje) partes.push(`⏰ ${p.vencendoHoje}`);
        if (p.atrasadas) partes.push(`⚠️ ${p.atrasadas}`);
        if (p.abertas) partes.push(`📌 ${p.abertas}`);
        if (!partes.length) partes.push('sem demandas');
        linhas.push(`• ${p.nome}: ${partes.join(' · ')}`);
      });
      linhas.push('_✅ concl · ⏰ hoje · ⚠️ atrasada · 📌 aberta_');
    }

    if (atrasadas.length) {
      linhas.push('');
      linhas.push('*⚠️ Atrasadas (top 5)*');
      atrasadas.slice(0, 5).forEach(t => {
        const dias = Math.floor((inicioDoDia - new Date(t.data).getTime()) / (24*60*60*1000));
        linhas.push(`• ${t.nome} — ${respNome(t)} (${dias}d)`);
      });
      if (atrasadas.length > 5) linhas.push(`_+${atrasadas.length - 5} outras_`);
    }

    linhas.push('');
    linhas.push('_Axcend · Abra o app pra detalhes_');
    const msg = linhas.join('\n');

    // Envia
    let enviados = 0;
    destinos.forEach(uid => {
      const u = usuarios.find(x => x.id === uid);
      if (!u) return;

      // Notif interna
      if (!db.store['sl_notifs']) db.store['sl_notifs'] = [];
      const dedupKey = `rel-diario:${hojeStr}:${uid}`;
      if (!db.store['sl_notifs'].some(n => n.dedupKey === dedupKey)) {
        db.store['sl_notifs'].unshift({
          id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
          destId: uid, destNome: u.nome,
          tipo: 'relatorio_diario',
          titulo: `📋 Relatório Diário ${dataBR}`,
          texto: `${concluidasHoje.length} concluídas · ${atrasadas.length} atrasadas · ${vencendoHoje.length} vencendo hoje`,
          lida: false,
          criado: Date.now(),
          dedupKey
        });
      }

      // WhatsApp
      if (u.whatsapp) {
        sendWhatsAppMessage(u.whatsapp, msg).catch(()=>{});
        enviados++;
      }
    });

    db.timestamps['sl_notifs'] = now();
    writeDB(db);

    console.log(`[RELATÓRIO-DIÁRIO] ${hojeStr} · enviado para ${enviados} pessoa(s)`);
    return { ok: true, data: hojeStr, enviados, destinos: destinos.length };
  } catch (err) {
    console.error('[RELATÓRIO-DIÁRIO] erro:', err.message);
    return { ok: false, erro: err.message };
  }
}

// Cron: checa de hora em hora
setInterval(_gerarRelatorioDiario, 60 * 60 * 1000);

// Endpoint: forçar manualmente
app.post('/api/relatorio-diario/rodar', authDiretoria, (req, res) => {
  const r = _gerarRelatorioDiario(true);
  if (!r.ok) return res.status(400).json(r);
  res.json(r);
});

// ══════════════════════════════════════════════
// WHATSAPP + AGENTE IA (Z-API + Claude/OpenAI)
// ══════════════════════════════════════════════

// Limpa número de telefone pro formato Z-API (55+DDD+numero, só dígitos)
function _waCleanPhone(phone) {
  if (!phone) return '';
  let p = String(phone).replace(/\D/g, '');
  // Adiciona 55 se faltar
  if (p.length === 11) p = '55' + p;       // DDD + 9 + 8 dig
  else if (p.length === 10) p = '55' + p;  // DDD + 8 dig (sem nono dígito)

  // Normaliza pra formato CANÔNICO sem o "nono dígito" do celular brasileiro
  // (Z-API às vezes manda com, às vezes sem — pra evitar mismatch sempre tira)
  // 13 dígitos: 55 + DDD(2) + 9 + 8 dig → vira 12 dígitos (55 + DDD + 8 dig)
  if (p.length === 13 && p.startsWith('55')) {
    // Verifica se o 5º dígito é '9' (nono dígito do celular)
    if (p[4] === '9') p = p.slice(0, 4) + p.slice(5);
  }
  return p;
}

// Envia mensagem via Z-API
async function sendWhatsAppMessage(phone, message) {
  try {
    const db = readDB();
    const cfg = db.store['sl_whatsapp_config'] || {};
    if (!cfg.ativo) return { ok: false, erro: 'WhatsApp desativado' };
    if (!cfg.zapi_instance || !cfg.zapi_token) return { ok: false, erro: 'Z-API não configurado' };
    const clean = _waCleanPhone(phone);
    if (!clean) return { ok: false, erro: 'telefone inválido' };

    const url = `https://api.z-api.io/instances/${cfg.zapi_instance}/token/${cfg.zapi_token}/send-text`;
    const headers = { 'Content-Type': 'application/json' };
    if (cfg.zapi_client_token) headers['Client-Token'] = cfg.zapi_client_token;

    const r = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ phone: clean, message })
    });
    const respText = await r.text();
    if (!r.ok) {
      console.error('[WA] erro Z-API:', r.status, respText);
      return { ok: false, erro: `Z-API ${r.status}: ${respText.slice(0, 200)}` };
    }
    return { ok: true, resposta: respText };
  } catch (err) {
    console.error('[WA] send erro:', err.message);
    return { ok: false, erro: err.message };
  }
}

// Endpoint: testa envio de mensagem (Diretoria)
app.post('/api/whatsapp/test', authDiretoria, async (req, res) => {
  const { phone, message } = req.body || {};
  const to = phone || (req.user && req.user.whatsapp);
  if (!to) return res.status(400).json({ error: 'Informe um telefone ou cadastre o seu no perfil.' });
  const r = await sendWhatsAppMessage(to, message || '🤖 Teste do TMX Digital! Está funcionando.');
  res.json(r);
});

// Webhook inbound da Z-API
app.post('/api/whatsapp/webhook', async (req, res) => {
  try {
    const body = req.body || {};
    console.log('[WA webhook]', JSON.stringify(body).slice(0, 500));

    // Ignora mensagens do próprio bot
    if (body.fromMe === true) return res.json({ ok: true, skipped: 'fromMe' });

    // Z-API pode mandar formatos diferentes — extrai texto e telefone
    const phone = body.phone || body.from || '';
    let text = '';
    if (body.text) {
      text = (typeof body.text === 'object') ? (body.text.message || body.text.body || '') : String(body.text);
    } else if (body.message) {
      text = (typeof body.message === 'object') ? (body.message.body || '') : String(body.message);
    } else if (body.body) {
      text = String(body.body);
    }
    text = (text || '').trim();

    if (!text || !phone) return res.json({ ok: true, skipped: 'sem-texto' });

    const db = readDB();
    const cfg = db.store['sl_whatsapp_config'] || {};
    if (!cfg.ativo) return res.json({ ok: true, skipped: 'desativado' });

    // Identifica usuário pelo telefone
    const clean = _waCleanPhone(phone);
    const user = (db.store['sl_usuarios'] || []).find(u =>
      u && u.whatsapp && _waCleanPhone(u.whatsapp) === clean && u.ativo !== false
    );

    if (!user) {
      await sendWhatsAppMessage(phone, '👋 Olá! Este número não está cadastrado no TMX Digital. Peça ao admin pra cadastrar seu WhatsApp no perfil.');
      return res.json({ ok: true, skipped: 'user-nao-encontrado' });
    }

    // Processa com IA (se configurada — env var ou cfg)
    let resposta = '';
    const _aiKeyResolved = _getAIKey();

    // ─── COMANDOS SLASH DIRETOS (atalho rápido, não passa pela IA) ───
    // /relatorio, /relatorio copy, /relatorio roi, /relatorio vagas, /relatorio semana, /relatorio mes
    // /help, /ajuda, /minhas, /risco
    const slashCmd = _processarComandoSlash(text, user, db);
    if (slashCmd !== null) {
      resposta = slashCmd;
    } else if (cfg.ai_provider && _aiKeyResolved) {
      resposta = await _processarMensagemIA(text, user, cfg);
    } else {
      resposta = `Olá ${user.nome}! 👋\n\nO agente IA ainda não foi configurado. Por enquanto só aceito comandos simples:\n• "tarefas" → tuas demandas pendentes\n• "relatorio" → resumo da semana\n\nMeus avisos de demandas atribuídas, rituais e alertas continuam chegando normalmente.`;
      // Respostas simples
      const lower = text.toLowerCase();
      if (lower.includes('tarefa') || lower.includes('demanda')) {
        const minhas = (db.store.tasks || []).filter(t => !t.arquivado && t.status !== 'CONCLUIDO' &&
          ((Array.isArray(t.respIds) && t.respIds.includes(user.id)) || t.respId === user.id));
        if (!minhas.length) resposta = `✅ Você não tem tarefas pendentes, ${user.nome}!`;
        else {
          resposta = `📋 Suas ${minhas.length} tarefa(s) pendente(s):\n\n` +
            minhas.slice(0, 10).map((t, i) => `${i+1}. *${t.nome}*${t.data ? ` (prazo: ${t.data})` : ''}`).join('\n');
        }
      } else if (lower.includes('relatori')) {
        const rels = db.store['sl_relatorios_semanais'] || [];
        if (!rels.length) resposta = '📊 Ainda não há relatórios gerados. Peça ao admin pra gerar o primeiro.';
        else {
          const r = rels[0];
          resposta = `📊 *Relatório ${r.periodo_ini} a ${r.periodo_fim}*\n\n` +
            `💸 Investimento: R$ ${Math.round((r.kpis.investimento)||0).toLocaleString('pt-BR')}\n` +
            `💵 Faturamento: R$ ${Math.round((r.kpis.retorno)||0).toLocaleString('pt-BR')}\n` +
            `💰 Lucro: R$ ${Math.round((r.kpis.lucro)||0).toLocaleString('pt-BR')}\n` +
            `📈 ROAS: ${(r.kpis.roas||0).toFixed(2).replace('.',',')}x\n\n` +
            `✅ ${r.demandas.concluidas} demandas concluídas\n` +
            `⏳ ${r.demandas.pendentes} pendentes · ⚠ ${r.demandas.atrasadas} atrasadas`;
        }
      }
    }

    await sendWhatsAppMessage(phone, resposta);

    // Audit
    audit(db, 'wa_mensagem_recebida', { userId: user.id, texto: text.slice(0, 200) }, null, { id: user.id, nome: user.nome, cargo: user.cargo });
    writeDB(db);

    res.json({ ok: true });
  } catch (err) {
    console.error('[WA webhook erro]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Processa mensagem com Claude API + tool use
async function _processarMensagemIA(texto, user, cfg) {
  try {
    if (cfg.ai_provider === 'claude') {
      return await _chamarClaude(texto, user, cfg);
    } else if (cfg.ai_provider === 'openai') {
      return await _chamarOpenAI(texto, user, cfg);
    }
    return 'IA não configurada.';
  } catch (e) {
    console.error('[IA] erro:', e.message);
    return `Opa, tive um problema ao processar: ${e.message}`;
  }
}

// Chama Claude com tool use
async function _chamarClaude(texto, user, cfg) {
  const aiKey = _getAIKey();
  if (!aiKey) throw new Error('IA não configurada (defina ANTHROPIC_API_KEY no Railway)');
  const tools = _agentTools();
  const hojeStr = new Date().toLocaleDateString('pt-BR', { weekday:'long', year:'numeric', month:'long', day:'numeric' });
  const systemPrompt = `Você é o assistente operacional do TMX Digital (sistema de gestão de tráfego pago em centralaxcend.com).
Usuário falando: ${user.nome} (cargo: ${user.cargo}, ID: ${user.id}).
Hoje: ${hojeStr}.

Responde em português brasileiro, tom direto e operacional. Use emojis com moderação (1-2 por mensagem).

VOCÊ PODE DELEGAR E GERENCIAR via WhatsApp:
- Criar demandas e atribuir responsável (tool: criar_demanda)
- Delegar/trocar responsável de demanda existente (tool: delegar_demanda)
- Marcar demandas como concluídas (tool: concluir_demanda)
- Adicionar comentários a demandas (tool: comentar_demanda)
- Aprovar/mover candidatos no funil de vagas (tool: aprovar_candidato)
- Listar tarefas, ROI, itens em risco, relatórios por setor (tools especializadas)

INTERPRETAÇÃO DE LINGUAGEM NATURAL:
- "cria pra Ana revisar VSL até sexta" → criar_demanda(nome='Revisar VSL', responsavel='Ana', prazo='2026-XX-XX')
- "delega #823 pra Carlos" → delegar_demanda(demandaId='823', responsavel='Carlos')
- "delega #823 pra Carlos também" → delegar_demanda(..., adicionar=true)
- "concluir #847" / "fecha #847" → concluir_demanda(demandaId='847')
- "aprova candidato fulano" → aprovar_candidato(candidato='fulano')
- "minhas tarefas" → listar_tarefas(escopo='minhas')

PRAZOS naturais: hoje, amanhã, sexta, segunda, próxima semana — converta pra YYYY-MM-DD usando a data atual.

CONFIRMAÇÃO: depois de criar/delegar/concluir, confirme em formato estruturado WhatsApp:
"✅ Demanda criada\n\n📋 *Nome*\n👤 Responsável\n📅 Prazo\n🔴 Prioridade\n\nID: #N"

Se faltar info importante (responsável, prazo), execute mesmo assim com valores razoáveis e pergunte ao final se quer ajustar.`;

  const body = {
    model: 'claude-sonnet-4-5-20250929',
    max_tokens: 1024,
    system: systemPrompt,
    messages: [{ role: 'user', content: texto }],
    tools
  };

  let r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': aiKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) { const err = await r.text(); throw new Error(`Claude ${r.status}: ${err.slice(0, 200)}`); }
  let data = await r.json();

  // Se Claude quis usar uma tool, executa e devolve
  let rounds = 0;
  while (data.stop_reason === 'tool_use' && rounds < 3) {
    rounds++;
    const toolUseBlocks = data.content.filter(c => c.type === 'tool_use');
    const toolResults = [];
    for (const tu of toolUseBlocks) {
      const result = await _executarTool(tu.name, tu.input || {}, user);
      toolResults.push({
        type: 'tool_result',
        tool_use_id: tu.id,
        content: typeof result === 'string' ? result : JSON.stringify(result)
      });
    }
    body.messages.push({ role: 'assistant', content: data.content });
    body.messages.push({ role: 'user', content: toolResults });
    r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': aiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!r.ok) { const err = await r.text(); throw new Error(`Claude ${r.status}: ${err.slice(0, 200)}`); }
    data = await r.json();
  }

  // Extrai texto da resposta final
  const textBlocks = (data.content || []).filter(c => c.type === 'text');
  return textBlocks.map(c => c.text).join('\n\n') || 'Não consegui formular uma resposta.';
}

async function _chamarOpenAI(texto, user, cfg) {
  const aiKey = _getAIKey();
  if (!aiKey) throw new Error('IA não configurada (defina AI_KEY ou ANTHROPIC_API_KEY no Railway)');
  // Simplificação: usa chat completion sem tool (pra suportar OpenAI precisaria traduzir tools)
  const body = {
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: `Você é o assistente do TMX Digital. Usuário: ${user.nome} (${user.cargo}). Responda em português.` },
      { role: 'user', content: texto }
    ]
  };
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + aiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`OpenAI ${r.status}`);
  const data = await r.json();
  return data.choices[0].message.content;
}

// Define as ferramentas (tools) disponíveis pro agente
function _agentTools() {
  return [
    {
      name: 'listar_tarefas',
      description: 'Lista tarefas/demandas do usuário atual ou de toda a empresa. Use quando perguntarem sobre tarefas, demandas ou o que fazer.',
      input_schema: {
        type: 'object',
        properties: {
          escopo: { type: 'string', enum: ['minhas','empresa','atrasadas'], description: 'minhas=só do usuário; empresa=todas; atrasadas=vencidas' },
          limite: { type: 'number', description: 'Quantas retornar, default 10' }
        }
      }
    },
    {
      name: 'criar_demanda',
      description: 'Cria uma nova demanda no sistema. Aceita parsing de prazo natural como "sexta", "amanhã", "próxima semana".',
      input_schema: {
        type: 'object',
        required: ['nome'],
        properties: {
          nome: { type: 'string' },
          responsavel: { type: 'string', description: 'Nome do responsável (ex: "Ana", "Carlos"). O sistema acha por nome parcial.' },
          prazo: { type: 'string', description: 'Data YYYY-MM-DD ou expressão natural (sexta, amanhã, próxima semana, 5d)' },
          descricao: { type: 'string' },
          prioridade: { type: 'string', enum: ['ALTA','MEDIA','BAIXA'], description: 'Prioridade da demanda' },
          setor: { type: 'string', description: 'Setor/categoria (Copy, Edição, Tráfego, etc.)' }
        }
      }
    },
    {
      name: 'delegar_demanda',
      description: 'Adiciona ou troca o responsável de uma demanda existente. Use quando pedirem "delega #ID pra X" ou "atribui a Y a demanda Z".',
      input_schema: {
        type: 'object',
        required: ['demandaId','responsavel'],
        properties: {
          demandaId: { type: 'string', description: 'ID da demanda (pode vir com # ou DEM-)' },
          responsavel: { type: 'string', description: 'Nome do novo responsável' },
          adicionar: { type: 'boolean', description: 'true = adiciona como co-responsável; false = substitui' }
        }
      }
    },
    {
      name: 'concluir_demanda',
      description: 'Marca uma demanda como concluída. Use quando disserem "concluir #ID", "fecha #ID", "finalizei #ID".',
      input_schema: {
        type: 'object',
        required: ['demandaId'],
        properties: {
          demandaId: { type: 'string', description: 'ID da demanda' }
        }
      }
    },
    {
      name: 'comentar_demanda',
      description: 'Adiciona um comentário a uma demanda existente.',
      input_schema: {
        type: 'object',
        required: ['demandaId','comentario'],
        properties: {
          demandaId: { type: 'string', description: 'ID da demanda' },
          comentario: { type: 'string', description: 'Texto do comentário' }
        }
      }
    },
    {
      name: 'aprovar_candidato',
      description: 'Move um candidato de uma vaga pro próximo estágio do funil. Use quando disserem "aprova candidato X", "passa fulano pra próxima etapa".',
      input_schema: {
        type: 'object',
        required: ['candidato'],
        properties: {
          candidato: { type: 'string', description: 'Nome ou email do candidato' },
          vaga: { type: 'string', description: 'Nome da vaga (opcional, se o candidato estiver em várias)' },
          proximoEstagio: { type: 'string', enum: ['triagem','entrevista','teste','aprovado','reprovado'], description: 'Estágio destino. Se omitido, avança um estágio.' }
        }
      }
    },
    {
      name: 'relatorio_setor',
      description: 'Gera relatório de demandas de um setor específico (Copy, Edição, Tráfego, Spy, Infra) num período. Use pra "relatorio copy semana", "relatorio tráfego mes", etc.',
      input_schema: {
        type: 'object',
        properties: {
          setor: { type: 'string', description: 'Setor/cargo (Copy, Edição, Tráfego, Spy, Infra, RH) — opcional, se omitido pega geral' },
          periodo: { type: 'string', enum: ['hoje','semana','mes'], description: 'Período do relatório, default semana' }
        }
      }
    },
    {
      name: 'relatorio_vagas',
      description: 'Resumo do funil de recrutamento (vagas abertas, candidatos por estágio, novos esta semana).',
      input_schema: { type: 'object', properties: {} }
    },
    {
      name: 'resumo_roi',
      description: 'Resumo dos KPIs (ROAS, Lucro, Investimento) da semana',
      input_schema: { type: 'object', properties: {} }
    },
    {
      name: 'itens_em_risco',
      description: 'Lista demandas atrasadas, paradas ou criativos em revisão há muito tempo',
      input_schema: { type: 'object', properties: {} }
    }
  ];
}

// ─── COMANDOS SLASH (atalhos rápidos, não passam pela IA) ───
function _processarComandoSlash(text, user, db) {
  const t = text.trim();
  if (!t.startsWith('/')) return null; // só processa se começa com /

  const parts = t.slice(1).toLowerCase().split(/\s+/);
  const cmd = parts[0] || '';
  const args = parts.slice(1);

  // /help · /ajuda · /comandos
  if (cmd === 'help' || cmd === 'ajuda' || cmd === 'comandos') {
    return `🤖 *Comandos disponíveis*\n\n` +
      `📊 *Relatórios*\n` +
      `/relatorio — resumo geral agora\n` +
      `/relatorio copy — só do setor Copy\n` +
      `/relatorio edicao — só Edição\n` +
      `/relatorio trafego — só Tráfego\n` +
      `/relatorio spy — só Spy\n` +
      `/relatorio roi — performance financeira\n` +
      `/relatorio vagas — funil recrutamento\n` +
      `/relatorio semana — últimos 7d (em qualquer setor)\n` +
      `/relatorio mes — mês atual\n\n` +
      `📋 *Demandas*\n` +
      `/minhas — minhas demandas pendentes\n` +
      `/risco — demandas atrasadas\n` +
      `/concluir #ID — marca como pronta\n\n` +
      `💬 *Linguagem natural também funciona*\n` +
      `"cria demanda pra Ana revisar VSL até sexta"\n` +
      `"delega #123 pra Carlos"\n` +
      `"aprova candidato fulano"`;
  }

  // /relatorio [setor|tipo] [periodo]
  if (cmd === 'relatorio' || cmd === 'relatório') {
    let setor = null, periodo = 'semana', tipo = 'geral';
    args.forEach(a => {
      if (['hoje','dia','agora'].includes(a)) periodo = 'hoje';
      else if (['semana','sem','7d','7dias'].includes(a)) periodo = 'semana';
      else if (['mes','mês','mensal','30d'].includes(a)) periodo = 'mes';
      else if (a === 'roi') tipo = 'roi';
      else if (a === 'vagas') tipo = 'vagas';
      else if (['copy','edicao','edição','trafego','tráfego','spy','infra','rh','diretoria'].includes(a)) setor = a;
    });
    return _gerarRelatorioSlash(db, { setor, periodo, tipo, user });
  }

  // /minhas — minhas demandas
  if (cmd === 'minhas' || cmd === 'tarefas' || cmd === 'demandas') {
    const tasks = (db.store.tasks || []).filter(t => t && !t.arquivado && t.status !== 'CONCLUIDO' &&
      ((Array.isArray(t.respIds) && t.respIds.includes(user.id)) || t.respId === user.id));
    if (!tasks.length) return `✅ Sem tarefas pendentes pra você, ${user.nome}!`;
    return `📋 *Suas ${tasks.length} tarefa(s) pendente(s)*\n\n` +
      tasks.slice(0, 15).map((t, i) => `${i+1}. *${t.nome}*${t.data ? ` _(prazo ${t.data})_` : ''} _#${t.id}_`).join('\n');
  }

  // /risco · /atrasadas
  if (cmd === 'risco' || cmd === 'atrasadas' || cmd === 'atraso') {
    const hojeStr = new Date().toISOString().slice(0, 10);
    const tasks = (db.store.tasks || []).filter(t => t && !t.arquivado && t.status !== 'CONCLUIDO' && t.data && t.data < hojeStr);
    if (!tasks.length) return `✅ Nenhuma demanda em atraso! 🎉`;
    return `⚠️ *${tasks.length} demanda(s) em atraso*\n\n` +
      tasks.slice(0, 15).map((t, i) => {
        const dias = Math.floor((new Date(hojeStr) - new Date(t.data))/(86400000));
        return `${i+1}. *${t.nome}*\n   👤 ${t.resp || 'sem resp'} · ⏰ ${dias}d atrasado · _#${t.id}_`;
      }).join('\n\n');
  }

  // /concluir #ID
  if (cmd === 'concluir' || cmd === 'concluido' || cmd === 'fechar') {
    const idArg = (args[0] || '').replace(/[#a-zA-Z-]/g, '');
    if (!idArg) return '❌ Falta o ID. Use: `/concluir #123`';
    const idNum = Number(idArg);
    const task = (db.store.tasks || []).find(t => t.id == idArg || t.id === idNum);
    if (!task) return `❌ Demanda *#${idArg}* não encontrada.`;
    task.status = 'CONCLUIDO';
    task.concluidoEm = new Date().toISOString();
    task._updatedAt = Date.now();
    db.timestamps.tasks = now();
    writeDB(db);
    return `✅ *Concluído!*\n\n📋 ${task.nome}\n👤 ${task.resp || '—'}\n\nID: #${task.id}`;
  }

  return null; // não é comando slash conhecido
}

// Gera relatório formatado pro WhatsApp baseado em setor + período + tipo
function _gerarRelatorioSlash(db, { setor, periodo, tipo, user }) {
  const hoje = new Date(); hoje.setHours(23,59,59,999);
  const inicio = new Date(hoje);
  if (periodo === 'hoje') inicio.setHours(0,0,0,0);
  else if (periodo === 'semana') inicio.setDate(hoje.getDate() - 7);
  else if (periodo === 'mes') inicio.setMonth(hoje.getMonth() - 1);
  const inicioStr = inicio.toISOString().slice(0,10);
  const hojeStr = new Date().toISOString().slice(0,10);
  const periodoLabel = { hoje:'hoje', semana:'últimos 7 dias', mes:'últimos 30 dias' }[periodo] || '';

  // Relatório ROI
  if (tipo === 'roi') {
    const rels = db.store['sl_relatorios_semanais'] || [];
    if (!rels.length) {
      try {
        const r = _gerarRelatorioSemanal(true);
        if (r.ok) return _fmtRelatorioROI(r.relatorio);
      } catch (e) {}
      return '📊 Ainda sem dados de ROI. Cadastre métricas pra começar.';
    }
    return _fmtRelatorioROI(rels[0]);
  }

  // Relatório Vagas
  if (tipo === 'vagas') {
    const vagas = (db.store['sl_vagas'] || []).filter(v => v.ativa !== false);
    const candidatos = db.store['sl_candidatos'] || [];
    const novosSem = candidatos.filter(c => c._criadoEm && c._criadoEm >= inicio.toISOString()).length;
    const porEstagio = {};
    candidatos.forEach(c => { porEstagio[c.estagio || 'triagem'] = (porEstagio[c.estagio || 'triagem']||0) + 1; });
    return `📲 *Vagas · ${periodoLabel}*\n\n` +
      `🎯 Vagas ativas: ${vagas.length}\n` +
      `👥 Candidatos totais: ${candidatos.length}\n` +
      `🆕 Novos ${periodoLabel}: ${novosSem}\n\n` +
      `📊 *Por estágio:*\n` +
      Object.entries(porEstagio).map(([est, qt]) => `• ${est}: ${qt}`).join('\n');
  }

  // Relatório de SETOR ou GERAL
  let tasks = (db.store.tasks || []).filter(t => t && !t.arquivado);
  const usuarios = db.store['sl_usuarios'] || [];

  // Filtra por setor (matcha responsáveis com cargo X)
  if (setor) {
    const setorNorm = setor.toLowerCase().replace(/[áàâã]/g,'a').replace(/[éê]/g,'e');
    const cargoMap = { copy:'Copy', edicao:'Editor', trafego:'Gestor de Tráfego', spy:'Spy', infra:'Infra', rh:'Diretoria', diretoria:'Diretoria' };
    const cargoAlvo = cargoMap[setorNorm];
    if (cargoAlvo) {
      const userIdsSetor = new Set(usuarios.filter(u => u.cargo === cargoAlvo).map(u => u.id));
      tasks = tasks.filter(t => {
        if (Array.isArray(t.respIds) && t.respIds.some(id => userIdsSetor.has(id))) return true;
        if (t.respId && userIdsSetor.has(t.respId)) return true;
        return false;
      });
    }
  }

  // Filtra por período (data criação ou prazo)
  const tasksPeriodo = tasks.filter(t => {
    if (t.data && t.data >= inicioStr) return true;
    if (t._updatedAt && new Date(t._updatedAt) >= inicio) return true;
    return false;
  });

  const concluidas = tasksPeriodo.filter(t => t.status === 'CONCLUIDO');
  const pendentes = tasksPeriodo.filter(t => t.status !== 'CONCLUIDO');
  const atrasadas = pendentes.filter(t => t.data && t.data < hojeStr);

  // Top responsáveis
  const porResp = {};
  tasksPeriodo.forEach(t => {
    const r = t.resp || '—';
    porResp[r] = (porResp[r]||0) + 1;
  });
  const topResp = Object.entries(porResp).sort((a,b) => b[1]-a[1]).slice(0,5);

  // Tempo médio (em dias) das concluídas
  let tempoMedio = '—';
  if (concluidas.length) {
    const dias = concluidas.map(t => {
      if (!t.concluidoEm || !t._updatedAt) return null;
      const cri = new Date(t._updatedAt);
      const fim = new Date(t.concluidoEm);
      return (fim - cri) / 86400000;
    }).filter(Boolean);
    if (dias.length) tempoMedio = (dias.reduce((a,b)=>a+b,0)/dias.length).toFixed(1) + 'd';
  }

  const titulo = setor ? `Setor ${setor.toUpperCase()} · ${periodoLabel}` : `Geral · ${periodoLabel}`;
  return `📊 *${titulo}*\n\n` +
    `📝 Demandas: ${tasksPeriodo.length} (${atrasadas.length} atrasadas)\n` +
    `✅ Concluídas: ${concluidas.length}\n` +
    `⏳ Pendentes: ${pendentes.length}\n` +
    `⏱️ Tempo médio: ${tempoMedio}\n\n` +
    (topResp.length ? `👥 *Top responsáveis:*\n` + topResp.map(([n,q]) => `• ${n} (${q})`).join('\n') : '');
}

function _fmtRelatorioROI(rel) {
  const k = rel.kpis || {};
  return `💰 *ROI · ${rel.periodo_ini || ''} a ${rel.periodo_fim || ''}*\n\n` +
    `💸 Investido: R$ ${Math.round(k.investimento || 0).toLocaleString('pt-BR')}\n` +
    `💵 Faturamento: R$ ${Math.round(k.retorno || 0).toLocaleString('pt-BR')}\n` +
    `💰 Lucro: R$ ${Math.round(k.lucro || 0).toLocaleString('pt-BR')}\n` +
    `📈 ROAS: ${(k.roas || 0).toFixed(2).replace('.',',')}x\n\n` +
    `✅ ${rel.demandas?.concluidas || 0} demandas concluídas · ⚠ ${rel.demandas?.atrasadas || 0} atrasadas`;
}

// Executa uma tool e retorna o resultado
async function _executarTool(name, input, user) {
  const db = readDB();
  try {
    if (name === 'listar_tarefas') {
      const escopo = input.escopo || 'minhas';
      const limite = input.limite || 10;
      let ts = (db.store.tasks || []).filter(t => t && !t.arquivado && t.status !== 'CONCLUIDO');
      const hojeStr = new Date().toISOString().slice(0, 10);
      if (escopo === 'minhas') {
        ts = ts.filter(t => (Array.isArray(t.respIds) && t.respIds.includes(user.id)) || t.respId === user.id);
      } else if (escopo === 'atrasadas') {
        ts = ts.filter(t => t.data && t.data < hojeStr);
      }
      return ts.slice(0, limite).map(t => ({
        id: t.id, nome: t.nome, status: t.status, prazo: t.data || null, responsavel: t.resp || null
      }));
    }
    if (name === 'criar_demanda') {
      if (!input.nome) return { erro: 'nome é obrigatório' };
      // Encontra responsável por nome
      let respId = null, respNome = '';
      if (input.responsavel) {
        const u = (db.store['sl_usuarios'] || []).find(x =>
          x && x.nome && x.nome.toLowerCase().includes(input.responsavel.toLowerCase()) && x.ativo !== false);
        if (u) { respId = u.id; respNome = u.nome; }
      }
      const nova = {
        id: Date.now(),
        nome: input.nome,
        status: 'BACKLOG',
        resp: respNome,
        respId,
        respIds: respId ? [respId] : [],
        data: input.prazo || '',
        desc: input.descricao || '',
        criado: new Date().toLocaleString('pt-BR'),
        arquivado: false,
        cmts: [],
        _updatedAt: Date.now()
      };
      if (!db.store.tasks) db.store.tasks = [];
      db.store.tasks.push(nova);
      db.timestamps.tasks = now();
      writeDB(db);
      return { ok: true, id: nova.id, mensagem: `Demanda "${nova.nome}" criada com sucesso${respNome ? ' e atribuída a '+respNome : ''}.` };
    }
    if (name === 'resumo_roi') {
      const rels = db.store['sl_relatorios_semanais'] || [];
      if (!rels.length) {
        // Calcula on-the-fly
        const r = _gerarRelatorioSemanal(true);
        if (r.ok) return r.relatorio.kpis;
        return { erro: 'sem dados de ROI ainda' };
      }
      return rels[0].kpis;
    }
    if (name === 'itens_em_risco') {
      const hojeStr = new Date().toISOString().slice(0, 10);
      const tasks = (db.store.tasks || []).filter(t => t && !t.arquivado);
      const atrasadas = tasks.filter(t => t.status !== 'CONCLUIDO' && t.data && t.data < hojeStr);
      return {
        atrasadas: atrasadas.length,
        lista: atrasadas.slice(0, 10).map(t => ({
          id: t.id, nome: t.nome, responsavel: t.resp,
          dias_atraso: Math.floor((new Date(hojeStr).getTime() - new Date(t.data).getTime())/(24*60*60*1000))
        }))
      };
    }

    // ── DELEGAR DEMANDA ──
    if (name === 'delegar_demanda') {
      const id = String(input.demandaId || '').replace(/[#a-zA-Z-]/g, '');
      if (!id) return { erro: 'demandaId é obrigatório' };
      const task = (db.store.tasks || []).find(t => t.id == id);
      if (!task) return { erro: `Demanda #${id} não encontrada` };
      const novoResp = (db.store['sl_usuarios'] || []).find(x =>
        x && x.nome && x.nome.toLowerCase().includes(String(input.responsavel || '').toLowerCase()) && x.ativo !== false);
      if (!novoResp) return { erro: `Usuário "${input.responsavel}" não encontrado` };

      if (input.adicionar) {
        if (!Array.isArray(task.respIds)) task.respIds = task.respId ? [task.respId] : [];
        if (!task.respIds.includes(novoResp.id)) task.respIds.push(novoResp.id);
        task.resp = (task.resp ? task.resp + ', ' : '') + novoResp.nome;
      } else {
        task.respId = novoResp.id;
        task.respIds = [novoResp.id];
        task.resp = novoResp.nome;
      }
      task._updatedAt = Date.now();
      db.timestamps.tasks = now();
      writeDB(db);
      // Notifica o novo responsável via WhatsApp
      if (novoResp.whatsapp) {
        sendWhatsAppMessage(novoResp.whatsapp, `📋 *Nova demanda atribuída*\n\n*${task.nome}*${task.data ? `\n📅 Prazo: ${task.data}` : ''}\n\n_#${task.id}_`).catch(()=>{});
      }
      return { ok: true, demanda: task.nome, novoResponsavel: novoResp.nome, modo: input.adicionar ? 'co-responsavel' : 'substituiu' };
    }

    // ── CONCLUIR DEMANDA ──
    if (name === 'concluir_demanda') {
      const id = String(input.demandaId || '').replace(/[#a-zA-Z-]/g, '');
      if (!id) return { erro: 'demandaId é obrigatório' };
      const task = (db.store.tasks || []).find(t => t.id == id);
      if (!task) return { erro: `Demanda #${id} não encontrada` };
      task.status = 'CONCLUIDO';
      task.concluidoEm = new Date().toISOString();
      task._updatedAt = Date.now();
      db.timestamps.tasks = now();
      writeDB(db);
      return { ok: true, demanda: task.nome, id: task.id };
    }

    // ── COMENTAR DEMANDA ──
    if (name === 'comentar_demanda') {
      const id = String(input.demandaId || '').replace(/[#a-zA-Z-]/g, '');
      if (!id) return { erro: 'demandaId é obrigatório' };
      const task = (db.store.tasks || []).find(t => t.id == id);
      if (!task) return { erro: `Demanda #${id} não encontrada` };
      if (!Array.isArray(task.cmts)) task.cmts = [];
      task.cmts.push({
        texto: input.comentario,
        autor: user.nome,
        autorId: user.id,
        data: new Date().toISOString()
      });
      task._updatedAt = Date.now();
      db.timestamps.tasks = now();
      writeDB(db);
      return { ok: true, demanda: task.nome, totalComentarios: task.cmts.length };
    }

    // ── APROVAR CANDIDATO ──
    if (name === 'aprovar_candidato') {
      const candidatos = db.store['sl_candidatos'] || [];
      const busca = String(input.candidato || '').toLowerCase();
      let candidato = candidatos.find(c =>
        (c.nome && c.nome.toLowerCase().includes(busca)) ||
        (c.email && c.email.toLowerCase().includes(busca))
      );
      if (!candidato) return { erro: `Candidato "${input.candidato}" não encontrado` };

      const estagios = ['triagem', 'entrevista', 'teste', 'aprovado', 'reprovado'];
      const estagioAtual = candidato.estagio || 'triagem';
      const idxAtual = estagios.indexOf(estagioAtual);
      let novoEstagio;
      if (input.proximoEstagio) {
        novoEstagio = input.proximoEstagio;
      } else {
        novoEstagio = estagios[Math.min(idxAtual + 1, estagios.length - 1)];
      }
      candidato.estagio = novoEstagio;
      candidato._updatedAt = Date.now();
      db.timestamps['sl_candidatos'] = now();
      writeDB(db);
      return { ok: true, candidato: candidato.nome, de: estagioAtual, para: novoEstagio };
    }

    // ── RELATÓRIO POR SETOR ──
    if (name === 'relatorio_setor') {
      const setor = input.setor || null;
      const periodo = input.periodo || 'semana';
      const texto = _gerarRelatorioSlash(db, { setor, periodo, tipo: 'geral', user });
      return { relatorio: texto };
    }

    // ── RELATÓRIO VAGAS ──
    if (name === 'relatorio_vagas') {
      const texto = _gerarRelatorioSlash(db, { periodo: 'semana', tipo: 'vagas', user });
      return { relatorio: texto };
    }

    return { erro: 'tool desconhecida: ' + name };
  } catch (e) {
    return { erro: e.message };
  }
}

// Helper para notificar via WhatsApp quando addNotif é chamado (integração com fluxo interno)
async function _notificarViaWhatsApp(destId, titulo, texto) {
  try {
    const db = readDB();
    const cfg = db.store['sl_whatsapp_config'] || {};
    if (!cfg.ativo) return;
    const u = (db.store['sl_usuarios'] || []).find(x => x.id === destId);
    if (!u || !u.whatsapp) return;
    const mensagem = `*${titulo}*\n\n${texto}\n\n_Axcend_`;
    await sendWhatsAppMessage(u.whatsapp, mensagem);
  } catch (e) { console.error('[WA notif]', e.message); }
}

// Endpoint: dispara notificação manual pra WhatsApp (usado internamente quando cria notif)
app.post('/api/whatsapp/notificar', async (req, res) => {
  const { destId, titulo, texto } = req.body || {};
  if (!destId || !texto) return res.status(400).json({ error: 'destId + texto obrigatórios' });
  await _notificarViaWhatsApp(destId, titulo || 'Notificação TMX Digital', texto);
  res.json({ ok: true });
});
setTimeout(_tickBackupRemoto, 2*60*1000);   // primeira tentativa 2min após boot

// POST /api/backup/remoto — força push manual
app.post('/api/backup/remoto', authDiretoria, async (req, res) => {
  const r = await pushBackupToGitHub('manual');
  if (!r.ok) return res.status(500).json(r);
  res.json(r);
});

// GET /api/backup/remoto/status — status do último push
app.get('/api/backup/remoto/status', authDiretoria, (req, res) => {
  const config = !!(process.env.GITHUB_BACKUP_TOKEN && process.env.GITHUB_BACKUP_REPO);
  let ultimo = null;
  try {
    const marker = JSON.parse(fs.readFileSync(REMOTE_BACKUP_MARKER, 'utf8'));
    if (marker && marker.ts) {
      const horasAtras = (Date.now() - marker.ts) / (60*60*1000);
      ultimo = {
        ts: marker.ts,
        iso: new Date(marker.ts).toISOString(),
        fmt: new Date(marker.ts).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
        arquivo: marker.arquivo,
        horasAtras: Math.round(horasAtras*10)/10,
        diasAtras: Math.round(horasAtras/24*10)/10
      };
    }
  } catch {}
  res.json({
    configurado: config,
    repo: process.env.GITHUB_BACKUP_REPO || null,
    ultimo
  });
});

// GET /api/backup/list — lista snapshots disponíveis (classificados por período)
app.get('/api/backup/list', authDiretoria, (req, res) => {
  try {
    const agora = new Date();
    const lista = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.endsWith('.json') || f.endsWith('.json.gz'))
      .map(f => {
        const st = fs.statSync(path.join(BACKUP_DIR, f));
        const data = _parseStamp(f) || st.mtime;
        const horasAtras = (agora - data) / (60*60*1000);
        let periodo;
        if (horasAtras < 24) periodo = 'hoje';
        else if (horasAtras < 48) periodo = 'ontem';
        else if (horasAtras < 7*24) periodo = 'esta_semana';
        else if (horasAtras < 30*24) periodo = 'este_mes';
        else if (horasAtras < 90*24) periodo = 'ultimos_3_meses';
        else if (horasAtras < 365*24) periodo = 'este_ano';
        else periodo = 'arquivo_historico';
        return {
          nome: f,
          tamanho: st.size,
          tamanhoFmt: (st.size/1024).toFixed(1) + ' KB',
          criado: data.toISOString(),
          criadoFmt: data.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
          periodo,
          horasAtras: Math.round(horasAtras)
        };
      })
      .sort((a,b) => new Date(b.criado) - new Date(a.criado));
    // Agrupa por período pra UI
    const grupos = {};
    lista.forEach(b => {
      if (!grupos[b.periodo]) grupos[b.periodo] = [];
      grupos[b.periodo].push(b);
    });
    res.json({
      total: lista.length,
      backups: lista,
      grupos,
      retencao: { horas: RET_HOURS, dias: RET_DAYS, semanas: RET_WEEKS, mensal: 'para sempre' }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/backup/download — baixa o db atual (sem salvar snapshot)
// Passa credenciais via headers x-user-email / x-user-senha
app.get('/api/backup/download', authDiretoria, (req, res) => {
  try {
    const conteudo = fs.readFileSync(DB_FILE, 'utf8');
    const stamp = new Date().toISOString().replace(/[:.]/g,'-').split('T').join('_').slice(0,19);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="scalelab-backup-${stamp}.json"`);
    res.send(conteudo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/backup/download/:nome — baixa um snapshot específico
app.get('/api/backup/download/:nome', authDiretoria, (req, res) => {
  const nome = req.params.nome.replace(/[^\w.-]/g,'');
  const fpath = path.join(BACKUP_DIR, nome);
  if (!fs.existsSync(fpath)) return res.status(404).json({ error: 'Backup não encontrado.' });
  // Descomprime na saida: quem baixa recebe JSON pronto pra usar/restaurar.
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${nome.replace(/\.gz$/, '')}"`);
  try { res.send(_lerSnapshot(fpath)); }
  catch (e) { res.status(500).json({ error: 'Não consegui ler o backup: ' + e.message }); }
});

// POST /api/backup/snapshot — força um snapshot agora
app.post('/api/backup/snapshot', authDiretoria, (req, res) => {
  const r = criarSnapshotBackup('manual');
  if (!r.ok) return res.status(500).json({ error: r.erro });
  res.json(r);
});

// POST /api/backup/restore — restaura a partir de JSON enviado (DESTRUTIVO)
// Salva snapshot atual antes de substituir
app.post('/api/backup/restore', authDiretoria, (req, res) => {
  const { dados, confirmar } = req.body || {};
  if (confirmar !== 'SIM_SUBSTITUIR_BANCO') {
    return res.status(400).json({ error: 'É necessário passar confirmar: "SIM_SUBSTITUIR_BANCO" no body.' });
  }
  if (!dados || typeof dados !== 'object') {
    return res.status(400).json({ error: 'Campo "dados" ausente ou inválido (precisa ser o objeto do db).' });
  }
  if (!dados.store || typeof dados.store !== 'object') {
    return res.status(400).json({ error: 'JSON inválido — falta a chave "store".' });
  }
  try {
    // Snapshot de segurança ANTES de substituir
    criarSnapshotBackup('pre-restore');
    // Escreve novo db
    _gravarDbTexto(JSON.stringify(dados, null, 2));
    // Audit (nota: logs do novo db serão no novo db)
    try { const ndb = readDB(); audit(ndb, 'backup_restore_upload', null, { tamanho: JSON.stringify(dados).length }, { id: req.user.id, nome: req.user.nome, cargo: req.user.cargo }); writeDB(ndb); } catch {}
    console.log(`[BACKUP] ${req.user.nome} restaurou o banco a partir de upload.`);
    res.json({ ok: true, message: 'Banco restaurado. Snapshot de segurança foi criado antes da substituição.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/backup/restore/:nome — restaura a partir de um snapshot existente
app.post('/api/backup/restore/:nome', authDiretoria, (req, res) => {
  const { confirmar } = req.body || {};
  if (confirmar !== 'SIM_SUBSTITUIR_BANCO') {
    return res.status(400).json({ error: 'É necessário passar confirmar: "SIM_SUBSTITUIR_BANCO" no body.' });
  }
  const nome = req.params.nome.replace(/[^\w.-]/g,'');
  const fpath = path.join(BACKUP_DIR, nome);
  if (!fs.existsSync(fpath)) return res.status(404).json({ error: 'Backup não encontrado.' });
  try {
    criarSnapshotBackup('pre-restore');
    const conteudo = _lerSnapshot(fpath);
    JSON.parse(conteudo);          // nao restaura arquivo quebrado
    _gravarDbTexto(conteudo);
    try { const ndb = readDB(); audit(ndb, 'backup_restore_snap', { snapshot: nome }, null, { id: req.user.id, nome: req.user.nome, cargo: req.user.cargo }); writeDB(ndb); } catch {}
    console.log(`[BACKUP] ${req.user.nome} restaurou a partir de ${nome}.`);
    res.json({ ok: true, message: `Banco restaurado de ${nome}.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── INICIA ──
// ══════════════════════════════════════════════
// ── VTURB (Analytics da VSL) ──
// ══════════════════════════════════════════════
// Doc: https://vturb.gitbook.io/analytics-api
// Autenticacao por dois headers; quase tudo e POST, menos players/list e quota.
const VTURB_URL = 'https://analytics.vturb.net';
const KEY_VTURB = 'sl_vturb';

function _vturbCfg(db) {
  const c = (db || readDB()).store[KEY_VTURB];
  const cfg = (c && typeof c === 'object') ? c : null;
  const doEnv = process.env.VTURB_API_TOKEN;
  if (doEnv && String(doEnv).trim()) {
    return Object.assign({}, cfg || { criadoEm: new Date().toISOString() },
      { token: String(doEnv).trim(), origemToken: 'env' });
  }
  return cfg;
}

// Se a VTurb reclamar da data, repete com o outro formato documentado — e GUARDA
// qual funcionou. Sem isso, com o formato errado toda chamada viraria duas, e o
// painel (uma por VSL) demoraria o dobro.
let _vturbFormato = null;      // null = ainda nao sei | 'utc' | 'iso'
async function _vturbApiData(token, caminho, corpo, per) {
  const comISO = () => Object.assign({}, corpo, { start_date: per.ini2, end_date: per.fim2 });
  if (_vturbFormato === 'iso') return await _vturbApi(token, caminho, comISO());
  try {
    const r = await _vturbApi(token, caminho, corpo);
    _vturbFormato = 'utc';
    return r;
  } catch (e) {
    if (!per || !/valid datetime|Start date|End date/i.test(e.message || '')) throw e;
    const r = await _vturbApi(token, caminho, comISO());
    _vturbFormato = 'iso';
    return r;
  }
}

async function _vturbApi(token, caminho, corpo, metodo) {
  const r = await fetch(VTURB_URL + caminho, {
    method: metodo || (corpo ? 'POST' : 'GET'),
    headers: { 'X-Api-Token': token, 'X-Api-Version': 'v1',
               'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: corpo ? JSON.stringify(corpo) : undefined
  });
  const txt = await r.text();
  let dados = null;
  try { dados = JSON.parse(txt); } catch (e) {}
  if (!r.ok) {
    const motivo = (dados && (dados.message || dados.error)) || txt.slice(0, 160);
    if (r.status === 401 || r.status === 403) {
      throw new Error('A VTurb recusou o token. Confira em app.vturb.com › Configurações › Analytics API.');
    }
    if (r.status === 429) throw new Error('Limite de requisições da VTurb atingido. Tente de novo em um minuto.');
    throw new Error('VTurb respondeu ' + r.status + ': ' + motivo);
  }
  return dados;
}

// Lista as VSLs da conta — evita ter que catar player_id na mão
async function _vturbPlayers(token) {
  const d = await _vturbApi(token, '/players/list', null, 'GET');
  const bruto = Array.isArray(d) ? d : (d && (d.players || d.data || d.results)) || [];
  // A VTurb organiza os videos em pastas (Concurso Kalebe, RENDA EXTRA...).
  // O nome do campo nao esta documentado, entao aceita as variacoes comuns.
  const pastaDe = x => x.folder_name || x.folderName || x.folder || x.directory ||
                       x.parent_name || (x.parent && (x.parent.name || x.parent)) || '';
  return bruto.map(x => ({
    id: x.id || x.player_id, nome: x.name || x.nome || '(sem nome)',
    // O nome do campo da duracao nao esta documentado e ja veio de formas
    // diferentes; aceitar as variacoes evita o "Video duration must be a
    // positive integer" que a VTurb devolve quando mandamos zero.
    duracao: Number(x.duration || x.video_duration || x.duration_in_seconds ||
                    x.durationSeconds || x.length || x.seconds) || 0,
    pitch: Number(x.pitch_time || x.pitchTime) || 0,
    pasta: String(pastaDe(x) || ''),
    criadoEm: x.created_at || null
  })).filter(x => x.id);
}

// A VTurb recusou "2026-08-07T00:00:00.000-03:00" com "Start date must be a valid
// datetime with hours, minutes, and seconds". A doc lista duas formas; a que ela
// aceita e "AAAA-MM-DD HH:MM:SS UTC". Convertemos o dia em Sao Paulo pra UTC.
function _vturbInstante(dia, fimDoDia) {
  const base = new Date(dia + (fimDoDia ? 'T23:59:59-03:00' : 'T00:00:00-03:00'));
  const iso = base.toISOString();                    // 2026-08-07T03:00:00.000Z
  return iso.slice(0, 10) + ' ' + iso.slice(11, 19) + ' UTC';
}
// formato alternativo, usado se a primeira forma for recusada
function _vturbInstanteISO(dia, fimDoDia) {
  const base = new Date(dia + (fimDoDia ? 'T23:59:59-03:00' : 'T00:00:00-03:00'));
  return base.toISOString().replace('Z', '+00:00');
}
function _vturbPeriodo(req) {
  const hoje = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
  const de  = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.de  || '')) ? req.query.de  : hoje;
  const ate = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.ate || '')) ? req.query.ate : hoje;
  return { de, ate,
           ini: _vturbInstante(de, false),  fim: _vturbInstante(ate, true),
           ini2:_vturbInstanteISO(de,false), fim2:_vturbInstanteISO(ate,true) };
}
function _vturbExige() {
  const cfg = _vturbCfg();
  if (!cfg || !cfg.token) throw new Error('VTurb ainda não conectada. Cole o token em Integrações.');
  return cfg;
}

// ── configuracao ──
app.get('/api/integracoes/vturb/me', authDiretoria, (req, res) => {
  const cfg = _vturbCfg() || {};
  res.json({ ok: true, conectado: !!cfg.token, origemToken: cfg.origemToken || 'tela',
             players: cfg.players || [], ultimoErro: cfg.ultimoErro || null,
             validadoEm: cfg.validadoEm || null });
});

app.post('/api/integracoes/vturb/config', authDiretoria, async (req, res) => {
  try {
    const token = String((req.body && req.body.token) || '').trim();
    if (!token) return res.status(400).json({ error: 'Informe o token da VTurb.' });
    // Valida antes de salvar: token que nao lista player nao serve pra nada,
    // e salvar assim mesmo faria a tela mentir que esta conectada.
    let players;
    try { players = await _vturbPlayers(token); }
    catch (e) { return res.status(400).json({ error: e.message }); }

    const db = readDB();
    const cfg = _vturbCfg(db) || { criadoEm: new Date().toISOString() };
    cfg.token = token; cfg.players = players; cfg.ultimoErro = null;
    cfg.validadoEm = new Date().toISOString(); cfg._updatedAt = Date.now();
    db.store[KEY_VTURB] = cfg;
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_VTURB] = now();
    audit(db, 'integracao.vturb.config', KEY_VTURB, { players: players.length }, req.user);
    writeDB(db);
    res.json({ ok: true, players });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/vturb/players', authUsuario, async (req, res) => {
  try {
    const cfg = _vturbExige();
    const players = await _vturbPlayers(cfg.token);
    res.json({ ok: true, players });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── curva de retenção da VSL ──
app.get('/api/vturb/retencao', authUsuario, async (req, res) => {
  try {
    const cfg = _vturbExige();
    const per = _vturbPeriodo(req); const de = per.de, ate = per.ate;
    const player = String(req.query.player || '');
    if (!player) return res.status(400).json({ error: 'Informe o player.' });
    const meta = (cfg.players || []).find(p => String(p.id) === player) || {};
    const dur = Number(req.query.duracao) || meta.duracao || 0;
    const base = { player_id: player, start_date: per.ini, end_date: per.fim, timezone: 'America/Sao_Paulo' };

    const [eng, conv, ses] = await Promise.all([
      _vturbApiData(cfg.token, '/times/user_engagement', Object.assign({ video_duration: dur }, base), per).catch(e => ({ _erro: e.message })),
      _vturbApiData(cfg.token, '/conversions/video_timed', base, per).catch(e => ({ _erro: e.message })),
      _vturbApiData(cfg.token, '/sessions/stats', Object.assign({ video_duration: dur, pitch_time: meta.pitch || 0 }, base), per).catch(e => ({ _erro: e.message }))
    ]);
    res.json({ ok: true, player, nome: meta.nome || '', duracao: dur, pitch: meta.pitch || 0,
               de, ate, engajamento: eng, conversoesNoVideo: conv, sessoes: ses });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── retenção separada por origem do tráfego = por criativo ──
// (as UTMs levam o nome do anúncio, então dá pra ver qual criativo segura mais)
app.get('/api/vturb/retencao-por-origem', authUsuario, async (req, res) => {
  try {
    const cfg = _vturbExige();
    const per = _vturbPeriodo(req);
    const player = String(req.query.player || '');
    if (!player) return res.status(400).json({ error: 'Informe o player.' });
    const meta = (cfg.players || []).find(p => String(p.id) === player) || {};
    // utm_content carrega o nome do anuncio nas campanhas daqui — por isso e o
    // padrao: agrupar por ele e comparar retencao POR CRIATIVO.
    const chave = String(req.query.chave || 'utm_content');

    // A rota exige a lista de valores a comparar; descobre quais existem no periodo.
    let valores = String(req.query.valores || '').split(',').map(v => v.trim()).filter(Boolean);
    let disponiveis = [];
    try {
      const vu = await _vturbApiData(cfg.token, '/traffic_origin/valid_utms', {
        player_id: player, start_date: per.ini, end_date: per.fim, timezone: 'America/Sao_Paulo'
      }, per);
      const bruto = (vu && (vu[chave] || vu.data || vu.utms || vu)) || [];
      disponiveis = (Array.isArray(bruto) ? bruto : [])
        .map(x => (typeof x === 'string') ? x : (x && (x.value || x.name || x[chave])))
        .filter(Boolean);
    } catch (e) { disponiveis = []; }
    if (!valores.length) valores = disponiveis.slice(0, 12);   // teto: a resposta cresce rapido
    if (!valores.length) {
      return res.json({ ok: true, player, nome: meta.nome || '', de: per.de, ate: per.ate,
        chave, valores: [], disponiveis, origens: { data: [] },
        aviso: 'Nenhuma origem identificada no período — confira se as UTMs estão chegando na página da VSL.' });
    }
    const d = await _vturbApiData(cfg.token, '/times/user_engagement_by_traffic_origin', {
      player_id: player, query_key: chave, values: valores,
      start_date: per.ini, end_date: per.fim, timezone: 'America/Sao_Paulo'
    }, per);
    res.json({ ok: true, player, nome: meta.nome || '', de: per.de, ate: per.ate,
               chave, valores, disponiveis, duracao: meta.duracao || 0, pitch: meta.pitch || 0, origens: d });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── retenção separada por um campo (dispositivo, país, navegador, utm) ──
// A rota da VTurb exige a lista de valores a comparar, entao pra device_type
// mandamos os tres conhecidos; pros utm_* descobrimos os que existem no periodo.
app.get('/api/vturb/por-campo', authUsuario, async (req, res) => {
  try {
    const cfg = _vturbExige();
    const per = _vturbPeriodo(req);
    const player = String(req.query.player || '');
    if (!player) return res.status(400).json({ error: 'Informe o player.' });
    const campo = String(req.query.campo || 'device_type');
    const permitidos = ['country','browser','device_type','utm_campain','utm_source',
                        'utm_medium','utm_content','utm_term'];
    if (permitidos.indexOf(campo) < 0) return res.status(400).json({ error: 'Campo não suportado.' });

    const chave = 'vturb-campo|' + player + '|' + campo + '|' + per.de + '|' + per.ate;
    const pronto = _vivoGet(chave, 120 * 1000);
    if (pronto) return res.json(Object.assign({ doCache: true }, pronto));

    let valores = String(req.query.valores || '').split(',').map(v => v.trim()).filter(Boolean);
    if (!valores.length) {
      if (campo === 'device_type') valores = ['mobile', 'desktop', 'tablet'];
      else if (campo === 'browser') valores = ['Chrome', 'Safari', 'Firefox', 'Edge'];
      else {
        try {
          const vu = await _vturbApiData(cfg.token, '/traffic_origin/valid_utms', {
            player_id: player, start_date: per.ini, end_date: per.fim, timezone: 'America/Sao_Paulo'
          }, per);
          const bruto = (vu && (vu[campo] || vu.data || vu.utms)) || [];
          valores = (Array.isArray(bruto) ? bruto : [])
            .map(x => (typeof x === 'string') ? x : (x && (x.value || x.name)))
            .filter(Boolean).slice(0, 10);
        } catch (e) { valores = []; }
      }
    }
    if (!valores.length) return res.json({ ok: true, player, campo, grupos: [],
      aviso: 'Nenhum valor encontrado para esse campo no período.' });

    const meta = (cfg.players || []).find(p => String(p.id) === player) || {};
    const d = await _vturbApiData(cfg.token, '/times/user_engagement_by_field', {
      player_id: player, field: campo, values: valores,
      video_duration: Number(req.query.duracao) || meta.duracao || 0,
      start_date: per.ini, end_date: per.fim, timezone: 'America/Sao_Paulo'
    }, per);

    const bruto = (d && (d.data || d)) || [];
    const grupos = (Array.isArray(bruto) ? bruto : []).map(g => ({
      nome: g.group_key || '(sem valor)',
      pontos: (g.group_values || []).map(x => ({ timed: x.timed, total_users: x.total_users }))
    })).filter(g => g.pontos.length);
    const saida = { ok: true, player, campo, valores, de: per.de, ate: per.ate, grupos };
    _vivoSet(chave, saida);
    res.json(saida);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── painel: uma linha por VSL, numa chamada só ──
// A tela precisa de todas as VSLs de uma vez; sem isso seriam N requisições do
// navegador e a página abriria devagar.
app.get('/api/vturb/painel', authUsuario, async (req, res) => {
  try {
    const cfg = _vturbExige();
    const per = _vturbPeriodo(req);
    const chave = 'vturb-painel|' + per.de + '|' + per.ate + '|' + String(req.query.players || '');
    const pronto = _vivoGet(chave, 120 * 1000);
    if (pronto) return res.json(Object.assign({ doCache: true }, pronto));

    // Lista SEMPRE fresca: usar o cache da configuracao escondia videos criados
    // depois que o token foi salvo.
    let todos = await _vturbPlayers(cfg.token).catch(() => (cfg.players || []));
    // mais novos primeiro — video recem-subido costuma ser o que esta no ar
    todos = todos.slice().sort((a, b) =>
      String(b.criadoEm || '').localeCompare(String(a.criadoEm || '')));

    // A lista completa vai inteira pra tela (e o que povoa o "VSLs rodando").
    // Consulta de metrica, que e uma chamada por video, so nas escolhidas.
    const pedidos = String(req.query.players || '').split(',').map(x => x.trim()).filter(Boolean);
    let players = pedidos.length
      ? todos.filter(p => pedidos.indexOf(String(p.id)) >= 0)
      : todos.slice(0, 8);                   // 1o acesso: as 8 mais recentes
    const limitado = !pedidos.length && todos.length > 8;

    const linhas = [], erros = [];
    // Em fila, 12 VSLs viravam 12 idas e voltas e a tela ficava ~20s carregando.
    // De 4 em 4 fica rapido e ainda cabe folgado no limite de requisicoes da VTurb.
    async function buscar(p) {
      try {
        const st = await _vturbApiData(cfg.token, '/sessions/stats', {
          player_id: p.id, start_date: per.ini, end_date: per.fim,
          video_duration: p.duracao || 0, pitch_time: p.pitch || 0,
          timezone: 'America/Sao_Paulo'
        }, per);
        const cent = v => (Number(v) || 0) / 100;
        linhas.push({
          id: p.id, nome: p.nome, duracao: p.duracao, pitch: p.pitch, pasta: p.pasta || '',
          viram:      Number(st.total_viewed_device_uniq || st.total_viewed) || 0,
          play:       Number(st.total_started_device_uniq || st.total_started) || 0,
          playRate:   Number(st.play_rate) || 0,
          terminaram: Number(st.total_finished_device_uniq || st.total_finished) || 0,
          engajamento:Number(st.engagement_rate) || 0,
          noPitch:    Number(st.total_over_pitch) || 0,
          pctPitch:   Number(st.over_pitch_rate) || 0,
          clicaram:   Number(st.total_clicked_device_uniq || st.total_clicked) || 0,
          vendas:     Number(st.total_conversions) || 0,
          conversao:  Number(st.overall_conversion_rate) || 0,
          receita:    cent(st.total_amount_brl)
        });
      } catch (e) { erros.push(p.nome + ': ' + e.message); }
    }
    // a primeira sozinha: ela descobre o formato de data que a VTurb aceita,
    // e as demais ja saem com o formato certo de primeira
    if (players.length) await buscar(players[0]);
    const resto = players.slice(1);
    for (let i = 0; i < resto.length; i += 4) {
      await Promise.all(resto.slice(i, i + 4).map(buscar));
    }
    linhas.sort((a, b) => b.receita - a.receita);
    linhas.forEach(l => { l.ticket = l.vendas ? l.receita / l.vendas : 0; });
    const saida = { ok: true, de: per.de, ate: per.ate, vsls: linhas, erros,
      // a tela precisa saber que existem outras, senao o corte fica invisivel
      todos: todos.map(p => ({ id: p.id, nome: p.nome, duracao: p.duracao,
                               pitch: p.pitch, criadoEm: p.criadoEm })),
      limitado: limitado };
    _vivoSet(chave, saida);
    res.json(saida);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── panorama: ranking das VSLs e quota da API ──
app.get('/api/vturb/resumo', authUsuario, async (req, res) => {
  try {
    const cfg = _vturbExige();
    const per = _vturbPeriodo(req); const de = per.de, ate = per.ate;
    const [rank, quota] = await Promise.all([
      _vturbApiData(cfg.token, '/events/leaderboard', { start_date: per.ini, end_date: per.fim, timezone: 'America/Sao_Paulo' }, per).catch(e => ({ _erro: e.message })),
      _vturbApi(cfg.token, '/quota/usage', null, 'GET').catch(e => ({ _erro: e.message }))
    ]);
    res.json({ ok: true, de, ate, ranking: rank, quota });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ══════════════════════════════════════════════
// ── FUNIS: pixel de rastreamento + redirecionador ──
// ══════════════════════════════════════════════
// Um pixel dispara varios eventos por visitante. Gravar evento a evento no
// db.json (que e lido e reescrito INTEIRO a cada operacao) derrubaria o sistema
// em poucas horas — foi disco cheio que ja tirou a aplicacao do ar hoje.
// Por isso: conta em memoria, agrega por dia, e grava em lote.
const KEY_FUNIS   = 'sl_funis';
const KEY_DESENHOS = 'sl_desenhos';   // quadros de rascunho de funil, por projeto

// ══════════════════════════════════════════════════════
// ── DESENHAR FUNIL ──
// Rascunho: caixas com print e link, decisoes, notas e setas. Nao tem relacao
// com o Mapa — o Mapa e o que esta MEDIDO, isto e onde se pensa antes de medir.
//
// Fica em chave propria e NAO entra no /api/store: um quadro carrega prints em
// base64 e o db.json e lido e escrito inteiro a cada operacao. Puxar isso junto
// com tasks e criativos a cada sync deixaria o app lento pra todo mundo.
// ══════════════════════════════════════════════════════
const DESENHO_MAX = 4 * 1024 * 1024;    // 4MB por quadro, ja com as imagens

function _desenhos(db) {
  const l = (db || readDB()).store[KEY_DESENHOS];
  return Array.isArray(l) ? l : [];
}
// Lista sem o conteudo: a tela de escolha nao precisa dos prints, e mandar
// megabytes so pra desenhar cartao seria desperdicio.
function _desenhoResumo(d) {
  return { id: d.id, projeto: d.projeto || '', nome: d.nome || 'Sem nome',
           itens: (d.itens || []).length, fios: (d.fios || []).length,
           criadoEm: d.criadoEm, atualizadoEm: d.atualizadoEm,
           capa: (d.itens || []).map(i => i.img).find(Boolean) ? true : false };
}

app.get('/api/desenhos', authUsuario, (req, res) => {
  try {
    const proj = String(req.query.projeto || '');
    const l = _desenhos().filter(d => !proj || (d.projeto || '') === proj);
    res.json({ ok: true, desenhos: l.map(_desenhoResumo)
      .sort((a, b) => String(b.atualizadoEm || '').localeCompare(String(a.atualizadoEm || ''))) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/desenhos/:id', authUsuario, (req, res) => {
  try {
    const d = _desenhos().find(x => x.id === req.params.id);
    if (!d) return res.status(404).json({ error: 'Quadro não encontrado.' });
    res.json({ ok: true, desenho: d });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/desenhos', authUsuario, (req, res) => {
  try {
    const b = req.body || {};
    const bruto = JSON.stringify(b.itens || []);
    if (bruto.length > DESENHO_MAX) {
      return res.status(413).json({ error: 'Quadro muito grande (' +
        Math.round(bruto.length/1048576) + 'MB). Use imagens menores ou divida em dois quadros.' });
    }
    const db = readDB();
    const l = _desenhos(db);
    const id = String(b.id || '').trim() || ('dz' + Date.now().toString(36) + Math.random().toString(36).slice(2,5));
    const i = l.findIndex(x => x.id === id);
    const agora = new Date().toISOString();
    const novo = {
      id, projeto: String(b.projeto || '').slice(0, 60),
      nome: String(b.nome || 'Sem nome').slice(0, 80),
      itens: Array.isArray(b.itens) ? b.itens : [],
      fios: Array.isArray(b.fios) ? b.fios : [],
      vista: b.vista && typeof b.vista === 'object' ? b.vista : null,
      criadoEm: i >= 0 ? l[i].criadoEm : agora,
      atualizadoEm: agora,
      porQuem: (req.user && req.user.nome) || ''
    };
    if (i >= 0) l[i] = novo; else l.push(novo);
    db.store[KEY_DESENHOS] = l;
    db.timestamps[KEY_DESENHOS] = now();
    writeDB(db);
    res.json({ ok: true, id, atualizadoEm: agora });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Vai pra lixeira como qualquer outra coisa: 30 dias pra voltar atras.
app.delete('/api/desenhos/:id', authUsuario, (req, res) => {
  try {
    const db = readDB();
    const l = _desenhos(db);
    const i = l.findIndex(x => x.id === req.params.id);
    if (i < 0) return res.status(404).json({ error: 'Quadro não encontrado.' });
    const item = l[i];
    l.splice(i, 1);
    db.store[KEY_DESENHOS] = l;
    db.timestamps[KEY_DESENHOS] = now();
    const lix = Array.isArray(db.store['sl_lixeira']) ? db.store['sl_lixeira'] : [];
    lix.push({ id: Date.now() + '-' + Math.random().toString(36).slice(2,8),
               sourceKey: KEY_DESENHOS, tipo: 'Desenho de funil',
               deletedAt: new Date().toISOString(),
               deletedBy: req.user && req.user.id, deletedByNome: req.user && req.user.nome,
               originalId: item.id, data: item });
    db.store['sl_lixeira'] = lix;
    db.timestamps['sl_lixeira'] = now();
    audit(db, 'desenho_excluido', { id: item.id }, item.nome, req.user);
    writeDB(db);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
const KEY_REDIRS  = 'sl_redirecionadores';
const KEY_FSTATS  = 'sl_funil_stats';
const KEY_ABSTATS = 'sl_ab_stats';        // contagem por teste × variante × dia
const KEY_JORNADA = 'sl_funil_jornada';   // caminho de cada visitante, 7 dias
const KEY_ATENCAO = 'sl_funil_atencao';   // rolagem e cliques por etapa × dia
const KEY_ADOCOES = 'sl_funil_adocoes';   // etapa nova herdando os ids do pixel velho

// ── Adoção de ids antigos ───────────────────────────────────────────────────
// Quando o funil é recriado, o código colado nas páginas continua mandando pro
// id velho e a tela nova nasce zerada — parece que "perdeu as métricas". Em vez
// de obrigar a recolar o pixel em tudo, a etapa nova passa a aceitar também os
// ids antigos. Nada é reescrito: o evento original fica intacto e dá pra desfazer.
//
// Fica numa chave SÓ DO SERVIDOR de propósito. Dentro de sl_funis, o próximo
// push do navegador (merge por id, last-write-wins) apagaria isto sem avisar.
function _adocoes(db) {
  return Array.isArray(db.store[KEY_ADOCOES]) ? db.store[KEY_ADOCOES] : [];
}
// Predicado + tradutor pra um funil: aceita as linhas dele e as adotadas,
// e diz em qual etapa do funil atual cada linha adotada deve cair.
function _mapaAdocao(db, funilId) {
  const para = {};                                  // "funilVelho|etapaVelha" -> etapa daqui
  _adocoes(db).forEach(a => {
    if (a.funil === funilId) para[(a.origemFunil || '') + '|' + a.origemEtapa] = a.etapa;
  });
  const chave = l => (l.funil || '') + '|' + l.etapa;
  return {
    aceita:  l => l.funil === funilId || para[chave(l)] != null,
    etapaDe: l => (l.funil === funilId ? l.etapa : para[chave(l)]) || l.etapa,
    tem:     Object.keys(para).length > 0
  };
}
// Todos os ids que valem por uma etapa: o dela mais os adotados.
function _idsDaEtapa(db, etapaId) {
  const ids = new Set([etapaId]);
  _adocoes(db).forEach(a => { if (a.etapa === etapaId && a.origemEtapa) ids.add(a.origemEtapa); });
  return ids;
}

let _fBuffer = {};          // "funil|etapa|data" -> { entradas, unicos, segundos, saidas, eventos:{} }
let _fVistos = new Map();   // "funil|etapa|data" -> Set(idVisitante); so os dias passados sao soltos
let _fSujo = false;
const _fChave = (f, e, d) => f + '|' + (e || '-') + '|' + d;
const _hojeBR = () => new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);

function _fContar(funil, etapa, tipo, visitante, extra) {
  const dia = _hojeBR();
  const k = _fChave(funil, etapa, dia);
  if (!_fBuffer[k]) _fBuffer[k] = { funil, etapa, data: dia, entradas: 0, unicos: 0, saidas: 0, segundos: 0, eventos: {} };
  const b = _fBuffer[k];
  if (tipo === 'entrou') {
    b.entradas++;
    if (visitante) {
      if (!_fVistos.has(k)) _fVistos.set(k, new Set());
      const set = _fVistos.get(k);
      if (!set.has(visitante)) { set.add(visitante); b.unicos++; }
    }
  } else if (tipo === 'saiu') {
    b.saidas++;
    // teto de 6h: aba esquecida aberta com o pixel antigo virava "600 min"
    b.segundos += Math.min(Number(extra && extra.segundos) || 0, 6 * 3600);
  } else {
    b.eventos[tipo] = (b.eventos[tipo] || 0) + 1;
  }
  _fSujo = true;
}

// Grava o acumulado de tempos em tempos — nunca a cada evento
function _fGravar() {
  if (!_fSujo) return;
  const pendente = _fBuffer; _fBuffer = {}; _fSujo = false;
  try {
    const db = readDB();
    const atual = Array.isArray(db.store[KEY_FSTATS]) ? db.store[KEY_FSTATS] : [];
    const indice = {};
    atual.forEach(l => { indice[_fChave(l.funil, l.etapa, l.data)] = l; });
    Object.values(pendente).forEach(n => {
      const k = _fChave(n.funil, n.etapa, n.data);
      const v = indice[k];
      if (!v) { atual.push(n); indice[k] = n; return; }
      v.entradas = (v.entradas || 0) + n.entradas;
      v.unicos   = (v.unicos   || 0) + n.unicos;
      v.saidas   = (v.saidas   || 0) + n.saidas;
      v.segundos = (v.segundos || 0) + n.segundos;
      v.eventos  = v.eventos || {};
      Object.keys(n.eventos).forEach(t => { v.eventos[t] = (v.eventos[t] || 0) + n.eventos[t]; });
    });
    // retencao: 180 dias de historico ja e bastante e mantem o banco pequeno
    const corte = new Date(Date.now() - 180 * 86400000).toISOString().slice(0, 10);
    db.store[KEY_FSTATS] = atual.filter(l => l.data >= corte);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_FSTATS] = now();
    writeDB(db);
  } catch (e) {
    console.error('[FUNIL] não consegui gravar as estatísticas:', e.message);
  }
}
setInterval(_fGravar, 30 * 1000);
// Zerar o mapa inteiro de 6 em 6h contava a MESMA pessoa de novo a cada limpeza:
// 'unicos' inflava ate 4x por dia (mais uma vez por deploy). O comentario acima
// sempre disse 'virada do dia' — o codigo e que fazia outra coisa.
// Agora solta so os dias que ja passaram; o de hoje fica de pe.
setInterval(() => {
  const hoje = _hojeBR();
  let soltos = 0;
  for (const k of _fVistos.keys()) {
    if (!k.endsWith('|' + hoje)) { _fVistos.delete(k); soltos++; }
  }
  if (soltos) console.log('[FUNIL] ' + soltos + ' dia(s) antigos soltos da memoria.');
}, 30 * 60 * 1000);

// Feed ao vivo (so memoria — nao vale a pena gravar)
const _fFeed = [];
function _fFeedPush(ev) { _fFeed.unshift(ev); if (_fFeed.length > 200) _fFeed.length = 200; }

// ── Recepcao do pixel ── (publico: roda no navegador de quem visita a pagina)
app.post('/api/funil/evento', express.text({ type: '*/*', limit: '16kb' }), (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  try {
    // sendBeacon manda como text/plain de proposito: assim o navegador nao faz
    // preflight e o evento nunca se perde. Aceita os dois formatos.
    let c = req.body;
    if (typeof c === 'string') { try { c = JSON.parse(c); } catch (e) { c = {}; } }
    c = c || {};
    const funil = String(c.funil || '').slice(0, 80);
    const etapa = String(c.etapa || '').slice(0, 60);
    const tipo  = String(c.tipo  || 'entrou').slice(0, 30);
    if (!funil) return res.sendStatus(204);
    const visitante = String(c.id || '').slice(0, 40);
    if (c.qid && typeof _qzLigarDestino === 'function') _qzLigarDestino(String(c.qid).slice(0, 40), visitante);
    // /697, /697/ e /697?x=1 sao a mesma pagina: normaliza antes de qualquer conta
    if (c.pg) c.pg = _normPg(c.pg);
    // Trafego do time aparece na lista de Leads (com filtro), mas nao entra em
    // nenhuma conta: nem nos blocos do mapa, nem no teste A/B.
    const interno = _pEhInterno(c, req);
    if (!interno) _fContar(funil, etapa, tipo, visitante, c);

    // Teste A/B: a variante chegou pela URL do redirecionador e o pixel a devolve
    // em todo evento. 'entrou' na 1a pagina conta pessoa; alcancar a etapa que e
    // a meta conta conversao — e a mesma pessoa nunca conta duas vezes.
    const teste = String(c.teste || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 60);
    const variante = String(c.variante || '').slice(0, 40);
    if (!interno && teste && variante && visitante && tipo === 'entrou') {
      _abContar(teste, variante, 'entrou', visitante);
      try {
        // retrato de 1 min dos testes: ler o db.json inteiro a cada visita era caro
        const r = _funisCache().redirs[teste];
        // meta e uma etapa do funil: chegar nela e a conversao do teste
        if (r && r.meta && r.meta !== 'compra' && String(r.meta) === etapa) _abContar(teste, variante, 'meta', visitante);
      } catch (e) {}
    }

    // so na entrada: os outros eventos sao da mesma pessoa, no mesmo aparelho
    if (tipo === 'entrou') c.quem = _quemE(req);
    _jRegistrar(visitante, funil, etapa, tipo, c);
    try { _pxRegistrar(c, req, interno); } catch (e) {}
    const pg = String(c.pg || '').slice(0, 160);
    if (!interno) {
      if (tipo === 'saiu')    _atSaida(etapa, c, pg);
      if (tipo === 'clique' && !Number(c.player))  _atClique(etapa, c.rotulo, c.posicao, pg);
      if (tipo === 'friccao' && !_ehPlayer(c.rotulo)) _atFriccao(etapa, c.rotulo, c.motivo, pg);
    }

    _fFeedPush({ momento: new Date().toISOString(), funil, etapa, tipo,
                 visitante: String(c.id || '').slice(0, 12),
                 utm: (c.utm && c.utm.content) || '', segundos: Number(c.segundos) || 0,
                 variante: variante || '' });
    res.sendStatus(204);
  } catch (e) { res.sendStatus(204); }
});

// ══════════════════════════════════════════════════════
// ── JORNADA POR PESSOA ──
// O pixel ja mandava o identificador do visitante em todo evento, mas o servidor
// so somava. Aqui a gente guarda o caminho de cada um — e o valor nao e bisbilhotar
// alguem, e poder perguntar "me mostra 10 que chegaram no checkout e nao compraram".
// ══════════════════════════════════════════════════════
const JORNADA_DIAS = 7, JORNADA_TETO = 4000, JORNADA_EVENTOS = 40;
let _jDiagUltimo = 0;   // limita o log de diagnostico da jornada a 1x/min
let _jBuffer = {}, _jSujo = false;

// ── Quem e o visitante: aparelho, navegador, sistema, pais ──────────────────
// Sai do User-Agent que o navegador ja manda em toda requisicao — nao precisa
// pedir nada a mais ao pixel, e nao guarda o UA cru (que e quase uma digital).
// Se um dia isso mudar, o dado dos dias anteriores nao volta: por isso comeca a
// ser guardado antes da tela que vai mostra-lo existir.
function _quemE(req) {
  const ua = String(req.headers['user-agent'] || '');
  if (!ua) return null;
  const toque = /Mobi|Android|iPhone|iPod/i.test(ua);
  const tablet = /iPad|Tablet|PlayBook|Silk/i.test(ua) || (/Android/i.test(ua) && !/Mobi/i.test(ua));

  let navegador = 'Outro';
  // ordem importa: quase todo navegador se diz Chrome/Safari no UA
  if (/Instagram/i.test(ua))            navegador = 'Instagram';
  else if (/FBAN|FBAV|FB_IAB/i.test(ua)) navegador = 'Facebook';
  else if (/EdgA?\//i.test(ua))         navegador = 'Edge';
  else if (/OPR\/|Opera/i.test(ua))     navegador = 'Opera';
  else if (/SamsungBrowser/i.test(ua))  navegador = 'Samsung';
  else if (/Firefox\//i.test(ua))       navegador = 'Firefox';
  else if (/Chrome\//i.test(ua))        navegador = 'Chrome';
  else if (/Safari\//i.test(ua))        navegador = 'Safari';

  let sistema = 'Outro';
  if (/iPhone|iPad|iPod/i.test(ua))     sistema = 'iOS';
  else if (/Android/i.test(ua))         sistema = 'Android';
  else if (/Windows/i.test(ua))         sistema = 'Windows';
  else if (/Mac OS X/i.test(ua))        sistema = 'Mac';
  else if (/Linux/i.test(ua))           sistema = 'Linux';

  // Pais so existe se a borda entregar. Railway sozinho nao entrega; com
  // Cloudflare na frente vem em cf-ipcountry. Sem isso fica vazio, e a tela
  // simplesmente nao mostra a secao — melhor do que inventar.
  const pais = String(req.headers['cf-ipcountry'] ||
                      req.headers['x-vercel-ip-country'] ||
                      req.headers['x-geo-country'] || '').toUpperCase().slice(0, 2);

  return { aparelho: tablet ? 'Tablet' : (toque ? 'Celular' : 'Computador'),
           navegador, sistema, pais: (pais && pais !== 'XX') ? pais : '' };
}

function _jRegistrar(visitante, funil, etapa, tipo, extra) {
  if (!visitante || !funil) return;
  const k = funil + '|' + visitante;
  if (!_jBuffer[k]) _jBuffer[k] = { id: visitante, funil, eventos: [] };
  const j = _jBuffer[k];
  const ev = { em: new Date().toISOString(), etapa, tipo };
  if (extra && Number(extra.segundos)) ev.segundos = Math.min(Number(extra.segundos), 6 * 3600);
  if (extra && Number(extra.atencao))  ev.atencao  = Number(extra.atencao);
  if (extra && Number(extra.rolagem))  ev.rolagem  = Number(extra.rolagem);
  if (extra && extra.motivo)  ev.motivo  = String(extra.motivo).slice(0, 20);
  if (extra && extra.versao)  ev.versao  = String(extra.versao).slice(0, 40);
  // O pixel sempre mandou as cinco utm e o referrer; so o criativo era guardado.
  // Sem origem/midia nao da pra olhar uma jornada e dizer se a pessoa veio do
  // Instagram, do Facebook ou de um site que linkou pra voce.
  if (extra && extra.utm) {
    const u = extra.utm;
    if (u.content)  ev.criativo = String(u.content).slice(0, 80);
    if (u.source)   ev.origem   = String(u.source).slice(0, 60);
    if (u.medium)   ev.midia    = String(u.medium).slice(0, 60);
    if (u.campaign) ev.campanha = String(u.campaign).slice(0, 80);
  }
  if (extra && extra.ref) ev.ref = String(extra.ref).slice(0, 200);
  // A origem do PRIMEIRO acesso, que e a que vale. Guardada tambem aqui porque
  // o navegador pode perder o storage (iOS limpa storage de script depois de 7
  // dias sem interacao) — no servidor ela nao evapora.
  if (extra && extra.primeiro && typeof extra.primeiro === 'object') {
    const pr = extra.primeiro, out = {};
    ['utm_source','utm_medium','utm_campaign','utm_content','utm_term',
     'fbclid','gclid','src','sck','em','pg','ref'].forEach(k => {
      if (pr[k]) out[k] = String(pr[k]).slice(0, 120);
    });
    if (Object.keys(out).length) ev.primeiro = out;
  }
  if (extra && extra.quem) {
    const q = extra.quem;
    if (q.aparelho)  ev.aparelho  = q.aparelho;
    if (q.navegador) ev.navegador = q.navegador;
    if (q.sistema)   ev.sistema   = q.sistema;
    if (q.pais)      ev.pais      = q.pais;
  }
  if (extra && extra.variante) ev.variante = String(extra.variante).slice(0, 40);
  if (extra && extra.teste)    ev.teste    = String(extra.teste).slice(0, 60);
  if (extra && extra.pg)       ev.pg       = String(extra.pg).slice(0, 160);
  if (extra && extra.rotulo)   ev.rotulo = String(extra.rotulo).slice(0, 70);
  j.eventos.push(ev);
  if (j.eventos.length > JORNADA_EVENTOS) j.eventos = j.eventos.slice(-JORNADA_EVENTOS);
  _jSujo = true;
}

// Quando a jornada aconteceu, em ms. Aceita ISO, numero ou lixo — um evento
// torto nunca pode derrubar a lista inteira com erro 500.
function _jQuando(j) {
  const evs = (j && j.eventos) || [];
  const ult = evs[evs.length - 1];
  const bruto = ult ? ult.em : (j && j.em);
  const t = typeof bruto === 'number' ? bruto : Date.parse(bruto);
  return Number.isFinite(t) ? t : 0;
}

function _jGravar() {
  if (!_jSujo) return;
  const pendente = _jBuffer; _jBuffer = {}; _jSujo = false;
  try {
    const db = readDB();
    let atual = Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [];
    const indice = {};
    atual.forEach(j => { indice[j.funil + '|' + j.id] = j; });
    Object.values(pendente).forEach(n => {
      const k = n.funil + '|' + n.id, v = indice[k];
      if (v) {
        v.eventos = v.eventos.concat(n.eventos).slice(-JORNADA_EVENTOS);
      } else { atual.push(n); indice[k] = n; }
    });
    // guarda os mais recentes primeiro, e corta pelo teto e pela idade
    const corte = Date.now() - JORNADA_DIAS * 86400000;
    atual = atual.filter(j => _jQuando(j) >= corte).sort((a, b) => {
      return _jQuando(b) - _jQuando(a);
    }).slice(0, JORNADA_TETO);
    db.store[KEY_JORNADA] = atual;
    db.timestamps[KEY_JORNADA] = now();
    writeDB(db);
  } catch (e) { console.error('[jornada] falhou ao gravar:', e.message); }
}
setInterval(_jGravar, 45 * 1000);

// ══════════════════════════════════════════════════════
// ── PESSOAS: a base que não esquece ──
// A jornada acima guarda 4.000 pessoas por 7 dias dentro do db.json — e o
// db.json inteiro é lido e regravado a cada escrita. Não dá pra pôr 78 mil
// visitantes ali. Aqui fica um SQLite à parte (o Node 22 já traz um), com o
// que Leads, a ficha, o Resultado e o A/B precisam.
// Visitante, lead e pedido ficam pra sempre; sessão 12 meses; evento 90 dias
// (menos, se o disco apertar — o volume do Railway é pequeno).
// ══════════════════════════════════════════════════════
let _sqlite = null;
try { _sqlite = require('node:sqlite'); }
catch (e) { console.warn('[PESSOAS] SQLite indisponível neste Node (' + process.version + '): ' + e.message); }
const PESSOAS_ARQ = path.join(DATA_DIR, 'pessoas.sqlite');
const SESSAO_MS = 30 * 60 * 1000;
const EVENTOS_DIAS = 90, SESSOES_DIAS = 365, EVENTOS_POR_SESSAO = 60, JANELA_CREDITO_DIAS = 7;
let _pdb = null, _pdbFalhou = false;
const _pq = {};
const _pIntIp = new Set(), _pIntVis = new Set();   // regras de tráfego interno
const _pSess = new Map();                           // visitante -> sessão aberta (atalho)
const _pVideo = new Map();                          // visitante -> onde está na VSL agora
let _pSal = '';

function _pessoas() {
  if (_pdb || _pdbFalhou || !_sqlite) return _pdb;
  try {
    const db = new _sqlite.DatabaseSync(PESSOAS_ARQ);
    db.exec(`
      PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000;
      CREATE TABLE IF NOT EXISTS cfg (k TEXT PRIMARY KEY, v TEXT);
      CREATE TABLE IF NOT EXISTS visitantes (
        id TEXT PRIMARY KEY, primeiro INTEGER, ultimo INTEGER,
        aparelho TEXT, sistema TEXT, navegador TEXT, pais TEXT, tela TEXT, ip TEXT,
        interno INTEGER DEFAULT 0, interno_por TEXT, lead TEXT,
        p_fonte TEXT, p_midia TEXT, p_camp TEXT, p_cont TEXT, p_termo TEXT, p_em INTEGER, p_pg TEXT, p_ref TEXT,
        u_fonte TEXT, u_midia TEXT, u_camp TEXT, u_cont TEXT, u_termo TEXT, u_em INTEGER,
        fbclid TEXT, fbc TEXT, fbp TEXT,
        sessoes INTEGER DEFAULT 0, eventos INTEGER DEFAULT 0,
        pitch_em INTEGER, checkout_em INTEGER, compra_em INTEGER, compras INTEGER DEFAULT 0, pago REAL DEFAULT 0,
        video INTEGER DEFAULT 0, mortos INTEGER DEFAULT 0,
        ult_tipo TEXT, ult_rot TEXT, ult_em INTEGER, ult_pg TEXT,
        funil TEXT, teste TEXT, variante TEXT, versao TEXT
      );
      CREATE INDEX IF NOT EXISTS vis_ultimo ON visitantes(ultimo);
      CREATE INDEX IF NOT EXISTS vis_lead ON visitantes(lead);
      CREATE TABLE IF NOT EXISTS sessoes (
        id TEXT PRIMARY KEY, visitante TEXT, inicio INTEGER, fim INTEGER, dur INTEGER DEFAULT 0,
        funil TEXT, versao TEXT, entrada TEXT,
        fonte TEXT, midia TEXT, camp TEXT, cont TEXT, termo TEXT, fbclid TEXT, fbc TEXT, fbp TEXT,
        teste TEXT, variante TEXT, interno INTEGER DEFAULT 0,
        pitch INTEGER DEFAULT 0, checkout INTEGER DEFAULT 0, video INTEGER DEFAULT 0,
        eventos INTEGER DEFAULT 0, saiu INTEGER DEFAULT 0, mortos INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS ses_vis ON sessoes(visitante, inicio);
      CREATE INDEX IF NOT EXISTS ses_inicio ON sessoes(inicio);
      CREATE TABLE IF NOT EXISTS paginas (
        sessao TEXT, pg TEXT, visitante TEXT, funil TEXT, etapa TEXT, em INTEGER, dia TEXT,
        interno INTEGER DEFAULT 0, PRIMARY KEY (sessao, pg)
      );
      CREATE INDEX IF NOT EXISTS pag_funil ON paginas(funil, dia);
      CREATE INDEX IF NOT EXISTS pag_pg ON paginas(pg, dia);
      CREATE INDEX IF NOT EXISTS pag_vis ON paginas(visitante);
      CREATE TABLE IF NOT EXISTS eventos (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sessao TEXT, visitante TEXT, funil TEXT, etapa TEXT,
        tipo TEXT, pg TEXT, em INTEGER, rot TEXT, extra TEXT
      );
      CREATE INDEX IF NOT EXISTS ev_vis ON eventos(visitante, em);
      CREATE INDEX IF NOT EXISTS ev_em ON eventos(em);
      CREATE TABLE IF NOT EXISTS leads (
        id TEXT PRIMARY KEY, email_h TEXT, tel_h TEXT, doc_h TEXT, email_mask TEXT, nome TEXT,
        criado INTEGER, interno INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS lead_email ON leads(email_h);
      CREATE INDEX IF NOT EXISTS lead_tel ON leads(tel_h);
      CREATE INDEX IF NOT EXISTS lead_doc ON leads(doc_h);
      CREATE TABLE IF NOT EXISTS lead_visitante (lead TEXT, visitante TEXT, por TEXT, em INTEGER,
        PRIMARY KEY (lead, visitante));
      CREATE INDEX IF NOT EXISTS lv_vis ON lead_visitante(visitante);
      CREATE TABLE IF NOT EXISTS pedidos (
        id TEXT PRIMARY KEY, pedido TEXT, status TEXT, pago INTEGER DEFAULT 0, estorno INTEGER DEFAULT 0,
        valor REAL, liquido REAL, produto TEXT, plano TEXT, metodo TEXT, motivo TEXT,
        visitante TEXT, lead TEXT, casou TEXT, sem_origem TEXT, sck TEXT,
        fonte TEXT, camp TEXT, cont TEXT, termo TEXT,
        cred_fonte TEXT, cred_camp TEXT, cred_cont TEXT, cred_canal TEXT, apoio TEXT,
        funil TEXT, teste TEXT, variante TEXT, renovacao INTEGER DEFAULT 0, em INTEGER, dia TEXT
      );
      CREATE INDEX IF NOT EXISTS ped_dia ON pedidos(dia);
      CREATE INDEX IF NOT EXISTS ped_vis ON pedidos(visitante);
      CREATE INDEX IF NOT EXISTS ped_lead ON pedidos(lead);
      CREATE TABLE IF NOT EXISTS internos (tipo TEXT, valor TEXT, em INTEGER, por TEXT, PRIMARY KEY (tipo, valor));
      CREATE TABLE IF NOT EXISTS camp_dia (dia TEXT, projeto TEXT, id TEXT, nome TEXT, conta TEXT,
        gasto REAL, imp INTEGER, cliques INTEGER, PRIMARY KEY (dia, projeto, id));
      CREATE TABLE IF NOT EXISTS camp_dia_ok (dia TEXT, projeto TEXT, em INTEGER, PRIMARY KEY (dia, projeto));
    `);
    // vídeo e pitch POR PÁGINA (antes só por visita: quem viu a VSL na 697 e
    // depois caiu no back redirect "passava do pitch" nas duas)
    try { db.exec('ALTER TABLE paginas ADD COLUMN video INTEGER DEFAULT 0'); } catch (e) {}
    try { db.exec('ALTER TABLE paginas ADD COLUMN pitch INTEGER DEFAULT 0'); } catch (e) {}
    try { db.exec('CREATE INDEX IF NOT EXISTS ev_tipo_em ON eventos(tipo, em)'); } catch (e) {}
    _pdb = db;
    let sal = db.prepare("SELECT v FROM cfg WHERE k='sal'").get();
    if (!sal) {
      _pSal = crypto.randomBytes(16).toString('hex');
      db.prepare("INSERT INTO cfg(k,v) VALUES('sal',?)").run(_pSal);
    } else _pSal = sal.v;
    db.prepare('SELECT tipo, valor FROM internos').all().forEach(r => {
      if (r.tipo === 'ip') _pIntIp.add(r.valor);
      if (r.tipo === 'visitante') _pIntVis.add(r.valor);
    });
    console.log('[PESSOAS] base aberta em ' + PESSOAS_ARQ);
  } catch (e) {
    _pdbFalhou = true;
    console.error('[PESSOAS] não consegui abrir a base:', e.message);
  }
  return _pdb;
}
function _q(sql) {
  if (!_pq[sql]) _pq[sql] = _pessoas().prepare(sql);
  return _pq[sql];
}
function _pCfg(k, v) {
  const db = _pessoas(); if (!db) return null;
  if (v === undefined) { const r = _q('SELECT v FROM cfg WHERE k=?').get(k); return r ? r.v : null; }
  _q('INSERT INTO cfg(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v));
  return v;
}

const _hashCurto = s => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 32);
const _diaBR = ms => new Date(ms - 3 * 3600000).toISOString().slice(0, 10);
// A mesma pagina tem de ser uma chave so: /697, /697/, /697?x=1 e WWW.site/697
function _normPg(u) {
  let s = String(u || '').trim().toLowerCase();
  if (!s) return '';
  s = s.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[?#].*$/, '').replace(/\/+$/, '');
  return s.slice(0, 160);
}
function _telNorm(t) {
  let d = String(t || '').replace(/\D/g, '');
  if (!d) return '';
  if (d.length === 10 || d.length === 11) d = '55' + d;
  return d.length >= 12 ? d : '';
}
function _mascEmail(e) {
  const m = String(e || '').trim().toLowerCase().match(/^([^@]+)@(.+)$/);
  if (!m) return '';
  return m[1].charAt(0) + '*****@' + m[2];
}
function _ipDe(req) {
  const xf = String((req && req.headers && req.headers['x-forwarded-for']) || '').split(',')[0].trim();
  return xf || (req && (req.ip || (req.socket && req.socket.remoteAddress))) || '';
}
function _ipHash(req) {
  const ip = _ipDe(req);
  if (!ip || !_pessoas()) return '';
  return _hashCurto(_pSal + '|ip|' + ip).slice(0, 20);
}
function _pEhInterno(c, req) {
  if (c && Number(c.interno) === 1) return 'cookie';
  const vis = String((c && c.id) || '');
  if (vis && _pIntVis.has(vis)) return 'manual';
  const ih = _ipHash(req);
  if (ih && _pIntIp.has(ih)) return 'ip';
  return '';
}

// ── Funis em memória ────────────────────────────────────────────────────────
// O evento do pixel chega o tempo todo. Ler o db.json (30 MB) a cada um pra
// saber o tipo da etapa ou o pitch da VSL travaria o servidor; um retrato de
// 1 minuto basta — funil não muda de segundo em segundo.
let _fcCache = { em: 0 };
function _funisCache() {
  if (_fcCache.em && Date.now() - _fcCache.em < 60000) return _fcCache;
  const novo = { em: Date.now(), funis: {}, etapaTipo: {}, etapaPitch: {}, urlEtapa: {}, pitchPlayer: {}, redirs: {} };
  try {
    const db = readDB();
    (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : []).forEach(f => {
      if (!f || !f.id) return;
      novo.funis[f.id] = f;
      (f.etapas || []).forEach(e => {
        novo.etapaTipo[e.id] = e.tipo || 'pagina';
        if (Number(e.pitch) > 0) novo.etapaPitch[e.id] = Number(e.pitch);
        if (e.url) novo.urlEtapa[_normPg(e.url)] = { funil: f.id, etapa: e.id, tipo: e.tipo || 'pagina', pitch: Number(e.pitch) || 0 };
      });
    });
    const vt = _vturbCfg(db);
    ((vt && vt.players) || []).forEach(p => { if (p.id && Number(p.pitch) > 0) novo.pitchPlayer[String(p.id)] = Number(p.pitch); });
    (Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : []).forEach(r => {
      if (r && r.slug) novo.redirs[String(r.slug).toLowerCase()] = r;
    });
  } catch (e) { if (_fcCache.em) return _fcCache; }
  _fcCache = novo;
  return novo;
}

// ── Gravação de cada evento do pixel ────────────────────────────────────────
const _EV_GUARDA = new Set(['entrou', 'saiu', 'checkout', 'clique', 'friccao', 'video', 'pitch']);
// 'quando' só vem na importação do histórico (evento com a hora dele)
function _pxRegistrar(c, req, interno, quando) {
  const db = _pessoas(); if (!db) return;
  const vis = String(c.id || '').slice(0, 40);
  if (!vis) return;
  const tipo = String(c.tipo || 'entrou').slice(0, 30);
  const agora = quando || Date.now(), dia = _diaBR(agora);
  const pg = _normPg(c.pg);
  const funil = String(c.funil || '').slice(0, 80);
  const cache = _funisCache();
  const porUrl = pg ? cache.urlEtapa[pg] : null;
  // a URL cadastrada ganha do data-e (o data-e vai junto quando a página é duplicada)
  const etapa = (porUrl && porUrl.funil === funil) ? porUrl.etapa : String(c.etapa || '').slice(0, 60);
  const tipoEtapa = (porUrl && porUrl.etapa === etapa) ? porUrl.tipo : (cache.etapaTipo[etapa] || '');
  const utm = c.utm || {}, pr = (c.primeiro && typeof c.primeiro === 'object') ? c.primeiro : {};
  const aqui = (c.aqui && typeof c.aqui === 'object') ? c.aqui : null;
  const txt = (v, n) => { const s = String(v == null ? '' : v).trim(); return s ? s.slice(0, n || 120) : null; };
  const eInt = interno ? 1 : 0;

  db.exec('BEGIN');
  try {
    // ── visitante ──
    let v = _q('SELECT id, interno, sessoes, pitch_em, checkout_em FROM visitantes WHERE id=?').get(vis);
    if (!v) {
      const aq = aqui || {};
      const pf = pr.utm_source || aq.utm_source || utm.source, pm = pr.utm_medium || aq.utm_medium || utm.medium,
            pc = pr.utm_campaign || aq.utm_campaign || utm.campaign, pn = pr.utm_content || aq.utm_content || utm.content,
            pt = pr.utm_term || aq.utm_term || utm.term;
      _q(`INSERT INTO visitantes(id, primeiro, ultimo, p_fonte, p_midia, p_camp, p_cont, p_termo, p_em, p_pg, p_ref,
            fbclid, fbc, fbp, interno, interno_por)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(vis, agora, agora,
        txt(pf, 80), txt(pm, 80), txt(pc, 120), txt(pn, 160), txt(pt, 80),
        Number(pr.em) > 0 && Number(pr.em) < agora ? Number(pr.em) : agora,
        txt(pr.pg ? _normPg(_pgCompleta(pr.pg, pg)) : pg, 160), txt(pr.ref || c.ref, 200),
        txt(pr.fbclid, 200), txt(pr.fbc, 200), txt(pr.fbp, 80), eInt, interno || null);
      v = { id: vis, interno: eInt, sessoes: 0, pitch_em: null, checkout_em: null };
    }

    // ── sessão: 30 min sem nada fecha ──
    let s = _pSess.get(vis);
    if (!s) {
      const r = _q('SELECT id, inicio, fim, funil FROM sessoes WHERE visitante=? ORDER BY inicio DESC LIMIT 1').get(vis);
      if (r) s = { id: r.id, inicio: r.inicio, fim: r.fim, funil: r.funil, pitch: 0, checkout: 0, eventos: 0 };
    }
    const aberta = s && (agora - s.fim) < SESSAO_MS;
    if (!aberta && (tipo === 'saiu' || tipo === 'video')) {
      // Saída ou pulso do vídeo depois de 30 min parado não abre visita nova:
      // é o fim da anterior chegando atrasado. Só marca, sem esticar o tempo.
      if (s && tipo === 'saiu') _q('UPDATE sessoes SET saiu=1 WHERE id=?').run(s.id);
      db.exec('COMMIT');
      return;
    }
    if (!aberta) {
      const o = aqui || {};
      // Sessão nova: a origem é a DESTE acesso. Sem UTM na URL agora, é direto
      // (ou quem trouxe a pessoa de volta foi o referrer), não o anúncio antigo.
      const semAqui = !aqui && !c.retorno;   // pixel antigo: não sabe separar, usa o que tem
      const fonte = o.utm_source || (semAqui ? utm.source : '') || '';
      s = { id: String(c.sid || '').slice(0, 30) || ('s' + agora.toString(36) + Math.random().toString(36).slice(2, 6)),
            inicio: agora, fim: agora, funil, pitch: 0, checkout: 0, eventos: 0 };
      // o sid do navegador pode repetir entre visitantes em aba compartilhada: nunca reaproveita
      if (_q('SELECT 1 FROM sessoes WHERE id=?').get(s.id)) s.id = s.id + '_' + Math.random().toString(36).slice(2, 5);
      _q(`INSERT INTO sessoes(id, visitante, inicio, fim, funil, versao, entrada, fonte, midia, camp, cont, termo,
            fbclid, fbc, fbp, teste, variante, interno)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(s.id, vis, agora, agora, funil || null, txt(c.versao, 40), pg || null,
        txt(fonte, 80), txt(o.utm_medium || (semAqui ? utm.medium : ''), 80),
        txt(o.utm_campaign || (semAqui ? utm.campaign : ''), 120), txt(o.utm_content || (semAqui ? utm.content : ''), 160),
        txt(o.utm_term || (semAqui ? utm.term : ''), 80),
        txt(o.fbclid, 200), txt(o.fbc || pr.fbc, 200), txt(o.fbp || pr.fbp, 80),
        txt(c.teste, 60), txt(c.variante, 40), eInt);
      // último toque PAGO: é o que leva o crédito da venda
      const canal = fonte ? _canalDe(fonte, _canaisCache()) : null;
      if (canal && canal.anuncios && !canal.apoio) {
        _q(`UPDATE visitantes SET u_fonte=?, u_midia=?, u_camp=?, u_cont=?, u_termo=?, u_em=? WHERE id=?`)
          .run(txt(fonte, 80), txt(o.utm_medium || utm.medium, 80), txt(o.utm_campaign || utm.campaign, 120),
               txt(o.utm_content || utm.content, 160), txt(o.utm_term || utm.term, 80), agora, vis);
      }
      _q('UPDATE visitantes SET sessoes=sessoes+1 WHERE id=?').run(vis);
    }
    _pSess.set(vis, s);

    // ── página vista nesta sessão (uma linha por página, não por evento) ──
    if (pg && tipo !== 'saiu') {
      _q(`INSERT OR IGNORE INTO paginas(sessao, pg, visitante, funil, etapa, em, dia, interno) VALUES(?,?,?,?,?,?,?,?)`)
        .run(s.id, pg, vis, funil || null, etapa || null, agora, dia, eInt);
    }

    // ── marcos: checkout e pitch ──
    let marco = '';
    if (tipo === 'checkout' || (tipo === 'entrou' && tipoEtapa === 'checkout')) {
      if (!s.checkout) {
        s.checkout = 1; marco = 'checkout';
        _q('UPDATE sessoes SET checkout=1 WHERE id=?').run(s.id);
        _q('UPDATE visitantes SET checkout_em=COALESCE(checkout_em, ?) WHERE id=?').run(agora, vis);
      }
    }
    if (tipo === 'video' || (tipo === 'saiu' && Number(c.vmax) > 0)) {
      const seg = Math.max(0, Math.round(Number(c.max || c.seg || c.vmax) || 0));
      // o pitch vem da página (URL cadastrada no mapa) antes do data-e: a /697
      // tem o pixel antigo, com o id e a etapa de outro funil, e assim nunca
      // achava o minuto do pitch — ninguém era marcado
      const pitch = (porUrl && porUrl.pitch) || cache.etapaPitch[etapa] || cache.pitchPlayer[String(c.player || '')] || 0;
      _q('UPDATE sessoes SET video=MAX(video, ?) WHERE id=?').run(seg, s.id);
      if (pg) _q('UPDATE paginas SET video=MAX(video, ?) WHERE sessao=? AND pg=?').run(seg, s.id, pg);
      _q('UPDATE visitantes SET video=MAX(video, ?) WHERE id=?').run(seg, vis);
      if (!quando && tipo === 'video') _pVideo.set(vis, { seg: Number(c.seg) || seg, em: agora, funil, pg, pitch, interno: eInt });
      // o pitch é da página: a mesma visita pode passar do pitch na 697 e não no back redirect
      const jaPg = pg ? _q('SELECT pitch FROM paginas WHERE sessao=? AND pg=?').get(s.id, pg) : null;
      if (pitch && seg >= pitch && !(jaPg && jaPg.pitch)) {
        s.pitch = 1; marco = 'pitch';
        if (pg) _q('UPDATE paginas SET pitch=1 WHERE sessao=? AND pg=?').run(s.id, pg);
        _q('UPDATE sessoes SET pitch=1 WHERE id=?').run(s.id);
        _q('UPDATE visitantes SET pitch_em=COALESCE(pitch_em, ?) WHERE id=?').run(agora, vis);
      }
    }

    // ── o evento em si (só os que contam a história, com teto por visita) ──
    const extra = {};
    if (tipo === 'saiu') { extra.seg = Math.min(Number(c.segundos) || 0, 6 * 3600); if (c.rolagem) extra.rol = Number(c.rolagem); }
    if (tipo === 'video') { extra.seg = Number(c.seg) || 0; if (c.marco) extra.marco = String(c.marco).slice(0, 12); }
    if (tipo === 'friccao') extra.motivo = String(c.motivo || '').slice(0, 12);
    if (tipo === 'clique' && Number(c.player)) extra.player = 1;
    if (tipo === 'checkout' && c.destino) extra.destino = String(c.destino).slice(0, 60);
    if (tipo === 'entrou') { if (c.variante) extra.variante = String(c.variante).slice(0, 40); if (c.teste) extra.teste = String(c.teste).slice(0, 60); if (c.retorno) extra.retorno = 1; }
    const rot = txt(c.rotulo, 80);
    if (_EV_GUARDA.has(tipo) && s.eventos < EVENTOS_POR_SESSAO && !(tipo === 'friccao' && _ehPlayer(c.rotulo))) {
      // vídeo guarda só os marcos (play, 1 min, 10 min); o pulso de cada minuto
      // fica na memória, pra tela ao vivo
      const segV = Number(c.seg) || 0;
      const marcoVideo = tipo !== 'video' || c.marco === 'play' ||
        (segV >= 60 && segV < 120) || (segV >= 600 && segV < 660);
      if (tipo === 'saiu') {
        // uma saída por página por visita: a segunda só atualiza a primeira
        const ja = _q("SELECT id FROM eventos WHERE sessao=? AND tipo='saiu' AND pg=? LIMIT 1").get(s.id, pg);
        if (ja) _q('UPDATE eventos SET em=?, extra=? WHERE id=?').run(agora, JSON.stringify(extra), ja.id);
        else { _q('INSERT INTO eventos(sessao, visitante, funil, etapa, tipo, pg, em, rot, extra) VALUES(?,?,?,?,?,?,?,?,?)')
                 .run(s.id, vis, funil || null, etapa || null, tipo, pg || null, agora, rot, JSON.stringify(extra)); s.eventos++; }
        _q('UPDATE sessoes SET saiu=1 WHERE id=?').run(s.id);
      } else if (marcoVideo) {
        _q('INSERT INTO eventos(sessao, visitante, funil, etapa, tipo, pg, em, rot, extra) VALUES(?,?,?,?,?,?,?,?,?)')
          .run(s.id, vis, funil || null, etapa || null, tipo, pg || null, agora, rot,
               Object.keys(extra).length ? JSON.stringify(extra) : null);
        s.eventos++;
      }
    }
    if (marco === 'pitch') {
      _q('INSERT INTO eventos(sessao, visitante, funil, etapa, tipo, pg, em, rot, extra) VALUES(?,?,?,?,?,?,?,?,?)')
        .run(s.id, vis, funil || null, etapa || null, 'pitch', pg || null, agora, null, JSON.stringify({ seg: Number(c.max || c.seg) || 0 }));
    }
    if (tipo === 'friccao' && c.motivo === 'morto' && !_ehPlayer(c.rotulo)) {
      _q('UPDATE sessoes SET mortos=mortos+1 WHERE id=?').run(s.id);
      _q('UPDATE visitantes SET mortos=mortos+1 WHERE id=?').run(vis);
    }

    // ── fecha a conta da visita e do visitante ──
    s.fim = agora;
    _q('UPDATE sessoes SET fim=?, dur=?, eventos=eventos+1 WHERE id=?').run(agora, Math.round((agora - s.inicio) / 1000), s.id);
    const conta = tipo !== 'video' && tipo !== 'saiu';
    const q = c.quem || null;
    _q(`UPDATE visitantes SET ultimo=?, eventos=eventos+1,
          ult_tipo=CASE WHEN ? THEN ? ELSE ult_tipo END, ult_rot=CASE WHEN ? THEN ? ELSE ult_rot END,
          ult_em=CASE WHEN ? THEN ? ELSE ult_em END, ult_pg=CASE WHEN ? THEN ? ELSE ult_pg END,
          aparelho=COALESCE(?, aparelho), sistema=COALESCE(?, sistema), navegador=COALESCE(?, navegador),
          pais=COALESCE(?, pais), tela=COALESCE(?, tela), ip=COALESCE(?, ip),
          funil=COALESCE(?, funil), teste=COALESCE(?, teste), variante=COALESCE(?, variante), versao=COALESCE(?, versao),
          interno=CASE WHEN ?=1 THEN 1 ELSE interno END, interno_por=COALESCE(interno_por, ?)
        WHERE id=?`).run(agora,
      conta ? 1 : 0, marco || tipo, conta ? 1 : 0, rot, conta ? 1 : 0, agora, conta ? 1 : 0, pg || null,
      q && q.aparelho || null, q && q.sistema || null, q && q.navegador || null, q && q.pais || null,
      txt(c.tela, 20), tipo === 'entrou' ? (_ipHash(req) || null) : null,
      funil || null, txt(c.teste, 60), txt(c.variante, 40), txt(c.versao, 40),
      eInt, interno || null, vis);
    db.exec('COMMIT');
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (e2) {}
    const t = Date.now();
    if (t - (_pxRegistrar._ultErro || 0) > 60000) { _pxRegistrar._ultErro = t; console.error('[PESSOAS] evento não gravou:', e.message); }
  }
}
// primeira página do first-touch vem só com o caminho; completa com o host atual
function _pgCompleta(pgPrimeiro, pgAtual) {
  const p = String(pgPrimeiro || '');
  if (!p || /^[a-z0-9-]+\.[a-z]/i.test(p.replace(/^https?:\/\//, ''))) return p;
  const host = String(pgAtual || '').split('/')[0];
  return host ? host + (p.charAt(0) === '/' ? p : '/' + p) : p;
}
let _canaisMem = { em: 0, lista: [] };
function _canaisCache() {
  if (_canaisMem.em && Date.now() - _canaisMem.em < 60000) return _canaisMem.lista;
  try { _canaisMem = { em: Date.now(), lista: _canaisCfg(readDB()) }; }
  catch (e) { _canaisMem.em = Date.now(); }
  return _canaisMem.lista;
}
// a sessão aberta sai do atalho de memória depois de 1h parada
setInterval(() => {
  const corte = Date.now() - 60 * 60 * 1000;
  for (const [k, s] of _pSess) if (s.fim < corte) _pSess.delete(k);
  const corteV = Date.now() - 3 * 60 * 1000;
  for (const [k, v] of _pVideo) if (v.em < corteV) _pVideo.delete(k);
}, 5 * 60 * 1000);

// rótulo de clique que é o player (ou um iframe/vídeo): nunca é clique morto
const _ehPlayer = r => /vturb|smartplayer|converteai|^iframe$|^video$|^vid[-_]/i.test(String(r || '').trim());

// ── Casamento venda ↔ pessoa ────────────────────────────────────────────────
// A Payt não devolve o src e às vezes limpa o sck: ligar só pelo id deixava a
// venda "sem origem" e a ficha dizendo "não comprou nesta jornada" de quem
// comprou. Agora, em ordem, parando no primeiro que achar:
//   1. sck/src com o id do visitante (o pixel põe no link do checkout)
//   2. e-mail  3. telefone  4. documento — cada um liga ao lead, e o lead ao
//      visitante mais recente dele (o lead nasce dos eventos do checkout:
//      pix gerado, carrinho abandonado, com sck, deixam o e-mail ligado)
//   5. nada → sem origem, com o motivo
// Crédito: o último toque PAGO do visitante nos 7 dias antes da venda.
// Recuperação (ligação, WhatsApp, e-mail) ajuda, mas nunca leva o crédito.
const _DOC_CAMPOS = ['customer.doc', 'customer.document', 'customer.cpf', 'customer.tax_id',
                     'customer.identification', 'cliente.cpf', 'cliente.documento', 'buyer.document'];
const _LIQ_CAMPOS = ['transaction.net_price', 'transaction.net_amount', 'transaction.seller_price',
                     'commission.net', 'net_amount', 'valor_liquido'];
function _pedidoRegistrar(venda, p, opts) {
  const db = _pessoas(); if (!db || !venda) return null;
  opts = opts || {};
  const em = Date.parse(venda.recebidoEm) || Date.now();
  // venda antiga sem status valia como paga (tudo contava); sem valor, não
  const stV = String(venda.status || '').trim();
  const pago = stV ? _PAGO.test(stV) : Number(venda.valor) > 0;
  const estorno = _ESTORNO.test(String(venda.status || '')) ? 1 : 0;
  const payload = p || {};
  const txt = (v, n) => { const s = String(v == null ? '' : v).trim(); return s ? s.slice(0, n || 120) : null; };

  // ── o lead: quem é, pelos dados que o checkout manda ──
  const email = String(venda.email || '').trim().toLowerCase();
  const eh = email.indexOf('@') > 0 ? _hashCurto(_pSal + '|e|' + email) : '';
  const tel = _telNorm(venda.telefone);
  const th = tel ? _hashCurto(_pSal + '|t|' + tel) : '';
  const doc = String(_pega(payload, _DOC_CAMPOS) || '').replace(/\D/g, '');
  const dh = doc.length >= 11 ? _hashCurto(_pSal + '|d|' + doc) : '';

  let resultado = null;
  db.exec('BEGIN');
  try {
    let lead = null;
    if (eh) lead = _q('SELECT id FROM leads WHERE email_h=? LIMIT 1').get(eh);
    if (!lead && th) lead = _q('SELECT id FROM leads WHERE tel_h=? LIMIT 1').get(th);
    if (!lead && dh) lead = _q('SELECT id FROM leads WHERE doc_h=? LIMIT 1').get(dh);
    let leadId = lead ? lead.id : null;
    if (!leadId && (eh || th || dh)) {
      leadId = 'L' + (eh || th || dh).slice(0, 16);
      _q('INSERT OR IGNORE INTO leads(id, email_h, tel_h, doc_h, email_mask, nome, criado) VALUES(?,?,?,?,?,?,?)')
        .run(leadId, eh || null, th || null, dh || null, _mascEmail(email) || null,
             venda.cliente ? _iniciais(venda.cliente) : null, em);
    } else if (leadId) {
      _q(`UPDATE leads SET email_h=COALESCE(email_h, ?), tel_h=COALESCE(tel_h, ?), doc_h=COALESCE(doc_h, ?),
            email_mask=COALESCE(email_mask, ?), nome=COALESCE(nome, ?) WHERE id=?`)
        .run(eh || null, th || null, dh || null, _mascEmail(email) || null,
             venda.cliente ? _iniciais(venda.cliente) : null, leadId);
    }

    // ── casamento em camadas ──
    let vis = '', casou = '';
    if (venda.vid) { vis = String(venda.vid).slice(0, 40); casou = 'sck'; }
    const porLead = (col, h) => h ? _q(`SELECT lv.visitante FROM leads l JOIN lead_visitante lv ON lv.lead = l.id
        LEFT JOIN visitantes v ON v.id = lv.visitante WHERE l.${col} = ? ORDER BY v.ultimo DESC LIMIT 1`).get(h) : null;
    if (!vis) { const r = porLead('email_h', eh); if (r) { vis = r.visitante; casou = 'email'; } }
    if (!vis) { const r = porLead('tel_h', th);   if (r) { vis = r.visitante; casou = 'telefone'; } }
    if (!vis) { const r = porLead('doc_h', dh);   if (r) { vis = r.visitante; casou = 'documento'; } }
    if (vis && leadId) {
      _q('INSERT OR IGNORE INTO lead_visitante(lead, visitante, por, em) VALUES(?,?,?,?)').run(leadId, vis, casou, em);
      _q('UPDATE visitantes SET lead=COALESCE(lead, ?) WHERE id=?').run(leadId, vis);
    }

    // ── crédito ──
    const canais = _canaisCache();
    let cred = null, sessaoRef = null;
    if (vis) {
      const ss = _q(`SELECT id, fonte, midia, camp, cont, termo, inicio, funil, teste, variante FROM sessoes
                     WHERE visitante=? AND inicio<=? AND inicio>=? ORDER BY inicio DESC LIMIT 60`)
        .all(vis, em + 60000, em - JANELA_CREDITO_DIAS * 86400000);
      sessaoRef = ss[0] || null;
      for (const s of ss) {
        const c = _canalDe(s.fonte, canais);
        if (c && c.anuncios && !c.apoio) { cred = { fonte: s.fonte, camp: s.camp, cont: s.cont, canal: c.id, s }; break; }
      }
      if (!cred) {
        // sem anúncio no caminho: fica com o último toque que não é de apoio
        for (const s of ss) {
          const c = _canalDe(s.fonte, canais);
          if (c && c.apoio) continue;
          cred = { fonte: s.fonte || 'direto', camp: s.camp, cont: s.cont, canal: c ? c.id : (s.fonte ? 'outro' : 'direto'), s };
          break;
        }
      }
    }
    const cVenda = _canalDe(venda.utmSource, canais);
    if (!cred && _origemVale(venda.utmSource) && !(cVenda && cVenda.apoio)) {
      cred = { fonte: venda.utmSource, camp: venda.utmCampaign, cont: venda.utmContent, canal: cVenda ? cVenda.id : 'outro' };
    }
    const apoio = (cVenda && cVenda.apoio) ? cVenda.nome : null;

    // ── sem origem: por quê ──
    let semOrigem = null;
    if (!cred && !venda.renovacao) {
      const utmTxt = [venda.utmSource, venda.utmCampaign, venda.utmContent, venda.utmTerm].join(' ');
      if (/\{\{/.test(utmTxt)) semOrigem = 'UTM com macro vazia';
      else if (vis) semOrigem = 'Jornada expirou (> 7 dias)';
      else if (apoio) semOrigem = null;          // veio pela recuperação: aparece como apoio
      else if (/^organic/i.test(String(venda.utmSource || '').trim())) semOrigem = 'Checkout limpou o src/sck';
      else semOrigem = 'Sem id nem UTM';
    }

    // ── líquido: o que o gateway diz que fica; sem isso, a tela desconta a taxa ──
    const liq = _pegaCom(payload, _LIQ_CAMPOS);
    let liquido = _num(liq.valor);
    if (liquido !== null && /^transaction\./.test(liq.caminho)) liquido = liquido / 100;
    if (liquido !== null && Number(venda.valor) > 0 && liquido > Number(venda.valor) * 1.01) liquido = liquido / 100;

    const ref = (cred && cred.s) || sessaoRef || {};
    const idPed = venda.pedidoId ? (String(venda.pedidoId).slice(0, 60) + '|' + String(venda.status || '').slice(0, 30)) : venda.id;
    const ins = _q(`INSERT OR IGNORE INTO pedidos(id, pedido, status, pago, estorno, valor, liquido, produto, plano, metodo, motivo,
        visitante, lead, casou, sem_origem, sck, fonte, camp, cont, termo, cred_fonte, cred_camp, cred_cont, cred_canal, apoio,
        funil, teste, variante, renovacao, em, dia)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      idPed, txt(venda.pedidoId, 60), txt(venda.status, 30), pago ? 1 : 0, estorno,
      Number(venda.valor) || 0, liquido, txt(venda.produto, 120), txt(venda.plano, 80), txt(venda.metodo, 30),
      pago ? null : txt(_motivoFalha(venda), 60),
      vis || null, leadId, casou || null, semOrigem, txt(venda.vid, 40),
      txt(venda.utmSource, 80), txt(venda.utmCampaign, 120), txt(venda.utmContent, 160), txt(venda.utmTerm, 80),
      cred ? txt(cred.fonte, 80) : null, cred ? txt(cred.camp, 120) : null, cred ? txt(cred.cont, 160) : null,
      cred ? cred.canal : null, apoio, ref.funil || null, ref.teste || null, ref.variante || null,
      venda.renovacao ? 1 : 0, em, _diaBR(em));

    if (ins.changes && vis) {
      const sid = sessaoRef ? sessaoRef.id : null;
      const rot = (txt(venda.produto, 60) || 'Pedido') + (Number(venda.valor) ? ' · R$ ' + Number(venda.valor).toFixed(2).replace('.', ',') : '');
      if (pago && !estorno) {
        _q('UPDATE visitantes SET compras=compras+1, pago=pago+?, compra_em=COALESCE(compra_em, ?), ult_tipo=?, ult_rot=?, ult_em=? WHERE id=?')
          .run(Number(venda.valor) || 0, em, 'compra', rot, em, vis);
      }
      _q('INSERT INTO eventos(sessao, visitante, funil, etapa, tipo, pg, em, rot, extra) VALUES(?,?,?,?,?,?,?,?,?)')
        .run(sid, vis, ref.funil || null, null, estorno ? 'estorno' : (pago ? 'compra' : 'tentativa'), null, em, rot,
             JSON.stringify({ status: venda.status || '', casou, metodo: venda.metodo || '',
                              motivo: pago ? '' : _motivoFalha(venda) }));
    }
    db.exec('COMMIT');
    resultado = { visitante: vis, casou, lead: leadId, semOrigem, cred: cred ? { fonte: cred.fonte, cont: cred.cont, canal: cred.canal } : null };
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (e2) {}
    console.error('[PESSOAS] pedido não gravou:', e.message);
    return null;
  }
  if (!opts.naoMexer && resultado) {
    // a venda do db.json passa a saber com quem casou — é o que o A/B e a
    // jornada antigos leem
    if (!venda.vid && resultado.visitante) venda.vid = resultado.visitante;
    if (resultado.casou === 'email' || resultado.casou === 'telefone' || resultado.casou === 'documento') venda.casadaPor = resultado.casou;
  }
  return resultado;
}

// ── Pitch das visitas que já chegaram ───────────────────────────────────────
// A visita guarda até que segundo do vídeo a pessoa foi. Quando o minuto do
// pitch de uma página muda (ou nunca tinha sido achado), refaz a marcação
// das visitas daquela página. Roda no boot e a cada 15 min; refaz tudo só
// da página cujo pitch mudou, e os últimos 3 dias das outras.
let _pitchAssinatura = {}, _pitchTimer = null;
function _pitchRecalcular() {
  const db = _pessoas(); if (!db) return;
  try {
    _fcCache.em = 0;
    const cache = _funisCache();
    const urls = {};
    Object.keys(cache.urlEtapa).forEach(u => { const p = cache.urlEtapa[u].pitch; if (p > 0) urls[u] = p; });
    const desde3 = Date.now() - 3 * 86400000;
    let marcadas = 0;
    db.exec('BEGIN');
    try {
      Object.keys(urls).forEach(u => {
        const p = urls[u], mudou = _pitchAssinatura[u] !== p;
        const desde = mudou ? 0 : desde3;
        // página com o próprio vídeo medido
        const r = _q(`UPDATE paginas SET pitch = CASE WHEN video >= ? THEN 1 ELSE 0 END WHERE pg = ? AND video > 0 AND em >= ?`).run(p, u, desde);
        // visitas de antes da medição por página: o vídeo da visita vale pra página de entrada dela
        const r2 = _q(`UPDATE paginas SET pitch = CASE WHEN (SELECT s.video FROM sessoes s WHERE s.id = paginas.sessao) >= ? THEN 1 ELSE 0 END
                       WHERE pg = ? AND video = 0 AND em >= ? AND sessao IN (SELECT s.id FROM sessoes s WHERE s.entrada = ? AND s.video > 0)`).run(p, u, desde, u);
        _q(`UPDATE sessoes SET pitch = CASE WHEN EXISTS (SELECT 1 FROM paginas x WHERE x.sessao = sessoes.id AND x.pitch = 1) THEN 1 ELSE 0 END
            WHERE id IN (SELECT sessao FROM paginas WHERE pg = ? AND em >= ?)`).run(u, desde);
        marcadas += (r.changes || 0) + (r2.changes || 0);
        _q(`UPDATE visitantes SET pitch_em = (SELECT MIN(s.fim) FROM sessoes s WHERE s.visitante = visitantes.id AND s.pitch = 1)
            WHERE id IN (SELECT DISTINCT visitante FROM paginas WHERE pg = ? AND em >= ?)`).run(u, mudou ? 0 : desde3);
        _pitchAssinatura[u] = p;
      });
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch (e2) {} throw e; }
    if (marcadas) console.log('[PESSOAS] pitch refeito em ' + marcadas + ' visita(s).');
  } catch (e) { console.error('[PESSOAS] recálculo do pitch falhou:', e.message); }
}
setTimeout(_pitchRecalcular, 60 * 1000);
setInterval(_pitchRecalcular, 15 * 60 * 1000);

// ── Importação do que já existe ─────────────────────────────────────────────
// Na primeira vez, a base nasce com a jornada dos últimos 7 dias e todas as
// vendas do webhook — senão a lista de Leads abriria vazia no dia do deploy.
function _pessoasImportar() {
  const db = _pessoas(); if (!db) return;
  if (_pCfg('importado_v1')) return;
  try {
    const t0 = Date.now();
    const dbj = readDB();
    const jn = Array.isArray(dbj.store[KEY_JORNADA]) ? dbj.store[KEY_JORNADA] : [];
    const evs = [];
    jn.forEach(j => (j.eventos || []).forEach(e => {
      const t = Date.parse(e.em); if (!Number.isFinite(t)) return;
      evs.push({ t, c: {
        id: j.id, funil: j.funil, etapa: e.etapa, tipo: e.tipo, pg: e.pg, segundos: e.segundos,
        rotulo: e.rotulo, motivo: e.motivo, versao: e.versao, teste: e.teste, variante: e.variante,
        utm: { source: e.origem, medium: e.midia, campaign: e.campanha, content: e.criativo },
        primeiro: e.primeiro || null, ref: e.ref,
        quem: (e.aparelho || e.navegador) ? { aparelho: e.aparelho, navegador: e.navegador, sistema: e.sistema, pais: e.pais } : null
      } });
    }));
    evs.sort((a, b) => a.t - b.t);
    evs.forEach(x => { try { _pxRegistrar(x.c, null, _pIntVis.has(String(x.c.id)) ? 'manual' : '', x.t); } catch (e) {} });
    _pSess.clear();
    const vendas = (Array.isArray(dbj.store[KEY_VENDAS]) ? dbj.store[KEY_VENDAS] : []).slice()
      .sort((a, b) => (Date.parse(a.recebidoEm) || 0) - (Date.parse(b.recebidoEm) || 0));
    vendas.forEach(v => { try { _pedidoRegistrar(Object.assign({}, v), null, { naoMexer: true }); } catch (e) {} });
    _pCfg('importado_v1', new Date().toISOString());
    console.log('[PESSOAS] importei ' + evs.length + ' eventos de ' + jn.length + ' jornadas e ' +
                vendas.length + ' vendas em ' + Math.round((Date.now() - t0) / 1000) + 's.');
  } catch (e) { console.error('[PESSOAS] importação falhou:', e.message); }
}
setTimeout(_pessoasImportar, 20 * 1000);

// ── Retenção e cópia ────────────────────────────────────────────────────────
// Evento vive 90 dias e sessão 12 meses; visitante, lead e pedido ficam. Se o
// disco apertar, o evento velho sai antes (o volume do Railway é pequeno e o
// db.json com os snapshots já ocupa a maior parte dele).
function _pessoasManter() {
  const db = _pessoas(); if (!db) return;
  try {
    const livre = _espacoLivreMB(DATA_DIR);
    const diasEv = (livre !== null && livre < 80) ? 21 : EVENTOS_DIAS;
    const agora = Date.now();
    const r1 = _q('DELETE FROM eventos WHERE em < ?').run(agora - diasEv * 86400000);
    const r2 = _q('DELETE FROM sessoes WHERE inicio < ?').run(agora - SESSOES_DIAS * 86400000);
    _q('DELETE FROM paginas WHERE em < ?').run(agora - SESSOES_DIAS * 86400000);
    if (r1.changes || r2.changes) console.log('[PESSOAS] retenção: ' + r1.changes + ' eventos e ' + r2.changes + ' sessões antigas saíram.');
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } catch (e) { console.error('[PESSOAS] manutenção falhou:', e.message); }
}
setInterval(_pessoasManter, 6 * 60 * 60 * 1000);

// Cópia diária compactada ao lado dos snapshots do db.json (a base não entra
// neles). Fica só a de hoje e a de ontem; se o disco estiver apertado, pula.
async function _pessoasCopia() {
  const db = _pessoas(); if (!db) return;
  try {
    const livre = _espacoLivreMB(DATA_DIR);
    let tam = 0; try { tam = fs.statSync(PESSOAS_ARQ).size / (1024 * 1024); } catch (e) {}
    if (livre !== null && livre < tam * 2 + 60) { console.warn('[PESSOAS] sem espaço pra cópia de hoje.'); return; }
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const dia = _diaBR(Date.now()).replace(/-/g, '');
    const alvo = path.join(BACKUP_DIR, 'pessoas-' + dia + '.sqlite.gz');
    if (fs.existsSync(alvo)) return;
    const tmp = path.join(BACKUP_DIR, 'pessoas-tmp.sqlite');
    try { fs.unlinkSync(tmp); } catch (e) {}
    db.exec("VACUUM INTO '" + tmp.replace(/'/g, "''") + "'");
    await new Promise((ok, erro) => {
      fs.createReadStream(tmp).pipe(require('zlib').createGzip()).pipe(fs.createWriteStream(alvo))
        .on('finish', ok).on('error', erro);
    });
    try { fs.unlinkSync(tmp); } catch (e) {}
    fs.readdirSync(BACKUP_DIR).filter(f => /^pessoas-\d{8}\.sqlite\.gz$/.test(f)).sort().reverse().slice(2)
      .forEach(f => { try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch (e) {} });
  } catch (e) { console.error('[PESSOAS] cópia falhou:', e.message); }
}
setInterval(_pessoasCopia, 6 * 60 * 60 * 1000);
setTimeout(_pessoasCopia, 10 * 60 * 1000);

// ══════════════════════════════════════════════════════
// ── ESCOPO DO FUNIL: uma regra só pra todas as telas ──
// "Chegaram 7" no topo contra 3.389 na Jornada: cada tela decidia sozinha o
// que era do funil. Agora o topo, o Resultado, o Mapa e os Leads perguntam
// aqui. A URL cadastrada na etapa manda; etapa sem URL (ou com URL que nunca
// apareceu, digitada errada) aceita pelo data-e do pixel deste funil; página
// ignorada não conta. O resto que tem o pixel deste funil é "fora do mapa".
// ══════════════════════════════════════════════════════
function _escopoFunil(dbj, funilId) {
  const f = (Array.isArray(dbj.store[KEY_FUNIS]) ? dbj.store[KEY_FUNIS] : []).find(x => x && x.id === funilId);
  if (!f || !_pessoas()) return null;
  const ids = new Set([f.id]);
  const ado = _adocoes(dbj).filter(a => a.funil === f.id);
  ado.forEach(a => { if (a.origemFunil) ids.add(a.origemFunil); });
  const etapaDeUrl = {}, etapaDeData = {}, tipoEtapa = {}, nomeEtapa = {};
  (f.etapas || []).forEach(e => {
    tipoEtapa[e.id] = e.tipo || 'pagina'; nomeEtapa[e.id] = e.nome || '';
    const urls = [e.url].concat(Array.isArray(e.urls) ? e.urls : []).map(_normPg).filter(Boolean);
    let viu = false;
    urls.forEach(u => { if (_q('SELECT 1 FROM paginas WHERE pg=? LIMIT 1').get(u)) { etapaDeUrl[u] = e.id; viu = true; } });
    if (!viu) {
      etapaDeData[e.id] = e.id;
      urls.forEach(u => { etapaDeUrl[u] = e.id; });   // ainda sem tráfego: vale quando chegar
    }
  });
  ado.forEach(a => { if (etapaDeData[a.etapa] && a.origemEtapa) etapaDeData[a.origemEtapa] = a.etapa; });
  // Bloco de teste A/B no desenho: as páginas das variantes dele são deste
  // funil, mesmo sem um bloco próprio. Sem isso, quem entrava pelo /r/bio
  // ficava fora da conta do funil (e a venda dele também).
  const redirs = Array.isArray(dbj.store[KEY_REDIRS]) ? dbj.store[KEY_REDIRS] : [];
  (f.etapas || []).filter(e => e.tipo === 'split' && e.slug).forEach(e => {
    const r = redirs.find(x => String(x.slug || '').toLowerCase() === String(e.slug).toLowerCase());
    ((r && r.destinos) || []).forEach(d => { const u = _normPg(d.url); if (u && !etapaDeUrl[u]) etapaDeUrl[u] = e.id; });
    tipoEtapa[e.id] = 'split';
  });
  const ignoradas = new Set((Array.isArray(f.paginasIgnoradas) ? f.paginasIgnoradas : []).map(_normPg).filter(Boolean));
  return { f, ids: [...ids], etapaDeUrl, etapaDeData, ignoradas, tipoEtapa, nomeEtapa };
}
const _ph = n => new Array(n).fill('?').join(',');
// pedaço de WHERE que diz "esta linha de páginas é do mapa deste funil"
function _escopoSql(esc, a) {
  a = a || 'p';
  const urls = Object.keys(esc.etapaDeUrl), dados = Object.keys(esc.etapaDeData);
  const partes = [], args = [];
  if (urls.length) { partes.push(a + '.pg IN (' + _ph(urls.length) + ')'); args.push(...urls); }
  if (dados.length) {
    partes.push('(' + a + '.funil IN (' + _ph(esc.ids.length) + ') AND ' + a + '.etapa IN (' + _ph(dados.length) + '))');
    args.push(...esc.ids, ...dados);
  }
  let where = partes.length ? '(' + partes.join(' OR ') + ')' : '0';
  const ign = [...esc.ignoradas];
  if (ign.length) { where += ' AND ' + a + '.pg NOT IN (' + _ph(ign.length) + ')'; args.push(...ign); }
  return { where, args };
}
// qual etapa daqui uma linha de páginas representa
function _etapaDaLinha(esc, pg, etapa) {
  return esc.etapaDeUrl[pg] || esc.etapaDeData[etapa] || null;
}
function _periodoMs(de, ate) {
  const ini = /^\d{4}-\d{2}-\d{2}$/.test(de) ? Date.parse(de + 'T00:00:00-03:00') : Date.now() - 7 * 86400000;
  const fim = /^\d{4}-\d{2}-\d{2}$/.test(ate) ? Date.parse(ate + 'T23:59:59.999-03:00') : Date.now();
  return { ini, fim, de: _diaBR(ini), ate: _diaBR(fim) };
}

// ══════════════════════════════════════════════════════
// ── LEADS ──
// Todas as pessoas do funil, sem o teto de 4.000. Busca, filtros e atalhos
// ("checkout e não comprou"). A paginação é no servidor: 78 mil linhas não
// cabem numa resposta, e nem precisam.
// ══════════════════════════════════════════════════════
function _leadsFiltro(req, esc) {
  const q = req.query || {};
  const per = _periodoMs(String(q.de || ''), String(q.ate || ''));
  const esq = _escopoSql(esc, 'p');
  const modo = ['atividade', 'primeiro', 'compra'].includes(q.quando) ? q.quando : 'atividade';
  const onde = [], args = [];
  // quem é do funil: esteve numa página do mapa (no período, no modo padrão)
  if (modo === 'atividade') {
    onde.push('v.id IN (SELECT DISTINCT p.visitante FROM paginas p WHERE p.dia BETWEEN ? AND ? AND ' + esq.where + ')');
    args.push(per.de, per.ate, ...esq.args);
  } else {
    onde.push('v.id IN (SELECT DISTINCT p.visitante FROM paginas p WHERE ' + esq.where + ')');
    args.push(...esq.args);
    onde.push(modo === 'primeiro' ? 'v.primeiro BETWEEN ? AND ?' : 'v.compra_em BETWEEN ? AND ?');
    args.push(per.ini, per.fim);
  }
  const base = { onde: onde.slice(), args: args.slice() };   // pros cards: sem os filtros da lista
  const interno = String(q.interno || '');
  if (interno === '1') onde.push('v.interno=1');
  else if (interno !== 'todos') onde.push('v.interno=0');
  const st = String(q.status || '');
  if (st === 'comprador') onde.push('v.compras>0');
  if (st === 'checkout') onde.push('v.checkout_em IS NOT NULL AND v.compras=0');
  if (st === 'identificado') onde.push('v.lead IS NOT NULL AND v.compras=0 AND v.checkout_em IS NULL');
  if (st === 'anonimo') onde.push('v.lead IS NULL AND v.compras=0 AND v.checkout_em IS NULL');
  if (q.checkout === 'sim') onde.push('v.checkout_em IS NOT NULL');
  if (q.checkout === 'nao') onde.push('v.checkout_em IS NULL');
  if (q.pitch === 'sim') onde.push('v.pitch_em IS NOT NULL');
  if (q.pitch === 'nao') onde.push('v.pitch_em IS NULL');
  if (q.pitch === 'hoje') { onde.push('v.pitch_em >= ?'); args.push(Date.parse(_diaBR(Date.now()) + 'T00:00:00-03:00')); }
  if (q.anuncio) { onde.push('(v.p_cont LIKE ? OR v.u_cont LIKE ?)'); const a = '%' + String(q.anuncio).slice(0, 80) + '%'; args.push(a, a); }
  if (q.pagina) { onde.push('EXISTS (SELECT 1 FROM paginas p2 WHERE p2.visitante=v.id AND p2.pg=?)'); args.push(_normPg(q.pagina)); }
  if (q.etapa) {
    const urls = Object.keys(esc.etapaDeUrl).filter(u => esc.etapaDeUrl[u] === q.etapa);
    const dados = Object.keys(esc.etapaDeData).filter(k => esc.etapaDeData[k] === q.etapa);
    const ps = [], pa = [];
    if (urls.length) { ps.push('p3.pg IN (' + _ph(urls.length) + ')'); pa.push(...urls); }
    if (dados.length) { ps.push('(p3.funil IN (' + _ph(esc.ids.length) + ') AND p3.etapa IN (' + _ph(dados.length) + '))'); pa.push(...esc.ids, ...dados); }
    onde.push(ps.length ? 'EXISTS (SELECT 1 FROM paginas p3 WHERE p3.visitante=v.id AND p3.dia BETWEEN ? AND ? AND (' + ps.join(' OR ') + '))' : '0');
    if (ps.length) args.push(per.de, per.ate, ...pa);
  }
  if (q.origem) {
    const canal = _canaisCache().find(c => c.id === q.origem);
    if (q.origem === 'sem') onde.push("(v.p_fonte IS NULL OR v.p_fonte='')");
    else if (canal) {
      const ps = [];
      (canal.fontes || []).forEach(x => {
        const y = _nrm(x); if (!y) return;
        if (y.slice(-1) === '*') { ps.push('lower(v.p_fonte) LIKE ?'); args.push(y.slice(0, -1) + '%'); }
        else { ps.push('lower(v.p_fonte) = ?'); args.push(y); }
      });
      onde.push(ps.length ? '(' + ps.join(' OR ') + ')' : '0');
    }
  }
  const busca = String(q.q || '').trim().slice(0, 120);
  if (busca) {
    const dig = busca.replace(/\D/g, '');
    if (busca.indexOf('@') > 0) {
      onde.push('v.lead IN (SELECT id FROM leads WHERE email_h=?)'); args.push(_hashCurto(_pSal + '|e|' + busca.toLowerCase()));
    } else if (dig.length >= 10 && /^[\d\s()+-]+$/.test(busca)) {
      onde.push('v.lead IN (SELECT id FROM leads WHERE tel_h=?)'); args.push(_hashCurto(_pSal + '|t|' + _telNorm(dig)));
    } else if (/^#?v?[a-z0-9]{4,}$/i.test(busca) && !/\s/.test(busca)) {
      const t = busca.replace(/^#/, '').toLowerCase();
      onde.push('(v.id LIKE ? OR v.id LIKE ? OR v.lead IN (SELECT id FROM leads WHERE nome LIKE ?))');
      args.push(t + '%', '%' + t, '%' + busca + '%');
    } else {
      onde.push('v.lead IN (SELECT id FROM leads WHERE nome LIKE ?)'); args.push('%' + busca + '%');
    }
  }
  return { onde, args, base, per };
}
// o que a lista mostra de cada pessoa
function _leadLinha(r, suspeitos) {
  const st = r.compras > 0 ? 'comprador' : (r.checkout_em ? 'checkout' : (r.lead ? 'identificado' : 'anonimo'));
  return {
    id: r.id, nome: r.nome || '', email: r.email_mask || '', status: st,
    toque: { fonte: r.p_fonte || '', cont: r.p_cont || '', camp: r.p_camp || '', em: r.p_em || r.primeiro },
    ultimo: { tipo: r.ult_tipo || '', rot: r.ult_rot || '', em: r.ult_em || r.ultimo, pg: r.ult_pg || '' },
    video: r.video || 0, pitch: !!r.pitch_em, visitas: r.sessoes || 0, pago: r.pago || 0,
    primeiro: r.primeiro, interno: !!r.interno, suspeito: !!(suspeitos && suspeitos.has(r.id))
  };
}
// "interno?": mais de 30 visitas em 14 dias, 3 páginas ou mais, e nunca comprou
function _suspeitosDe(ids) {
  const out = new Set();
  if (!ids.length) return out;
  _q('SELECT s.visitante, COUNT(*) n FROM sessoes s WHERE s.visitante IN (' + _ph(ids.length) + ') AND s.inicio > ? GROUP BY s.visitante HAVING n > 30')
    .all(...ids, Date.now() - 14 * 86400000).forEach(r => {
      const pgs = _q('SELECT COUNT(DISTINCT pg) n FROM paginas WHERE visitante=?').get(r.visitante);
      const v = _q('SELECT compras FROM visitantes WHERE id=?').get(r.visitante);
      if (pgs && pgs.n >= 3 && v && !v.compras) out.add(r.visitante);
    });
  return out;
}

app.get('/api/funil/pessoas', authUsuario, (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const fl = _leadsFiltro(req, esc);
    const por = [20, 50, 100].includes(Number(req.query.por)) ? Number(req.query.por) : 20;
    const pag = Math.max(1, parseInt(req.query.pag, 10) || 1);
    const ordem = { recente: 'v.ultimo DESC', primeiro: 'v.primeiro DESC', pago: 'v.pago DESC, v.ultimo DESC',
                    visitas: 'v.sessoes DESC', video: 'v.video DESC' }[req.query.ordem] || 'v.ultimo DESC';
    const where = fl.onde.join(' AND ');
    const total = _q('SELECT COUNT(*) n FROM visitantes v WHERE ' + where).get(...fl.args).n;
    const linhas = _q('SELECT v.*, l.nome, l.email_mask FROM visitantes v LEFT JOIN leads l ON l.id = v.lead WHERE ' +
                      where + ' ORDER BY ' + ordem + ' LIMIT ? OFFSET ?').all(...fl.args, por, (pag - 1) * por);
    const sus = _suspeitosDe(linhas.filter(r => !r.interno).map(r => r.id));
    // cards: o funil inteiro no período, sem os filtros da lista
    const bw = fl.base.onde.join(' AND ');
    const c = _q(`SELECT
        SUM(CASE WHEN v.interno=0 THEN 1 ELSE 0 END) pessoas,
        SUM(CASE WHEN v.interno=0 AND v.lead IS NOT NULL THEN 1 ELSE 0 END) identificadas,
        SUM(CASE WHEN v.interno=0 AND v.compras>0 THEN 1 ELSE 0 END) compradores,
        SUM(CASE WHEN v.interno=0 AND v.checkout_em IS NOT NULL AND v.compras=0 THEN 1 ELSE 0 END) checkout,
        SUM(CASE WHEN v.interno=1 THEN 1 ELSE 0 END) internos
      FROM visitantes v WHERE ` + bw).get(...fl.base.args);
    // gente em páginas com o pixel deste funil que não são etapa
    const esq = _escopoSql(esc, 'p');
    const fora = _q('SELECT COUNT(DISTINCT p.visitante) n FROM paginas p WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND p.funil IN (' +
                    _ph(esc.ids.length) + ') AND NOT ' + esq.where).get(fl.per.de, fl.per.ate, ...esc.ids, ...esq.args).n;
    res.json({ ok: true, total, pag, por, cards: {
        pessoas: c.pessoas || 0, identificadas: c.identificadas || 0, compradores: c.compradores || 0,
        checkoutSemCompra: c.checkout || 0, internos: c.internos || 0, foraDoMapa: fora || 0 },
      // valor de venda é da Diretoria (igual sl_vendas): os outros veem só que comprou
      linhas: linhas.map(r => { const l = _leadLinha(r, sus); if (!_ehDir(req)) { l.pago = l.pago > 0 ? true : 0; l.ultimo.rot = _semValor(l.ultimo.rot); } return l; }) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Exportar: a mesma lista, com os mesmos filtros, em CSV (até 50 mil linhas)
app.get('/api/funil/pessoas.csv', authUsuario, (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).send('Base de pessoas indisponível.');
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).send('Funil não encontrado.');
    const fl = _leadsFiltro(req, esc);
    const linhas = _q('SELECT v.*, l.nome, l.email_mask FROM visitantes v LEFT JOIN leads l ON l.id = v.lead WHERE ' +
                      fl.onde.join(' AND ') + ' ORDER BY v.ultimo DESC LIMIT 50000').all(...fl.args);
    const cel = x => { const s = String(x == null ? '' : x); return /[;"\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const dt = ms => ms ? new Date(ms - 3 * 3600000).toISOString().slice(0, 16).replace('T', ' ') : '';
    const out = ['id;nome;email;status;fonte;anuncio;campanha;ultimo_evento;ultimo_em;video_seg;passou_pitch;visitas;total_pago;primeiro_contato;interno'];
    linhas.forEach(r => {
      const l = _leadLinha(r);
      out.push([l.id, l.nome, l.email, l.status, l.toque.fonte, l.toque.cont, l.toque.camp, l.ultimo.tipo + (l.ultimo.rot ? ' ' + l.ultimo.rot : ''),
                dt(l.ultimo.em), l.video, l.pitch ? 'sim' : 'nao', l.visitas, String(l.pago.toFixed(2)).replace('.', ','),
                dt(l.primeiro), l.interno ? 'sim' : 'nao'].map(cel).join(';'));
    });
    const db = readDB();
    audit(db, 'leads_exportados', { funil: esc.f.id }, { linhas: linhas.length }, req.user);
    writeDB(db);
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Content-Disposition', 'attachment; filename="leads-' + String(esc.f.nome || 'funil').replace(/[^\w-]+/g, '-').slice(0, 40) + '.csv"');
    res.send('﻿' + out.join('\n'));
  } catch (e) { res.status(500).send(e.message); }
});

// ══════════════════════════════════════════════════════
// ── FICHA DA PESSOA ──
// Lê sessões + pedidos, não a jornada de 7 dias: lead de 60 dias atrás
// continua abrindo inteiro.
// ══════════════════════════════════════════════════════
function _resumoDaPessoa(v, evs, peds, nomeEtapa) {
  const curto = s => String(s || '').split('|')[0].trim().slice(0, 40);
  const frases = [];
  let a = '';
  if (v.p_cont) a = 'Veio do ' + curto(v.p_cont);
  else if (v.p_fonte) a = 'Veio de ' + curto(v.p_fonte);
  else a = 'Chegou direto';
  if (v.video >= 60) a += ', assistiu ' + Math.round(v.video / 60) + ' min' + (v.pitch_em ? ' e passou do pitch' : '');
  else if (v.video > 0) a += ', deu play e parou antes de 1 min';
  const morto = evs.filter(e => e.tipo === 'friccao' && /morto|raiva/.test(e.extra || '')).map(e => e.rot).filter(Boolean);
  if (morto.length) a += ', travou em "' + morto[0] + '"';
  const recusas = peds.filter(p => !p.pago && /cart|recus/i.test(p.motivo || ''));
  if (recusas.length) a += ', tentou ' + (recusas[0].produto || 'comprar') + ' e foi recusado' + (recusas[0].motivo ? ' (' + recusas[0].motivo.toLowerCase() + ')' : '');
  const pagos = peds.filter(p => p.pago && !p.estorno);
  if (pagos.length) a += (recusas.length ? ' e fechou ' : ', comprou ') + (pagos[0].produto || 'o produto') +
                         (pagos[0].metodo ? ' no ' + (/pix/.test(pagos[0].metodo) ? 'pix' : /card|cart/.test(pagos[0].metodo) ? 'cartão' : pagos[0].metodo) : '');
  else if (v.checkout_em) a += ', abriu o checkout e não comprou';
  frases.push(a + '.');
  let s = '';
  if (morto.length) s = 'Sinal: "' + morto[0] + '" parece clicável e não é.';
  else if (v.checkout_em && !pagos.length) s = 'Sinal: está na fila de recuperação.';
  else if (v.pitch_em && !v.checkout_em) s = 'Sinal: viu a oferta e não clicou em comprar.';
  else if (!v.video && !v.checkout_em && !pagos.length && v.sessoes <= 1) s = 'Sinal: saiu antes do vídeo começar.';
  if (s) frases.push(s);
  return frases.join(' ');
}

app.get('/api/pessoa/:id', authUsuario, (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const id = String(req.params.id || '').slice(0, 40);
    const v = _q('SELECT * FROM visitantes WHERE id=?').get(id);
    if (!v) return res.status(404).json({ error: 'Pessoa não encontrada.' });
    const lead = v.lead ? _q('SELECT id, nome, email_mask, email_h, tel_h FROM leads WHERE id=?').get(v.lead) : null;
    const outros = v.lead ? _q('SELECT visitante FROM lead_visitante WHERE lead=? AND visitante<>?').all(v.lead, id).map(r => r.visitante) : [];
    const peds = _q('SELECT * FROM pedidos WHERE visitante=? OR (lead IS NOT NULL AND lead=?) ORDER BY em DESC LIMIT 40').all(id, v.lead || '');
    const sessoes = _q('SELECT * FROM sessoes WHERE visitante=? ORDER BY inicio DESC LIMIT 20').all(id);
    const evs = _q('SELECT * FROM eventos WHERE visitante=? ORDER BY em ASC LIMIT 600').all(id);
    const dbj = readDB();
    const funis = Array.isArray(dbj.store[KEY_FUNIS]) ? dbj.store[KEY_FUNIS] : [];
    const nomeEtapa = {}; funis.forEach(f => (f.etapas || []).forEach(e => { nomeEtapa[e.id] = e.nome; }));
    const funil = funis.find(f => f.id === v.funil) || null;
    // contato completo só pra Diretoria: a lista mostra o e-mail mascarado
    let contato = null;
    if (req.user && req.user.cargo === 'Diretoria' && lead) {
      const vendas = Array.isArray(dbj.store[KEY_VENDAS]) ? dbj.store[KEY_VENDAS] : [];
      const achada = vendas.slice().reverse().find(x => {
        const e = String(x.email || '').trim().toLowerCase();
        if (lead.email_h && e && _hashCurto(_pSal + '|e|' + e) === lead.email_h) return true;
        const t = _telNorm(x.telefone);
        return !!(lead.tel_h && t && _hashCurto(_pSal + '|t|' + t) === lead.tel_h);
      });
      if (achada) contato = { email: achada.email || '', telefone: _telNorm(achada.telefone) || '', nome: achada.cliente || '' };
    }
    const dir = _ehDir(req);
    const pagos = peds.filter(p => p.pago && !p.estorno);
    const credito = pagos[0] ? { fonte: pagos[0].cred_fonte, camp: pagos[0].cred_camp, cont: pagos[0].cred_cont,
                                 canal: pagos[0].cred_canal, casou: pagos[0].casou, apoio: pagos[0].apoio } : null;
    const pitchSeg = (() => { const e = evs.find(x => x.tipo === 'pitch'); try { return e ? JSON.parse(e.extra || '{}').seg || 0 : 0; } catch (er) { return 0; } })();
    const visitas = sessoes.map(s => ({
      id: s.id, inicio: s.inicio, fim: s.fim, dur: s.dur, entrada: s.entrada, fonte: s.fonte, cont: s.cont, camp: s.camp,
      teste: s.teste, variante: s.variante, pitch: !!s.pitch, checkout: !!s.checkout, video: s.video, interno: !!s.interno,
      eventos: evs.filter(e => e.sessao === s.id).map(e => {
        let x = {}; try { x = JSON.parse(e.extra || '{}'); } catch (er) {}
        return { tipo: e.tipo, em: e.em, pg: e.pg, rot: dir ? e.rot : _semValor(e.rot), etapa: nomeEtapa[e.etapa] || '', extra: x };
      })
    }));
    // eventos sem sessão (venda que chegou quando a pessoa não estava no site)
    const soltos = evs.filter(e => !e.sessao || !sessoes.some(s => s.id === e.sessao)).map(e => {
      let x = {}; try { x = JSON.parse(e.extra || '{}'); } catch (er) {}
      return { tipo: e.tipo, em: e.em, pg: e.pg, rot: dir ? e.rot : _semValor(e.rot), etapa: nomeEtapa[e.etapa] || '', extra: x };
    });
    res.json({ ok: true,
      pessoa: { id: v.id, nome: (contato && contato.nome) ? _iniciais(contato.nome) : (lead && lead.nome) || '',
                email: lead ? lead.email_mask : '', status: v.compras > 0 ? 'comprador' : (v.checkout_em ? 'checkout' : (v.lead ? 'identificado' : 'anonimo')),
                primeiro: v.primeiro, ultimo: v.ultimo, eventos: v.eventos, sessoes: v.sessoes, interno: !!v.interno, internoPor: v.interno_por || '',
                aparelho: v.aparelho, sistema: v.sistema, navegador: v.navegador, pais: v.pais, tela: v.tela, outrosAparelhos: outros.length },
      contato,
      cards: { pago: dir ? (v.pago || 0) : null, compras: v.compras || 0, ateCompra: v.compra_em ? Math.max(0, v.compra_em - v.primeiro) : null,
               video: v.video || 0, pitch: !!v.pitch_em, pitchSeg, mortos: v.mortos || 0 },
      marcos: { visitou: v.primeiro, pitch: v.pitch_em, checkout: v.checkout_em, comprou: v.compra_em },
      funil: funil ? { id: funil.id, nome: funil.nome, versao: v.versao || '', teste: v.teste || '', variante: v.variante || '' } : null,
      atribuicao: {
        primeiro: { fonte: v.p_fonte, midia: v.p_midia, camp: v.p_camp, cont: v.p_cont, termo: v.p_termo, em: v.p_em },
        ultimo: v.u_em ? { fonte: v.u_fonte, midia: v.u_midia, camp: v.u_camp, cont: v.u_cont, termo: v.u_termo, em: v.u_em } : null,
        credito, regra: 'Crédito: último anúncio pago nos ' + JANELA_CREDITO_DIAS + ' dias antes da venda. Recuperação ajuda, mas não leva o crédito.',
        fbclid: !!v.fbclid, fbc: !!v.fbc, fbp: !!v.fbp },
      pedidos: peds.map(p => ({ id: p.id, pedido: p.pedido, status: p.status, pago: !!p.pago, estorno: !!p.estorno, valor: dir ? p.valor : null,
        produto: p.produto, plano: p.plano, metodo: p.metodo, motivo: p.motivo, casou: p.casou, em: p.em })),
      capi: { conectado: false, aviso: 'Envio de Purchase à Meta (CAPI) ainda não está ligado: precisa do token da Meta.' },
      visitas, soltos,
      resumo: _resumoDaPessoa(v, evs, peds, nomeEtapa) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const _ehDir = req => !!(req && req.user && req.user.cargo === 'Diretoria');
const _semValor = t => String(t || '').replace(/\s*·\s*R\$\s*[\d.,]+/g, '');
// "Ydeshi G. O.": o primeiro nome inteiro e as iniciais do resto
function _iniciais(n) {
  const p = String(n || '').trim().split(/\s+/).filter(Boolean);
  if (!p.length) return '';
  const cap = w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
  return [cap(p[0])].concat(p.slice(1).filter(w => w.length > 2).map(w => w.charAt(0).toUpperCase() + '.')).join(' ');
}

// Marcar como tráfego interno: sai de todas as métricas e do A/B, mas continua
// visível na lista com o filtro. Pode levar o IP junto (o resto do time que
// usa a mesma rede some também).
app.post('/api/pessoa/:id/interno', authDiretoria, (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const id = String(req.params.id || '').slice(0, 40);
    const v = _q('SELECT id, ip FROM visitantes WHERE id=?').get(id);
    if (!v) return res.status(404).json({ error: 'Pessoa não encontrada.' });
    const marcar = req.body && req.body.interno !== false;
    const comIp = !!(req.body && req.body.ip) && !!v.ip;
    const agora = Date.now(), por = (req.user && req.user.nome) || '';
    const db = _pessoas();
    db.exec('BEGIN');
    try {
      if (marcar) {
        _q('INSERT OR IGNORE INTO internos(tipo, valor, em, por) VALUES(?,?,?,?)').run('visitante', id, agora, por);
        _pIntVis.add(id);
        if (comIp) { _q('INSERT OR IGNORE INTO internos(tipo, valor, em, por) VALUES(?,?,?,?)').run('ip', v.ip, agora, por); _pIntIp.add(v.ip); }
      } else {
        _q("DELETE FROM internos WHERE tipo='visitante' AND valor=?").run(id); _pIntVis.delete(id);
        if (v.ip) { _q("DELETE FROM internos WHERE tipo='ip' AND valor=?").run(v.ip); _pIntIp.delete(v.ip); }
      }
      // o passado também: senão ele sai das contas só daqui pra frente
      const alvo = comIp ? _q('SELECT id FROM visitantes WHERE ip=?').all(v.ip).map(r => r.id) : [id];
      if (!alvo.includes(id)) alvo.push(id);
      const val = marcar ? 1 : 0;
      alvo.forEach(x => {
        _q('UPDATE visitantes SET interno=?, interno_por=? WHERE id=?').run(val, marcar ? (comIp ? 'ip' : 'manual') : null, x);
        _q('UPDATE sessoes SET interno=? WHERE visitante=?').run(val, x);
        _q('UPDATE paginas SET interno=? WHERE visitante=?').run(val, x);
      });
      db.exec('COMMIT');
      const dbj = readDB();
      audit(dbj, marcar ? 'trafego_interno_marcado' : 'trafego_interno_desmarcado', { visitante: id }, { ip: comIp, pessoas: alvo.length }, req.user);
      writeDB(dbj);
      res.json({ ok: true, interno: marcar, pessoas: alvo.length });
    } catch (e) { try { db.exec('ROLLBACK'); } catch (e2) {} throw e; }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── RESULTADO DO FUNIL ──
// O dinheiro do funil: o gasto das campanhas DESTE funil (pela regra de
// campanha da origem) contra as vendas que chegaram por ele. Antes o gasto
// vivia em Métricas de Ads, sem ligação nenhuma com o funil.
// ══════════════════════════════════════════════════════
// Gasto por campanha e por dia, guardado aqui: dia fechado não é buscado de
// novo; hoje e ontem são relidos a cada 10 min (a Meta fecha o dia atrasada).
async function _campDia(dia, projetoId, podeBuscar) {
  const proj = String(projetoId || '');
  const ok = _q('SELECT em FROM camp_dia_ok WHERE dia=? AND projeto=?').get(dia, proj);
  const recente = dia >= _diaBR(Date.now() - 86400000);
  const precisa = !ok || (recente && Date.now() - ok.em > 10 * 60000);
  const arquivo = () => _q('SELECT * FROM camp_dia WHERE dia=? AND projeto=?').all(dia, proj);
  if (!precisa) return { linhas: arquivo(), buscou: false };
  if (!podeBuscar) return { linhas: arquivo(), buscou: false, faltou: !ok };
  try {
    const achado = await _utmifyDashboardsAtivos();
    const lista = _filtrarProjeto(achado.lista, proj);
    const soma = {};
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      const r = await _utmifyChamarTool(achado.cfg.token, 'get_meta_ad_objects', {
        dashboardId: d.id, level: 'campaign', dateRange: { from: dia + 'T00:00:00' + off, to: dia + 'T23:59:59' + off } });
      ((r && r.results) || []).forEach(c => {
        const id = String(c.id || c.campaignId || c.name || '').slice(0, 40);
        if (!id) return;
        const x = soma[id] || (soma[id] = { id, nome: String(c.name || '').trim().slice(0, 160), conta: String(c.accountId || '').slice(0, 40), gasto: 0, imp: 0, cliques: 0 });
        x.gasto += (Number(c.spend) || 0) / 100; x.imp += Number(c.impressions) || 0; x.cliques += Number(c.inlineLinkClicks) || 0;
      });
    }
    const db = _pessoas();
    db.exec('BEGIN');
    try {
      _q('DELETE FROM camp_dia WHERE dia=? AND projeto=?').run(dia, proj);
      Object.values(soma).forEach(x => _q('INSERT INTO camp_dia(dia, projeto, id, nome, conta, gasto, imp, cliques) VALUES(?,?,?,?,?,?,?,?)')
        .run(dia, proj, x.id, x.nome, x.conta, x.gasto, x.imp, x.cliques));
      _q('INSERT INTO camp_dia_ok(dia, projeto, em) VALUES(?,?,?) ON CONFLICT(dia, projeto) DO UPDATE SET em=excluded.em').run(dia, proj, Date.now());
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch (e2) {} throw e; }
    return { linhas: arquivo(), buscou: true };
  } catch (e) {
    return { linhas: arquivo(), buscou: false, erro: e.message, faltou: !ok };
  }
}
const _campNaFila = new Set();
function _campAtualizarDepois(de, ate, proj) {
  const k = de + '|' + ate + '|' + proj;
  if (_campNaFila.has(k)) return;
  _campNaFila.add(k);
  _campanhasPeriodo(de, ate, proj, 3).catch(() => {}).then(() => _campNaFila.delete(k));
}
async function _campanhasPeriodo(de, ate, projetoId, maxBuscas) {
  const dias = [];
  for (let t = Date.parse(ate + 'T12:00:00Z'); dias.length < 400; t -= 86400000) {
    const d = new Date(t).toISOString().slice(0, 10);
    if (d < de) break;
    dias.push(d);
  }
  const porDia = {}; let buscas = 0, faltam = 0; const erros = [];
  for (const d of dias) {            // do mais recente pro mais antigo: o que importa chega antes
    const r = await _campDia(d, projetoId, buscas < (maxBuscas == null ? 8 : maxBuscas));
    if (r.buscou) buscas++;
    if (r.faltou) faltam++;
    if (r.erro && erros.indexOf(r.erro) < 0) erros.push(r.erro);
    porDia[d] = r.linhas;
  }
  return { porDia, faltam, erros };
}
// Que campanhas são deste funil: a regra do Resultado (se houver) ou a que
// está nas origens do mapa (campanha fixa ou "contém CONCURSO").
function _regraCampanhas(f) {
  const esc = f && f.escopoCampanhas;
  if (esc && esc.valor) {
    const v = String(esc.valor);
    if (esc.tipo === 'lista') { const l = v.split(/[\n,;]+/).map(_nrm).filter(Boolean); return n => l.includes(_nrm(n)); }
    if (esc.tipo === 'regex') { try { const re = new RegExp(v, 'i'); return n => re.test(String(n || '')); } catch (e) { return null; } }
    const r = _nrm(v); return n => _nrm(n).indexOf(r) >= 0;
  }
  const fontes = (f.fontes || []).concat((f.etapas || []).filter(e => e.tipo === 'fonte'));
  const fixas = fontes.map(x => x.utmCampanha).filter(Boolean).map(_nrm);
  const contem = fontes.map(x => x.utmRegra).filter(Boolean).map(_nrm);
  if (!fixas.length && !contem.length) return null;
  return n => { const x = _nrm(n); return fixas.includes(x) || contem.some(r => x.indexOf(r) >= 0); };
}
function _descRegra(f) {
  const esc = f && f.escopoCampanhas;
  if (esc && esc.valor) return esc.tipo === 'lista' ? 'lista de campanhas' : (esc.tipo === 'regex' ? 'regex ' + esc.valor : 'campanhas com “' + esc.valor + '”');
  const fontes = (f.fontes || []);
  const c = fontes.find(x => x.utmRegra); if (c) return 'campanhas com “' + c.utmRegra + '”';
  const x = fontes.find(y => y.utmCampanha); if (x) return 'campanha ' + x.utmCampanha;
  return '';
}
async function _projetoIdDoFunil(f) {
  try {
    const { lista } = await _utmifyDashboardsAtivos();
    const d = lista.find(x => String((x.nome || '').trim()) === String(f.projeto || '').trim());
    return d ? String(d.id) : '';
  } catch (e) { return ''; }
}
// Vendas pagas do período que são deste funil, e por onde cada uma entrou:
//   jornada  — a pessoa esteve numa página do mapa
//   campanha — sem pessoa, mas a campanha da UTM é deste funil
//   produto  — sem pessoa nem campanha, funil único do projeto e produto do projeto
function _vendasDoFunil(dbj, esc, per, nomeCampanha, regra) {
  const esq = _escopoSql(esc, 'p');
  const todos = _q('SELECT * FROM pedidos WHERE dia BETWEEN ? AND ? AND renovacao=0').all(per.de, per.ate);
  const cacheVis = {};
  const doFunil = vis => {
    if (cacheVis[vis] === undefined) cacheVis[vis] = !!_q('SELECT 1 FROM paginas p WHERE p.visitante=? AND ' + esq.where + ' LIMIT 1').get(vis, ...esq.args);
    return cacheVis[vis];
  };
  const funisDoProj = (Array.isArray(dbj.store[KEY_FUNIS]) ? dbj.store[KEY_FUNIS] : []).filter(x => x && x.projeto === esc.f.projeto);
  const produtos = _produtosCfg(dbj);
  const unico = funisDoProj.length === 1;
  const campDe = v => {
    const t = String(v || '').trim(); if (!t) return '';
    const partes = t.split('|').map(x => x.trim());
    for (const p of partes) { if (/^\d{6,}$/.test(p) && nomeCampanha[p]) return nomeCampanha[p]; }
    return partes[0];
  };
  const out = [];
  todos.forEach(o => {
    let por = '';
    if (o.visitante && doFunil(o.visitante)) por = 'jornada';
    else if (!o.visitante && regra) { const n = campDe(o.cred_camp || o.camp); if (n && regra(n)) por = 'campanha'; }
    if (!por && !o.visitante && unico) {
      const pr = _produtoDe(o.produto, produtos);
      if (pr ? (pr.projeto === esc.f.projeto) : !produtos.length) por = 'produto';
    }
    if (por) out.push(Object.assign({ por }, o));
  });
  return out;
}

// faturamento e margem: mesma regra de sl_vendas (Diretoria)
app.get('/api/funil/resultado', authDiretoria, async (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const f = esc.f, per = _periodoMs(String(req.query.de || ''), String(req.query.ate || ''));
    const custos = _custosCfg(dbj);

    // ── investimento: só as campanhas deste funil ──
    const projetoId = await _projetoIdDoFunil(f);
    const camp = await _campanhasPeriodo(per.de, per.ate, projetoId, Number(req.query.buscar) === 0 ? 0 : 8);
    const regra = _regraCampanhas(f);
    const nomeCampanha = {}, contas = new Set(), porDiaGasto = {};
    let gasto = 0, imp = 0, cliques = 0, campanhas = {};
    Object.keys(camp.porDia).forEach(d => camp.porDia[d].forEach(c => {
      nomeCampanha[c.id] = c.nome;
      if (regra && !regra(c.nome)) return;
      gasto += c.gasto; imp += c.imp; cliques += c.cliques;
      porDiaGasto[d] = (porDiaGasto[d] || 0) + c.gasto;
      if (c.conta && c.gasto > 0) contas.add(c.conta);
      const k = c.nome || c.id;
      const x = campanhas[k] || (campanhas[k] = { nome: c.nome, gasto: 0, cliques: 0, imp: 0 });
      x.gasto += c.gasto; x.cliques += c.cliques; x.imp += c.imp;
    }));

    // ── pessoas: a mesma contagem do topo, do Mapa e dos Leads ──
    const esq = _escopoSql(esc, 'p');
    const conta = extra => _q('SELECT COUNT(DISTINCT p.visitante) n FROM paginas p JOIN sessoes s ON s.id = p.sessao WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND ' +
                              esq.where + (extra || '')).get(per.de, per.ate, ...esq.args).n || 0;
    const chegaram = conta(), pitch = conta(' AND s.pitch=1');
    const ckSet = new Set(_q('SELECT DISTINCT p.visitante FROM paginas p JOIN sessoes s ON s.id = p.sessao WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND s.checkout=1 AND ' +
                             esq.where).all(per.de, per.ate, ...esq.args).map(r => r.visitante));
    const porDiaPessoas = {};
    _q('SELECT p.dia, COUNT(DISTINCT p.visitante) n FROM paginas p WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND ' + esq.where + ' GROUP BY p.dia')
      .all(per.de, per.ate, ...esq.args).forEach(r => { porDiaPessoas[r.dia] = r.n; });

    // ── vendas ──
    const vendas = _vendasDoFunil(dbj, esc, per, nomeCampanha, regra);
    const liq = o => (o.liquido != null ? o.liquido : (Number(o.valor) || 0) * (1 - (custos.gateway || 0) / 100));
    const pagas = vendas.filter(o => o.pago && !o.estorno);
    const estornos = vendas.filter(o => o.estorno);
    pagas.forEach(o => { if (o.visitante) ckSet.add(o.visitante); });
    const checkout = ckSet.size;
    const fat = pagas.reduce((a, o) => a + liq(o), 0);
    const reembolso = estornos.reduce((a, o) => a + (Number(o.valor) || 0), 0);
    const clientes = new Set(pagas.map(o => o.lead || o.visitante || o.pedido || o.id)).size;
    const produtos = _produtosCfg(dbj);
    const principal = produtos.find(p => p.papel === 'principal' && (p.projeto === f.projeto || p.projeto === projetoId));
    const doPrincipal = principal ? pagas.filter(o => { const pr = _produtoDe(o.produto, produtos); return pr && pr.id === principal.id; }) : pagas;
    const ticketPrincipal = doPrincipal.length ? doPrincipal.reduce((a, o) => a + liq(o), 0) / doPrincipal.length : 0;
    const saldo = fat - reembolso;
    const imposto = saldo * (custos.imposto || 0) / 100;
    const impostoFb = gasto * (custos.impostoAds || 0) / 100;
    const custoProduto = pagas.length * (custos.custoVenda || 0);
    const margem = saldo - imposto - gasto - impostoFb - custoProduto;
    const aliquota = (custos.imposto || 0) / 100;
    const roasEmpate = (1 + (custos.impostoAds || 0) / 100) / Math.max(0.05, 1 - aliquota);
    const roasAlvo = Number(f.roasAlvo) > 0 ? Number(f.roasAlvo) : Math.round(roasEmpate * 100) / 100;
    const porDiaVendas = {};
    pagas.forEach(o => { const x = porDiaVendas[o.dia] || (porDiaVendas[o.dia] = { n: 0, fat: 0 }); x.n++; x.fat += liq(o); });

    // ── etapas com custo e a maior queda ──
    const compraram = pagas.length;
    const etapas = [
      { k: 'impressoes', nome: 'Impressões', fonte: 'Meta', n: imp, custo: imp ? gasto / imp * 1000 : 0, rotCusto: 'CPM' },
      { k: 'cliques', nome: 'Cliques', fonte: 'Meta', n: cliques, custo: cliques ? gasto / cliques : 0, rotCusto: 'CPC' },
      { k: 'chegaram', nome: 'Chegaram na página', fonte: 'pixel TMX', n: chegaram, custo: chegaram ? gasto / chegaram : 0 },
      { k: 'pitch', nome: 'Passaram do pitch', fonte: 'Vturb', n: pitch, custo: pitch ? gasto / pitch : 0 },
      { k: 'checkout', nome: 'Abriram checkout', fonte: 'clique no botão', n: checkout, custo: checkout ? gasto / checkout : 0 },
      { k: 'compraram', nome: 'Compraram', fonte: 'webhook Payt', n: compraram, custo: compraram ? gasto / compraram : 0, rotCusto: 'CPA' }
    ];
    let queda = null;
    for (let i = 1; i < etapas.length; i++) {
      const a = etapas[i - 1], b = etapas[i];
      if (a.k === 'impressoes' || !a.n || (b.k === 'pitch' && !b.n)) continue;   // sem Vturb no funil, o pitch fica fora
      const de = (b.k === 'checkout' && !pitch) ? etapas[2] : a;
      const taxa = b.n / (de.n || 1);
      if (!queda || taxa < queda.taxa) queda = { de: de.k, para: b.k, deNome: de.nome, paraNome: b.nome, taxa };
    }
    if (queda) {
      const tent = _q('SELECT motivo, COUNT(*) n FROM pedidos WHERE dia BETWEEN ? AND ? AND pago=0 AND motivo IS NOT NULL GROUP BY motivo ORDER BY n DESC')
        .all(per.de, per.ate);
      const totT = tent.reduce((a, r) => a + r.n, 0), cartao = tent.filter(r => /cart/i.test(r.motivo)).reduce((a, r) => a + r.n, 0);
      if (queda.para === 'compraram') {
        queda.frase = totT ? (Math.round(cartao / totT * 10) + ' de cada 10 tentativas que não pagaram foram ' + (cartao / totT >= 0.5 ? 'cartão recusado' : 'pix ou boleto sem pagar') +
                        '. Veja quem abriu o checkout e não comprou antes de mexer em criativo.')
                     : 'Veja quem abriu o checkout e não comprou antes de mexer em criativo.';
        queda.acao = { rotulo: 'Ver checkout sem compra', aba: 'leads', filtro: { status: 'checkout' } };
      } else if (queda.para === 'chegaram') {
        queda.frase = Math.round((1 - queda.taxa) * 100) + '% de quem clica não chega na página. É redirect lento, página pesada ou pixel faltando.';
        queda.acao = { rotulo: 'Abrir Pixel e saúde', aba: 'pixel' };
      } else if (queda.para === 'pitch') {
        queda.frase = 'A VSL perde a maioria antes da oferta. Veja em que minuto eles saem.';
        queda.acao = { rotulo: 'Ver onde saem', aba: 'atencao' };
      } else if (queda.para === 'checkout') {
        queda.frase = 'Viram a oferta e não clicaram em comprar. Confira cliques mortos no botão e no card do plano.';
        queda.acao = { rotulo: 'Ver cliques', aba: 'atencao' };
      } else {
        queda.frase = 'Esta é a passagem que mais perde gente no período.';
      }
    }

    // ── por dia ──
    const dias = [];
    for (let t = Date.parse(per.de + 'T12:00:00Z'); ; t += 86400000) {
      const d = new Date(t).toISOString().slice(0, 10); if (d > per.ate || dias.length > 400) break;
      const g = porDiaGasto[d] || 0, v = porDiaVendas[d] || { n: 0, fat: 0 };
      dias.push({ dia: d, gasto: g, fat: v.fat, vendas: v.n, roas: g ? v.fat / g : 0, chegaram: porDiaPessoas[d] || 0 });
    }
    const notas = (Array.isArray(dbj.store[KEY_FUNIL_NOTAS]) ? dbj.store[KEY_FUNIL_NOTAS] : [])
      .filter(n => n.funil === f.id && n.dia >= per.de && n.dia <= per.ate);

    // ── vendas sem origem (do projeto, no período) ──
    const semOrigemTodas = _q("SELECT * FROM pedidos WHERE dia BETWEEN ? AND ? AND pago=1 AND estorno=0 AND renovacao=0 AND sem_origem IS NOT NULL")
      .all(per.de, per.ate).filter(o => { const pr = _produtoDe(o.produto, produtos); return !produtos.length || !pr || pr.projeto === f.projeto || pr.projeto === projetoId; });
    const motivos = {};
    semOrigemTodas.forEach(o => { const m = motivos[o.sem_origem] || (motivos[o.sem_origem] = { motivo: o.sem_origem, vendas: 0, valor: 0 }); m.vendas++; m.valor += Number(o.valor) || 0; });

    // ── por onde a venda chegou ──
    const canais = _canaisCache();
    const porCanal = {};
    pagas.forEach(o => {
      let k, nome, apoio = false;
      if (o.cred_canal) {
        const c = canais.find(x => x.id === o.cred_canal);
        k = o.cred_canal; nome = c ? c.nome : (o.cred_canal === 'direto' ? 'Direto' : (o.cred_fonte || 'Outro'));
        if (k === 'meta' && /^ig|insta/i.test(o.cred_fonte || '')) { k = 'meta_ig'; nome = 'Instagram'; }
        else if (k === 'meta') nome = 'Facebook';
      } else if (o.apoio) { k = 'apoio'; nome = o.apoio; apoio = true; }
      else { k = 'sem'; nome = 'Sem origem'; }
      const x = porCanal[k] || (porCanal[k] = { k, nome, vendas: 0, fat: 0, apoio });
      x.vendas++; x.fat += liq(o);
    });
    const gastoMeta = gasto;
    const fontes = Object.values(porCanal).sort((a, b) => b.fat - a.fat).map(x => Object.assign(x, {
      roas: (x.k === 'meta' || x.k === 'meta_ig') && gastoMeta ? x.fat / gastoMeta : null }));

    res.json({ ok: true, funil: { id: f.id, nome: f.nome }, de: per.de, ate: per.ate,
      regra: _descRegra(f), semRegra: !regra, contas: contas.size, faltamDias: camp.faltam, erros: camp.erros,
      cards: {
        investimento: gasto, faturamento: fat, vendas: pagas.length, roas: gasto ? fat / gasto : 0, roasAlvo, roasEmpate,
        margem, imposto, impostoFb, custoProduto, aliquota: custos.imposto || 0, aliquotaFb: custos.impostoAds || 0,
        cpa: doPrincipal.length ? gasto / doPrincipal.length : 0, vendasPrincipal: doPrincipal.length,
        principal: principal ? principal.nome : '', cpaMax: ticketPrincipal * (1 - aliquota) - (custos.custoVenda || 0),
        ticket: clientes ? fat / clientes : 0, clientes, cac: clientes ? gasto / clientes : 0,
        reembolso, reembolsoPct: (fat + reembolso) ? reembolso / (fat + reembolso) * 100 : 0, estornos: estornos.length,
        chargebacks: estornos.filter(o => /chargeback/i.test(o.status || '')).length,
        porJornada: vendas.filter(o => o.por === 'jornada' && o.pago).length,
        porCampanha: vendas.filter(o => o.por === 'campanha' && o.pago).length,
        porProduto: vendas.filter(o => o.por === 'produto' && o.pago).length
      },
      topo: { investido: gasto, cliques, chegaram, checkout, compraram },
      etapas, queda, dias, notas,
      semOrigem: { total: semOrigemTodas.length, motivos: Object.values(motivos).sort((a, b) => b.vendas - a.vendas) },
      fontes, campanhas: Object.values(campanhas).sort((a, b) => b.gasto - a.gasto).slice(0, 30) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Anotações da equipe no gráfico por dia ("trocou a VSL em 26/09")
const KEY_FUNIL_NOTAS = 'sl_funil_notas';
app.post('/api/funil/notas', authUsuario, (req, res) => {
  try {
    const b = req.body || {};
    const funil = String(b.funil || '').slice(0, 80), dia = String(b.dia || '').slice(0, 10), texto = String(b.texto || '').trim().slice(0, 140);
    if (!funil || !/^\d{4}-\d{2}-\d{2}$/.test(dia)) return res.status(400).json({ error: 'Informe o funil e o dia.' });
    const db = readDB();
    let l = Array.isArray(db.store[KEY_FUNIL_NOTAS]) ? db.store[KEY_FUNIL_NOTAS] : [];
    if (b.apagar) l = l.filter(n => n.id !== b.apagar);
    else {
      if (!texto) return res.status(400).json({ error: 'Escreva a anotação.' });
      l.push({ id: 'nt' + Date.now().toString(36), funil, dia, texto, autor: (req.user && req.user.nome) || '', em: new Date().toISOString() });
    }
    db.store[KEY_FUNIL_NOTAS] = l.slice(-2000);
    db.timestamps[KEY_FUNIL_NOTAS] = now();
    writeDB(db);
    res.json({ ok: true, notas: l.filter(n => n.funil === funil) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Vendas do funil ou sem origem, pra tela abrir a lista por trás do número
app.get('/api/funil/vendas-lista', authDiretoria, async (req, res) => {
  try {
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const per = _periodoMs(String(req.query.de || ''), String(req.query.ate || ''));
    let l;
    if (req.query.tipo === 'sem') {
      l = _q("SELECT * FROM pedidos WHERE dia BETWEEN ? AND ? AND pago=1 AND estorno=0 AND renovacao=0 AND sem_origem IS NOT NULL ORDER BY em DESC LIMIT 300").all(per.de, per.ate);
      if (req.query.motivo) l = l.filter(o => o.sem_origem === req.query.motivo);
    } else {
      l = _vendasDoFunil(dbj, esc, per, {}, _regraCampanhas(esc.f)).filter(o => o.pago && !o.estorno).sort((a, b) => b.em - a.em).slice(0, 300);
      if (req.query.dia) l = l.filter(o => o.dia === req.query.dia);
    }
    res.json({ ok: true, vendas: l.map(o => ({ pedido: o.pedido, em: o.em, produto: o.produto, valor: o.valor, metodo: o.metodo,
      visitante: o.visitante, casou: o.casou, semOrigem: o.sem_origem, fonte: o.cred_fonte || o.fonte, anuncio: o.cred_cont || o.cont,
      utm: [o.fonte, o.camp, o.cont].filter(Boolean).join(' · '), por: o.por || '' })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/interno/regras', authUsuario, (req, res) => {
  try {
    if (!_pessoas()) return res.json({ ok: true, ips: 0, pessoas: 0 });
    const r = _q("SELECT SUM(tipo='ip') ips, SUM(tipo='visitante') pessoas FROM internos").get();
    res.json({ ok: true, ips: r.ips || 0, pessoas: r.pessoas || 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Diagnostico: pra onde o pixel esta mandando de verdade ──
// Sem isso, pixel apontando pro funil errado vira zero calado — e zero calado
// parece "nao funciona", quando na verdade o dado esta la, so noutro lugar.
// Traz pra uma etapa daqui os eventos que o pixel manda pro id antigo.
// Nao reescreve evento nenhum: so registra a equivalencia, e da pra desfazer.
app.post('/api/funil/adotar', authUsuario, (req, res) => {
  try {
    const b = req.body || {};
    const funil = String(b.funil || '').slice(0, 80);
    const etapa = String(b.etapa || '').slice(0, 80);
    const origemFunil = String(b.origemFunil || '').slice(0, 80);
    const origemEtapa = String(b.origemEtapa || '').slice(0, 80);
    if (!funil || !etapa || !origemEtapa) {
      return res.status(400).json({ error: 'Informe o funil, a etapa e a origem.' });
    }
    if (origemFunil === funil && origemEtapa === etapa) {
      return res.status(400).json({ error: 'A etapa já é ela mesma.' });
    }
    const db = readDB();
    const f = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : [])
      .find(x => x.id === funil);
    if (!f) return res.status(404).json({ error: 'Funil não encontrado.' });
    if (!(f.etapas || []).some(e => e.id === etapa)) {
      return res.status(404).json({ error: 'Essa etapa não é deste funil.' });
    }
    const lista = _adocoes(db);
    // uma origem só pode alimentar uma etapa, senão o mesmo evento contaria duas vezes
    const jaTem = lista.find(a =>
      a.origemFunil === origemFunil && a.origemEtapa === origemEtapa);
    if (jaTem) {
      return res.status(409).json({ error: jaTem.etapa === etapa
        ? 'Essa origem já está trazida pra cá.'
        : 'Essa origem já está ligada a outra etapa. Desfaça lá primeiro.' });
    }
    lista.push({ id: 'ado_' + crypto.randomBytes(6).toString('hex'),
      funil, etapa, origemFunil, origemEtapa,
      em: new Date().toISOString(), por: req.user && req.user.nome });
    db.store[KEY_ADOCOES] = lista;
    db.timestamps[KEY_ADOCOES] = now();
    audit(db, 'funil_adotar_origem', { funil, etapa },
      { origemFunil, origemEtapa }, req.user);
    writeDB(db);
    res.json({ ok: true, adocoes: lista.filter(a => a.funil === funil) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/funil/adotar/:id', authUsuario, (req, res) => {
  try {
    const db = readDB();
    const lista = _adocoes(db);
    const alvo = lista.find(a => a.id === req.params.id);
    if (!alvo) return res.status(404).json({ error: 'Não encontrado.' });
    db.store[KEY_ADOCOES] = lista.filter(a => a.id !== alvo.id);
    db.timestamps[KEY_ADOCOES] = now();
    audit(db, 'funil_desfazer_origem', { funil: alvo.funil, etapa: alvo.etapa },
      { origemFunil: alvo.origemFunil, origemEtapa: alvo.origemEtapa }, req.user);
    writeDB(db);
    res.json({ ok: true, adocoes: db.store[KEY_ADOCOES].filter(a => a.funil === alvo.funil) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Imposto, taxa e custo — o que separa faturamento de dinheiro que fica.
app.get('/api/custos', authUsuario, (req, res) => {
  res.json({ ok: true, custos: _custosCfg(readDB()) });
});

app.post('/api/custos', authDiretoria, (req, res) => {
  try {
    const b = req.body || {};
    const custos = {};
    for (const k of Object.keys(CUSTOS_PADRAO)) {
      let v = Number(b[k]);
      if (!Number.isFinite(v) || v < 0) v = 0;
      // percentual acima de 90 quase sempre e engano de digitacao; o custo por
      // venda em reais nao tem teto
      if (k !== 'custoVenda' && v > 90) v = 90;
      custos[k] = v;
    }
    const db = readDB();
    db.store[KEY_CUSTOS] = custos;
    db.timestamps[KEY_CUSTOS] = now();
    audit(db, 'custos_margem', {},
      Object.keys(custos).map(k => k + '=' + custos[k]).join(' '), req.user);
    writeDB(db);
    res.json({ ok: true, custos });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Preco de cada plano — e o que deixa dizer qual venda foi qual.
app.get('/api/planos', authUsuario, (req, res) => {
  const cfg = _planosCfg(readDB());
  res.json({ ok: true, tolerancia: cfg.tolerancia,
             planos: cfg.planos.map(p => ({ chave: p.chave, rotulo: p.rotulo,
                                            meses: p.meses, preco: Number(p.preco) || 0 })) });
});

app.post('/api/planos', authDiretoria, (req, res) => {
  try {
    const b = req.body || {};
    const entrada = Array.isArray(b.planos) ? b.planos : [];
    // so aceita as quatro chaves conhecidas; o resto e ruido
    const planos = PLANOS_PADRAO.map(base => {
      const d = entrada.find(x => x && x.chave === base.chave) || {};
      const preco = Number(d.preco);
      return Object.assign({}, base, { preco: Number.isFinite(preco) && preco > 0 ? preco : 0 });
    });
    let tol = Number(b.tolerancia);
    if (!Number.isFinite(tol) || tol < 1)  tol = 10;
    if (tol > 40) tol = 40;   // acima disso as faixas se sobrepoem e a conta vira ficcao
    const db = readDB();
    db.store[KEY_PLANOS] = { planos, tolerancia: tol };
    db.timestamps[KEY_PLANOS] = now();
    audit(db, 'planos_precos', { tolerancia: tol },
      { precos: planos.map(p => p.chave + '=' + p.preco).join(' ') }, req.user);
    writeDB(db);
    res.json({ ok: true, planos, tolerancia: tol });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/funil/diagnostico', authUsuario, (req, res) => {
  try {
    const db = readDB();
    const funis = Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : [];
    const nomeFunil = {}, nomeEtapa = {};
    funis.forEach(f => {
      nomeFunil[f.id] = f.nome || f.id;
      (f.etapas || []).forEach(e => { nomeEtapa[e.id] = { nome: e.nome, funil: f.id }; });
    });

    const linhas = (Array.isArray(db.store[KEY_FSTATS]) ? db.store[KEY_FSTATS] : [])
      .concat(Object.values(_fBuffer));
    const corte = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
    const vistos = {};
    linhas.filter(l => l.data >= corte && !String(l.funil || '').startsWith('redir:')).forEach(l => {
      const k = l.funil + '|' + l.etapa;
      if (!vistos[k]) vistos[k] = {
        funil: l.funil, etapa: l.etapa,
        funilNome: nomeFunil[l.funil] || null,
        etapaNome: (nomeEtapa[l.etapa] && nomeEtapa[l.etapa].nome) || null,
        // a etapa pode existir, mas noutro funil — e o engano mais comum
        etapaDeOutroFunil: !!(nomeEtapa[l.etapa] && nomeEtapa[l.etapa].funil !== l.funil),
        entradas: 0, unicos: 0
      };
      vistos[k].entradas += l.entradas || 0;
      vistos[k].unicos   += l.unicos   || 0;
    });

    const funilAtual = String(req.query.funil || '').slice(0, 80);
    const adotadas = _adocoes(db);
    const chaveAdo = {};
    adotadas.forEach(a => { chaveAdo[(a.origemFunil || '') + '|' + a.origemEtapa] = a; });
    Object.values(vistos).forEach(v => {
      const a = chaveAdo[(v.funil || '') + '|' + v.etapa];
      v.adotadaPor = a ? { id: a.id, funil: a.funil, etapa: a.etapa } : null;
    });

    const lista = Object.values(vistos).sort((a, b) => b.entradas - a.entradas);
    res.json({ ok: true, desde: corte, recebendo: lista,
      adocoes: funilAtual ? adotadas.filter(a => a.funil === funilAtual) : adotadas,
      // o que o pixel manda e nao casa com funil nenhum salvo
      orfaos: lista.filter(x => !x.funilNome || !x.etapaNome),
      funis: funis.map(f => ({ id: f.id, nome: f.nome,
        etapas: (f.etapas || []).map(e => ({ id: e.id, nome: e.nome })) })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Vendas por página ───────────────────────────────────────────────────────
// A pergunta que ele faz o tempo todo: rodando cinco VSLs, qual delas vende.
// A ligacao ja existia toda e ninguem juntava: o pixel guarda a pagina em cada
// evento, o link do checkout leva tmx_vid, e a venda chega com esse vid. Aqui
// os tres viram uma tabela.
//
// Duas leituras, porque sao perguntas diferentes:
//   entrada  — a pagina do PRIMEIRO acesso: quem trouxe a pessoa
//   venda    — a ultima pagina antes do checkout: quem convenceu
// Numa VSL unica as duas dao igual. Com pre-venda + VSL elas divergem, e a
// diferenca e exatamente o que diz qual das duas esta fazendo o trabalho.
// ══════════════════════════════════════════════════════
// ── SAÚDE DO FUNIL ──
// Uma pergunta só: dá pra confiar nos números deste funil? Cada checagem diz o
// que está quebrado, o que isso estraga na leitura e o que fazer — ordenadas
// pelo estrago. Tudo aqui é leitura: nada é corrigido sozinho.
// ══════════════════════════════════════════════════════
const _saudeCache = {};   // funil -> { em, saida }: cada rodada abre as páginas de verdade

// Só abre endereço público: a URL vem do cadastro do funil, e sem essa trava
// qualquer usuário faria o servidor bater em endereço interno da rede.
function _saudeUrlPublica(u) {
  try {
    const x = new URL(u);
    if (!/^https?:$/.test(x.protocol)) return false;
    const h = x.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.railway.internal')) return false;
    if (/^[\d.]+$/.test(h) || h.indexOf(':') >= 0) return false;   // IP cru (v4 ou v6)
    return true;
  } catch (e) { return false; }
}

// funilId pode ser um id ou a lista de ids que valem pelo funil (o dele e os
// ids antigos adotados): pixel antigo já ligado não é "pixel de outro funil".
async function _saudeAbrirPagina(url, funilId) {
  const ids = Array.isArray(funilId) ? funilId : [funilId];
  if (!_saudeUrlPublica(url)) return { erro: 'endereço inválido ou interno' };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 7000);
  try {
    const r = await fetch(url, { signal: ctrl.signal, redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CentralTMX-Saude/1.0)' } });
    const html = (await r.text()).slice(0, 800000);
    const tags = html.match(/<script[^>]*px\.js[^>]*>/gi) || [];
    const doFunil = tags.filter(tg => ids.some(id => id && (tg.indexOf('"' + id + '"') >= 0 || tg.indexOf("'" + id + "'") >= 0)));
    const etapas = doFunil.map(tg => (tg.match(/data-e=["']([^"']+)["']/i) || [])[1] || '');
    return { http: r.status, tag: tags.length > 0, doFunil: doFunil.length > 0, etapas };
  } catch (e) {
    return { erro: e.name === 'AbortError' ? 'não respondeu em 7s' : 'não abriu (' + ((e.cause && e.cause.code) || e.message) + ')' };
  } finally { clearTimeout(t); }
}

app.get('/api/funil/saude', authUsuario, async (req, res) => {
  try {
    const fid = String(req.query.funil || '').slice(0, 80);
    const forcar = req.query.forcar === '1';
    const pronto = _saudeCache[fid];
    if (!forcar && pronto && Date.now() - pronto.em < 60 * 1000) return res.json(Object.assign({ doCache: true }, pronto.saida));

    const db = readDB();
    const funis = Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : [];
    const f = funis.find(x => x && x.id === fid);
    if (!f) return res.status(404).json({ error: 'Funil não encontrado.' });

    const checks = [];   // { nivel: 'ruim'|'atencao'|'ok', peso, titulo, texto, acao }
    // o id deste funil e os ids antigos que ele adotou (pixel velho já ligado)
    const idsAceitos = [f.id].concat(_adocoes(db).filter(a => a.funil === f.id && a.origemFunil).map(a => a.origemFunil));
    const agora = Date.now(), corte24 = agora - 86400000, corte7 = agora - 7 * 86400000;

    // ── 1. Páginas: a tag está lá? e o pixel está chegando? ──────────────
    const jorn = (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
      .concat(Object.values(typeof _jBuffer === 'object' && _jBuffer ? _jBuffer : {}));
    const porEtapa = {};
    jorn.forEach(j => {
      if (!j || idsAceitos.indexOf(j.funil) < 0) return;
      (j.eventos || []).forEach(ev => {
        if (!ev || ev.tipo !== 'entrou') return;
        const x = porEtapa[ev.etapa] = porEtapa[ev.etapa] || { ultimo: '', n24: 0 };
        if (String(ev.em) > x.ultimo) x.ultimo = String(ev.em);
        if (new Date(ev.em).getTime() >= corte24) x.n24++;
      });
    });
    const paginas = (f.etapas || []).filter(e => e && e.tipo !== 'fonte' && e.tipo !== 'checkout' && e.tipo !== 'recuperacao');
    const abertas = await Promise.all(paginas.slice(0, 10).map(async e => {
      const url = String(e.url || '').trim();
      let med = porEtapa[e.id] || { ultimo: '', n24: 0 };
      // pela URL, na base de pessoas: a página com pixel antigo reporta com o
      // data-e velho e nunca caía no contador da etapa nova
      if (url && _pessoas()) {
        const r = _q('SELECT MAX(em) ult, SUM(CASE WHEN em >= ? THEN 1 ELSE 0 END) n FROM paginas WHERE pg=?').get(corte24, _normPg(url));
        if (r && r.ult && (!med.ultimo || r.ult > Date.parse(med.ultimo))) med = { ultimo: new Date(r.ult).toISOString(), n24: r.n || 0 };
      }
      const linha = { etapa: e.id, nome: e.nome || e.id, tipo: e.tipo || '', url, ultimo: med.ultimo || null, n24: med.n24 };
      if (!url) { linha.status = 'sem_link'; return linha; }
      const r = await _saudeAbrirPagina(/^https?:\/\//i.test(url) ? url : 'https://' + url, idsAceitos);
      Object.assign(linha, r);
      const chegando = med.ultimo && new Date(med.ultimo).getTime() >= corte24;
      if (r.erro || (r.http && r.http >= 400)) linha.status = chegando ? 'ok' : 'fora_do_ar';
      else if (r.doFunil) linha.status = chegando ? 'ok' : 'sem_visita';
      else if (chegando) linha.status = 'ok_dinamico';    // tag injetada por script: não aparece no HTML cru
      else if (r.tag) linha.status = 'outro_funil';
      else linha.status = 'sem_tag';
      if (r.doFunil && r.etapas.length && r.etapas.indexOf(e.id) < 0) linha.etapaErrada = r.etapas[0];
      return linha;
    }));
    const semTag = abertas.filter(p => p.status === 'sem_tag' || p.status === 'outro_funil');
    const semLink = abertas.filter(p => p.status === 'sem_link');
    const foraAr = abertas.filter(p => p.status === 'fora_do_ar');
    const etapaErr = abertas.filter(p => p.etapaErrada);
    // a primeira página sem pixel pesa mais; as seguintes somam menos, senão
    // um funil de 5 páginas iria a zero só por isso e esconderia o resto
    semTag.forEach((p, i) => checks.push({ nivel: 'ruim', peso: i ? 12 : 25,
      titulo: 'Página "' + p.nome + '" sem o pixel deste funil',
      texto: (p.status === 'outro_funil' ? 'Tem uma tag do Central TMX, mas de outro funil. ' : 'Não encontrei a tag no código da página. ') +
             'Ninguém que passa por ela é contado, e as vendas que saem dela chegam sem dizer de onde vieram.',
      acao: { rotulo: 'Copiar o pixel', aba: 'pixel', etapa: p.etapa } }));
    foraAr.forEach(p => checks.push({ nivel: 'ruim', peso: 20,
      titulo: 'Página "' + p.nome + '" não abriu',
      texto: (p.erro || ('respondeu ' + p.http)) + '. Se o anúncio manda gente pra cá, esse tráfego está sendo pago à toa.',
      acao: { rotulo: 'Abrir a página', url: p.url } }));
    semLink.forEach(p => checks.push({ nivel: 'atencao', peso: 5,
      titulo: 'Etapa "' + p.nome + '" sem link no mapa',
      texto: 'Sem o endereço, não dá pra conferir se o pixel está nela.',
      acao: { rotulo: 'Pôr o link no mapa', aba: 'mapa' } }));
    etapaErr.forEach(p => checks.push({ nivel: 'atencao', peso: 8,
      titulo: 'Página "' + p.nome + '" marcada como outra etapa',
      texto: 'O pixel dela diz data-e="' + p.etapaErrada + '". Os números dessa página caem em outro bloco do mapa.',
      acao: { rotulo: 'Copiar o pixel certo', aba: 'pixel', etapa: p.etapa } }));
    const okPag = abertas.filter(p => p.status === 'ok' || p.status === 'ok_dinamico');
    if (abertas.length && okPag.length === abertas.length)
      checks.push({ nivel: 'ok', peso: 0, titulo: 'Pixel em todas as páginas', texto: okPag.length + ' página(s) com a tag e recebendo visitas nas últimas 24h.' });

    // ── 2. Webhook de vendas ────────────────────────────────────────────
    const cfgV = _vendasCfg(db);
    const vendas = Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : [];
    const ultimoEv = vendas.length ? vendas[vendas.length - 1].recebidoEm : null;
    const hojeBRT = new Date(agora - 3 * 3600000).toISOString().slice(0, 10);
    const evHoje = vendas.filter(v => String(v.recebidoEm || '').slice(0, 10) === hojeBRT);
    const webhook = { configurado: !!(cfgV && cfgV.token), ultimo: ultimoEv, hoje: evHoje.length,
                      pagasHoje: evHoje.filter(_vendaPaga).length };
    if (!webhook.configurado) {
      checks.push({ nivel: 'ruim', peso: 30, titulo: 'Webhook de vendas não configurado',
        texto: 'Sem ele, nenhuma venda do checkout chega aqui: o funil não tem como saber quem comprou.',
        acao: { rotulo: 'Configurar', link: 'integracoes' } });
    } else if (!ultimoEv || new Date(ultimoEv).getTime() < agora - 6 * 3600000) {
      checks.push({ nivel: 'atencao', peso: 15, titulo: 'Webhook sem evento há mais de 6h',
        texto: ultimoEv ? 'Último evento em ' + new Date(ultimoEv).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) + '. Se houve venda nesse intervalo, o checkout parou de avisar.' : 'Nenhum evento recebido ainda.',
        acao: { rotulo: 'Ver integração', link: 'integracoes' } });
    } else {
      checks.push({ nivel: 'ok', peso: 0, titulo: 'Webhook de vendas recebendo',
        texto: 'Último evento às ' + new Date(ultimoEv).toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit' }) +
               ' · ' + evHoje.length + ' evento(s) hoje · ' + webhook.pagasHoje + ' pago(s).' });
    }

    // ── 3. Vendas com origem (últimos 7 dias) ───────────────────────────
    const pagas7 = vendas.filter(v => _vendaPaga(v) && new Date(v.recebidoEm).getTime() >= corte7 && !v.renovacao);
    const comVid = pagas7.filter(v => v.vid).length;
    const comUtm = pagas7.filter(v => v.vid || _origemVale(v.utmContent) || _origemVale(v.utmCampaign)).length;
    const porId  = pagas7.filter(v => /^\d{6,}$/.test(String(v.utmCampaign || '').trim())).length;
    const porNome = pagas7.filter(v => _origemVale(v.utmCampaign) && !/^\d{6,}$/.test(String(v.utmCampaign).trim())).length;
    const origem = { pagas: pagas7.length, comVid, comUtm, porId, porNome };
    if (pagas7.length) {
      const pct = x => Math.round(x / pagas7.length * 100);
      if (pct(comUtm) < 70) checks.push({ nivel: 'ruim', peso: 20,
        titulo: pct(comUtm) + '% das vendas chegam com origem',
        texto: (pagas7.length - comUtm) + ' de ' + pagas7.length + ' vendas pagas nos últimos 7 dias não trazem anúncio nem id de visitante. ' +
               'Elas somam no faturamento mas não entram no CPA de nenhum criativo.',
        acao: { rotulo: 'Ver como marcar as vendas', aba: 'pixel' } });
      if (porNome > 0) checks.push({ nivel: 'atencao', peso: 10,
        titulo: 'Anúncios mandando a campanha pelo nome',
        texto: porNome + ' venda(s) chegaram com utm_campaign = nome da campanha. Duplicou ou renomeou, perdeu o vínculo. ' +
               'O padrão seguro usa o id: utm_campaign={{campaign.id}}.' });
    }

    // ── 4. Produtos que venderam fora do cadastro ───────────────────────
    // Com catalogo: produto que nao esta nele e BLOQUEANTE — foi o Acervo fora do
    // cadastro que deixou R$ 4 mil sem dono num dia no FunnelWay. Sem catalogo
    // ainda, cai na regra antiga: plano que nao se identifica pelo nome nem preco.
    const cfgPl = _planosCfg(db);
    const catalogo = typeof _produtosCfg === 'function' ? _produtosCfg(db) : [];
    const soltos = {};
    pagas7.forEach(v => {
      if (catalogo.length ? _produtoDe(v.produto, catalogo) : (_planoPorNome(v.produto) || _planoPorValor(v.valor, cfgPl))) return;
      const k = String(v.produto || '(sem nome)').trim() || '(sem nome)';
      const x = soltos[k] = soltos[k] || { produto: k, vendas: 0, receita: 0 };
      x.vendas++; x.receita += Number(v.valor) || 0;
    });
    const produtosSoltos = Object.values(soltos).sort((a, b) => b.receita - a.receita || b.vendas - a.vendas);
    if (produtosSoltos.length) {
      const tot = produtosSoltos.reduce((a, x) => a + x.receita, 0);
      checks.push(catalogo.length ? { nivel: 'ruim', peso: 20,
        titulo: 'Produto vendendo fora do cadastro',
        texto: produtosSoltos.slice(0, 3).map(x => x.produto + ' (' + x.vendas + ')').join(', ') +
               (tot ? ' — R$ ' + Math.round(tot).toLocaleString('pt-BR') : '') +
               ' nos últimos 7 dias sem estar em Produtos. CPA, ROAS por produto e esteira não contam essas vendas.',
        acao: { rotulo: 'Cadastrar e vincular', aba: 'produtos' } } : { nivel: 'atencao', peso: 8,
        titulo: 'Nenhum produto cadastrado',
        texto: 'Sem o cadastro, não dá pra saber qual é o produto principal nem separar upsell. ' +
               produtosSoltos.slice(0, 3).map(x => x.produto + ' (' + x.vendas + ')').join(', ') + ' venderam nos últimos 7 dias.',
        acao: { rotulo: 'Cadastrar produtos', aba: 'produtos' } });
    }

    // ── 5. Campanhas contadas em mais de um funil ───────────────────────
    const fontesDe = x => (x.fontes || []).concat((x.etapas || []).filter(e => e && e.tipo === 'fonte'));
    // campanha fixa conta como ela mesma; regra por nome ("contém X") conta como a regra
    const camposDe = x => fontesDe(x).map(o => String(o.utmCampanha || '').trim() || (o.utmRegra ? 'contém ' + String(o.utmRegra).trim() : '')).filter(Boolean);
    const irmaos = funis.filter(x => x && x.id !== f.id && (x.projeto || '') === (f.projeto || ''));
    const minhas = camposDe(f);
    if (!minhas.length) {
      const tambemTudo = irmaos.filter(x => !camposDe(x).length);
      if (tambemTudo.length) checks.push({ nivel: 'atencao', peso: 8,
        titulo: 'Este funil e mais ' + tambemTudo.length + ' contam o projeto inteiro',
        texto: 'Nenhum deles tem campanha amarrada na origem (' + tambemTudo.slice(0, 3).map(x => '"' + x.nome + '"').join(', ') + '). ' +
               'O clique e o gasto do projeto aparecem em todos — somar os funis conta o mesmo dinheiro duas vezes.',
        acao: { rotulo: 'Amarrar a campanha', aba: 'mapa' } });
    } else {
      const repetidas = [];
      const bate = (a, b) => {
        if (a === b) return true;
        const ra = a.indexOf('contém ') === 0 ? a.slice(7).toLowerCase() : null, rb = b.indexOf('contém ') === 0 ? b.slice(7).toLowerCase() : null;
        if (ra && !rb) return b.toLowerCase().indexOf(ra) >= 0;
        if (rb && !ra) return a.toLowerCase().indexOf(rb) >= 0;
        return false;
      };
      irmaos.forEach(x => camposDe(x).forEach(c => { if (minhas.some(m => bate(m, c))) repetidas.push({ campanha: c, funil: x.nome }); }));
      if (repetidas.length) checks.push({ nivel: 'atencao', peso: 8,
        titulo: 'Campanha contada em dois funis',
        texto: repetidas.slice(0, 3).map(r => '"' + r.campanha + '" também está em "' + r.funil + '"').join('; ') + '.',
        acao: { rotulo: 'Ver no mapa', aba: 'mapa' } });
    }

    // ── nota: 100 menos o estrago, nunca abaixo de zero ─────────────────
    const nota = Math.max(0, 100 - checks.reduce((a, c) => a + (c.peso || 0), 0));
    const ordem = { ruim: 0, atencao: 1, ok: 2 };
    checks.sort((a, b) => (ordem[a.nivel] - ordem[b.nivel]) || (b.peso - a.peso));
    const saida = { ok: true, funil: { id: f.id, nome: f.nome }, nota,
      bloqueiam: checks.filter(c => c.nivel === 'ruim').length,
      checks, paginas: abertas, webhook, origem, produtosSoltos, rodouEm: new Date().toISOString() };
    _saudeCache[fid] = { em: Date.now(), saida };
    res.json(saida);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── PRODUTOS, CANAIS E LINKS ──
// Tres cadastros pequenos que destravam o resto: qual produto e principal (e
// em que projeto ele vende), qual utm_source e de qual canal, e quais anuncios
// estao mandando a campanha pelo id. Sem eles, venda de upsell some da conta,
// recuperacao rouba o credito do anuncio e renomear campanha quebra o vinculo.
// ══════════════════════════════════════════════════════
const KEY_PRODUTOS = 'sl_produtos';
const KEY_CANAIS   = 'sl_canais';
// '*' no fim = comeca com. Sem ele, igual — 'an' (audience network) casaria
// com 'android' se fosse prefixo.
const CANAIS_PADRAO = [
  { id: 'meta', nome: 'Meta Ads', fontes: ['fb*', 'ig*', 'facebook*', 'instagram*', 'meta*', 'an', 'msg', 'messenger'], anuncios: true, apoio: false },
  { id: 'recuperacao', nome: 'Recuperação', fontes: ['paytcall*', 'whatsapp*', 'wpp', 'email', 'e-mail', 'sms', 'recuperacao*', 'remarketing'], anuncios: false, apoio: true },
  { id: 'organico', nome: 'Orgânico', fontes: ['organic', 'organico', 'orgânico', 'seo', 'bio', 'link_in_bio', 'direct', 'direto'], anuncios: false, apoio: false },
  { id: 'google', nome: 'Google', fontes: ['google*', 'gads', 'youtube*', 'yt'], anuncios: true, apoio: false }
];
const _nrm = t => String(t || '').trim().toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/\s+/g, ' ');

function _canaisCfg(db) {
  const c = (db || readDB()).store[KEY_CANAIS];
  return (c && Array.isArray(c.lista) && c.lista.length) ? c.lista : CANAIS_PADRAO;
}
function _canalDe(fonte, canais) {
  const f = _nrm(fonte);
  if (!f) return null;
  for (const c of canais) {
    for (const x of (c.fontes || [])) {
      const y = _nrm(x);
      if (!y) continue;
      if (y.slice(-1) === '*' ? f.indexOf(y.slice(0, -1)) === 0 : f === y) return c;
    }
  }
  return null;
}
function _produtosCfg(db) {
  const c = (db || readDB()).store[KEY_PRODUTOS];
  return (c && Array.isArray(c.lista)) ? c.lista : [];
}
function _produtoDe(nome, lista) {
  const n = _nrm(nome);
  if (!n) return null;
  return lista.find(p => _nrm(p.nome) === n || (p.apelidos || []).some(a => _nrm(a) === n)) || null;
}
// campanha por id (a Meta devolve so digitos) x pelo nome x macro que nao virou valor
function _tipoCampanha(v) {
  const t = String(v || '').trim();
  if (!t) return 'vazio';
  if (/^\{\{.*\}\}$/.test(t)) return 'macro';
  if (/^\d{6,}$/.test(t)) return 'id';
  return 'nome';
}

app.get('/api/produtos', authUsuario, (req, res) => {
  try {
    const db = readDB(), lista = _produtosCfg(db);
    const corte = Date.now() - 30 * 86400000, vistos = {};
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (!_vendaPaga(v) || new Date(v.recebidoEm).getTime() < corte) return;
      const nome = String(v.produto || '').trim() || '(sem nome)';
      const x = vistos[nome] = vistos[nome] || { nome, vendas: 0, receita: 0, ultima: '' };
      x.vendas++; x.receita += Number(v.valor) || 0;
      if (String(v.recebidoEm) > x.ultima) x.ultima = String(v.recebidoEm);
    });
    const saida = Object.values(vistos).map(x => {
      const p = _produtoDe(x.nome, lista);
      return Object.assign(x, { cadastrado: !!p, produtoId: p ? p.id : null, projeto: p ? (p.projeto || '') : '' });
    }).sort((a, b) => b.receita - a.receita || b.vendas - a.vendas);
    res.json({ ok: true, lista, vistos: saida });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/produtos', authDiretoria, (req, res) => {
  try {
    const bruto = Array.isArray(req.body && req.body.lista) ? req.body.lista : null;
    if (!bruto) return res.status(400).json({ error: 'Mande a lista de produtos.' });
    const PAPEIS = ['principal', 'bump', 'upsell', 'downsell'];
    const lista = bruto.slice(0, 200).map(p => ({
      id: String(p.id || ('pr' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6))).slice(0, 40),
      nome: String(p.nome || '').trim().slice(0, 120),
      apelidos: (Array.isArray(p.apelidos) ? p.apelidos : []).map(a => String(a).trim().slice(0, 120)).filter(Boolean).slice(0, 20),
      projeto: String(p.projeto || '').slice(0, 60),
      papel: PAPEIS.indexOf(p.papel) >= 0 ? p.papel : 'principal',
      ofertas: (Array.isArray(p.ofertas) ? p.ofertas : []).slice(0, 30).map(o => ({
        nome: String(o.nome || '').trim().slice(0, 80),
        preco: Math.max(0, Number(String(o.preco).replace(',', '.')) || 0),
        periodo: ['mes', 'trimestre', 'semestre', 'ano', 'unico'].indexOf(o.periodo) >= 0 ? o.periodo : 'unico'
      })).filter(o => o.nome)
    })).filter(p => p.nome);
    const db = readDB();
    db.store[KEY_PRODUTOS] = { lista, _updatedAt: Date.now() };
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_PRODUTOS] = now();
    audit(db, 'produtos_salvos', KEY_PRODUTOS, { total: lista.length }, req.user);
    writeDB(db);
    res.json({ ok: true, lista });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/canais', authUsuario, (req, res) => {
  try {
    const db = readDB(), c = db.store[KEY_CANAIS];
    res.json({ ok: true, lista: _canaisCfg(db), padrao: !(c && Array.isArray(c.lista) && c.lista.length) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/canais', authDiretoria, (req, res) => {
  try {
    const bruto = Array.isArray(req.body && req.body.lista) ? req.body.lista : null;
    if (!bruto) return res.status(400).json({ error: 'Mande a lista de canais.' });
    const lista = bruto.slice(0, 40).map(c => ({
      id: String(c.id || ('cn' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5))).slice(0, 40),
      nome: String(c.nome || '').trim().slice(0, 60),
      fontes: (Array.isArray(c.fontes) ? c.fontes : []).map(f => String(f).trim().toLowerCase().slice(0, 60)).filter(Boolean).slice(0, 40),
      anuncios: !!c.anuncios, apoio: !!c.apoio
    })).filter(c => c.nome);
    const db = readDB();
    db.store[KEY_CANAIS] = { lista, _updatedAt: Date.now() };
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_CANAIS] = now();
    audit(db, 'canais_salvos', KEY_CANAIS, { total: lista.length }, req.user);
    writeDB(db);
    res.json({ ok: true, lista });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Faturamento por canal. Regra de credito: canal de APOIO (recuperacao) nunca
// fica com a venda quando se sabe de onde a pessoa veio — o anuncio de origem
// leva, e o apoio aparece como "ajudou". Foi assim que o FunnelWay jogava a
// venda recuperada por ligacao no colo da Payt e tirava do criativo.
app.get('/api/canais/resumo', authUsuario, async (req, res) => {
  try {
    const dias = Math.max(1, Math.min(90, parseInt(req.query.dias, 10) || 28));
    const db = readDB(), canais = _canaisCfg(db);
    const corte = Date.now() - dias * 86400000;
    // primeira origem conhecida de cada visitante (jornada guarda 7 dias)
    const origemDoVid = {};
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer || {})).forEach(j => {
      if (!j || !j.id || origemDoVid[j.id]) return;
      const ev = (j.eventos || []).find(e => e && e.primeiro && e.primeiro.utm_source);
      if (ev) origemDoVid[j.id] = ev.primeiro.utm_source;
    });
    const por = {}, semCanal = {};
    canais.forEach(c => { por[c.id] = { id: c.id, nome: c.nome, fontes: c.fontes, apoio: !!c.apoio, anuncios: !!c.anuncios, vendas: 0, faturamento: 0, ajudou: 0, ajudouValor: 0 }; });
    let semUtm = { vendas: 0, faturamento: 0 }, renov = { vendas: 0, faturamento: 0 }, total = 0;
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (!_vendaPaga(v) || new Date(v.recebidoEm).getTime() < corte) return;
      const val = Number(v.valor) || 0; total += val;
      if (v.renovacao) { renov.vendas++; renov.faturamento += val; return; }
      // a fonte crua: 'organic' tambem classifica (no canal Organico), porque
      // tratar como vazio escondia o tamanho do buraco que a tela precisa mostrar
      const fonte = String(v.utmSource || '').trim();
      let c = _canalDe(fonte, canais);
      // venda que caiu em canal sem anuncio (recuperacao, "organic" cravado pelo
      // checkout) mas cuja pessoa veio de anuncio: o credito volta pro anuncio
      if ((!c || !c.anuncios) && v.vid && origemDoVid[v.vid]) {
        const orig = _canalDe(origemDoVid[v.vid], canais);
        if (orig && orig.anuncios) {
          if (c) { por[c.id].ajudou++; por[c.id].ajudouValor += val; }
          c = orig;
        }
      }
      if (c) { por[c.id].vendas++; por[c.id].faturamento += val; return; }
      if (!fonte) { semUtm.vendas++; semUtm.faturamento += val; return; }
      const k = String(fonte).slice(0, 60);
      const x = semCanal[k] = semCanal[k] || { fonte: k, vendas: 0, faturamento: 0 };
      x.vendas++; x.faturamento += val;
    });
    // gasto: o mesmo panorama das Metricas de Ads; vai pro canal de anuncio principal
    let investimento = null, avisoGasto = '';
    try {
      const hojeBRT = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
      const deBRT = new Date(corte - 3 * 3600000).toISOString().slice(0, 10);
      const pano = await _utmifyPanorama(deBRT, hojeBRT, '');
      investimento = Number((pano.kpis || {}).investimento) || 0;
    } catch (e) { avisoGasto = 'Sem o gasto da Utmify agora: ' + e.message; }
    const alvoGasto = canais.find(c => c.anuncios && c.id === 'meta') || canais.find(c => c.anuncios);
    const lista = Object.values(por).map(c => Object.assign(c, {
      investimento: (alvoGasto && c.id === alvoGasto.id) ? investimento : null,
      roas: (alvoGasto && c.id === alvoGasto.id && investimento) ? c.faturamento / investimento : null
    })).sort((a, b) => b.faturamento - a.faturamento);
    res.json({ ok: true, dias, total, canais: lista, semUtm, renovacao: renov,
      semCanal: Object.values(semCanal).sort((a, b) => b.faturamento - a.faturamento).slice(0, 30),
      avisoGasto, historicoDesde: '2026-09-29' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Validador: como cada anuncio esta mandando a campanha. Olha o que CHEGOU
// (pixel + vendas), nao o que esta escrito no gerenciador — e o que chegou que
// decide se a venda vai ter dono.
app.get('/api/links/validador', authUsuario, (req, res) => {
  try {
    const dias = Math.max(1, Math.min(30, parseInt(req.query.dias, 10) || 7));
    const db = readDB(), corte = Date.now() - dias * 86400000;
    const por = {};
    const somar = (criativo, campanha, fonte, visita, venda, valor) => {
      const k = String(criativo || '').trim() || '(sem utm_content)';
      const x = por[k] = por[k] || { criativo: k, visitas: 0, vendas: 0, faturamento: 0, campanhas: {}, fontes: {} };
      x.visitas += visita; x.vendas += venda; x.faturamento += valor;
      const c = String(campanha || '').trim();
      x.campanhas[c] = (x.campanhas[c] || 0) + 1;
      if (fonte) x.fontes[fonte] = (x.fontes[fonte] || 0) + 1;
    };
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer || {})).forEach(j => {
      const ev = (j && j.eventos || []).find(e => e && e.tipo === 'entrou' && new Date(e.em).getTime() >= corte);
      if (!ev) return;
      const pr = ev.primeiro || {};
      somar(pr.utm_content || ev.criativo, pr.utm_campaign || ev.campanha, pr.utm_source || ev.origem, 1, 0, 0);
    });
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (!_vendaPaga(v) || v.renovacao || new Date(v.recebidoEm).getTime() < corte) return;
      if (!_origemVale(v.utmContent) && !_origemVale(v.utmCampaign)) return;
      somar(v.utmContent, v.utmCampaign, v.utmSource, 0, 1, Number(v.valor) || 0);
    });
    const linhas = Object.values(por).map(x => {
      const lista = Object.entries(x.campanhas).sort((a, b) => b[1] - a[1]);
      const principal = lista.length ? lista[0][0] : '';
      const tipos = {};
      lista.forEach(([c, n]) => { const t = _tipoCampanha(c); tipos[t] = (tipos[t] || 0) + n; });
      const tipo = _tipoCampanha(principal);
      return { criativo: x.criativo, visitas: x.visitas, vendas: x.vendas, faturamento: x.faturamento,
               campanha: principal, tipo, tipos, fonte: (Object.entries(x.fontes).sort((a, b) => b[1] - a[1])[0] || [''])[0],
               ok: tipo === 'id' && x.criativo !== '(sem utm_content)' };
    }).sort((a, b) => (a.ok - b.ok) || (b.visitas + b.vendas * 50) - (a.visitas + a.vendas * 50));
    res.json({ ok: true, dias, linhas: linhas.slice(0, 80), foraDoPadrao: linhas.filter(l => !l.ok).length, total: linhas.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── PIXEL E SAÚDE ──
// Junta o pixel com os alertas que ficavam soltos. A nota vale dinheiro: cada
// ponto é uma parte das vendas que dá (ou não) pra ligar a um anúncio.
//   vendas ligadas à jornada 35 · webhook com sck 20 · UTM por ID 15 ·
//   páginas no mapa 15 · páginas com pixel 15
// Os problemas vêm em ordem de R$ em jogo, cada um com o botão que resolve.
// ══════════════════════════════════════════════════════
const _pxsCache = {};
app.get('/api/funil/pixel-saude', authUsuario, async (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const fid = String(req.query.funil || '').slice(0, 80);
    const pronto = _pxsCache[fid];
    if (req.query.forcar !== '1' && pronto && Date.now() - pronto.em < 60 * 1000) return res.json(Object.assign({ doCache: true }, pronto.saida));
    const dbj = readDB();
    const esc = _escopoFunil(dbj, fid);
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const f = esc.f, agora = Date.now(), ini7 = agora - 7 * 86400000, de7 = _diaBR(ini7), hoje = _diaBR(agora);
    const esq = _escopoSql(esc, 'p');
    const dir = _ehDir(req);

    // ── vendas pagas dos últimos 7 dias do projeto: quantas ligadas a alguém ──
    const produtos = _produtosCfg(dbj);
    const doProjeto = o => { const pr = _produtoDe(o.produto, produtos); return !produtos.length || !pr || pr.projeto === f.projeto; };
    const pagas7 = _q('SELECT * FROM pedidos WHERE em >= ? AND pago=1 AND estorno=0 AND renovacao=0').all(ini7).filter(doProjeto);
    const ligadas = pagas7.filter(o => o.visitante);
    const pctLigadas = pagas7.length ? ligadas.length / pagas7.length : null;
    const semOrigem = pagas7.filter(o => !o.visitante && !o.cred_canal);
    const valorSemOrigem = semOrigem.reduce((a, o) => a + (Number(o.valor) || 0), 0);

    // ── webhook com sck: dos eventos do checkout, quantos trouxeram o id ──
    const ev7 = _q('SELECT COUNT(*) n, SUM(CASE WHEN sck IS NOT NULL AND sck<>\'\' THEN 1 ELSE 0 END) c FROM pedidos WHERE em >= ?').get(ini7);
    const pctSck = ev7.n ? (ev7.c || 0) / ev7.n : null;

    // ── UTM por id: visitas de anúncio que chegaram com o id do anúncio ──
    const ses = _q('SELECT s.fonte, s.cont, s.camp FROM sessoes s WHERE s.inicio >= ? AND s.interno=0 AND s.id IN (SELECT DISTINCT p.sessao FROM paginas p WHERE p.dia >= ? AND ' + esq.where + ')')
      .all(ini7, de7, ...esq.args);
    const canais = _canaisCache();
    const deAnuncio = ses.filter(s => { const c = _canalDe(s.fonte, canais); return c && c.anuncios; });
    const comId = deAnuncio.filter(s => /\d{6,}/.test(String(s.cont || '')));
    const pctUtm = deAnuncio.length ? comId.length / deAnuncio.length : null;
    const macros = {};
    ses.forEach(s => { [s.cont, s.camp].forEach(v => { if (/\{\{/.test(String(v || ''))) macros[v] = (macros[v] || 0) + 1; }); });

    // ── páginas: no mapa x fora; com pixel x sem ──
    const fora = _q('SELECT p.pg, COUNT(DISTINCT p.visitante) n FROM paginas p WHERE p.dia >= ? AND p.interno=0 AND p.funil IN (' + _ph(esc.ids.length) + ') AND NOT ' +
                    esq.where + ' GROUP BY p.pg ORDER BY n DESC').all(de7, ...esc.ids, ...esq.args);
    const dentro = _q('SELECT p.pg, COUNT(DISTINCT p.visitante) n, MAX(p.em) ult FROM paginas p WHERE p.dia >= ? AND ' + esq.where + ' GROUP BY p.pg').all(de7, ...esq.args);
    const pgsMapa = dentro.length, pgsTotal = dentro.length + fora.length;
    const gentePorPg = {}; dentro.forEach(x => { gentePorPg[x.pg] = x; });
    const etapasUrl = (f.etapas || []).filter(e => e.url && e.tipo !== 'checkout' && e.tipo !== 'recuperacao' && e.tipo !== 'fonte');
    const comPixel = etapasUrl.filter(e => { const x = gentePorPg[_normPg(e.url)]; return x && x.ult >= agora - 86400000; });

    const pontos = {
      ligadas: { peso: 35, valor: pctLigadas, rot: 'Vendas ligadas à jornada', txt: pctLigadas == null ? 'sem venda em 7 dias' : Math.round(pctLigadas * 100) + '%' },
      sck:     { peso: 20, valor: pctSck, rot: 'Webhook com sck', txt: pctSck == null ? 'sem evento' : Math.round(pctSck * 100) + '%' },
      utm:     { peso: 15, valor: pctUtm, rot: 'UTM por ID', txt: pctUtm == null ? 'sem anúncio' : Math.round(pctUtm * 100) + '%' },
      mapa:    { peso: 15, valor: pgsTotal ? pgsMapa / pgsTotal : null, rot: 'Páginas no mapa', txt: pgsTotal ? pgsMapa + ' de ' + pgsTotal : 'sem visita' },
      pixel:   { peso: 15, valor: etapasUrl.length ? comPixel.length / etapasUrl.length : null, rot: 'Páginas com pixel', txt: etapasUrl.length ? comPixel.length + ' de ' + etapasUrl.length : 'sem link' }
    };
    // critério sem dado nenhum não pesa contra: a nota é sobre o que dá pra medir
    let soma = 0, pesoMedido = 0;
    Object.values(pontos).forEach(p => { if (p.valor != null) { soma += p.peso * p.valor; pesoMedido += p.peso; } });
    const nota = pesoMedido ? Math.round(soma / pesoMedido * 100) : 0;

    // ── problemas, por R$ em jogo ──
    const ticket = pagas7.length ? pagas7.reduce((a, o) => a + (Number(o.valor) || 0), 0) / pagas7.length : 0;
    const probs = [];
    const raw = Array.isArray(dbj.store[KEY_VENDAS_RAW]) ? dbj.store[KEY_VENDAS_RAW] : [];
    const ultRaw = raw.length ? raw[raw.length - 1] : null;
    const ultLink = ultRaw ? _doLink(ultRaw.payload || {}) : {};
    const ultSck = ultRaw ? (_pega(ultRaw.payload || {}, ['sck', 'src', 'trackingParameters.sck']) || ultLink.sck || ultLink.src || '') : '';
    if (ultRaw && !/tmx_/.test(String(ultSck))) {
      probs.push({ nivel: 'ruim', emJogo: valorSemOrigem, chave: 'sck',
        titulo: 'Checkout está chegando sem o id do visitante',
        texto: 'Último webhook: utm_source=' + (ultLink.utm_source || _pega(ultRaw.payload || {}, ['utm_source']) || 'vazio') + ', sck ' + (ultSck ? '"' + String(ultSck).slice(0, 30) + '"' : 'vazio') +
               '. Sem o id, a venda só liga pela jornada se o e-mail já apareceu antes. Confira se o pixel está na página do botão de compra.',
        acao: { rotulo: 'Ver como resolver', tipo: 'sck' } });
    }
    if (fora.length) {
      const gente = fora.reduce((a, x) => a + x.n, 0);
      probs.push({ nivel: 'ruim', emJogo: ticket * Math.max(1, Math.round(gente * 0.004)), chave: 'fora',
        titulo: fora.length + ' página' + (fora.length === 1 ? ' recebe' : 's recebem') + ' gente e não ' + (fora.length === 1 ? 'está' : 'estão') + ' no mapa',
        texto: fora.slice(0, 2).map(x => '/' + x.pg.split('/').slice(1).join('/') + ' (' + x.n.toLocaleString('pt-BR') + ' pessoas)').join(' e ') +
               (fora.length > 2 ? ' são as principais' : '') + '. Quem passa só por elas não entra em nenhuma etapa do funil.',
        acao: { rotulo: 'Adicionar ao mapa', aba: 'mapa' } });
    }
    const semUrl = (f.etapas || []).filter(e => !e.url && e.tipo !== 'fonte' && (e.tipo === 'checkout' || e.tipo === 'obrigado'));
    if (semUrl.length) probs.push({ nivel: 'atencao', emJogo: 0, chave: 'semurl',
      titulo: semUrl.map(e => e.nome).join(' e ') + ' sem URL',
      texto: 'Sem URL a etapa nunca conta ninguém. Checkout de terceiro: o clique no botão já marca "abriu checkout" sozinho.',
      acao: { rotulo: 'Configurar', aba: 'mapa', etapa: semUrl[0].id } });
    const nMacro = Object.keys(macros).length;
    if (nMacro) probs.push({ nivel: 'atencao', emJogo: 0, chave: 'macro',
      titulo: nMacro + ' anúncio' + (nMacro === 1 ? '' : 's') + ' com macro vazia',
      texto: 'Chegou ' + Object.keys(macros).slice(0, 2).map(m => String(m).slice(0, 40)).join(' e ') + ' ao pé da letra. O anúncio está com a UTM digitada errada.',
      acao: { rotulo: 'Ver anúncio', tipo: 'macro' } });
    if (pctUtm != null && pctUtm < 0.8 && deAnuncio.length >= 20) probs.push({ nivel: 'atencao', emJogo: 0, chave: 'utm',
      titulo: Math.round((1 - pctUtm) * 100) + '% das visitas de anúncio sem o id do anúncio',
      texto: 'Com o nome no lugar do id, renomear o anúncio quebra o vínculo. Padrão: utm_content={{ad.id}}.',
      acao: { rotulo: 'Ver o padrão', tipo: 'utm' } });
    const semPix = etapasUrl.filter(e => comPixel.indexOf(e) < 0);
    semPix.forEach(e => probs.push({ nivel: 'ruim', emJogo: 0, chave: 'pixel', titulo: 'Página "' + (e.nome || e.id) + '" sem visita do pixel há 24h',
      texto: 'Ou o pixel não está nela, ou está com o id de outro funil. Teste a URL abaixo.', acao: { rotulo: 'Testar a URL', tipo: 'testar', url: e.url } }));
    probs.push({ nivel: 'ok', emJogo: 0, chave: 'norm', titulo: '/697 e /697/ contadas como uma página só',
      texto: 'Normalização de URL ligada: maiúscula, barra no fim e ?parâmetros não viram página nova.', selo: 'corrigido' });
    const ultEv = _q('SELECT MAX(p.em) m FROM paginas p WHERE ' + esq.where).get(...esq.args).m;
    const hojeGente = _q('SELECT COUNT(DISTINCT p.visitante) n FROM paginas p WHERE p.dia=? AND ' + esq.where).get(hoje, ...esq.args).n;
    if (comPixel.length) probs.push({ nivel: 'ok', emJogo: 0, chave: 'vivo', titulo: 'Pixel recebendo em ' + comPixel.length + ' página' + (comPixel.length === 1 ? '' : 's'),
      texto: (ultEv ? 'último evento há ' + _haQuanto(agora - ultEv) + ' · ' : '') + hojeGente.toLocaleString('pt-BR') + ' pessoas hoje · clique no player Vturb não conta como clique morto' });
    const ordem = { ruim: 0, atencao: 1, ok: 2 };
    probs.sort((a, b) => (ordem[a.nivel] - ordem[b.nivel]) || (b.emJogo - a.emJogo));
    if (!dir) probs.forEach(p => { p.emJogo = null; });

    // ── o que o pixel faz sozinho ──
    const conta7 = t => _q('SELECT COUNT(*) n FROM eventos WHERE em >= ? AND tipo=?').get(ini7, t).n;
    const reg = _q("SELECT SUM(tipo='ip') ips, SUM(tipo='visitante') pessoas FROM internos").get();
    const sozinho = [
      { ic: '🔗', rot: 'Cola sck e UTMs em todo link de checkout', status: 'ligado' },
      { ic: '🛒', rot: 'Marca "abriu checkout" no clique do botão', status: conta7('checkout') ? 'ligado' : 'esperando clique' },
      { ic: '🎬', rot: 'Lê retenção e pitch do player Vturb', status: conta7('video') ? 'ligado' : 'sem player visto' },
      { ic: '🧑‍💻', rot: 'Ignora tráfego interno (cookie ou IP)', status: (reg.ips || 0) ? reg.ips + ' IP' + (reg.ips === 1 ? '' : 's') : ((reg.pessoas || 0) ? reg.pessoas + ' pessoa' + (reg.pessoas === 1 ? '' : 's') : 'ligado') },
      { ic: '🔒', rot: 'Consentimento LGPD', status: 'desligado' }
    ];

    // ── webhook ao vivo: o último que chegou e como foi ligado ──
    let webhook = null;
    if (ultRaw) {
      const p = ultRaw.payload || {}, vn = _normalizarVenda(p);
      const campo = (k, v, st) => ({ campo: k, valor: v, status: st });
      const temSck = /tmx_/.test(String(ultSck));
      const ped = _q('SELECT * FROM pedidos ORDER BY em DESC LIMIT 1').get();
      webhook = { em: ultRaw.em, campos: [
          campo('status', vn.status || '', vn.status ? 'ok' : 'falta'),
          campo('email', _mascEmail(vn.email) || '', vn.email ? 'ok' : 'falta'),
          campo('sck', ultSck ? String(ultSck).slice(0, 40) : '', temSck ? 'ok' : (ultSck ? 'sem id' : 'falta')),
          campo('utm_content', vn.utmContent ? String(vn.utmContent).slice(0, 40) : '', _origemVale(vn.utmContent) ? 'ok' : 'vazio'),
          campo('amount', dir && vn.valor != null ? 'R$ ' + Number(vn.valor).toFixed(2).replace('.', ',') : (vn.valor != null ? '•••' : ''), vn.valor != null ? 'ok' : 'falta')
        ],
        ligacao: ped ? { casou: ped.casou || '', visitante: ped.visitante || '', anuncio: ped.cred_cont ? String(ped.cred_cont).split('|')[0] : '',
                         variante: ped.variante || '', teste: ped.teste || '', semOrigem: ped.sem_origem || '' } : null };
    }

    const saida = { ok: true, funil: { id: f.id, nome: f.nome }, nota, pontos, emJogo: dir ? valorSemOrigem : null, vendasSemOrigem: semOrigem.length,
      problemas: probs, sozinho, webhook, macros: Object.entries(macros).map(([v, n]) => ({ valor: v, n })).slice(0, 20),
      paginas: dentro.map(x => ({ pg: x.pg, pessoas: x.n, ultimo: x.ult })).sort((a, b) => b.pessoas - a.pessoas).slice(0, 30) };
    _pxsCache[fid] = { em: Date.now(), saida };
    res.json(saida);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
function _haQuanto(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.round(s / 60) + ' min';
  if (s < 86400) return Math.round(s / 3600) + 'h';
  return Math.round(s / 86400) + ' dias';
}

// "Testar uma URL": abre a página, procura a tag e diz quando foi o último evento
app.post('/api/funil/testar-url', authUsuario, async (req, res) => {
  try {
    const fid = String((req.body && req.body.funil) || '').slice(0, 80);
    let url = String((req.body && req.body.url) || '').trim().slice(0, 400);
    if (!url) return res.status(400).json({ error: 'Cole a URL da página.' });
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    const dbT = readDB();
    const idsT = [fid].concat(_adocoes(dbT).filter(a => a.funil === fid && a.origemFunil).map(a => a.origemFunil));
    const r = await _saudeAbrirPagina(url, idsT);
    const pg = _normPg(url);
    const ult = _pessoas() ? _q('SELECT MAX(em) m, COUNT(DISTINCT visitante) n FROM paginas WHERE pg=? AND em >= ?').get(pg, Date.now() - 86400000) : null;
    const quais = _pessoas() ? _q('SELECT funil, etapa, COUNT(*) n FROM paginas WHERE pg=? AND em >= ? GROUP BY funil, etapa ORDER BY n DESC LIMIT 3').all(pg, Date.now() - 7 * 86400000) : [];
    res.json({ ok: true, url, pg, abriu: !r.erro, http: r.http || null, erro: r.erro || null, tag: !!r.tag, doFunil: !!r.doFunil,
      etapas: r.etapas || [], ultimoEvento: ult && ult.m ? ult.m : null, pessoas24h: ult ? ult.n : 0, reportaComo: quais });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Páginas fora do mapa ────────────────────────────────────────────────────
// URLs com o pixel deste funil que não são etapa. Ordenadas por gente, com o
// data-e mais comum (pra sugerir onde encaixar) e a sugestão automática: se
// elas levam mais da metade do tráfego de um split, são as variantes dele.
app.get('/api/funil/fora-do-mapa', authUsuario, (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const per = _periodoMs(String(req.query.de || ''), String(req.query.ate || ''));
    const esq = _escopoSql(esc, 'p');
    const linhas = _q('SELECT p.pg, COUNT(DISTINCT p.visitante) pessoas FROM paginas p WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND p.funil IN (' +
                      _ph(esc.ids.length) + ') AND NOT ' + esq.where + ' GROUP BY p.pg ORDER BY pessoas DESC LIMIT 60')
      .all(per.de, per.ate, ...esc.ids, ...esq.args);
    const pgs = linhas.map(l => {
      const vendas = _q('SELECT COUNT(DISTINCT o.visitante) n FROM pedidos o WHERE o.pago=1 AND o.estorno=0 AND o.visitante IN (SELECT DISTINCT visitante FROM paginas WHERE pg=? AND dia BETWEEN ? AND ?)')
        .get(l.pg, per.de, per.ate).n;
      const de = _q('SELECT etapa, COUNT(*) n FROM paginas WHERE pg=? AND dia BETWEEN ? AND ? GROUP BY etapa ORDER BY n DESC LIMIT 1').get(l.pg, per.de, per.ate);
      return { pg: l.pg, pessoas: l.pessoas, vendas, etapaDeclarada: de ? de.etapa : '', ignorada: false };
    });
    // sugestão: pra cada teste do projeto, que páginas de fora recebem o tráfego dele
    const sugestoes = [];
    (Array.isArray(dbj.store[KEY_REDIRS]) ? dbj.store[KEY_REDIRS] : []).filter(r => r && (r.projeto || '') === (esc.f.projeto || '')).forEach(r => {
      const slug = String(r.slug || '').toLowerCase(); if (!slug) return;
      const tot = _q('SELECT COUNT(*) n FROM sessoes WHERE lower(teste)=? AND inicio BETWEEN ? AND ?').get(slug, per.ini, per.fim).n;
      if (tot < 20) return;
      const porPg = _q('SELECT entrada pg, COUNT(*) n FROM sessoes WHERE lower(teste)=? AND inicio BETWEEN ? AND ? GROUP BY entrada').all(slug, per.ini, per.fim);
      const foraSet = new Set(pgs.map(x => x.pg));
      const delas = porPg.filter(x => foraSet.has(x.pg) && x.n / tot >= 0.1);
      const share = delas.reduce((a, x) => a + x.n, 0) / tot;
      if (share > 0.5) sugestoes.push({ teste: slug, nome: r.nome || slug, paginas: delas.map(x => x.pg), pct: share });
    });
    res.json({ ok: true, paginas: pgs, sugestoes, ignoradas: [...esc.ignoradas] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Números de cada bloco do mapa no período, da mesma base do topo e dos Leads
app.get('/api/funil/mapa-numeros', authUsuario, async (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const per = _periodoMs(String(req.query.de || ''), String(req.query.ate || ''));
    const esq = _escopoSql(esc, 'p');
    const linhas = _q('SELECT p.pg, p.etapa, p.visitante, s.pitch, s.checkout FROM paginas p JOIN sessoes s ON s.id = p.sessao WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND ' + esq.where)
      .all(per.de, per.ate, ...esq.args);
    const por = {}, todos = new Set(), pitch = new Set(), ck = new Set();
    linhas.forEach(l => {
      const et = _etapaDaLinha(esc, l.pg, l.etapa); if (!et) return;
      const x = por[et] || (por[et] = { pessoas: new Set(), pitch: new Set(), checkout: new Set() });
      x.pessoas.add(l.visitante); todos.add(l.visitante);
      if (l.pitch) { x.pitch.add(l.visitante); pitch.add(l.visitante); }
      if (l.checkout) { x.checkout.add(l.visitante); ck.add(l.visitante); }
    });
    const etapas = {};
    Object.keys(por).forEach(k => { etapas[k] = { pessoas: por[k].pessoas.size, pitch: por[k].pitch.size, checkout: por[k].checkout.size }; });
    // o nome das campanhas vem do arquivo do Resultado (sem buscar nada fora)
    const nomes = {};
    _q('SELECT id, nome FROM camp_dia WHERE dia BETWEEN ? AND ?').all(per.de, per.ate).forEach(c => { nomes[c.id] = c.nome; });
    const pagasT = _vendasDoFunil(dbj, esc, per, nomes, _regraCampanhas(esc.f)).filter(o => o.pago && !o.estorno);
    const comprou = pagasT.length;
    // quem comprou passou pelo checkout, mesmo se o clique no botão não foi visto
    pagasT.forEach(o => { if (o.visitante) ck.add(o.visitante); });
    // investido e cliques do topo: o mesmo arquivo de campanhas do Resultado,
    // pela mesma regra — nunca um número de clique diferente do da outra aba
    let investido = null, cliques = null;
    try {
      // responde com o que já está guardado (sem esperar a Utmify) e manda
      // buscar o que falta em segundo plano: a próxima leitura já vem completa
      const proj = await _projetoIdDoFunil(esc.f);
      const camp = await _campanhasPeriodo(per.de, per.ate, proj, 0);
      _campAtualizarDepois(per.de, per.ate, proj);
      const regra = _regraCampanhas(esc.f);
      investido = 0; cliques = 0;
      Object.keys(camp.porDia).forEach(d => camp.porDia[d].forEach(c => { if (!regra || regra(c.nome)) { investido += c.gasto; cliques += c.cliques; } }));
    } catch (e) {}
    res.json({ ok: true, chegaram: todos.size, pitch: pitch.size, checkout: ck.size, compraram: comprou, etapas,
               investido, cliques, semRegra: !_regraCampanhas(esc.f) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── NÚMEROS DE CADA BLOCO DO DESENHO ──
// O funil é o que a pessoa desenhou: fontes, redirect do teste, páginas,
// checkout, obrigado. Aqui cada bloco ganha os números do período, conferidos
// na base de pessoas, e cada seta ganha quantos de um bloco chegaram no outro.
// Página com pixel que não está no desenho não entra em bloco nenhum.
//   fonte Meta Ads   → cliques e gasto pela regra de campanha + quem chegou
//                      vindo de anúncio (utm_source fb/ig… sem "bio")
//   fonte Instagram  → quem chegou com "bio" na UTM (link da bio)
//   fonte UTM        → quem chegou com a UTM que você definir
//   fonte orgânico   → quem chegou sem UTM nenhuma
//   redirect (split) → cliques no link do teste e a divisão real
// ══════════════════════════════════════════════════════
app.get('/api/funil/blocos', authUsuario, async (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const f = esc.f, per = _periodoMs(String(req.query.de || ''), String(req.query.ate || ''));
    const dir = _ehDir(req), custos = _custosCfg(dbj), canais = _canaisCache();
    const liq = o => (o.liquido != null ? o.liquido : (Number(o.valor) || 0) * (1 - (custos.gateway || 0) / 100));
    const esq = _escopoSql(esc, 'p');
    const linhas = _q(`SELECT p.visitante, p.pg, p.etapa, p.pitch ppitch, s.checkout, s.pitch, s.fonte, s.midia, s.camp, s.cont, s.teste
                       FROM paginas p JOIN sessoes s ON s.id = p.sessao
                       WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND ` + esq.where).all(per.de, per.ate, ...esq.args);
    const porEtapa = {}, todos = new Set(), ck = new Set(), pit = new Set(), toques = {}, testes = {};
    const pitEtapa = {};      // quem passou do pitch NESTA página
    linhas.forEach(l => {
      const et = _etapaDaLinha(esc, l.pg, l.etapa);
      if (!et) return;
      (porEtapa[et] = porEtapa[et] || new Set()).add(l.visitante);
      if (l.ppitch) (pitEtapa[et] = pitEtapa[et] || new Set()).add(l.visitante);
      todos.add(l.visitante);
      if (l.checkout) ck.add(l.visitante);
      if (l.pitch) pit.add(l.visitante);
      const k = [l.fonte, l.midia, l.camp, l.cont].join('|');
      const t = toques[l.visitante] || (toques[l.visitante] = {});
      if (!t[k]) t[k] = { fonte: l.fonte || '', midia: l.midia || '', camp: l.camp || '', cont: l.cont || '' };
      if (l.teste) (testes[l.visitante] = testes[l.visitante] || new Set()).add(String(l.teste).toLowerCase());
    });

    // vendas do funil no período, por pessoa
    const nomes = {};
    _q('SELECT id, nome FROM camp_dia WHERE dia BETWEEN ? AND ?').all(per.de, per.ate).forEach(c => { nomes[c.id] = c.nome; });
    const nomeCamp = v => { const t = String(v || '').trim(); const p = t.split('|').map(x => x.trim()); for (const x of p) if (/^\d{6,}$/.test(x) && nomes[x]) return nomes[x]; return p[0] || ''; };
    const vendas = _vendasDoFunil(dbj, esc, per, nomes, _regraCampanhas(f)).filter(o => o.pago && !o.estorno);
    const vendaPor = {}, compradores = new Set();
    vendas.forEach(o => { if (o.visitante) { (vendaPor[o.visitante] = vendaPor[o.visitante] || []).push(o); compradores.add(o.visitante); } });
    const abriramSet = new Set([...ck, ...compradores]);

    // ── Cada venda é de UMA página: a do último clique em comprar antes da
    // compra (sem clique visto, a última página do funil antes dela). Antes a
    // venda contava em toda página por onde o comprador passou: quem comprou
    // na 697 e depois caiu no back redirect virava venda das duas.
    const ckEtapa = {};      // quem clicou em comprar NESTA página (no período)
    const evDe = {};         // visitante -> [{em, et, ck}]
    const alvoEv = [...compradores];
    _q(`SELECT visitante, pg, etapa, em FROM eventos WHERE tipo='checkout' AND em BETWEEN ? AND ?`).all(per.ini, per.fim).forEach(x => {
      const et = _etapaDaLinha(esc, _normPg(x.pg), x.etapa); if (!et || !todos.has(x.visitante)) return;
      (ckEtapa[et] = ckEtapa[et] || new Set()).add(x.visitante);
    });
    for (let i = 0; i < alvoEv.length; i += 400) {
      const lote = alvoEv.slice(i, i + 400);
      _q(`SELECT visitante, pg, etapa, em FROM eventos WHERE tipo='checkout' AND em <= ? AND visitante IN (` + _ph(lote.length) + `)`).all(per.fim + 3600000, ...lote).forEach(x => {
        const et = _etapaDaLinha(esc, _normPg(x.pg), x.etapa); if (et) (evDe[x.visitante] = evDe[x.visitante] || []).push({ em: x.em, et, ck: 1 });
      });
      _q(`SELECT visitante, pg, etapa, em FROM paginas WHERE em <= ? AND visitante IN (` + _ph(lote.length) + `)`).all(per.fim + 3600000, ...lote).forEach(x => {
        const et = _etapaDaLinha(esc, x.pg, x.etapa); if (et) (evDe[x.visitante] = evDe[x.visitante] || []).push({ em: x.em, et, ck: 0 });
      });
    }
    // A venda é da página que TROUXE a pessoa (a primeira do funil nos 7 dias
    // antes da compra). Se o clique de compra foi em outra página (o back
    // redirect, por exemplo), essa outra ganha a venda como "salva" por ela,
    // sem tirar da página de origem — e o total continua batendo.
    const vendaDaEtapa = {}, salvasDaEtapa = {};
    vendas.forEach(o => {
      if (!o.visitante) return;
      const lim = (o.em || 0) + 10 * 60000, desde = (o.em || 0) - 7 * 86400000;
      const evs = (evDe[o.visitante] || []).filter(x => x.em <= lim && x.em >= desde);
      const pags = evs.filter(x => !x.ck).sort((a, b) => a.em - b.em);
      const cliques = evs.filter(x => x.ck).sort((a, b) => b.em - a.em);
      const entrada = pags.length ? pags[0].et : (cliques.length ? cliques[cliques.length - 1].et : null);
      if (entrada) (vendaDaEtapa[entrada] = vendaDaEtapa[entrada] || []).push(o);
      const clique = cliques.length ? cliques[0].et : null;
      if (clique && entrada && clique !== entrada) {
        const x = salvasDaEtapa[clique] || (salvasDaEtapa[clique] = { n: 0, de: {} });
        x.n++; x.de[entrada] = (x.de[entrada] || 0) + 1;
      }
    });
    // página: pessoas da página, pitch e cliques NELA, e as vendas que saíram dela
    const medirPagina = (id, lst) => {
      const s = porEtapa[id] || new Set();
      const vf = (vendaDaEtapa[id] || []).filter(o => casaProd(o, lst));
      const sv = salvasDaEtapa[id];
      return { pessoas: s.size, checkout: (ckEtapa[id] || new Set()).size, pitch: (pitEtapa[id] || new Set()).size,
               vendas: vf.length, faturamento: dir ? vf.reduce((a, o) => a + liq(o), 0) : null,
               conversao: s.size ? vf.length / s.size : 0, produtos: topProd(vf),
               salvas: sv ? sv.n : 0, salvasDe: sv ? Object.entries(sv.de).sort((a, b) => b[1] - a[1]).map(([et, n]) => ({ nome: esc.nomeEtapa[et] || et, n })) : [] };
    };
    // Produto do bloco: o checkout vende o principal, o upsell vende outro. A
    // venda de cada um chega no webhook com o nome do produto, e é por ele que
    // o bloco separa o que é dele.
    const prodLista = e => String((e && e.produto) || '').split(/[,;\n]+/).map(_nrm).filter(Boolean);
    const casaProd = (o, lst) => !lst.length || lst.some(p => { const x = _nrm(o.produto); return x === p || x.indexOf(p) >= 0; });
    const topProd = lst => {
      const c = {}; lst.forEach(o => { const k = String(o.produto || '(sem nome)').trim(); c[k] = (c[k] || 0) + 1; });
      return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([nome, n]) => ({ nome, n }));
    };
    const medir = (s, filtro) => {
      let n = 0, fat = 0, c = 0, p = 0; const doBloco = [];
      s.forEach(v => { if (ck.has(v)) c++; if (pit.has(v)) p++; (vendaPor[v] || []).forEach(o => { if (filtro && !filtro(o)) return; n++; fat += liq(o); doBloco.push(o); }); });
      return { pessoas: s.size, checkout: c, pitch: p, vendas: n, faturamento: dir ? fat : null, conversao: s.size ? n / s.size : 0, produtos: topProd(doBloco) };
    };
    const ehBio = t => /bio/i.test([t.fonte, t.midia, t.camp, t.cont].join(' '));
    const casa = (t, fl) => ['fonte', 'midia', 'camp', 'cont'].every(k => {
      const q = fl && String(fl[k] || '').trim().toLowerCase(); if (!q) return true;
      return String(t[k] || '').toLowerCase().indexOf(q) >= 0;
    });
    const quem = teste => { const s = new Set(); Object.keys(toques).forEach(v => { if (Object.values(toques[v]).some(teste)) s.add(v); }); return s; };

    // gasto por campanha (arquivo do Resultado, sem esperar a Utmify)
    let camps = [];
    try {
      const proj = await _projetoIdDoFunil(f);
      const camp = await _campanhasPeriodo(per.de, per.ate, proj, 0);
      _campAtualizarDepois(per.de, per.ate, proj);
      Object.keys(camp.porDia).forEach(d => { camps = camps.concat(camp.porDia[d]); });
    } catch (e) {}
    const regraFunil = _regraCampanhas(f);

    const conj = {}, nos = {};
    (f.fontes || []).forEach(o => {
      const canal = o.canal || 'meta';
      let s, extra = {};
      if (canal === 'instagram') s = quem(t => (o.filtro && Object.values(o.filtro).some(Boolean)) ? casa(t, o.filtro) : ehBio(t));
      else if (canal === 'utm') s = quem(t => casa(t, o.filtro || {}));
      else if (canal === 'organico') s = quem(t => !t.fonte);
      else {
        // Meta Ads: a regra da própria origem (campanha fixa ou "contém"), senão a do funil
        const fixa = o.utmCampanha ? _nrm(o.utmCampanha) : '', contem = o.utmRegra ? _nrm(o.utmRegra) : '';
        const regra = (fixa || contem) ? (n => { const x = _nrm(n); return (fixa && x === fixa) || (contem && x.indexOf(contem) >= 0); }) : regraFunil;
        // campanha que veio só pelo id e não está no arquivo: não dá pra dizer
        // que é de outro funil, então conta (só exclui quando o nome não bate)
        s = quem(t => {
          const c = _canalDe(t.fonte, canais);
          if (!c || c.id !== 'meta' || ehBio(t)) return false;
          if (!regra || !t.camp) return true;
          const nm = nomeCamp(t.camp);
          return /^\d{6,}$/.test(nm) || regra(nm);
        });
        let cl = 0, gasto = 0;
        camps.forEach(c => { if (!regra || regra(c.nome)) { cl += c.cliques; gasto += c.gasto; } });
        extra = { cliques: cl, investido: gasto, regra: o.utmCampanha || o.utmRegra || '' };
      }
      // Link da bio que é um teste A/B (/r/bio): quem chegou por ele veio da
      // bio, com ou sem "bio" na UTM. Vale o teste escolhido na origem e o
      // bloco de teste ligado nela no desenho.
      if (canal !== 'meta') {
        const slugs = new Set();
        if (o.slug) slugs.add(String(o.slug).toLowerCase());
        (f.ligacoes || []).forEach(l => { if (l[0] !== o.id) return; const alvo = (f.etapas || []).find(e => e.id === l[1]); if (alvo && alvo.tipo === 'split' && alvo.slug) slugs.add(String(alvo.slug).toLowerCase()); });
        if (slugs.size) {
          slugs.forEach(sl => _q('SELECT DISTINCT visitante FROM sessoes WHERE lower(teste)=? AND interno=0 AND inicio BETWEEN ? AND ?')
            .all(sl, per.ini, per.fim).forEach(r => s.add(r.visitante)));
          extra.testes = [...slugs];
        }
      }
      conj[o.id] = s;
      nos[o.id] = Object.assign({ tipo: 'fonte', canal }, medir(s), extra);
    });
    const abst = (Array.isArray(dbj.store[KEY_ABSTATS]) ? dbj.store[KEY_ABSTATS] : []).concat(Object.values(_abBuffer));
    const redirs = Array.isArray(dbj.store[KEY_REDIRS]) ? dbj.store[KEY_REDIRS] : [];
    (f.etapas || []).forEach(e => {
      const temPagina = porEtapa[e.id] && porEtapa[e.id].size;
      if (e.tipo === 'split') {
        const slug = String(e.slug || '').toLowerCase();
        const s = new Set();
        if (slug) _q('SELECT DISTINCT visitante FROM sessoes WHERE lower(teste)=? AND interno=0 AND inicio BETWEEN ? AND ?')
          .all(slug, per.ini, per.fim).forEach(r => s.add(r.visitante));
        const r = redirs.find(x => String(x.slug || '').toLowerCase() === slug);
        const sorteio = {};
        abst.filter(l => l.teste === slug && l.data >= per.de && l.data <= per.ate).forEach(l => { sorteio[l.variante] = (sorteio[l.variante] || 0) + (l.sorteios || 0); });
        const tot = Object.values(sorteio).reduce((a, n) => a + n, 0);
        conj[e.id] = s;
        nos[e.id] = Object.assign({ tipo: 'split', slug, nomeTeste: r ? (r.nome || r.slug) : '', cliques: tot,
          divisao: ((r && r.destinos) || []).map((d, i) => { const id = String(d.id || ('v' + i)); return { nome: d.nome || ('Variante ' + (i + 1)), url: d.url || '', pct: tot ? (sorteio[id] || 0) / tot : null }; }) }, medir(s));
      } else if (e.tipo === 'checkout' && !temPagina) {
        // Checkout do gateway não recebe pixel: vale quem clicou em comprar, e
        // quem comprou (passou pelo checkout mesmo se o clique não foi visto).
        // "Compraram" é toda venda do funil (do produto do bloco, se escolhido):
        // o mesmo número do Obrigado e do topo.
        const lst = prodLista(e);
        const vf = vendas.filter(o => casaProd(o, lst));
        conj[e.id] = abriramSet;
        nos[e.id] = { tipo: 'checkout', viaClique: true, produto: e.produto || '', integracao: e.integracao || '',
                      pessoas: abriramSet.size, cliques: ck.size, vendas: vf.length, faturamento: dir ? vf.reduce((a, o) => a + liq(o), 0) : null,
                      // conversão só com venda que tem pessoa: a que entrou pela campanha
                      // ou pelo produto não passou por clique nenhum que dê pra contar
                      conversao: abriramSet.size ? vf.filter(o => o.visitante).length / abriramSet.size : 0,
                      semPessoa: vf.filter(o => !o.visitante).length,
                      produtos: topProd(vf), semClique: [...compradores].filter(v => !ck.has(v)).length };
      } else if ((e.tipo === 'obrigado' || ((e.tipo === 'upsell' || e.tipo === 'downsell') && (e.pagamento || prodLista(e).length))) && !temPagina) {
        // sem página com pixel: o bloco é a venda em si (do produto dele, se escolhido)
        const lst = prodLista(e);
        const vf = (e.tipo === 'obrigado' || lst.length) ? vendas.filter(o => casaProd(o, lst)) : [];
        const quem = new Set(vf.map(o => o.visitante).filter(Boolean));
        conj[e.id] = quem;
        nos[e.id] = { tipo: e.tipo, viaVenda: true, produto: e.produto || '', integracao: e.integracao || '',
                      pessoas: quem.size, vendas: vf.length, faturamento: dir ? vf.reduce((a, o) => a + liq(o), 0) : null,
                      semPessoa: vf.filter(o => !o.visitante).length, produtos: topProd(vf), semProduto: e.tipo !== 'obrigado' && !lst.length };
      } else if (e.tipo === 'recuperacao') {
        const vr = vendas.filter(o => o.apoio);
        const s = new Set(vr.map(o => o.visitante).filter(Boolean));
        conj[e.id] = s;
        nos[e.id] = { tipo: 'recuperacao', pessoas: s.size, vendas: vr.length, faturamento: dir ? vr.reduce((a, o) => a + liq(o), 0) : null };
      } else {
        const s = porEtapa[e.id] || new Set(), lst = prodLista(e);
        conj[e.id] = s;
        nos[e.id] = Object.assign({ tipo: e.tipo || 'pagina', produto: e.produto || '' }, medirPagina(e.id, lst));
      }
    });
    const fios = {};
    (f.ligacoes || []).forEach(l => {
      const A = conj[l[0]], B = conj[l[1]];
      if (!A || !B || !A.size) return;
      let n = 0; A.forEach(v => { if (B.has(v)) n++; });
      fios[l[0] + '|' + l[1]] = { n, pct: n / A.size };
    });
    // páginas com o pixel do funil que não estão no desenho (só a contagem)
    const fora = _q('SELECT p.pg, COUNT(DISTINCT p.visitante) n FROM paginas p WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND p.funil IN (' +
                    _ph(esc.ids.length) + ') AND NOT ' + esq.where + ' GROUP BY p.pg ORDER BY n DESC LIMIT 30')
      .all(per.de, per.ate, ...esc.ids, ...esq.args).filter(x => !esc.ignoradas.has(x.pg));
    res.json({ ok: true, de: per.de, ate: per.ate, chegaram: todos.size, vendas: vendas.length, nos, fios, fora });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── FLUXO DO FUNIL ──
// O mapa desenhado à mão misturava setas que ninguém liga com números que
// vinham de lugares diferentes ("740% de quem entrou"). O Fluxo é montado
// sozinho: fonte → página de entrada → checkout → compra. Cada pessoa conta
// UMA vez, na primeira página do funil em que chegou no período; então as
// páginas somam o total e nenhuma porcentagem passa de 100%.
// A venda vai pra página de entrada de quem comprou (ligada pela jornada).
// ══════════════════════════════════════════════════════
app.get('/api/funil/fluxo', authUsuario, async (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const per = _periodoMs(String(req.query.de || ''), String(req.query.ate || ''));
    const dir = _ehDir(req), custos = _custosCfg(dbj);
    const esq = _escopoSql(esc, 'p');
    const linhas = _q(`SELECT p.visitante, p.pg, p.etapa, p.funil, p.em, s.checkout, s.pitch FROM paginas p JOIN sessoes s ON s.id = p.sessao
                       WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND ((` + esq.where + `) OR p.funil IN (` + _ph(esc.ids.length) + `))
                       ORDER BY p.em`).all(per.de, per.ate, ...esq.args, ...esc.ids);
    const pessoa = {};
    linhas.forEach(l => {
      if (esc.ignoradas.has(l.pg)) return;
      const noMapa = !!(esc.etapaDeUrl[l.pg] || (esc.ids.indexOf(l.funil) >= 0 && esc.etapaDeData[l.etapa]));
      const x = pessoa[l.visitante] || (pessoa[l.visitante] = { entrada: null, entradaFora: null, checkout: 0, pitch: 0, noMapa: false });
      if (noMapa && !x.entrada) x.entrada = l.pg;
      if (!noMapa && !x.entradaFora) x.entradaFora = l.pg;
      if (noMapa) x.noMapa = true;
      if (l.checkout) x.checkout = 1;
      if (l.pitch) x.pitch = 1;
      if (noMapa && !x.etapa) x.etapa = _etapaDaLinha(esc, l.pg, l.etapa);
    });
    const pgs = {};
    const pg = (k, fora) => pgs[k] || (pgs[k] = { pg: k, fora, pessoas: 0, checkout: 0, pitch: 0, vendas: 0, compradores: new Set(), fat: 0, etapa: null });
    let chegaram = 0, checkout = 0, pitch = 0;
    Object.keys(pessoa).forEach(v => {
      const x = pessoa[v];
      if (x.noMapa) {
        const p = pg(x.entrada, false); p.etapa = p.etapa || x.etapa;
        p.pessoas++; p.checkout += x.checkout; p.pitch += x.pitch;
        chegaram++; checkout += x.checkout; pitch += x.pitch;
      } else if (x.entradaFora) {
        const p = pg(x.entradaFora, true); p.pessoas++; p.checkout += x.checkout; p.pitch += x.pitch;
      }
    });

    // vendas do funil no período (a mesma regra do Resultado)
    const nomes = {};
    _q('SELECT id, nome FROM camp_dia WHERE dia BETWEEN ? AND ?').all(per.de, per.ate).forEach(c => { nomes[c.id] = c.nome; });
    const liq = o => (o.liquido != null ? o.liquido : (Number(o.valor) || 0) * (1 - (custos.gateway || 0) / 100));
    const vendas = _vendasDoFunil(dbj, esc, per, nomes, _regraCampanhas(esc.f)).filter(o => o.pago && !o.estorno);
    let semPagina = 0, fatSemPagina = 0, fat = 0;
    const porComo = { jornada: 0, campanha: 0, produto: 0 };
    vendas.forEach(o => {
      porComo[o.por] = (porComo[o.por] || 0) + 1;
      fat += liq(o);
      let alvo = o.visitante && pessoa[o.visitante] && pessoa[o.visitante].noMapa ? pessoa[o.visitante].entrada : null;
      if (!alvo && o.visitante) {
        // comprou hoje, mas chegou antes do período: vai pra última página do mapa dele
        const r = _q('SELECT p.pg FROM paginas p WHERE p.visitante=? AND ' + esq.where + ' ORDER BY p.em DESC LIMIT 1').get(o.visitante, ...esq.args);
        if (r) alvo = r.pg;
      }
      if (!alvo) { semPagina++; fatSemPagina += liq(o); return; }
      const p = pg(alvo, false);
      p.vendas++; p.fat += liq(o); if (o.visitante) p.compradores.add(o.visitante);
    });

    // páginas que são variante de um teste A/B do projeto
    const teste = {};
    (Array.isArray(dbj.store[KEY_REDIRS]) ? dbj.store[KEY_REDIRS] : []).filter(r => r && (r.projeto || '') === (esc.f.projeto || '') && r.ativo !== false && !r.vencedora)
      .forEach(r => (r.destinos || []).forEach((d, i) => {
        const k = _normPg(d.url); if (k && !teste[k]) teste[k] = { teste: r.nome || r.slug, variante: d.nome || ('Variante ' + (i + 1)), controle: i === 0 };
      }));

    // fonte: o arquivo de campanhas do Resultado (sem esperar a Utmify)
    let cliques = null, investido = null;
    try {
      const proj = await _projetoIdDoFunil(esc.f);
      const camp = await _campanhasPeriodo(per.de, per.ate, proj, 0);
      _campAtualizarDepois(per.de, per.ate, proj);
      const regra = _regraCampanhas(esc.f);
      cliques = 0; investido = 0;
      Object.keys(camp.porDia).forEach(d => camp.porDia[d].forEach(c => { if (!regra || regra(c.nome)) { cliques += c.cliques; investido += c.gasto; } }));
    } catch (e) {}

    const lista = Object.values(pgs).map(p => ({
      pg: p.pg, fora: p.fora, nome: p.etapa ? (esc.nomeEtapa[p.etapa] || '') : '', tipo: p.etapa ? (esc.tipoEtapa[p.etapa] || '') : '',
      etapa: p.etapa || null, pessoas: p.pessoas, pitch: p.pitch, checkout: p.checkout, vendas: p.vendas,
      faturamento: dir ? p.fat : null, teste: teste[p.pg] || null,
      share: (!p.fora && chegaram) ? p.pessoas / chegaram : null,
      conversao: p.pessoas ? p.vendas / p.pessoas : 0, taxaCheckout: p.pessoas ? p.checkout / p.pessoas : 0
    }));
    const dentro = lista.filter(p => !p.fora).sort((a, b) => b.pessoas - a.pessoas);
    const fora = lista.filter(p => p.fora && p.pessoas > 0).sort((a, b) => b.pessoas - a.pessoas).slice(0, 6);
    res.json({ ok: true, de: per.de, ate: per.ate, semRegra: !_regraCampanhas(esc.f),
      fonte: { cliques, investido, chegaram, perdaClique: (cliques && chegaram <= cliques) ? 1 - chegaram / cliques : null },
      paginas: dentro, fora,
      checkout: { pessoas: checkout, pct: chegaram ? checkout / chegaram : 0 },
      pitch: { pessoas: pitch, pct: chegaram ? pitch / chegaram : 0 },
      compraram: { vendas: vendas.length, faturamento: dir ? fat : null, conversao: chegaram ? (vendas.length - semPagina) / chegaram : 0,
                   deCheckout: checkout ? (vendas.length - semPagina) / checkout : 0, semPagina, fatSemPagina: dir ? fatSemPagina : null, porComo } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── JORNADA AO VIVO ──
// Quem está no funil agora: na página (5 min), vendo a VSL e em que minuto,
// no checkout (15 min), a última venda e o feed do que importa. A tela pede
// de 5 em 5 segundos; tudo aqui é consulta curta na base de pessoas.
// ══════════════════════════════════════════════════════
app.get('/api/funil/ao-vivo', authUsuario, (req, res) => {
  try {
    if (!_pessoas()) return res.status(503).json({ error: 'A base de pessoas não abriu neste servidor.' });
    const dbj = readDB();
    const esc = _escopoFunil(dbj, String(req.query.funil || ''));
    if (!esc) return res.status(404).json({ error: 'Funil não encontrado.' });
    const agora = Date.now(), hoje = _diaBR(agora), iniHoje = Date.parse(hoje + 'T00:00:00-03:00');
    const esq = _escopoSql(esc, 'p');
    const dir = _ehDir(req);
    // na página agora: visita com sinal de vida nos últimos 5 min
    const agoraPg = _q(`SELECT p.pg, COUNT(DISTINCT s.visitante) n FROM sessoes s JOIN paginas p ON p.sessao = s.id
                        WHERE s.fim >= ? AND s.interno=0 AND ` + esq.where + ` GROUP BY p.pg ORDER BY n DESC`).all(agora - 5 * 60000, ...esq.args);
    const naPagina = _q(`SELECT COUNT(DISTINCT s.visitante) n FROM sessoes s JOIN paginas p ON p.sessao = s.id
                         WHERE s.fim >= ? AND s.interno=0 AND ` + esq.where).get(agora - 5 * 60000, ...esq.args).n;
    // na VSL agora: pulso do vídeo nos últimos 2 min (fica na memória)
    const urls = new Set(Object.keys(esc.etapaDeUrl)), ids = new Set(esc.ids);
    const vendo = [];
    for (const [vis, v] of _pVideo) if (agora - v.em < 2 * 60000 && !v.interno && (urls.has(v.pg) || ids.has(v.funil))) vendo.push(v);
    const faixas = [
      { rot: '0 a 1 min', n: vendo.filter(v => v.seg < 60).length },
      { rot: '1 a 10 min', n: vendo.filter(v => v.seg >= 60 && v.seg < 600 && !(v.pitch && v.seg >= v.pitch)).length },
      { rot: '10 min a pitch', n: vendo.filter(v => v.seg >= 600 && !(v.pitch && v.seg >= v.pitch)).length },
      { rot: 'Depois do pitch', n: vendo.filter(v => v.pitch && v.seg >= v.pitch).length }
    ];
    const noCheckout = _q(`SELECT COUNT(DISTINCT e.visitante) n FROM eventos e WHERE e.tipo='checkout' AND e.em >= ? AND (e.funil IN (` + _ph(esc.ids.length) + `) OR e.pg IN (` +
                           _ph(Math.max(1, urls.size)) + `))`).get(agora - 15 * 60000, ...esc.ids, ...(urls.size ? [...urls] : [''])).n;
    const ultVenda = _q(`SELECT o.* FROM pedidos o WHERE o.pago=1 AND o.estorno=0 AND (o.funil IN (` + _ph(esc.ids.length) + `) OR o.visitante IN
                          (SELECT DISTINCT p.visitante FROM paginas p WHERE p.dia >= ? AND ` + esq.where + `)) ORDER BY o.em DESC LIMIT 1`)
      .get(...esc.ids, _diaBR(agora - 30 * 86400000), ...esq.args);
    // o feed: o que aconteceu, do mais novo pro mais velho
    const tipos = req.query.tudo === '1' ? null : ['compra', 'tentativa', 'checkout', 'pitch', 'friccao', 'estorno'];
    const evs = _q(`SELECT e.*, v.p_fonte, v.p_cont, l.nome FROM eventos e LEFT JOIN visitantes v ON v.id = e.visitante LEFT JOIN leads l ON l.id = v.lead
                    WHERE e.em >= ? AND (e.funil IN (` + _ph(esc.ids.length) + `) OR e.pg IN (` + _ph(Math.max(1, urls.size)) + `))` +
                    (tipos ? ` AND e.tipo IN (` + _ph(tipos.length) + `)` : ``) + ` AND COALESCE(v.interno,0)=0 ORDER BY e.em DESC LIMIT 40`)
      .all(agora - 24 * 3600000, ...esc.ids, ...(urls.size ? [...urls] : ['']), ...(tipos || []));
    const feed = evs.filter(e => tipos || e.tipo !== 'video').map(e => {
      let x = {}; try { x = JSON.parse(e.extra || '{}'); } catch (er) {}
      // no "só importantes" o clique morto fica de fora; o de raiva entra
      if (tipos && e.tipo === 'friccao' && x.motivo !== 'raiva') return null;
      return { tipo: e.tipo, em: e.em, visitante: e.visitante, nome: e.nome || '', fonte: e.p_fonte || '', anuncio: e.p_cont ? String(e.p_cont).split('|')[0] : '',
               pg: e.pg || '', rot: dir ? (e.rot || '') : _semValor(e.rot), extra: x };
    }).filter(Boolean);
    // alertas do dia: clique morto por elemento + o que as regras apontaram hoje
    const mortos = _q(`SELECT e.rot, COUNT(*) n FROM eventos e WHERE e.tipo='friccao' AND e.em >= ? AND e.extra LIKE '%morto%' AND
                       (e.funil IN (` + _ph(esc.ids.length) + `) OR e.pg IN (` + _ph(Math.max(1, urls.size)) + `)) GROUP BY e.rot ORDER BY n DESC LIMIT 3`)
      .all(iniHoje, ...esc.ids, ...(urls.size ? [...urls] : ['']));
    const alertas = mortos.filter(m => m.n >= 5 && m.rot).map(m => ({ nivel: 'atencao',
      titulo: '"' + String(m.rot).slice(0, 40) + '" com ' + m.n + ' cliques mortos hoje',
      texto: 'Parece clicável e não é. Transformar em botão (ou tirar a cara de botão) tende a subir o checkout.' }));
    const regLog = Array.isArray(dbj.store['sl_regras_log']) ? dbj.store['sl_regras_log'] : [];
    const verbo = { pausar: 'sugere pausar', orcamento: 'sugere subir o orçamento', alerta: 'avisa', trava: 'segurou' };
    regLog.filter(l => l.dia === hoje && !l.desfeito).slice(-3).reverse().forEach(l => {
      alertas.unshift({ nivel: l.tipo === 'orcamento' ? 'bom' : 'ruim', titulo: String(l.alvo || 'Regra').slice(0, 60) + ': ' + String(l.racional || '').split('.')[0],
        texto: 'Regra "' + (l.regraNome || l.regra) + '" ' + (verbo[l.tipo] || 'avisa') + (l.simulado ? ' (simulação).' : '.'), regras: true });
    });
    res.json({ ok: true, em: agora,
      cards: { naPagina, porPagina: agoraPg.slice(0, 3).map(x => ({ pg: x.pg, n: x.n })), vendo: vendo.length,
               passaramPitch: vendo.filter(v => v.pitch && v.seg >= v.pitch).length, noCheckout,
               ultimaVenda: ultVenda ? { em: ultVenda.em, valor: dir ? ultVenda.valor : null, produto: ultVenda.produto || '',
                                         anuncio: ultVenda.cred_cont ? String(ultVenda.cred_cont).split('|')[0] : '' } : null },
      faixas, feed, alertas });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── RECUPERAÇÃO ──
// Quem tentou pagar e não pagou, quanto isso vale e por quê. Só olha o que o
// checkout mandou pelo webhook: nada é inventado. Método de pagamento e
// telefone são guardados a partir de 29/09 — antes disso o motivo sai genérico.
// ══════════════════════════════════════════════════════
const _FALHOU = /^(canceled|cancelled|cancelad|waiting|pending|pendente|aguardando|lost_cart|abandon|refused|recusad|expired|expirad|billet_printed|boleto)/i;
const _ESTORNO = /(chargeback|refund|reembols|estorn)/i;
function _motivoFalha(v) {
  const st = String(v.status || '').toLowerCase(), m = String(v.metodo || '').toLowerCase();
  const pix = /pix/.test(m), cartao = /card|cart|credit|credito|crédito/.test(m), boleto = /billet|boleto|bank_slip/.test(m);
  if (/lost_cart|abandon/.test(st)) return 'Carrinho abandonado';
  if (/waiting|pending|pendente|aguardando|billet_printed/.test(st)) {
    if (pix) return (v.expiraEm && new Date(v.expiraEm).getTime() < Date.now()) ? 'Pix expirado' : 'Pix gerado, não pago';
    if (boleto) return 'Boleto não pago';
    return 'Aguardando pagamento';
  }
  if (/expired|expirad/.test(st)) return pix ? 'Pix expirado' : 'Pagamento expirado';
  if (/refused|recusad|canceled|cancelled|cancelad/.test(st)) {
    if (cartao) return 'Cartão recusado';
    if (pix) return 'Pix expirado';
    if (boleto) return 'Boleto vencido';
    return 'Cancelado (motivo não informado)';
  }
  return 'Não pago';
}
function _pessoaDaVenda(v) {
  const e = String(v.email || '').trim().toLowerCase();
  if (e) return 'e:' + e;
  const t = String(v.telefone || '').replace(/\D/g, '');
  if (t.length >= 10) return 't:' + t.slice(-11);
  const n = String(v.cliente || '').trim().toLowerCase();
  return n ? 'n:' + n : '';
}
function _canalRecuperacao(v) {
  const f = String(v.utmSource || '').toLowerCase();
  if (/paytcall|ligac|call/.test(f)) return 'Ligação Payt';
  if (/whats|wpp|zap/.test(f)) return 'WhatsApp';
  if (/mail/.test(f)) return 'E-mail';
  if (/sms/.test(f)) return 'SMS';
  return 'Voltou sozinho';
}
function _nomeCurto(n) {
  const p = String(n || '').trim().split(/\s+/).filter(Boolean);
  if (!p.length) return '(sem nome)';
  return p[0].charAt(0).toUpperCase() + p[0].slice(1).toLowerCase() + (p.length > 1 ? ' ' + p[p.length - 1].charAt(0).toUpperCase() + '.' : '');
}

app.get('/api/recuperacao', authDiretoria, (req, res) => {
  try {
    const dias = Math.max(1, Math.min(60, parseInt(req.query.dias, 10) || 1));
    const db = readDB(), agora = Date.now();
    // "hoje" é o dia de Brasília; os outros períodos contam pra trás
    const hojeBRT = new Date(agora - 3 * 3600000).toISOString().slice(0, 10);
    const inicio = dias === 1 ? new Date(hojeBRT + 'T03:00:00Z').getTime() : agora - dias * 86400000;
    const vendas = (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : [])
      .filter(v => v && !v.renovacao).slice().sort((a, b) => String(a.recebidoEm).localeCompare(String(b.recebidoEm)));
    // quanto a pessoa assistiu, pelo pixel (quando existe a jornada)
    const atencao = {};
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer || {})).forEach(j => {
      if (!j || !j.id) return;
      (j.eventos || []).forEach(e => { const s = Number(e.atencao || e.segundos) || 0; if (s > (atencao[j.id] || 0)) atencao[j.id] = s; });
    });
    const pessoas = {};
    vendas.forEach(v => {
      const k = _pessoaDaVenda(v); if (!k) return;
      (pessoas[k] = pessoas[k] || []).push(v);
    });
    const fila = [], recuperadas = [], motivos = {}, porCanal = {};
    let emJogo = 0, recuperado = 0;
    Object.keys(pessoas).forEach(k => {
      const evs = pessoas[k];
      const falhas = evs.filter(v => !_vendaPaga(v) && !_ESTORNO.test(String(v.status || '')) && _FALHOU.test(String(v.status || '')) &&
                                     new Date(v.recebidoEm).getTime() >= inicio);
      if (!falhas.length) return;
      const primeira = falhas[0];
      const pagouDepois = evs.find(v => _vendaPaga(v) && String(v.recebidoEm) >= String(primeira.recebidoEm));
      const ultima = falhas[falhas.length - 1];
      const motivo = _motivoFalha(ultima);
      if (pagouDepois) {
        const canal = _canalRecuperacao(pagouDepois);
        const val = Number(pagouDepois.valor) || 0;
        recuperado += val;
        const c = porCanal[canal] = porCanal[canal] || { canal, vendas: 0, valor: 0 };
        c.vendas++; c.valor += val;
        recuperadas.push({ nome: _nomeCurto(pagouDepois.cliente || ultima.cliente), valor: val, canal, motivo,
          tentativas: falhas.length, minutos: Math.round((new Date(pagouDepois.recebidoEm) - new Date(primeira.recebidoEm)) / 60000) });
        return;
      }
      const valor = Math.max.apply(null, falhas.map(v => Number(v.valor) || 0));
      emJogo += valor;
      motivos[motivo] = (motivos[motivo] || 0) + 1;
      const vid = (falhas.find(v => v.vid) || {}).vid;
      fila.push({
        nome: _nomeCurto(ultima.cliente), produto: ultima.plano || ultima.produto || '', valor, motivo,
        tentativas: falhas.length, ultima: ultima.recebidoEm,
        horas: Math.max(0, Math.round((agora - new Date(ultima.recebidoEm).getTime()) / 3600000)),
        telefone: String(ultima.telefone || (evs.find(v => v.telefone) || {}).telefone || ''),
        assistiu: vid && atencao[vid] ? Math.round(atencao[vid]) : null
      });
    });
    // aprovação no cartão e pix pendente, no mesmo período
    const doPeriodo = vendas.filter(v => new Date(v.recebidoEm).getTime() >= inicio);
    const cartao = doPeriodo.filter(v => /card|cart|credit/i.test(v.metodo || ''));
    const cartaoPago = cartao.filter(_vendaPaga).length;
    const cartaoRecusado = cartao.filter(v => /refused|recusad|cancel/i.test(v.status || '')).length;
    const pixPendente = doPeriodo.filter(v => /pix/i.test(v.metodo || '') && /waiting|pending|aguardando/i.test(v.status || '') &&
      !(v.expiraEm && new Date(v.expiraEm).getTime() < agora) &&
      !vendas.some(x => _vendaPaga(x) && x.pedidoId && x.pedidoId === v.pedidoId));
    fila.sort((a, b) => (b.valor - a.valor) || (a.horas - b.horas));
    // sugestão: recusa no cartão em compra cara é quase sempre limite
    let sugestao = '';
    const recusas = motivos['Cartão recusado'] || 0;
    if (recusas >= 3) {
      const caras = fila.filter(x => x.motivo === 'Cartão recusado' && x.valor >= 400).length;
      if (caras) sugestao = caras + ' recusa(s) no cartão em compras acima de R$ 400. Recusa em valor alto costuma ser limite: ' +
                            'oferecer o plano mais barato (mensal) pra quem tentou o anual recupera parte dessas vendas.';
    }
    const semMetodo = doPeriodo.filter(v => !v.metodo).length;
    res.json({ ok: true, dias, desde: new Date(inicio).toISOString(),
      emJogo: { valor: emJogo, pessoas: fila.length },
      recuperado: { valor: recuperado, vendas: recuperadas.length,
                    taxa: (recuperadas.length + fila.length) ? recuperadas.length / (recuperadas.length + fila.length) : 0 },
      cartao: { pagos: cartaoPago, recusados: cartaoRecusado, taxa: (cartaoPago + cartaoRecusado) ? cartaoPago / (cartaoPago + cartaoRecusado) : null },
      pixPendente: { quantos: pixPendente.length, valor: pixPendente.reduce((a, v) => a + (Number(v.valor) || 0), 0) },
      motivos: Object.entries(motivos).map(([motivo, n]) => ({ motivo, n })).sort((a, b) => b.n - a.n),
      porCanal: Object.values(porCanal).sort((a, b) => b.valor - a.valor),
      fila: fila.slice(0, 200), recuperadas: recuperadas.slice(0, 50), sugestao,
      semMetodo, historicoDesde: '2026-09-29' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── ASSINATURAS E LTV ──
// O ROAS do dia não enxerga renovação: um criativo que "empata" pode trazer
// cliente que vale 30% menos no terceiro mês. Aqui cada assinatura vira uma
// linha do tempo de pagamentos — pelo código da assinatura quando o checkout
// manda, e pela pessoa + produto quando é venda antiga.
// ══════════════════════════════════════════════════════
const _DIAS_PLANO = { mensal: 31, trimestral: 92, semestral: 183, anual: 366 };
function _planoDaVenda(v, cfg) {
  const per = String(v.periodicidade || '').toLowerCase();
  if (/month|mensal/.test(per)) return 'mensal';
  if (/quarter|trimes/.test(per)) return 'trimestral';
  if (/semi|semes|six/.test(per)) return 'semestral';
  if (/year|annual|anual/.test(per)) return 'anual';
  const pn = _planoPorNome(v.plano) || _planoPorNome(v.produto);
  if (pn) return pn.chave;
  const pv = cfg ? _planoPorValor(v.valor, cfg) : null;
  return pv ? pv.chave : 'outro';
}
const _mesDe = iso => String(iso || '').slice(0, 7);
function _mesesEntre(a, b) { const [ya, ma] = a.split('-').map(Number), [yb, mb] = b.split('-').map(Number); return (yb - ya) * 12 + (mb - ma); }

app.get('/api/assinaturas', authUsuario, async (req, res) => {
  try {
    const db = readDB(), cfg = _planosCfg(db), agora = Date.now();
    const pagas = (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).filter(_vendaPaga)
      .slice().sort((a, b) => String(a.recebidoEm).localeCompare(String(b.recebidoEm)));
    const subs = {};
    pagas.forEach(v => {
      const k = v.assinatura ? 's:' + v.assinatura : (_pessoaDaVenda(v) ? _pessoaDaVenda(v) + '|' + _nrm(v.produto) : '');
      if (!k) return;
      const x = subs[k] = subs[k] || { pagamentos: [], plano: '', criativo: '', produto: v.produto || '' };
      x.pagamentos.push({ em: v.recebidoEm, valor: Number(v.valor) || 0 });
      if (!x.plano || x.plano === 'outro') x.plano = _planoDaVenda(v, cfg);
      if (!x.criativo && _origemVale(v.utmContent)) x.criativo = String(v.utmContent);
    });
    const lista = Object.values(subs).map(x => {
      const inicio = x.pagamentos[0].em, ultimo = x.pagamentos[x.pagamentos.length - 1].em;
      const dur = _DIAS_PLANO[x.plano] || 31;
      const cobreAte = new Date(new Date(ultimo).getTime() + dur * 86400000);
      const total = x.pagamentos.reduce((a, p) => a + p.valor, 0);
      const ate90 = x.pagamentos.filter(p => new Date(p.em) - new Date(inicio) <= 90 * 86400000).reduce((a, p) => a + p.valor, 0);
      return { plano: x.plano, criativo: x.criativo, inicio, ultimo, cobreAte: cobreAte.toISOString(),
               ativo: cobreAte.getTime() + 7 * 86400000 >= agora, pagamentos: x.pagamentos.length, total, ate90,
               idadeDias: Math.floor((agora - new Date(inicio).getTime()) / 86400000) };
    });
    const mesAtual = new Date(agora - 3 * 3600000).toISOString().slice(0, 7);
    const ativos = lista.filter(x => x.ativo).length;
    const recorrenteMes = pagas.filter(v => _mesDe(v.recebidoEm) === mesAtual && (v.renovacao || Number(v.cobrancas) > 1))
                               .reduce((a, v) => a + (Number(v.valor) || 0), 0);
    // coortes por mês de entrada: % que ainda está coberta (pagou e o período vale) em cada mês
    const coortes = {};
    lista.forEach(x => {
      const m0 = _mesDe(x.inicio), c = coortes[m0] = coortes[m0] || { mes: m0, clientes: 0, meses: [0, 0, 0, 0] };
      c.clientes++;
      for (let k = 0; k < 4; k++) {
        const [y, m] = m0.split('-').map(Number);
        const ini = new Date(Date.UTC(y, m - 1 + k, 1)), fim = new Date(Date.UTC(y, m + k, 0));
        if (ini.getTime() > agora) { c.meses[k] = null; continue; }
        if (c.meses[k] === null) continue;
        // coberto nesse mês = algum pagamento cobre o começo do mês (ou é o próprio mês de entrada)
        const coberto = k === 0 || new Date(x.cobreAte).getTime() >= ini.getTime() + 5 * 86400000;
        if (coberto) c.meses[k]++;
      }
    });
    const tabCoortes = Object.values(coortes).sort((a, b) => a.mes.localeCompare(b.mes)).map(c => ({
      mes: c.mes, clientes: c.clientes, pct: c.meses.map(n => n === null ? null : (c.clientes ? n / c.clientes : 0)) }));
    // LTV por plano: 90 dias só com quem já tem 90 dias; senão, o que pagou até hoje
    const porPlano = {};
    lista.forEach(x => {
      const p = porPlano[x.plano] = porPlano[x.plano] || { plano: x.plano, clientes: 0, entrada: 0, somaAteHoje: 0, com90: 0, soma90: 0, mensalVelhos: 0, mensalSo1: 0 };
      p.clientes++; p.entrada += x.pagamentos ? (x.total / x.pagamentos) : 0; p.somaAteHoje += x.total;
      if (x.idadeDias >= 90) { p.com90++; p.soma90 += x.ate90; }
      if (x.plano === 'mensal' && x.idadeDias >= 35) { p.mensalVelhos++; if (x.pagamentos < 2) p.mensalSo1++; }
    });
    const planos = Object.values(porPlano).map(p => ({ plano: p.plano, clientes: p.clientes,
      entrada: p.clientes ? p.entrada / p.clientes : 0,
      ltv90: p.com90 ? p.soma90 / p.com90 : null, ltvAteHoje: p.clientes ? p.somaAteHoje / p.clientes : 0,
      cancelaMes1: p.mensalVelhos ? p.mensalSo1 / p.mensalVelhos : null }))
      .sort((a, b) => b.clientes - a.clientes);
    const porCri = {};
    lista.forEach(x => {
      if (!x.criativo) return;
      const c = porCri[x.criativo] = porCri[x.criativo] || { criativo: x.criativo, clientes: 0, soma: 0, velhos: 0, renovaram: 0 };
      c.clientes++; c.soma += x.total;
      if (x.plano === 'mensal' && x.idadeDias >= 35) { c.velhos++; if (x.pagamentos >= 2) c.renovaram++; }
    });
    const criativos = Object.values(porCri).filter(c => c.clientes >= 2).map(c => ({ criativo: c.criativo, clientes: c.clientes,
      ltvAteHoje: c.soma / c.clientes, renovacaoMes2: c.velhos ? c.renovaram / c.velhos : null }))
      .sort((a, b) => b.ltvAteHoje - a.ltvAteHoje).slice(0, 20);
    const com90 = lista.filter(x => x.idadeDias >= 90);
    const ltv90Medio = com90.length ? com90.reduce((a, x) => a + x.ate90, 0) / com90.length : null;
    const ltvAteHoje = lista.length ? lista.reduce((a, x) => a + x.total, 0) / lista.length : 0;
    // CPA atual pra comparar: gasto ÷ vendas aprovadas dos últimos 30 dias (Utmify)
    let cpa30 = null;
    try {
      const fim = new Date(agora - 3 * 3600000).toISOString().slice(0, 10), ini = new Date(agora - 30 * 86400000 - 3 * 3600000).toISOString().slice(0, 10);
      const pano = await _utmifyPanorama(ini, fim, '');
      const k = pano.kpis || {};
      if (Number(k.cpa) > 0) cpa30 = Number(k.cpa);
    } catch (e) {}
    const primeiro = pagas.length ? pagas[0].recebidoEm : null;
    res.json({ ok: true, assinantes: lista.length, ativos, recorrenteMes, mesAtual,
      ltv90Medio, ltvAteHoje, cpaMaximo: ltv90Medio != null ? ltv90Medio : ltvAteHoje, cpaBase: ltv90Medio != null ? '90d' : 'ateHoje',
      cpa30, coortes: tabCoortes, planos, criativos,
      historicoDesde: primeiro, diasDeHistorico: primeiro ? Math.floor((agora - new Date(primeiro).getTime()) / 86400000) : 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── CRIATIVO ATÉ A VENDA ──
// Uma linha por anúncio, do gasto à venda: Utmify (gasto, clique, checkout,
// venda), o pixel (quem chegou de verdade na página) e — na tela — a VTurb
// (quem passou do pitch, pelo utm_content). O nome do anúncio é quebrado no
// padrão da casa (estrutura | nicho | AD | conta | data) e as veiculações do
// mesmo AD somam juntas.
// ══════════════════════════════════════════════════════
function _partesDoNome(nome) {
  const t = String(nome || '').split('|').map(x => x.trim()).filter(Boolean);
  const achaAd = t.find(x => /^AD[\w.\-]*$/i.test(x)) || (String(nome).match(/\bAD[\w.\-]+/i) || [])[0] || '';
  const data = t.find(x => /^\d{1,2}\/\d{1,2}(\/\d{2,4})?$/.test(x)) || '';
  const out = { ad: achaAd ? achaAd.toUpperCase() : '', estrutura: '', nicho: '', conta: '', data };
  if (t.length >= 4 && achaAd) {
    const i = t.indexOf(achaAd);
    out.estrutura = t[0] !== achaAd ? t[0] : '';
    out.nicho = i > 1 ? t[i - 1] : '';
    out.conta = t[i + 1] && t[i + 1] !== data ? t[i + 1] : '';
  }
  return out;
}
function _diagnosticoCriativo(x) {
  const temVolume = x.cliques >= 50;
  if (x.vendas >= 3 && x.roas >= 1.5) return { nivel: 'ok', rot: 'Escalar' };
  if (temVolume && x.pctChegou != null && x.pctChegou < 0.7) return { nivel: 'ruim', rot: 'Perde ' + Math.round((1 - x.pctChegou) * 100) + '% antes da página' };
  if (x.investimento < 800 && x.roas >= 1.3) return { nivel: 'ok', rot: 'Pouco gasto, testar mais' };
  if (x.investimento >= 1000 && x.roas < 0.6) return { nivel: 'ruim', rot: 'Cortar' };
  if (x.ctr >= 3 && x.roas < 1) return { nivel: 'atencao', rot: 'Traz clique, não traz comprador' };
  return { nivel: 'info', rot: 'Segurar' };
}
app.get('/api/criativos/ate-a-venda', authUsuario, async (req, res) => {
  try {
    const de = String(req.query.de || '').slice(0, 10), ate = String(req.query.ate || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) return res.status(400).json({ error: 'Informe de/ate.' });
    const projeto = String(req.query.projeto || '').slice(0, 40);
    const ads = await new Promise(resolve => _rotaAnuncios({ query: { de, ate, projeto } },
      { json: d => resolve(d), status: () => ({ json: d => resolve(Object.assign({ erroRota: true }, d)) }) }));
    if (!ads || ads.erroRota || ads.error) return res.status(400).json({ error: (ads && ads.error) || 'Não consegui buscar os anúncios.' });
    const por = {};
    (ads.anuncios || []).forEach(a => {
      const pt = _partesDoNome(a.nome);
      const k = pt.ad || String(a.nome || '').trim();
      const x = por[k] = por[k] || { chave: k, nomes: [], estrutura: pt.estrutura, nicho: pt.nicho, contas: [], ids: [],
        investimento: 0, receita: 0, vendas: 0, ics: 0, cliques: 0, impressoes: 0, chegaram: 0, conteudos: {} };
      if (x.nomes.length < 6 && x.nomes.indexOf(a.nome) < 0) x.nomes.push(a.nome);
      if (pt.conta && x.contas.indexOf(pt.conta) < 0) x.contas.push(pt.conta);
      (a.ids || []).forEach(i => { if (x.ids.indexOf(i) < 0) x.ids.push(i); });
      x.investimento += a.investimento || 0; x.receita += a.receita || 0; x.vendas += a.vendas || 0;
      x.ics += a.ics || 0; x.cliques += a.cliques || 0; x.impressoes += a.impressoes || 0;
    });
    // pixel: quem chegou, pelo utm_content do primeiro toque (código AD no texto, ou id do anúncio)
    const db = readDB();
    const iniMs = new Date(de + 'T03:00:00Z').getTime(), fimMs = new Date(ate + 'T03:00:00Z').getTime() + 86400000;
    const porId = {}; Object.values(por).forEach(x => x.ids.forEach(i => { porId[i] = x; }));
    const chaves = Object.keys(por).filter(k => /^AD/i.test(k)).sort((a, b) => b.length - a.length);
    const casar = c => {
      const t = String(c || '').trim(); if (!t) return null;
      if (porId[t]) return porId[t];
      const T = t.toUpperCase();
      const k = chaves.find(ch => T === ch || T.indexOf(ch) >= 0);
      return k ? por[k] : (por[t] || null);
    };
    let semAnuncio = 0;
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer || {})).forEach(j => {
      const ev = (j && j.eventos || []).find(e => e && e.tipo === 'entrou' && new Date(e.em).getTime() >= iniMs && new Date(e.em).getTime() < fimMs);
      if (!ev) return;
      const c = (ev.primeiro && ev.primeiro.utm_content) || ev.criativo;
      const x = casar(c);
      if (!x) { if (c) semAnuncio++; return; }
      x.chegaram++; x.conteudos[c] = (x.conteudos[c] || 0) + 1;
    });
    const linhas = Object.values(por).map(x => {
      const r = Object.assign(x, {
        ctr: x.impressoes ? x.cliques / x.impressoes * 100 : 0,
        pctChegou: x.cliques >= 20 && x.chegaram ? Math.min(1, x.chegaram / x.cliques) : null,
        pctCheckout: x.cliques ? x.ics / x.cliques : 0,
        cpa: x.vendas ? x.investimento / x.vendas : null,
        roas: x.investimento ? x.receita / x.investimento : 0,
        conteudos: Object.keys(x.conteudos).slice(0, 5)
      });
      r.diagnostico = _diagnosticoCriativo(r);
      return r;
    }).filter(x => x.investimento > 0 || x.vendas > 0).sort((a, b) => b.investimento - a.investimento);
    res.json({ ok: true, de, ate, linhas: linhas.slice(0, 80), semAnuncio,
      temPixel: linhas.some(x => x.chegaram > 0), erros: ads.erros || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── REGRAS E ALERTAS ──
// Kill por CPIC/CPA, escala por ROAS, página que caiu, webhook parado. Tudo em
// MODO SIMULAÇÃO: a regra registra o que faria, com o motivo e o número que a
// disparou, e nada é mexido na Meta — isso exige a API da Meta com permissão
// de gerenciar anúncios, que ainda não está conectada. A avaliação automática
// e o aviso no WhatsApp nascem desligados: quem liga é a Diretoria, na tela.
// ══════════════════════════════════════════════════════
const KEY_REGRAS = 'sl_regras', KEY_REGRAS_LOG = 'sl_regras_log';
const REGRAS_PADRAO = [
  { id: 'kill_cpic', nome: 'Kill por CPIC', tipo: 'kill_cpic', ativa: true, gastoMin: 120, acao: 'pausar' },
  { id: 'kill_cpa', nome: 'Kill por CPA', tipo: 'kill_cpa', ativa: true, cpaAlvo: 150, multiplo: 2, acao: 'pausar' },
  { id: 'escala', nome: 'Escala', tipo: 'escala', ativa: true, roasMin: 1.8, vendasMin: 3, aumento: 20, acao: 'orcamento' },
  { id: 'pagina_caiu', nome: 'Página caiu', tipo: 'pagina_caiu', ativa: true, minutos: 15, acao: 'alerta' },
  { id: 'webhook_parado', nome: 'Webhook parado', tipo: 'webhook_parado', ativa: true, minutos: 30, acao: 'alerta' },
  { id: 'protecao', nome: 'Janela de proteção', tipo: 'protecao', ativa: true, acao: 'trava' }
];
function _regrasCfg(db) {
  const c = (db || readDB()).store[KEY_REGRAS] || {};
  const salvas = Array.isArray(c.lista) ? c.lista : [];
  // regra nova do padrão entra sozinha; a configuração que ele mexeu fica
  const lista = REGRAS_PADRAO.map(p => Object.assign({}, p, salvas.find(x => x.id === p.id) || {}));
  return { lista, automatico: !!c.automatico, whatsapp: !!c.whatsapp, simulacao: true };
}

async function _regrasAvaliar(origem) {
  const db0 = readDB(), cfg = _regrasCfg(db0), R = {};
  cfg.lista.forEach(r => { R[r.id] = r; });
  const agora = Date.now(), hojeBRT = new Date(agora - 3 * 3600000).toISOString().slice(0, 10);
  const horaBRT = new Date(agora - 3 * 3600000).getUTCHours() + new Date(agora - 3 * 3600000).getUTCMinutes() / 60;
  const novas = [];
  const acao = (regra, alvo, tipo, racional, extra) => novas.push(Object.assign({
    id: 'ra' + agora.toString(36) + Math.random().toString(36).slice(2, 6), em: new Date(agora).toISOString(), dia: hojeBRT,
    regra: regra.id, regraNome: regra.nome, alvo, tipo, racional, simulado: true, origem: origem || 'manual', desfeito: null }, extra || {}));

  // anúncios de hoje (mesma fonte das Métricas de Ads)
  let ads = [], erroAds = '';
  try {
    const r = await new Promise(resolve => _rotaAnuncios({ query: { de: hojeBRT, ate: hojeBRT, projeto: '' } },
      { json: d => resolve(d), status: () => ({ json: d => resolve(Object.assign({ erroRota: true }, d)) }) }));
    if (r && !r.erroRota && !r.error) ads = r.anuncios || []; else erroAds = (r && r.error) || 'Utmify não respondeu';
  } catch (e) { erroAds = e.message; }
  // janela de proteção: anúncio no primeiro dia de gasto (a Utmify não diz a hora em que nasceu)
  const hist = db0.store[KEY_ADS_HIST] || {};
  const jaGastou = new Set();
  Object.keys(hist).forEach(k => { if (k.slice(0, 10) < hojeBRT) ((hist[k] || {}).anuncios || []).forEach(a => { if ((a.investimento || 0) > 0) jaGastou.add(String(a.nome || '').trim().toLowerCase()); }); });
  const protegido = a => R.protecao && R.protecao.ativa && !jaGastou.has(String(a.nome || '').trim().toLowerCase());
  const horasDia = Math.max(1, horaBRT), restante = Math.max(0, 24 - horaBRT);

  ads.forEach(a => {
    const nome = a.nome, inv = a.investimento || 0;
    const evita = Math.round(inv / horasDia * restante);
    if (R.kill_cpic && R.kill_cpic.ativa && inv >= R.kill_cpic.gastoMin && !(a.ics > 0)) {
      if (protegido(a)) acao(R.protecao, nome, 'trava', 'Seria pausado (gastou R$ ' + Math.round(inv) + ' sem checkout), mas está no 1º dia de gasto.');
      else acao(R.kill_cpic, nome, 'pausar', 'Gastou R$ ' + Math.round(inv) + ' e nenhum checkout. Limite: R$ ' + R.kill_cpic.gastoMin + '.', { gasto: inv, evitado: evita });
    } else if (R.kill_cpa && R.kill_cpa.ativa && inv >= R.kill_cpa.cpaAlvo * R.kill_cpa.multiplo && !(a.vendas > 0)) {
      if (protegido(a)) acao(R.protecao, nome, 'trava', 'Seria pausado (R$ ' + Math.round(inv) + ' sem venda), mas está no 1º dia de gasto.');
      else acao(R.kill_cpa, nome, 'pausar', 'Gastou R$ ' + Math.round(inv) + ' (' + R.kill_cpa.multiplo + 'x o CPA alvo de R$ ' + R.kill_cpa.cpaAlvo + ') e nenhuma venda.', { gasto: inv, evitado: evita });
    }
    if (R.escala && R.escala.ativa && (a.vendas || 0) >= R.escala.vendasMin && (a.roas || 0) >= R.escala.roasMin) {
      acao(R.escala, nome, 'orcamento', 'ROAS ' + (a.roas || 0).toFixed(2).replace('.', ',') + ' com ' + a.vendas + ' vendas hoje. Orçamento +' + R.escala.aumento + '%.', { gasto: inv });
    }
  });

  // página caiu: gasto rodando e nenhuma visita no pixel nos últimos N minutos
  if (R.pagina_caiu && R.pagina_caiu.ativa && ads.some(a => (a.investimento || 0) > 0) && horaBRT >= 7) {
    const corte = agora - R.pagina_caiu.minutos * 60000;
    const jorn = (Array.isArray(db0.store[KEY_JORNADA]) ? db0.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer || {}));
    const temPixel = jorn.some(j => (j.eventos || []).some(e => new Date(e.em).getTime() >= agora - 86400000));
    const recente = jorn.some(j => (j.eventos || []).some(e => e.tipo === 'entrou' && new Date(e.em).getTime() >= corte));
    if (temPixel && !recente) acao(R.pagina_caiu, 'Páginas do funil', 'alerta', 'Anúncio gastando e nenhuma visita no pixel nos últimos ' + R.pagina_caiu.minutos + ' min. Página fora do ar ou pixel caiu.');
  }
  // webhook parado, só em horário de venda
  if (R.webhook_parado && R.webhook_parado.ativa && horaBRT >= 8) {
    const v = Array.isArray(db0.store[KEY_VENDAS]) ? db0.store[KEY_VENDAS] : [];
    const ult = v.length ? new Date(v[v.length - 1].recebidoEm).getTime() : 0;
    if (ult && agora - ult > R.webhook_parado.minutos * 60000)
      acao(R.webhook_parado, 'Webhook de vendas', 'alerta', 'Nenhum evento do checkout há ' + Math.round((agora - ult) / 60000) + ' min.');
  }

  // grava sem repetir a mesma regra no mesmo alvo no mesmo dia
  const db = readDB();
  const log = Array.isArray(db.store[KEY_REGRAS_LOG]) ? db.store[KEY_REGRAS_LOG] : [];
  const visto = new Set(log.filter(x => x.dia === hojeBRT).map(x => x.regra + '|' + x.alvo));
  const entram = novas.filter(n => !visto.has(n.regra + '|' + n.alvo));
  if (entram.length) {
    db.store[KEY_REGRAS_LOG] = log.concat(entram).slice(-1500);
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_REGRAS_LOG] = now();
    writeDB(db);
    // aviso no WhatsApp só quando ligado na tela, e só o que é alerta ou pausa
    if (cfg.whatsapp && typeof _notificarViaWhatsApp === 'function') {
      const importantes = entram.filter(x => x.tipo === 'alerta' || x.tipo === 'pausar');
      if (importantes.length) {
        const dir = (db.store['sl_usuarios'] || []).filter(u => u && u.cargo === 'Diretoria');
        const texto = importantes.slice(0, 6).map(x => '• ' + x.regraNome + ' — ' + x.alvo + ': ' + x.racional).join('\n') + '\n(modo simulação: nada foi mexido na Meta)';
        dir.forEach(u => { try { _notificarViaWhatsApp(u.id, 'Regras do Central TMX', texto); } catch (e) {} });
      }
    }
  }
  return { novas: entram.length, avaliados: ads.length, erroAds };
}

app.get('/api/regras', authDiretoria, (req, res) => {
  try {
    const db = readDB(), cfg = _regrasCfg(db);
    const hojeBRT = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
    const log = (Array.isArray(db.store[KEY_REGRAS_LOG]) ? db.store[KEY_REGRAS_LOG] : []).slice().reverse();
    const hoje = log.filter(x => x.dia === hojeBRT);
    const porRegraHoje = {}; hoje.forEach(x => { porRegraHoje[x.regra] = (porRegraHoje[x.regra] || 0) + 1; });
    res.json({ ok: true, config: cfg, porRegraHoje,
      resumo: { acoes: hoje.length, pausas: hoje.filter(x => x.tipo === 'pausar').length, escalas: hoje.filter(x => x.tipo === 'orcamento').length,
                alertas: hoje.filter(x => x.tipo === 'alerta').length, travas: hoje.filter(x => x.tipo === 'trava').length,
                evitado: hoje.filter(x => x.tipo === 'pausar' && !x.desfeito).reduce((a, x) => a + (x.evitado || 0), 0),
                revertidas: log.filter(x => x.desfeito && x.tipo === 'pausar').length },
      log: log.slice(0, 120) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/regras', authDiretoria, (req, res) => {
  try {
    const b = req.body || {}, db = readDB(), atual = _regrasCfg(db);
    const num = (v, min, max, pad) => { const n = Number(String(v).replace(',', '.')); return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : pad; };
    const lista = atual.lista.map(r => {
      const x = (Array.isArray(b.lista) ? b.lista : []).find(y => y && y.id === r.id) || {};
      const o = Object.assign({}, r, { ativa: x.ativa !== undefined ? !!x.ativa : r.ativa });
      if ('gastoMin' in r) o.gastoMin = num(x.gastoMin, 10, 100000, r.gastoMin);
      if ('cpaAlvo' in r) o.cpaAlvo = num(x.cpaAlvo, 1, 100000, r.cpaAlvo);
      if ('multiplo' in r) o.multiplo = num(x.multiplo, 1, 10, r.multiplo);
      if ('roasMin' in r) o.roasMin = num(x.roasMin, 0.1, 20, r.roasMin);
      if ('vendasMin' in r) o.vendasMin = Math.round(num(x.vendasMin, 1, 1000, r.vendasMin));
      if ('aumento' in r) o.aumento = Math.round(num(x.aumento, 1, 100, r.aumento));
      if ('minutos' in r) o.minutos = Math.round(num(x.minutos, 5, 720, r.minutos));
      return o;
    });
    db.store[KEY_REGRAS] = { lista, automatico: !!b.automatico, whatsapp: !!b.whatsapp, _updatedAt: Date.now() };
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_REGRAS] = now();
    audit(db, 'regras_salvas', KEY_REGRAS, { automatico: !!b.automatico, whatsapp: !!b.whatsapp }, req.user);
    writeDB(db);
    res.json({ ok: true, config: _regrasCfg(db) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/regras/avaliar', authDiretoria, async (req, res) => {
  try { res.json(Object.assign({ ok: true }, await _regrasAvaliar('manual'))); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/regras/desfazer', authDiretoria, (req, res) => {
  try {
    const id = String((req.body && req.body.id) || '');
    const db = readDB(), log = Array.isArray(db.store[KEY_REGRAS_LOG]) ? db.store[KEY_REGRAS_LOG] : [];
    const x = log.find(y => y.id === id);
    if (!x) return res.status(404).json({ error: 'Ação não encontrada.' });
    x.desfeito = { em: new Date().toISOString(), por: (req.user && req.user.nome) || '' };
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_REGRAS_LOG] = now();
    audit(db, 'regra_desfeita', x.regra, { alvo: x.alvo, tipo: x.tipo }, req.user);
    writeDB(db);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Avaliação automática a cada 30 min — só roda se a Diretoria ligou na tela.
setInterval(() => {
  try { if (_regrasCfg().automatico) _regrasAvaliar('automatico').catch(e => console.error('[regras]', e.message)); }
  catch (e) {}
}, 30 * 60 * 1000);

// ══════════════════════════════════════════════════════
// ── PAGAMENTOS E ATRIBUIÇÃO DE UMA PESSOA (ficha do lead) ──
// Todas as tentativas de pagamento dela (pelo id do visitante e, a partir
// dele, pelo e-mail/telefone), o motivo de cada falha e de onde ela veio no
// primeiro e no último toque — com a regra de crédito dita em texto: canal de
// apoio (recuperação) e "organic" cravado pelo checkout nunca roubam a venda
// do anúncio de origem.
// ══════════════════════════════════════════════════════
app.get('/api/lead/pagamentos', authDiretoria, (req, res) => {
  try {
    const vid = String(req.query.vid || '').slice(0, 40);
    if (!vid) return res.status(400).json({ error: 'Informe o visitante.' });
    const db = readDB(), canais = _canaisCfg(db);
    const todas = Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : [];
    const doVid = todas.filter(v => v && v.vid === vid);
    const chaves = new Set(doVid.map(_pessoaDaVenda).filter(Boolean));
    const dela = todas.filter(v => v && (v.vid === vid || chaves.has(_pessoaDaVenda(v))))
      .slice().sort((a, b) => String(a.recebidoEm).localeCompare(String(b.recebidoEm)));
    const tentativas = dela.map(v => ({
      em: v.recebidoEm, status: v.status, pago: _vendaPaga(v), estorno: _ESTORNO.test(String(v.status || '')),
      motivo: _vendaPaga(v) ? '' : _motivoFalha(v), valor: Number(v.valor) || 0,
      oferta: v.plano || v.produto || '', metodo: v.metodo || '', origem: v.utmSource || '', renovacao: !!v.renovacao }));
    const pagos = tentativas.filter(t => t.pago && !t.estorno);
    const falhas = tentativas.filter(t => !t.pago && !t.estorno && _FALHOU.test(String(t.status || '')));
    // primeiro toque: o que o pixel guardou na primeira visita dessa pessoa
    let primeiro = null;
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer || {})).forEach(j => {
      if (!j || j.id !== vid) return;
      (j.eventos || []).forEach(e => {
        if (e && e.primeiro && (!primeiro || String(e.em) < primeiro.em)) {
          const p = e.primeiro;
          primeiro = { em: e.em, origem: p.utm_source || '', campanha: p.utm_campaign || '', anuncio: p.utm_content || '', termo: p.utm_term || '' };
        }
      });
    });
    const ultPago = dela.filter(v => _vendaPaga(v)).pop() || dela[dela.length - 1] || null;
    const ultimo = ultPago ? { em: ultPago.recebidoEm, origem: ultPago.utmSource || '', campanha: ultPago.utmCampaign || '', anuncio: ultPago.utmContent || '' } : null;
    const cPrim = primeiro ? _canalDe(primeiro.origem, canais) : null;
    const cUlt = ultimo ? _canalDe(ultimo.origem, canais) : null;
    let credito = 'ultimo', regra = 'O crédito fica com o último toque.';
    if (cPrim && cPrim.anuncios && (!cUlt || !cUlt.anuncios)) {
      credito = 'primeiro';
      regra = (cUlt && cUlt.apoio ? 'O último toque foi ' + cUlt.nome + ', que é canal de apoio: ' : 'O último toque não é anúncio: ') +
              'o crédito fica com o anúncio que trouxe a pessoa, e o apoio aparece como ajuda.';
    } else if (!ultimo || (!_origemVale(ultimo.origem) && !_origemVale(ultimo.anuncio))) {
      credito = primeiro ? 'primeiro' : 'nenhum';
      regra = primeiro ? 'A venda chegou sem origem: vale o primeiro toque que o pixel guardou.' : 'Sem origem no checkout e sem visita com UTM no pixel.';
    }
    res.json({ ok: true, vid, tentativas, pagos: pagos.length, totalPago: pagos.reduce((a, t) => a + t.valor, 0),
      falhas: falhas.length, recusasCartao: falhas.filter(t => t.motivo === 'Cartão recusado').length,
      atribuicao: { primeiro, ultimo, canalPrimeiro: cPrim ? cPrim.nome : '', canalUltimo: cUlt ? cUlt.nome : '', credito, regra } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── VERSÕES DO FUNIL ──
// "Publicar versão" guarda a foto do funil e o que mudou em relação à anterior
// (etapa que entrou ou saiu, link trocado, campanha da origem, divisão do teste
// A/B). É o que permite olhar um número e saber se ele é de antes ou depois
// da mudança — e voltar atrás.
// ══════════════════════════════════════════════════════
const KEY_FUNIS_VERSOES = 'sl_funis_versoes';
function _funilFoto(f, db) {
  const redirs = (Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : []).filter(r => r && (r.funil === f.id || (f.projeto && r.projeto === f.projeto)));
  return {
    etapas: (f.etapas || []).map(e => ({ id: e.id, nome: e.nome || '', tipo: e.tipo || '', url: e.url || '' })),
    fontes: (f.fontes || []).map(o => ({ id: o.id, nome: o.nome || '', campanha: o.utmCampanha || '', regra: o.utmRegra || '' })),
    ligacoes: (f.ligacoes || []).map(l => l.join('>')).sort(),
    testes: redirs.map(r => ({ slug: r.slug, nome: r.nome || r.slug, divisao: (r.destinos || []).map(d => ({ nome: d.nome || d.url || '', peso: Number(d.peso) || 1 })) }))
  };
}
function _funilDiff(a, b) {
  const mud = [];
  if (!a) return ['Primeira versão publicada'];
  const porId = l => { const o = {}; (l || []).forEach(x => { o[x.id] = x; }); return o; };
  const ea = porId(a.etapas), eb = porId(b.etapas);
  b.etapas.forEach(e => {
    const x = ea[e.id];
    if (!x) mud.push('+ ' + (e.nome || e.tipo));
    else {
      if (x.nome !== e.nome) mud.push(x.nome + ' → ' + e.nome);
      if (x.url !== e.url) mud.push('Link de ' + e.nome + (e.url ? ' trocado' : ' removido'));
    }
  });
  a.etapas.forEach(e => { if (!eb[e.id]) mud.push('− ' + (e.nome || e.tipo)); });
  const fa = porId(a.fontes);
  b.fontes.forEach(o => {
    const x = fa[o.id], de = x ? (x.campanha || (x.regra ? 'contém ' + x.regra : 'projeto todo')) : null;
    const para = o.campanha || (o.regra ? 'contém ' + o.regra : 'projeto todo');
    if (!x) mud.push('+ origem ' + o.nome);
    else if (de !== para) mud.push('Tráfego de ' + o.nome + ': ' + de + ' → ' + para);
  });
  const la = new Set(a.ligacoes), lb = new Set(b.ligacoes);
  const novas = b.ligacoes.filter(l => !la.has(l)).length, tiradas = a.ligacoes.filter(l => !lb.has(l)).length;
  if (novas || tiradas) mud.push('Caminhos: ' + (novas ? '+' + novas : '') + (novas && tiradas ? ' ' : '') + (tiradas ? '−' + tiradas : ''));
  const ta = {}; (a.testes || []).forEach(t => { ta[t.slug] = t; });
  (b.testes || []).forEach(t => {
    const x = ta[t.slug];
    const pct = d => { const tot = d.reduce((s, y) => s + y.peso, 0) || 1; return d.map(y => Math.round(y.peso / tot * 100)).join('/'); };
    if (x && pct(x.divisao) !== pct(t.divisao)) mud.push('Split ' + t.nome + ' ' + pct(x.divisao) + ' → ' + pct(t.divisao));
    if (!x) mud.push('+ teste ' + t.nome);
  });
  return mud.length ? mud : ['Sem mudança de estrutura'];
}
app.post('/api/funis/versao', authUsuario, (req, res) => {
  try {
    const f = req.body && req.body.funil;
    if (!f || !f.id) return res.status(400).json({ error: 'Mande o funil.' });
    const txt = JSON.stringify(f);
    if (txt.length > 400000) return res.status(413).json({ error: 'Funil grande demais pra guardar como versão.' });
    const db = readDB();
    const todas = Array.isArray(db.store[KEY_FUNIS_VERSOES]) ? db.store[KEY_FUNIS_VERSOES] : [];
    const doFunil = todas.filter(v => v.funil === f.id);
    const ant = doFunil[doFunil.length - 1];
    const foto = _funilFoto(f, db);
    const v = { id: 'fv' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5), funil: f.id, n: (ant ? ant.n : 0) + 1,
      em: new Date().toISOString(), autor: (req.user && (req.user.nome || req.user.email)) || '', nota: String((req.body && req.body.nota) || '').slice(0, 200),
      diff: _funilDiff(ant && ant.foto, foto), foto, snapshot: JSON.parse(txt) };
    // guarda as 40 mais recentes de cada funil
    const outras = todas.filter(x => x.funil !== f.id);
    db.store[KEY_FUNIS_VERSOES] = outras.concat(doFunil.concat([v]).slice(-40));
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_FUNIS_VERSOES] = now();
    audit(db, 'funil_versao_publicada', f.id, { n: v.n, mudancas: v.diff.length }, req.user);
    writeDB(db);
    res.json({ ok: true, versao: { id: v.id, n: v.n, em: v.em, diff: v.diff } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/funis/versoes', authUsuario, (req, res) => {
  try {
    const fid = String(req.query.funil || '').slice(0, 80);
    const db = readDB();
    const lista = (Array.isArray(db.store[KEY_FUNIS_VERSOES]) ? db.store[KEY_FUNIS_VERSOES] : []).filter(v => v.funil === fid)
      .map(v => ({ id: v.id, n: v.n, em: v.em, autor: v.autor, nota: v.nota, diff: v.diff })).reverse();
    // o que mudou desde a última publicada, sem publicar: é o "Publicar v18 · 3 mudanças" do botão
    let pendente = null;
    const f = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : []).find(x => x && x.id === fid);
    const ult = (Array.isArray(db.store[KEY_FUNIS_VERSOES]) ? db.store[KEY_FUNIS_VERSOES] : []).filter(v => v.funil === fid).pop();
    if (f) pendente = _funilDiff(ult && ult.foto, _funilFoto(f, db));
    res.json({ ok: true, lista, pendente, proxima: (lista[0] ? lista[0].n : 0) + 1 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/funis/versao/:id', authUsuario, (req, res) => {
  try {
    const db = readDB();
    const v = (Array.isArray(db.store[KEY_FUNIS_VERSOES]) ? db.store[KEY_FUNIS_VERSOES] : []).find(x => x.id === req.params.id);
    if (!v) return res.status(404).json({ error: 'Versão não encontrada.' });
    res.json({ ok: true, id: v.id, n: v.n, em: v.em, snapshot: v.snapshot });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/funil/vendas-por-pagina', authUsuario, (req, res) => {
  try {
    const db = readDB();
    const de  = String(req.query.de  || '').slice(0, 10);
    const ate = String(req.query.ate || '').slice(0, 10);
    const noDia = iso => (!de || String(iso).slice(0,10) >= de) &&
                         (!ate || String(iso).slice(0,10) <= ate);

    const jornadas = (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
      .concat(Object.values(_jBuffer));
    const porVid = {};
    jornadas.forEach(j => { if (j && j.id) porVid[j.id] = j; });

    // ── Recuperar o id das vendas que ja entraram ───────────────────────────
    // O vid e extraido uma vez, na hora que o webhook chega, e fica congelado
    // na venda. As que entraram antes do pixel esconder o id no sck ficaram com
    // vid vazio pra sempre — mas o payload CRU foi guardado. Se o id estava la
    // e a leitura antiga nao sabia procurar, da pra recuperar agora, sem pedir
    // pra ninguem comprar de novo.
    const cru = Array.isArray(db.store[KEY_VENDAS_RAW]) ? db.store[KEY_VENDAS_RAW] : [];
    const cruPorPedido = {};
    cru.forEach(r => {
      const pl = (r && (r.payload || r.body)) || r;
      const id = String(_pega(pl, ['orderId','order_id','id','transaction_id','codigo','code']) || '');
      if (id) cruPorPedido[id] = pl;
    });
    let recuperadas = 0;

    const vendas = (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : [])
      .filter(v => v && noDia(v.recebidoEm))
      .map(v => {
        if (v.vid || !v.pedidoId) return v;
        const pl = cruPorPedido[v.pedidoId];
        if (!pl) return v;
        const achado = _vidDaVenda(pl);
        if (!achado) return v;
        recuperadas++;
        return Object.assign({}, v, { vid: achado, vidRecuperado: true });
      });

    // aprovada: o resto ainda pode cair, e contar pedido como venda infla tudo
    const aprovada = v => /paid|approved|aprovad|complet|pago/i.test(String(v.status||''));

    // Checkout de gateway nao e pagina sua: nunca leva credito de venda (o
    // credito vai pra pagina que convenceu) e por isso apareceria na lista com
    // muitos visitantes e 0% — parecendo a pior pagina do funil, quando na
    // verdade esta fora da conta. Uma constante so, pra credito e listagem nao
    // divergirem.
    const EH_CHECKOUT = /checkout|pagamento|pay\.|carrinho|payt|kiwify|hotmart|monetizze|eduzz|cakto|ticto|kirvano|perfectpay/i;

    const paginas = {};
    const cx = pg => (paginas[pg] = paginas[pg] ||
      { pg, entrada:{vendas:0, receita:0}, venda:{vendas:0, receita:0}, visitantes:0 });

    // quantas pessoas passaram por cada pagina, pra virar taxa de conversao
    const vistos = {};
    jornadas.forEach(j => {
      const daqui = new Set();
      (j.eventos || []).forEach(e => { if (e.pg && noDia(e.em)) daqui.add(e.pg); });
      daqui.forEach(pg => { cx(pg); vistos[pg] = (vistos[pg] || new Set()).add(j.id); });
    });
    Object.keys(vistos).forEach(pg => { cx(pg).visitantes = vistos[pg].size; });

    let semVid = 0, semJornada = 0, casadas = 0;
    vendas.forEach(v => {
      if (!aprovada(v)) return;
      if (!v.vid) { semVid++; return; }
      const j = porVid[v.vid];
      if (!j) { semJornada++; return; }
      casadas++;
      const evs = (j.eventos || []).filter(e => e.pg);
      if (!evs.length) return;
      const valor = Number(v.valor) || 0;

      // entrada: a pagina do primeiro toque, se o pixel a guardou; senao o
      // primeiro evento com pagina
      const pr = (evs.find(e => e.primeiro && e.primeiro.pg) || {}).primeiro;
      const pgEntrada = (pr && pr.pg) || evs[0].pg;
      cx(pgEntrada).entrada.vendas++;
      cx(pgEntrada).entrada.receita += valor;

      // venda: a ultima pagina que NAO e checkout — a que convenceu.
      // Se so houver checkout, ele mesmo leva o credito.
      const proprias = evs.filter(e => !EH_CHECKOUT.test(e.pg));
      const pgVenda = (proprias.length ? proprias[proprias.length-1] : evs[evs.length-1]).pg;
      cx(pgVenda).venda.vendas++;
      cx(pgVenda).venda.receita += valor;
    });

    // ── Vendas por variante do teste A/B ────────────────────────────────────
    // A pergunta que decide qual VSL fica no ar: das duas que estao dividindo o
    // trafego, qual VENDE. Taxa de clique nao responde isso — variante pode
    // levar mais gente pro checkout e converter menos.
    // A variante viaja no evento da jornada (ev.variante/ev.teste), gravada
    // quando o link do teste sorteou. Mesma juncao pelo tmx_vid das vendas.
    // O que viaja na URL e o ID do destino (escolhido.id), nao o nome. Ele e
    // estavel, que e o que a atribuicao precisa — mas ilegivel na tela: a
    // tabela mostrava 'vmsxxcdtd' onde devia mostrar 'Variante 2'.
    // Aqui o id vira nome; o nome do TESTE tambem, que na URL e o slug.
    const reds = Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : [];
    const nomeDaVariante = (slug, vid) => {
      const r = reds.find(x => x && x.slug === slug);
      if (!r) return vid;
      const ds = r.destinos || [];
      const d = ds.find((x, i) => String(x.id || ('v' + i)) === String(vid));
      if (!d) return vid;
      // nome repetido entre variantes deixa de distinguir: cola a URL junto
      const repetido = d.nome && ds.filter(x => x.nome === d.nome).length > 1;
      const url = String(d.url || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
      if (!d.nome) return url || vid;
      return repetido && url ? (d.nome + ' · ' + url.split('/').pop()) : d.nome;
    };
    const nomeDoTeste = slug => {
      const r = reds.find(x => x && x.slug === slug);
      return (r && r.nome) || slug;
    };

    const porVariante = {};
    const cxV = (teste, variante) => {
      const k = teste + '||' + variante;
      return (porVariante[k] = porVariante[k] ||
        { teste: nomeDoTeste(teste), variante: nomeDaVariante(teste, variante),
          varianteId: variante, pessoas: 0, vendas: 0, receita: 0 });
    };
    const vistosVar = {};
    jornadas.forEach(j => {
      const daqui = new Set();
      (j.eventos || []).forEach(e => {
        if (!e.variante || !noDia(e.em)) return;
        daqui.add((e.teste || '(sem nome)') + '||' + e.variante);
      });
      daqui.forEach(k => {
        const corte = k.indexOf('||');
        cxV(k.slice(0, corte), k.slice(corte + 2));
        (vistosVar[k] = vistosVar[k] || new Set()).add(j.id);
      });
    });
    Object.keys(vistosVar).forEach(k => {
      const corte = k.indexOf('||');
      cxV(k.slice(0, corte), k.slice(corte + 2)).pessoas = vistosVar[k].size;
    });

    vendas.forEach(v => {
      if (!aprovada(v) || !v.vid) return;
      const j = porVid[v.vid];
      if (!j) return;
      // a variante do PRIMEIRO evento que a tiver: e a que o sorteio deu
      const ev = (j.eventos || []).find(e => e.variante);
      if (!ev) return;
      const c = cxV(ev.teste || '(sem nome)', ev.variante);
      c.vendas++; c.receita += Number(v.valor) || 0;
    });

    const variantes = Object.values(porVariante)
      .filter(v => v.pessoas || v.vendas)
      .map(v => Object.assign({}, v, {
        conversao: v.pessoas ? (v.vendas / v.pessoas) * 100 : 0,
        porVisitante: v.pessoas ? v.receita / v.pessoas : 0
      }))
      .sort((a, b) => b.receita - a.receita || b.pessoas - a.pessoas);

    const lista = Object.values(paginas)
      .filter(p => !EH_CHECKOUT.test(p.pg))
      .filter(p => p.visitantes || p.entrada.vendas || p.venda.vendas)
      .map(p => Object.assign({}, p, {
        conversao: p.visitantes ? (p.venda.vendas / p.visitantes) * 100 : 0,
        ticket: p.venda.vendas ? p.venda.receita / p.venda.vendas : 0
      }))
      .sort((a, b) => b.venda.receita - a.venda.receita || b.visitantes - a.visitantes);

    res.json({ ok: true, de, ate, paginas: lista, variantes,
      // sem isto a tela mostra zero e voce nao sabe se e "nao vendeu" ou
      // "nao consegui ligar a venda a ninguem"
      // ── O que a Payt REALMENTE manda ────────────────────────────────────
      // Ja errei duas hipoteses sobre por que a venda chega sem dono. Em vez de
      // adivinhar uma terceira, a tela passa a mostrar os campos do payload cru
      // que se parecem com rastreamento — e se algum deles tem 'tmx_' dentro.
      camposRecebidos: (() => {
        const raw = Array.isArray(db.store[KEY_VENDAS_RAW]) ? db.store[KEY_VENDAS_RAW] : [];
        const ult = raw[raw.length - 1];
        if (!ult) return null;
        const corpo = ult.body || ult.payload || ult;
        const achados = [];
        const varrer = (o, prefixo, nivel) => {
          if (!o || typeof o !== 'object' || nivel > 3) return;
          Object.keys(o).forEach(k => {
            const v = o[k], caminho = prefixo ? prefixo + '.' + k : k;
            if (v && typeof v === 'object') return varrer(v, caminho, nivel + 1);
            if (!/utm|src|sck|xcod|track|tmx|param|origem|source|ref/i.test(k)) return;
            const txt = String(v == null ? '' : v);
            achados.push({ campo: caminho, valor: txt.slice(0, 60),
                           temTmx: /tmx_[A-Za-z0-9]{6,}/.test(txt) });
          });
        };
        varrer(corpo, '', 0);
        return { quando: ult.recebidoEm || ult.em || null,
                 campos: achados.slice(0, 14),
                 // se nenhum campo tem tmx_, o gateway limpou tudo no caminho
                 algumTemTmx: achados.some(a => a.temTmx) };
      })(),
      diagnostico: { vendasNoPeriodo: vendas.length, aprovadas: vendas.filter(aprovada).length,
                     casadas, semVid, semJornada, recuperadas,
                     webhookLigado: (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS].length : 0) > 0 } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/funil/jornadas', authUsuario, (req, res) => {
  try {
    const funil = String(req.query.funil || '').slice(0, 80);
    const filtro = String(req.query.filtro || 'todas').slice(0, 40);
    const db = readDB();
    const f = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : [])
      .find(x => String(x.id) === funil) || null;
    // tipo de cada etapa: e o que deixa perguntar "chegou no checkout e nao comprou"
    const tipo = {};
    ((f && f.etapas) || []).forEach(e => { tipo[e.id] = e.tipo || 'pagina'; });

    const adoJ = _mapaAdocao(db, funil);
    // a jornada guarda o funil no topo e a etapa em cada passo — traduz os dois
    const trazer = j => {
      if (!funil || j.funil === funil || !adoJ.tem) return j;
      return Object.assign({}, j, { eventos: (j.eventos || []).map(e =>
        Object.assign({}, e, { etapa: adoJ.etapaDe({ funil: j.funil, etapa: e.etapa }) })) });
    };
    // Escolher uma pagina JA e o recorte: o pixel pode estar reportando sob outro
    // id de funil e a pagina continua sendo a mesma pagina. Filtrar por funil
    // aqui fazia a jornada vir vazia enquanto a atencao — que sempre olhou por
    // pagina — mostrava 30 pessoas na mesma tela.
    const pg = String(req.query.pg || '').slice(0, 160);
    // ── Aceitar tambem pela PAGINA, igual o /api/funil/stats faz ─────────────
    // La a jornada vale se o funil bate OU se a pagina do evento e uma das URLs
    // cadastradas nas etapas. Aqui so existia a primeira via — entao jornada que
    // reporta sob outro data-f entrava na CONTAGEM e sumia da LISTA. Na mesma
    // tela: 1.477 pessoas na etapa e "5 entraram" na jornada. Duas regras
    // diferentes pro mesmo recorte nunca podiam ter existido.
    const _normJ = u => String(u || '').trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[?#].*$/, '').replace(/\/+$/, '');
    const urlsDoFunilJ = new Set();
    ((f && f.etapas) || []).forEach(e => { if (e.url) urlsDoFunilJ.add(_normJ(e.url)); });
    const porFunil = j => !funil || pg ||
      adoJ.aceita({ funil: j.funil, etapa: (j.eventos && j.eventos[0] || {}).etapa }) ||
      (j.eventos || []).some(e => e.pg && urlsDoFunilJ.has(_normJ(e.pg)));
    // ── Contadores de diagnostico ───────────────────────────────────────────
    // A tela mostrava 5 onde a etapa contava 1.477 e nao havia como saber onde
    // as outras sumiram: funil? periodo? pagina escolhida? teto de retencao?
    // Cada peneira agora conta quanto derrubou, e a tela diz qual foi.
    const _brutas = (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
      .concat(Object.values(_jBuffer));
    const diag = { noBanco: _brutas.length, doFunil: 0, noPeriodo: 0, aposPagina: 0,
                   pgEscolhida: pg || null, teto: JORNADA_TETO, dias: JORNADA_DIAS };
    let lista = _brutas.filter(porFunil).map(trazer);
    diag.doFunil = lista.length;

    // O seletor de periodo do Funis nao chegava aqui: a tela dizia "Hoje" e a
    // piramide somava os 7 dias inteiros. Numeros de dias diferentes lado a lado.
    const de  = String(req.query.de  || '').slice(0, 10);
    const ate = String(req.query.ate || '').slice(0, 10);
    const emDia = e => String(e.em || '').slice(0, 10);
    if (de || ate) {
      lista = lista.map(j => {
        const evs = (j.eventos || []).filter(e =>
          (!de || emDia(e) >= de) && (!ate || emDia(e) <= ate));
        return evs.length ? Object.assign({}, j, { eventos: evs }) : null;
      }).filter(Boolean);
    }
    diag.noPeriodo = lista.length;

    // O seletor de paginas sai daqui, ANTES do filtro por pagina. Montado depois,
    // sobrava so a pagina escolhida — o select se reconstruia com uma opcao so e
    // jogava fora as outras quatro, e a tela voltava sozinha pra pagina anterior.
    // E monta a partir de TODAS as jornadas do periodo, nao so as deste funil:
    // senao a pagina que reporta sob id antigo aparecia como "sem dado ainda".
    const paginas = {};
    const paraLista = funil && !pg
      ? (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
          .concat(Object.values(_jBuffer))
          .filter(j => (j.eventos || []).some(e =>
            (!de || emDia(e) >= de) && (!ate || emDia(e) <= ate)))
      : lista;
    paraLista.forEach(j => (j.eventos || []).forEach(e => {
      if (!e.pg) return;
      if (de && emDia(e) < de) return;
      if (ate && emDia(e) > ate) return;
      if (!paginas[e.pg]) paginas[e.pg] = { pg: e.pg, pessoas: new Set() };
      paginas[e.pg].pessoas.add(j.id);
    }));

    // Filtro por pagina: com 5 VSLs na mesma etapa, e a unica forma de saber
    // qual delas retem. Mantem a jornada inteira de quem passou pela pagina.
    // Igualdade exata de string: o pixel grava host+pathname sem barra final nem
    // query, entao normalmente casa. Normalizo dos dois lados assim mesmo — se
    // um dia entrar valor de outra origem, o filtro nao pode devolver vazio em
    // silencio, que foi o modo de falha que custou horas aqui.
    if (pg) {
      const alvoPg = _normJ(pg);
      lista = lista.filter(j => (j.eventos || []).some(e => _normJ(e.pg || '') === alvoPg));
    }
    diag.aposPagina = lista.length;

    // filtra por quem veio de um teste especifico — a variante viaja no evento
    const teste = String(req.query.teste || '').slice(0, 60);
    if (teste) lista = lista.filter(j => j.eventos.some(e => e.teste === teste || e.variante));

    const passou = (j, t) => j.eventos.some(e => tipo[e.etapa] === t);

    // ── Segmentos: classifica cada visitante pelo que ele FEZ, nao pelo que a
    //    media diz. E o funil de atencao — quem so olhou, quem leu, quem travou.
    const maior = (j, campo) => j.eventos.reduce((m, e) => Math.max(m, Number(e[campo]) || 0), 0);
    const seg = (j) => {
      const cliques  = j.eventos.filter(e => e.tipo === 'clique').length;
      const friccao  = j.eventos.filter(e => e.tipo === 'friccao').length;
      const rolagem  = maior(j, 'rolagem');
      const atencao  = maior(j, 'atencao');
      const segundos = maior(j, 'segundos');
      const saiu     = j.eventos.some(e => e.tipo === 'saiu');
      return {
        friccao:  friccao > 0,
        // abandono so vale se a saida foi registrada; sem 'saiu' nao da pra saber
        abandono: saiu && segundos > 0 && segundos <= 5,
        cliques:  cliques > 0,
        leitor:   rolagem >= 75 && atencao >= 45,
        engajado: cliques > 0 || rolagem >= 50 || atencao >= 30,
        alta:     passou(j, 'checkout') || passou(j, 'obrigado'),
        soOlhou:  cliques === 0 && rolagem < 25 && atencao < 15
      };
    };
    const cache = new Map();
    const S = (j) => { if (!cache.has(j)) cache.set(j, seg(j)); return cache.get(j); };

    // Degraus de tempo: a pergunta que ele faz e "de quem abriu, quantos passaram
    // de 5 minutos?". Usa a atencao (aba visivel), nao o tempo de parede — quem
    // deixou a aba aberta em segundo plano nao assistiu nada.
    const seg1 = j => j.eventos.reduce((m, e) => Math.max(m, Number(e.atencao) || 0), 0);
    const passouDe = (j, s) => seg1(j) >= s;

    // O marco da oferta: o minuto em que a VSL mostra o preco. Quem nao chegou
    // ate ali nunca viu a oferta — cair antes disso e problema de retencao do
    // video, cair depois e problema de oferta. Sao consertos diferentes.
    const oferta = Math.max(0, Math.min(7200, parseInt(req.query.oferta, 10) || 0));

    const contagem = {
      todas: lista.length,
      'abriu':      lista.length,
      // quantos ja fecharam a pagina — o resto ainda pode estar la agora
      sairam:       lista.filter(j => j.eventos.some(e => e.tipo === 'saiu')).length,
      oferta:       oferta ? lista.filter(j => passouDe(j, oferta)).length : 0,
      'tempo-1m':   lista.filter(j => passouDe(j, 60)).length,
      'tempo-5m':   lista.filter(j => passouDe(j, 300)).length,
      'tempo-10m':  lista.filter(j => passouDe(j, 600)).length,
      'tempo-20m':  lista.filter(j => passouDe(j, 1200)).length,
      'checkout-sem-compra': lista.filter(j => passou(j, 'checkout') && !passou(j, 'obrigado')).length,
      comprou:      lista.filter(j => passou(j, 'obrigado')).length,
      'alta-intencao': lista.filter(j => S(j).alta).length,
      leitor:       lista.filter(j => S(j).leitor).length,
      engajado:     lista.filter(j => S(j).engajado).length,
      'so-olhou':   lista.filter(j => S(j).soOlhou).length,
      friccao:      lista.filter(j => S(j).friccao).length,
      abandono:     lista.filter(j => S(j).abandono).length,
      voltou:       lista.filter(j => j.eventos.filter(e => e.tipo === 'entrou').length > 1).length
    };

    const filtros = {
      'abriu':     () => true,
      oferta:      j => oferta && passouDe(j, oferta),
      'tempo-1m':  j => passouDe(j, 60),
      'tempo-5m':  j => passouDe(j, 300),
      'tempo-10m': j => passouDe(j, 600),
      'tempo-20m': j => passouDe(j, 1200),
      'checkout-sem-compra': j => passou(j, 'checkout') && !passou(j, 'obrigado'),
      comprou:      j => passou(j, 'obrigado'),
      'alta-intencao': j => S(j).alta,
      leitor:       j => S(j).leitor,
      engajado:     j => S(j).engajado,
      'so-olhou':   j => S(j).soOlhou,
      friccao:      j => S(j).friccao,
      abandono:     j => S(j).abandono,
      voltou:       j => j.eventos.filter(e => e.tipo === 'entrou').length > 1
    };
    if (filtros[filtro]) lista = lista.filter(filtros[filtro]);

    lista = lista.sort((a, b) => {
      return _jQuando(b) - _jQuando(a);
    }).slice(0, 40);

    // A venda entra pelo tmx_vid que o pixel colou no link do checkout. E o que
    // transforma "visitante c0" em "Fulano, R$ 297, pagou 21min depois de entrar".
    // Enquanto o webhook de vendas estiver desligado isso vem vazio — e a tela
    // diz isso, em vez de fingir que a pessoa nao comprou.
    const porVid = {};
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (!v || !v.vid || !_vendaPaga(v)) return;
      const atual = porVid[v.vid];
      // mais de uma compra do mesmo visitante: soma o valor, guarda a primeira
      if (atual) {
        atual.valor += Number(v.valor) || 0;
        atual.compras += 1;
        if (!atual.cliente && v.cliente) atual.cliente = v.cliente;
        if (!atual.email && v.email)     atual.email   = v.email;
      } else {
        porVid[v.vid] = {
          cliente: v.cliente || '', email: v.email || '', produto: v.produto || '',
          valor: Number(v.valor) || 0, compras: 1, status: v.status || '',
          em: v.recebidoEm || ''
        };
      }
    });

    // ── Deixa rastro no log quando o numero sai pequeno ─────────────────────
    // Sem acesso ao banco de producao, a unica forma de descobrir qual peneira
    // esvazia a lista e a propria producao contar. Sai no maximo 1x por minuto,
    // e so quando ha o que investigar — log que sai sempre ninguem le.
    if (contagem.todas < 50 || diag.noBanco < 100) {
      const agora = Date.now();
      if (!_jDiagUltimo || agora - _jDiagUltimo > 60000) {
        _jDiagUltimo = agora;
        console.log('[JORNADA/diag] funil=' + funil + ' periodo=' + de + '..' + ate +
          ' | noBanco=' + diag.noBanco + ' doFunil=' + diag.doFunil +
          ' noPeriodo=' + diag.noPeriodo + ' aposPagina=' + diag.aposPagina +
          ' pg=' + (diag.pgEscolhida || '-') + ' | mostrou=' + contagem.todas);
      }
    }

    res.json({ ok: true, funil, filtro, contagem, de, ate, pg, oferta, diag,
      paginas: Object.values(paginas).map(x => ({ pg: x.pg, pessoas: x.pessoas.size }))
                     .sort((a, b) => b.pessoas - a.pessoas),
      etapas: ((f && f.etapas) || []).map(e => ({ id: e.id, nome: e.nome, tipo: e.tipo })),
      jornadas: lista.map(j => {
        const o = Object.assign({}, j, { segmentos: S(j) });
        if (porVid[j.id]) o.venda = porVid[j.id];
        return o;
      }) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── ATENÇÃO DA PÁGINA ──
// Rolagem em faixas e cliques por elemento. Sem imagem de propósito: a mancha
// colorida quase nunca muda decisao; saber que metade nunca ve o botao muda.
// ══════════════════════════════════════════════════════
let _atBuffer = {}, _atSujo = false;

function _atChave(etapa, dia, pg) { return etapa + '|' + dia + '|' + (pg || ''); }

const TEMPO_PASSO = 30, TEMPO_FAIXAS = 121;   // 0 a 60min, de 30 em 30 segundos
function _tempoFaixa(seg) {
  return Math.max(0, Math.min(TEMPO_FAIXAS - 1, Math.floor((Number(seg) || 0) / TEMPO_PASSO)));
}
// quantos ficaram ATE PELO MENOS este ponto
function _quantosAte(tempos, segundos) {
  if (!Array.isArray(tempos)) return 0;
  const de = Math.ceil((Number(segundos) || 0) / TEMPO_PASSO);
  let n = 0;
  for (let i = de; i < tempos.length; i++) n += tempos[i] || 0;
  return n;
}

function _atNovo(etapa, dia, pg) {
  return { etapa, data: dia, pg: pg || '', saidas: 0, f25: 0, f50: 0, f75: 0, f100: 0,
           cliques: {}, friccao: {},
           atencaoSoma: 0, atencaoN: 0, rapidos: 0,
           // histograma de tempo em faixas de 30s ate 60min, + a ultima acumula
           // o resto. Guardar assim deixa calcular QUALQUER marco depois — e o
           // pitch muda de video pra video, entao marco fixo nao serviria.
           tempos: new Array(TEMPO_FAIXAS).fill(0),
           lcp: [], cls: [], fcp: [], erros: 0 };
}
function _atPega(etapa, pg) {
  const dia = _hojeBR(), k = _atChave(etapa, dia, pg);
  if (!_atBuffer[k]) _atBuffer[k] = _atNovo(etapa, dia, pg);
  return _atBuffer[k];
}

function _atSaida(etapa, c, pg) {
  if (!etapa) return;
  const b = _atPega(etapa, pg);
  b.saidas++;
  const p = Number(c.rolagem) || 0;
  // faixas cumulativas: quem chegou a 75% tambem passou por 25 e 50
  if (p >= 25) b.f25++;
  if (p >= 50) b.f50++;
  if (p >= 75) b.f75++;
  if (p >= 95) b.f100++;

  // atencao e o tempo com a aba VISIVEL, nao o tempo de parede
  const at = Number(c.atencao);
  if (at >= 0 && at < 7200) {
    b.atencaoSoma += at; b.atencaoN++;
    if (!b.tempos) b.tempos = new Array(TEMPO_FAIXAS).fill(0);
    b.tempos[_tempoFaixa(at)]++;
  }
  // quick-back: saiu nos primeiros 5s. Quase sempre e pagina errada ou lenta.
  if ((Number(c.segundos) || 0) <= 5) b.rapidos++;

  // Web Vitals: guarda as amostras pra calcular o percentil 75 depois.
  // Media esconde o problema — o P75 e o que a maioria de fato sentiu.
  if (Number(c.lcp) > 0 && b.lcp.length < 500) b.lcp.push(Number(c.lcp));
  if (Number(c.fcp) > 0 && b.fcp.length < 500) b.fcp.push(Number(c.fcp));
  if (Number(c.cls) >= 0 && b.cls.length < 500) b.cls.push(Number(c.cls));
  b.erros += Number(c.erros) || 0;
  _atSujo = true;
}

function _atFriccao(etapa, rotulo, motivo, pg) {
  if (!etapa || !rotulo) return;
  const b = _atPega(etapa, pg);
  const r = String(rotulo).slice(0, 70);
  if (!b.friccao[r]) b.friccao[r] = { mortos: 0, raiva: 0 };
  if (motivo === 'raiva') b.friccao[r].raiva++; else b.friccao[r].mortos++;
  _atSujo = true;
}

function _atClique(etapa, rotulo, posicao, pg) {
  if (!etapa || !rotulo) return;
  const b = _atPega(etapa, pg);
  const r = String(rotulo).slice(0, 70);
  if (!b.cliques[r]) b.cliques[r] = { n: 0, pos: Number(posicao) || 0 };
  b.cliques[r].n++;
  if (Number(posicao)) b.cliques[r].pos = Number(posicao);
  _atSujo = true;
}

function _atGravar() {
  if (!_atSujo) return;
  const pendente = _atBuffer; _atBuffer = {}; _atSujo = false;
  try {
    const db = readDB();
    const atual = Array.isArray(db.store[KEY_ATENCAO]) ? db.store[KEY_ATENCAO] : [];
    const indice = {};
    atual.forEach(l => { indice[_atChave(l.etapa, l.data, l.pg)] = l; });
    Object.values(pendente).forEach(n => {
      const k = _atChave(n.etapa, n.data, n.pg), v = indice[k];
      if (!v) { atual.push(n); indice[k] = n; return; }
      v.saidas += n.saidas; v.f25 += n.f25; v.f50 += n.f50; v.f75 += n.f75; v.f100 += n.f100;
      if (!v.tempos) v.tempos = new Array(TEMPO_FAIXAS).fill(0);
      (n.tempos || []).forEach((q, i) => { v.tempos[i] = (v.tempos[i] || 0) + q; });
      v.atencaoSoma = (v.atencaoSoma || 0) + (n.atencaoSoma || 0);
      v.atencaoN    = (v.atencaoN    || 0) + (n.atencaoN    || 0);
      v.rapidos     = (v.rapidos     || 0) + (n.rapidos     || 0);
      v.erros       = (v.erros       || 0) + (n.erros       || 0);
      ['lcp','fcp','cls'].forEach(m => {
        v[m] = (v[m] || []).concat(n[m] || []).slice(-500);
      });
      Object.keys(n.cliques).forEach(r => {
        if (!v.cliques[r]) v.cliques[r] = { n: 0, pos: n.cliques[r].pos };
        v.cliques[r].n += n.cliques[r].n;
        if (n.cliques[r].pos) v.cliques[r].pos = n.cliques[r].pos;
      });
      v.friccao = v.friccao || {};
      Object.keys(n.friccao || {}).forEach(r => {
        if (!v.friccao[r]) v.friccao[r] = { mortos: 0, raiva: 0 };
        v.friccao[r].mortos += n.friccao[r].mortos;
        v.friccao[r].raiva  += n.friccao[r].raiva;
      });
    });
    const corte = new Date(Date.now() - 90 * 86400000).toISOString().slice(0, 10);
    db.store[KEY_ATENCAO] = atual.filter(l => l.data >= corte);
    db.timestamps[KEY_ATENCAO] = now();
    writeDB(db);
  } catch (e) { console.error('[atencao] falhou ao gravar:', e.message); }
}
setInterval(_atGravar, 45 * 1000);

// P75: o valor que 3 em cada 4 pessoas tiveram ou melhor. Media esconde
// o problema quando um punhado de aparelhos ruins puxa a cauda.
function _p75(lista) {
  if (!lista || !lista.length) return null;
  const l = lista.slice().sort((a, b) => a - b);
  return l[Math.min(l.length - 1, Math.floor(l.length * 0.75))];
}

app.get('/api/funil/atencao', authUsuario, (req, res) => {
  try {
    // Aceita por etapa OU por pagina. Com 5 VSLs na mesma etapa do mapa, so a
    // pagina separa uma da outra — e e essa comparacao que decide qual fica.
    const etapa = String(req.query.etapa || '').slice(0, 60);
    const soPg  = String(req.query.pg || '').slice(0, 160);
    if (!etapa && !soPg) return res.status(400).json({ error: 'Informe a etapa ou a página.' });
    const de  = String(req.query.de  || '').slice(0, 10);
    const ate = String(req.query.ate || '').slice(0, 10);
    const db = readDB();
    const idsEtapa = etapa ? _idsDaEtapa(db, etapa) : null;
    const pg = soPg;
    let linhas = (Array.isArray(db.store[KEY_ATENCAO]) ? db.store[KEY_ATENCAO] : [])
      .concat(Object.values(_atBuffer))
      .filter(l => !idsEtapa || idsEtapa.has(l.etapa));
    // quais paginas usam esta etapa — e o que deixa comparar 5 VSLs entre si
    const paginas = {};
    linhas.forEach(l => {
      if (de && l.data < de) return;
      if (ate && l.data > ate) return;
      // histórico gravado antes da normalização: /697 e /697/ viram uma linha só
      const k = _normPg(l.pg) || '';
      if (!paginas[k]) paginas[k] = { pg: k, saidas: 0 };
      paginas[k].saidas += l.saidas || 0;
    });
    if (pg) { const alvo = _normPg(pg); linhas = linhas.filter(l => (_normPg(l.pg) || '') === alvo); }
    if (de)  linhas = linhas.filter(l => l.data >= de);
    if (ate) linhas = linhas.filter(l => l.data <= ate);

    const t = { saidas: 0, f25: 0, f50: 0, f75: 0, f100: 0,
                atencaoSoma: 0, atencaoN: 0, rapidos: 0, erros: 0 };
    const tempos = new Array(TEMPO_FAIXAS).fill(0);
    const cl = {}, fr = {}, vit = { lcp: [], fcp: [], cls: [] };
    linhas.forEach(l => {
      t.saidas += l.saidas; t.f25 += l.f25; t.f50 += l.f50; t.f75 += l.f75; t.f100 += l.f100;
      t.atencaoSoma += l.atencaoSoma || 0; t.atencaoN += l.atencaoN || 0;
      t.rapidos += l.rapidos || 0; t.erros += l.erros || 0;
      (l.tempos || []).forEach((q, i) => { tempos[i] += q; });
      ['lcp','fcp','cls'].forEach(m => { vit[m] = vit[m].concat(l[m] || []); });
      Object.keys(l.cliques || {}).forEach(r => {
        if (_ehPlayer(r)) return;      // play no vídeo não diz nada sobre a página
        if (!cl[r]) cl[r] = { rotulo: r, n: 0, pos: l.cliques[r].pos };
        cl[r].n += l.cliques[r].n;
        if (l.cliques[r].pos) cl[r].pos = l.cliques[r].pos;
      });
      Object.keys(l.friccao || {}).forEach(r => {
        // o pixel antigo marcava o player e a FAQ como clique morto; o novo
        // não marca mais, e o histórico sai da conta pelo mesmo critério
        if (_ehPlayer(r)) return;
        if (!fr[r]) fr[r] = { rotulo: r, mortos: 0, raiva: 0 };
        fr[r].mortos += l.friccao[r].mortos;
        fr[r].raiva  += l.friccao[r].raiva;
      });
    });
    const base = t.saidas || 1;
    res.json({ ok: true, etapa, de, ate, pg,
      paginas: Object.values(paginas).filter(x => x.saidas > 0)
                     .sort((a, b) => b.saidas - a.saidas),
      rolagem: {
        saidas: t.saidas,
        f25: (t.f25 / base) * 100, f50: (t.f50 / base) * 100,
        f75: (t.f75 / base) * 100, f100: (t.f100 / base) * 100,
        n25: t.f25, n50: t.f50, n75: t.f75, n100: t.f100
      },
      atencao: {
        media: t.atencaoN ? Math.round(t.atencaoSoma / t.atencaoN) : null,
        medidos: t.atencaoN,
        rapidos: t.rapidos,
        pctRapidos: (t.rapidos / base) * 100
      },
      // funil de tempo: quantos ainda estavam na pagina em cada marco
      tempo: {
        medidos: t.atencaoN,
        marcos: [30, 60, 300, 600, 900, 1200, 1800].map(seg => ({
          segundos: seg,
          pessoas: _quantosAte(tempos, seg),
          pct: t.atencaoN ? (_quantosAte(tempos, seg) / t.atencaoN) * 100 : 0
        })),
        pitch: (Number(req.query.pitch) > 0) ? {
          segundos: Number(req.query.pitch),
          pessoas: _quantosAte(tempos, Number(req.query.pitch)),
          pct: t.atencaoN ? (_quantosAte(tempos, Number(req.query.pitch)) / t.atencaoN) * 100 : 0
        } : null
      },
      vitais: {
        lcp: _p75(vit.lcp), fcp: _p75(vit.fcp),
        cls: vit.cls.length ? Math.round(_p75(vit.cls) * 1000) / 1000 : null,
        amostras: vit.lcp.length, erros: t.erros
      },
      cliques: Object.values(cl).map(c => Object.assign(c, {
        pct: t.saidas > 0 ? (c.n / t.saidas) * 100 : 0
      })).sort((a, b) => b.n - a.n).slice(0, 25),
      friccao: Object.values(fr).map(f => Object.assign(f, {
        total: f.mortos + f.raiva
      })).sort((a, b) => b.total - a.total).slice(0, 20)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── TESTE A/B ──
// O link ja dividia o trafego; o que faltava era anotar quem levou qual e
// reencontrar essa pessoa na conversao. A variante viaja na URL (tmx_v), o pixel
// a guarda no dominio de destino e devolve em todo evento.
// ══════════════════════════════════════════════════════
let _abBuffer = {}, _abSujo = false;
// ── Quem ja foi contado, e que precisa SOBREVIVER a restart ────────────────
// Isto vivia so na memoria. Todo deploy zerava, e a mesma pessoa voltava a
// contar como 'pessoa' e como 'meta' — em dia de dez deploys, o teste vira
// ficcao. E o mesmo defeito do _fVistos, aqui contaminando direto o veredito
// que decide qual variante fica no ar.
//
// So o dia de hoje precisa sobreviver: a chave do contador ja e por dia, entao
// quem volta amanha conta de novo por definicao. Guardar so hoje mantem o custo
// em ~60KB com 4 mil visitantes, e nao repete o disco cheio de agosto.
const KEY_ABVISTOS = 'sl_ab_vistos';
const AB_VISTOS_TETO = 120000;        // ids no total; acima disso avisa e para
let _abTetoAvisado = false;
let _abVistos = new Map();            // por chave: quem ja foi contado como unico
let _abVistosSujo = false;

function _abVistosCarregar() {
  try {
    const db = readDB();
    const guardado = db.store[KEY_ABVISTOS];
    if (!guardado || typeof guardado !== 'object') return;
    const hoje = _hojeBR();
    let n = 0;
    Object.keys(guardado).forEach(k => {
      // "teste|variante|dia|tipo" — so o dia de hoje volta
      const partes = k.split('|');
      if (partes[2] !== hoje) return;
      _abVistos.set(k, new Set(guardado[k] || []));
      n += (guardado[k] || []).length;
    });
    if (n) console.log('[AB] ' + n + ' visitante(s) ja contados hoje foram recuperados do disco.');
  } catch (e) { console.error('[AB] nao consegui recuperar quem ja foi contado:', e.message); }
}

function _abVistosGravar() {
  if (!_abVistosSujo) return;
  _abVistosSujo = false;
  try {
    const hoje = _hojeBR(), saida = {};
    let total = 0;
    _abVistos.forEach((set, k) => {
      if (k.split('|')[2] !== hoje) return;
      saida[k] = Array.from(set);
      total += saida[k].length;
    });
    const db = readDB();
    db.store[KEY_ABVISTOS] = saida;
    db.timestamps[KEY_ABVISTOS] = now();
    writeDB(db);
  } catch (e) { console.error('[AB] falhou ao gravar quem ja foi contado:', e.message); }
}
setInterval(_abVistosGravar, 60 * 1000);
// Recupera antes de atender o primeiro evento: se o primeiro visitante chegar
// com a memoria vazia, ele conta duas vezes e o estrago ja esta feito.
_abVistosCarregar();
// solta os dias passados da memoria — o contador ja e por dia
setInterval(() => {
  const hoje = _hojeBR();
  _abVistos.forEach((_, k) => { if (k.split('|')[2] !== hoje) _abVistos.delete(k); });
}, 30 * 60 * 1000);

function _abChave(teste, variante, dia) { return teste + '|' + variante + '|' + dia; }

// tipo: 'sorteio' (redirecionador) | 'entrou' | 'meta'
function _abContar(teste, variante, tipo, visitante) {
  if (!teste || !variante) return;
  const dia = _hojeBR(), k = _abChave(teste, variante, dia);
  if (!_abBuffer[k]) _abBuffer[k] = { teste, variante, data: dia, sorteios: 0, pessoas: 0, metas: 0 };
  const b = _abBuffer[k];
  if (tipo === 'sorteio') b.sorteios++;
  else if (visitante) {
    // pessoa e meta contam UMA vez por visitante: sem isso quem recarrega a
    // pagina de obrigado vira duas vendas e o teste vira ficcao.
    const kv = k + '|' + tipo;
    if (!_abVistos.has(kv)) _abVistos.set(kv, new Set());
    const set = _abVistos.get(kv);
    if (!set.has(visitante)) {
      // Teto de seguranca: em vez de crescer sem limite e voltar a encher o
      // disco, para de guardar e avisa. Contar a mais e ruim; derrubar o site
      // e pior, e ja aconteceu.
      let total = 0;
      _abVistos.forEach(sx => { total += sx.size; });
      if (total >= AB_VISTOS_TETO) {
        if (!_abTetoAvisado) {
          _abTetoAvisado = true;
          console.warn('[AB] teto de ' + AB_VISTOS_TETO + ' visitantes atingido hoje. ' +
                       'A partir daqui pode haver contagem repetida no teste A/B.');
        }
      } else {
        set.add(visitante);
        _abVistosSujo = true;
      }
      if (tipo === 'meta') b.metas++; else b.pessoas++;
    }
  }
  _abSujo = true;
}

function _abGravar() {
  if (!_abSujo) return;
  const pendente = _abBuffer; _abBuffer = {}; _abSujo = false;
  try {
    const db = readDB();
    const atual = Array.isArray(db.store[KEY_ABSTATS]) ? db.store[KEY_ABSTATS] : [];
    const indice = {};
    atual.forEach(l => { indice[_abChave(l.teste, l.variante, l.data)] = l; });
    Object.values(pendente).forEach(n => {
      const k = _abChave(n.teste, n.variante, n.data), v = indice[k];
      if (v) { v.sorteios += n.sorteios; v.pessoas += n.pessoas; v.metas += n.metas; }
      else { atual.push(n); indice[k] = n; }
    });
    const corte = new Date(Date.now() - 180 * 86400000).toISOString().slice(0, 10);
    db.store[KEY_ABSTATS] = atual.filter(l => l.data >= corte);
    db.timestamps[KEY_ABSTATS] = now();
    writeDB(db);
  } catch (e) { console.error('[ab] falhou ao gravar:', e.message); }
}
setInterval(_abGravar, 30 * 1000);

// ── Estatística: a diferença é real ou é sorte? ──
// Teste z de duas proporções. Sem isso a tela mostraria "A está na frente" e
// deixaria a pessoa matar a variante certa por causa de ruído.
// ── Estatística bayesiana do teste ─────────────────────────────────────────
// Beta(1+conversões, 1+não conversões) pra cada variante e 20 mil sorteios:
// sai a chance de cada uma ser melhor que o controle, o lift e a perda
// esperada de escolher errado. O teste frequentista de antes continua lá; este
// responde a pergunta que a operação faz ("qual a chance de a B ser melhor?").
function _gama(k) {
  if (k < 1) return _gama(k + 1) * Math.pow(Math.random(), 1 / k);
  const d = k - 1 / 3, c = 1 / Math.sqrt(9 * d);
  for (;;) {
    let x, v;
    do { const u1 = Math.random() || 1e-12, u2 = Math.random(); x = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2); v = 1 + c * x; } while (v <= 0);
    v = v * v * v; const u = Math.random();
    if (u < 1 - 0.0331 * x * x * x * x || Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
  }
}
function _beta(a, b) { const x = _gama(a), y = _gama(b); return x / (x + y); }
function _abBayes(variantes, opc) {
  opc = opc || {};
  const N = opc.sorteios || 20000, minVendas = opc.minVendas || 40;
  const vs = variantes.filter(v => (v.pessoas || 0) > 0);
  if (vs.length < 2) return { pronto: false, motivo: 'uma-so' };
  const ctrl = vs.find(v => v.controle) || vs[0];
  const conv = v => (v.usaVendas ? v.vendas : v.metas) || 0;
  // R$ por visita = conversão × ticket; sem ticket da variante, usa o do teste todo
  const vendasTot = vs.reduce((a, v) => a + (v.vendas || 0), 0), recTot = vs.reduce((a, v) => a + (v.receita || 0), 0);
  const ticketGeral = vendasTot ? recTot / vendasTot : 0;
  const ticket = v => (v.vendas > 0 ? v.receita / v.vendas : ticketGeral);
  const amostras = vs.map(v => { const a = 1 + conv(v), b = 1 + Math.max(0, v.pessoas - conv(v)); const arr = new Float64Array(N); for (let i = 0; i < N; i++) arr[i] = _beta(a, b); return arr; });
  const ic = vs.indexOf(ctrl);
  const resultado = vs.map((v, j) => {
    let melhorQueCtrl = 0, melhorDeTodas = 0, perda = 0, somaJ = 0, somaC = 0;
    for (let i = 0; i < N; i++) {
      const pj = amostras[j][i], pc = amostras[ic][i];
      somaJ += pj; somaC += pc;
      if (pj > pc) melhorQueCtrl++;
      let max = 0; for (let t = 0; t < vs.length; t++) if (amostras[t][i] > max) max = amostras[t][i];
      if (pj >= max) melhorDeTodas++;
      perda += Math.max(0, max - pj);
    }
    const mj = somaJ / N, mc = somaC / N;
    return { id: v.id, nome: v.nome, controle: j === ic, pessoas: v.pessoas, conversoes: conv(v), vendas: v.vendas || 0,
             conversao: mj, rpv: mj * ticket(v),
             chanceMelhorQueControle: j === ic ? null : melhorQueCtrl / N,
             chanceMelhor: melhorDeTodas / N,
             lift: j === ic ? null : (mc ? (mj - mc) / mc : null),
             liftRpv: j === ic ? null : ((mc * ticket(ctrl)) ? (mj * ticket(v) - mc * ticket(ctrl)) / (mc * ticket(ctrl)) : null),
             perdaEsperada: mj ? (perda / N) / mj : null };
  });
  const lider = resultado.slice().sort((a, b) => b.chanceMelhor - a.chanceMelhor)[0];
  const minVendasLado = Math.min.apply(null, vs.map(v => v.vendas || 0));
  // quanto falta pra 95%: tamanho por braço pela aproximação normal da diferença
  // observada, contra quantas pessoas por dia o teste recebe hoje
  let diasPara95 = null;
  const pc = conv(ctrl) / ctrl.pessoas, outro = vs.find(v => v !== ctrl && v.id === lider.id) || vs.find(v => v !== ctrl);
  const pl = conv(outro) / outro.pessoas;
  if (pl !== pc && opc.diasRodando > 0) {
    const nAlvo = Math.ceil(Math.pow(1.645 + 0.84, 2) * (pc * (1 - pc) + pl * (1 - pl)) / Math.pow(pl - pc, 2));
    const porDia = Math.min(ctrl.pessoas, outro.pessoas) / opc.diasRodando;
    const faltam = Math.max(0, nAlvo - Math.min(ctrl.pessoas, outro.pessoas));
    diasPara95 = porDia > 0 ? Math.ceil(faltam / porDia) : null;
  }
  const chanceLider = lider.controle ? (1 - Math.max.apply(null, resultado.filter(r => !r.controle).map(r => r.chanceMelhorQueControle || 0))) : lider.chanceMelhorQueControle;
  return { pronto: chanceLider >= 0.95 && minVendasLado >= minVendas, lider: lider.id, chanceLider, minVendas, minVendasLado,
           diasPara95, controle: ctrl.id, variantes: resultado, criterio: vs[0].usaVendas ? 'vendas' : 'meta' };
}

function _abJulgar(a, b) {
  const n1 = a.pessoas || 0, x1 = a.metas || 0;
  const n2 = b.pessoas || 0, x2 = b.metas || 0;
  if (n1 < 1 || n2 < 1) return { pronto: false, motivo: 'sem-gente' };
  const p1 = x1 / n1, p2 = x2 / n2;
  if (x1 + x2 === 0) return { pronto: false, motivo: 'sem-conversao', p1, p2 };

  // Teste de PRECO: se as variantes valem valores diferentes, comparar taxa de
  // conversao da a resposta errada. 5% a R$147 rende R$7,35 por visitante;
  // 4% a R$197 rende R$7,88 — converte menos e fatura mais. O criterio passa a
  // ser receita por visitante, e a variancia entra vezes o preco ao quadrado.
  const v1 = Number(a.valor) || 0, v2 = Number(b.valor) || 0;
  const porPreco = v1 > 0 && v2 > 0 && v1 !== v2;

  if (porPreco) {
    const m1 = p1 * v1, m2 = p2 * v2;
    const va1 = (p1 * (1 - p1) * v1 * v1) / n1;
    const va2 = (p2 * (1 - p2) * v2 * v2) / n2;
    const se = Math.sqrt(va1 + va2);
    if (!se) return { pronto: false, motivo: 'sem-variacao', p1, p2, criterio: 'receita' };
    const z = Math.abs(m1 - m2) / se;
    const conf = z >= 2.576 ? 99 : (z >= 1.96 ? 95 : (z >= 1.645 ? 90 : 0));
    const dif = Math.abs(m1 - m2);
    let precisa = null;
    if (dif > 0) {
      const nAlvo = Math.ceil(
        (Math.pow(1.96 + 0.84, 2) * (p1*(1-p1)*v1*v1 + p2*(1-p2)*v2*v2)) / (dif * dif));
      precisa = Math.max(0, nAlvo - Math.min(n1, n2));
    }
    return {
      pronto: z >= 1.96, z: Number(z.toFixed(3)), conf, criterio: 'receita',
      p1, p2, rpv1: m1, rpv2: m2,
      lider: m1 >= m2 ? 'a' : 'b',
      // o lider por conversao pode ser o OUTRO — a tela precisa contar isso
      liderConversao: p1 >= p2 ? 'a' : 'b',
      ganho: (m1 && m2) ? Math.abs(m1 - m2) / Math.min(m1, m2) : 0,
      faltamPorLado: precisa
    };
  }

  const pp = (x1 + x2) / (n1 + n2);
  const se = Math.sqrt(pp * (1 - pp) * (1 / n1 + 1 / n2));
  if (!se) return { pronto: false, motivo: 'sem-variacao', p1, p2 };
  const z = Math.abs(p1 - p2) / se;
  // 1.96 = 95% de confiança nos dois sentidos
  const conf = z >= 2.576 ? 99 : (z >= 1.96 ? 95 : (z >= 1.645 ? 90 : 0));
  const dif = Math.abs(p1 - p2);
  let precisa = null;
  if (dif > 0) {
    const nAlvo = Math.ceil(
      (Math.pow(1.96 + 0.84, 2) * (p1 * (1 - p1) + p2 * (1 - p2))) / (dif * dif));
    precisa = Math.max(0, nAlvo - Math.min(n1, n2));
  }
  return {
    pronto: z >= 1.96, z: Number(z.toFixed(3)), conf, criterio: 'conversao',
    p1, p2, lider: p1 >= p2 ? 'a' : 'b', liderConversao: p1 >= p2 ? 'a' : 'b',
    ganho: (p1 && p2) ? Math.abs(p1 - p2) / Math.min(p1, p2) : 0,
    faltamPorLado: precisa
  };
}

// ── Números de um teste ──
// Declarar vencedora: o link do split continua o mesmo nos anúncios e passa a
// mandar todo mundo pra ela. Desfaz com variante vazia.
app.post('/api/ab/vencedora', authDiretoria, (req, res) => {
  try {
    const slug = String((req.body && req.body.teste) || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
    const variante = String((req.body && req.body.variante) || '').slice(0, 40);
    const db = readDB();
    const lista = Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : [];
    const r = lista.find(x => String(x.slug || '').toLowerCase() === slug);
    if (!r) return res.status(404).json({ error: 'Teste não encontrado.' });
    if (variante && !(r.destinos || []).some((d, i) => String(d.id || ('v' + i)) === variante))
      return res.status(400).json({ error: 'Essa variante não é deste teste.' });
    const antes = r.vencedora || null;
    // Só declara com 95% de chance e o mínimo de vendas dos dois lados. Antes
    // disso a "vencedora" é sorte, e o link passaria a mandar 100% pra ela.
    let resultado = null;
    if (variante) {
      const st = _abV2(slug, '', '');
      const vd = st && st.veredito;
      if (!vd || !vd.podeDeclarar || vd.sugerida !== variante) {
        return res.status(409).json({ error: vd
          ? (vd.podeDeclarar ? 'Os dados apontam a outra variante como vencedora.' : 'Ainda não dá pra declarar: ' + Math.round(Math.max(vd.chance || 0, 1 - (vd.chance || 0)) * 100) + '% de chance e ' + vd.vendasMenorLado +
            ' vendas no lado com menos (precisa de 95% e ' + vd.minPorLado + ').')
          : 'Ainda não há dados suficientes pra declarar.' });
      }
      resultado = { chance: vd.chance, liftRpp: variante === vd.desafiante ? vd.liftRpp : (vd.liftRpp != null ? -vd.liftRpp : null), em: new Date().toISOString() };
    }
    if (variante) { r.vencedora = variante; r.encerradoEm = new Date().toISOString(); r.estado = 'encerrado'; r.resultado = resultado; }
    else { delete r.vencedora; delete r.encerradoEm; r.estado = 'rodando'; }
    r._updatedAt = Date.now();
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY_REDIRS] = now();
    audit(db, variante ? 'ab_vencedora_declarada' : 'ab_vencedora_desfeita', slug, { variante, antes }, req.user);
    writeDB(db);
    res.json({ ok: true, teste: slug, vencedora: r.vencedora || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ab/stats', authUsuario, (req, res) => {
  try {
    const slug = String(req.query.teste || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!slug) return res.status(400).json({ error: 'Informe o teste.' });
    const db = readDB();
    const r = (Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : [])
      .find(x => String(x.slug || '').toLowerCase() === slug);
    if (!r) return res.status(404).json({ error: 'Teste não encontrado.' });

    let linhas = Array.isArray(db.store[KEY_ABSTATS]) ? db.store[KEY_ABSTATS] : [];
    linhas = linhas.filter(l => l.teste === slug)
                   .concat(Object.values(_abBuffer).filter(l => l.teste === slug));
    // sem o 'ate' a tela dizia "Hoje" e somava tudo desde sempre
    const de  = String(req.query.de  || '').slice(0, 10);
    const ate = String(req.query.ate || '').slice(0, 10);
    if (de)  linhas = linhas.filter(l => l.data >= de);
    if (ate) linhas = linhas.filter(l => l.data <= ate);

    const porVar = {};
    (r.destinos || []).forEach((d, i) => {
      porVar[String(d.id || ('v' + i))] = {
        id: String(d.id || ('v' + i)), nome: d.nome || ('Variante ' + (i + 1)),
        url: d.url || '', peso: Number(d.peso) || 1, valor: Number(d.valor) || 0,
        sorteios: 0, pessoas: 0, metas: 0
      };
    });
    linhas.forEach(l => {
      const v = porVar[l.variante];
      if (!v) return;
      v.sorteios += l.sorteios || 0; v.pessoas += l.pessoas || 0; v.metas += l.metas || 0;
    });
    // ── Faturamento de verdade, nao o preco digitado ────────────────────────
    // O 'valor' de cada destino e um preco cadastrado a mao: serve pra comparar
    // ofertas de precos diferentes, mas nao e o que entrou no caixa. A venda
    // chega com o tmx_vid e a jornada daquele visitante sabe em que variante ele
    // caiu — e por ai que da pra dizer quanto cada variante realmente faturou.
    const varDoVisitante = {};
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
      .concat(Object.values(_jBuffer))
      .forEach(j => {
        if (!j || !j.id) return;
        (j.eventos || []).forEach(e => {
          if (e && String(e.teste || '').toLowerCase() === slug && e.variante) {
            varDoVisitante[j.id] = String(e.variante);
          }
        });
      });
    let vendasSemVariante = 0;
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (!v || !v.vid || !_vendaPaga(v)) return;
      const dia = String(v.recebidoEm || '').slice(0, 10);
      if (de && dia && dia < de) return;
      if (ate && dia && dia > ate) return;
      const alvo = porVar[varDoVisitante[v.vid]];
      if (!alvo) { vendasSemVariante++; return; }
      alvo.receita = (alvo.receita || 0) + (Number(v.valor) || 0);
      alvo.vendas  = (alvo.vendas  || 0) + 1;
    });

    const variantes = Object.values(porVar).map(v => Object.assign(v, {
      conversao: v.pessoas > 0 ? (v.metas / v.pessoas) * 100 : 0,
      // receita por visitante: so faz sentido com valor informado
      rpv: (v.valor > 0 && v.pessoas > 0) ? (v.metas * v.valor) / v.pessoas : null,
      receita: v.receita || 0,
      vendas:  v.vendas  || 0,
      ticket:  (v.vendas > 0) ? (v.receita / v.vendas) : null,
      // o que a variante rende por pessoa que caiu nela — e por aqui que se
      // compara variante cara com variante barata sem se enganar
      receitaPorPessoa: (v.pessoas > 0) ? ((v.receita || 0) / v.pessoas) : null
    }));

    // ── A divisao esta justa? ───────────────────────────────────────────────
    // Peso configurado contra sorteio real. Divisao torta invalida a comparacao:
    // a variante que recebeu mais gente tende a parecer melhor so por volume, e
    // quem olha a tela nao tem como saber que o desempate foi o sorteio.
    const totalSorteios = variantes.reduce((a, v) => a + (v.sorteios || 0), 0);
    const totalPeso     = variantes.reduce((a, v) => a + (v.peso || 0), 0);
    variantes.forEach(v => {
      v.fatiaReal = totalSorteios ? (v.sorteios / totalSorteios) * 100 : null;
      v.fatiaAlvo = totalPeso     ? (v.peso     / totalPeso)     * 100 : null;
      v.desvio = (v.fatiaReal != null && v.fatiaAlvo != null) ? (v.fatiaReal - v.fatiaAlvo) : null;
    });
    // Com pouca gente o sorteio oscila sozinho; abaixo de 200 nao da pra acusar
    // nada. O limite de 5 pontos e o mesmo criterio de "ja da pra confiar".
    const divisao = {
      total: totalSorteios,
      torta: totalSorteios >= 200 && variantes.some(v => v.desvio != null && Math.abs(v.desvio) > 5),
      cedoDemais: totalSorteios < 200
    };

    // Ordena pelo criterio certo: com precos diferentes, quem fatura mais por
    // visitante; senao, quem converte mais.
    const valores = variantes.map(v => v.valor).filter(v => v > 0);
    const precoVaria = valores.length >= 2 && new Set(valores).size > 1;
    const ord = variantes.slice().sort((x, y) => precoVaria
      ? ((y.rpv || 0) - (x.rpv || 0))
      : (y.conversao - x.conversao));
    const julgamento = (ord.length >= 2) ? _abJulgar(ord[0], ord[1]) : { pronto: false, motivo: 'uma-so' };

    // Bayes: a conversão é a meta do teste quando existe; sem meta, a venda.
    const usaVendas = !r.meta;
    const diasRodando = r.criadoEm ? Math.max(1, (Date.now() - new Date(r.criadoEm).getTime()) / 86400000) : 1;
    const bayes = _abBayes(variantes.map((v, i) => Object.assign({}, v, { usaVendas, controle: i === 0 })),
                           { diasRodando, minVendas: Number(r.minVendas) || 40 });

    // Fora do teste: gente que caiu direto numa página das variantes sem passar
    // pelo link do split (anúncio antigo com link direto). Não entra na
    // comparação — mas se vende, precisa aparecer, senão some da conta.
    const caminho = u => { try { const x = new URL(/^https?:/i.test(u) ? u : 'https://' + u); return (x.hostname.replace(/^www\./, '') + x.pathname).replace(/\/+$/, '').toLowerCase(); } catch (e) { return ''; } };
    const paginasDoTeste = new Set((r.destinos || []).map(d => caminho(d.url)).filter(Boolean));
    const foraVids = new Set();
    (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : []).concat(Object.values(_jBuffer)).forEach(j => {
      if (!j || !j.id) return;
      (j.eventos || []).forEach(e => {
        if (!e || e.tipo !== 'entrou' || e.teste || !e.pg) return;
        const dia = String(e.em || '').slice(0, 10);
        if ((de && dia < de) || (ate && dia > ate)) return;
        const pgc = String(e.pg).replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[?#].*$/, '').replace(/\/+$/, '').toLowerCase();
        for (const alvo of paginasDoTeste) if (pgc === alvo || pgc.endsWith(alvo.slice(alvo.indexOf('/')))) { foraVids.add(j.id); break; }
      });
    });
    let foraVendas = 0, foraReceita = 0;
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (v && v.vid && foraVids.has(v.vid) && !varDoVisitante[v.vid] && _vendaPaga(v)) { foraVendas++; foraReceita += Number(v.valor) || 0; }
    });
    const foraDoTeste = { visitas: foraVids.size, vendas: foraVendas, receita: foraReceita };

    res.json({
      ok: true, teste: slug, nome: r.nome || slug, hipotese: r.hipotese || '',
      meta: r.meta || null, estado: r.estado || (r.ativo === false ? 'pausado' : 'rodando'),
      criadoEm: r.criadoEm || null, variantes,
      lider: ord[0] ? ord[0].id : null, segundo: ord[1] ? ord[1].id : null,
      precoVaria, julgamento, divisao, vendasSemVariante, bayes, foraDoTeste,
      vencedora: r.vencedora || null, diasRodando: Math.round(diasRodando),
      // Quem converte mais nem sempre e quem fatura mais. Quando os dois nao
      // sao o mesmo, dizer isso vale mais que eleger um vencedor.
      liderReceita: (function () {
        const comReceita = variantes.filter(v => v.receita > 0);
        if (!comReceita.length) return null;
        return comReceita.sort((x, y) => (y.receitaPorPessoa || 0) - (x.receitaPorPessoa || 0))[0].id;
      })()
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── TESTE A/B v2 ──
// A comparação sai da base de pessoas: quem caiu em cada variante (pela visita
// que chegou com o teste), quem passou do pitch, quem abriu o checkout e quem
// COMPROU (venda ligada à pessoa, não página de obrigado). Sem meta escolhida,
// a meta é a compra: teste que "só divide" não diz quem ganhou.
// ══════════════════════════════════════════════════════
// Bootstrap do R$ por pessoa sem reamostrar 8 mil zeros: o número de
// compradores de cada reamostra sai da binomial (aproximação normal) e só as
// receitas deles são sorteadas.
function _normalPadrao() { const u = Math.random() || 1e-12, v = Math.random(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
function _bootRpp(n, receitas, B) {
  const out = new Float64Array(B), k = receitas.length;
  if (!n) return out;
  const p = k / n;
  for (let b = 0; b < B; b++) {
    let kk = n < 60 ? (() => { let c = 0; for (let i = 0; i < n; i++) if (Math.random() < p) c++; return c; })()
                    : Math.round(n * p + Math.sqrt(n * p * (1 - p)) * _normalPadrao());
    kk = Math.max(0, Math.min(n, kk));
    let soma = 0;
    for (let i = 0; i < kk && k; i++) soma += receitas[(Math.random() * k) | 0];
    out[b] = soma / n;
  }
  return out;
}
function _abV2(slug, de, ate) {
  const dbj = readDB();
  const r = (Array.isArray(dbj.store[KEY_REDIRS]) ? dbj.store[KEY_REDIRS] : []).find(x => String(x.slug || '').toLowerCase() === slug);
  if (!r) return null;
  const custos = _custosCfg(dbj);
  const inicioTeste = r.criadoEm ? Date.parse(r.criadoEm) : 0;
  const per = (de || ate) ? _periodoMs(de, ate) : { ini: inicioTeste || Date.now() - 30 * 86400000, fim: Date.now() };
  per.de = _diaBR(per.ini); per.ate = _diaBR(per.fim);
  const meta = r.meta || 'compra';
  const vars = (r.destinos || []).map((d, i) => ({ id: String(d.id || ('v' + i)), nome: d.nome || ('Variante ' + (i + 1)), url: d.url || '',
    peso: Number(d.peso) || 1, sorteios: 0, pessoas: 0, pitch: 0, checkout: 0, vendas: 0, receita: 0, metas: 0, receitas: [], porDia: {} }));
  const porId = {}; vars.forEach(v => { porId[v.id] = v; });

  // cliques no link (o sorteio acontece no redirecionador)
  (Array.isArray(dbj.store[KEY_ABSTATS]) ? dbj.store[KEY_ABSTATS] : []).concat(Object.values(_abBuffer))
    .filter(l => l.teste === slug && l.data >= per.de && l.data <= per.ate)
    .forEach(l => { const v = porId[l.variante]; if (v) { v.sorteios += l.sorteios || 0; v.metasEtapa = (v.metasEtapa || 0) + (l.metas || 0); } });

  // quem caiu em qual variante: a primeira visita com o teste, sem o time
  const db = _pessoas();
  const liq = o => (o.liquido != null ? o.liquido : (Number(o.valor) || 0) * (1 - (custos.gateway || 0) / 100));
  const quem = {};
  if (db) {
    _q(`SELECT visitante, variante, MIN(inicio) ini, MAX(pitch) pitch, MAX(checkout) ck FROM sessoes
        WHERE lower(teste)=? AND interno=0 AND inicio BETWEEN ? AND ? GROUP BY visitante`).all(slug, per.ini, per.fim)
      .forEach(x => {
        const v = porId[String(x.variante || '')]; if (!v) return;
        quem[x.visitante] = v.id;
        v.pessoas++; if (x.pitch) v.pitch++; if (x.ck) v.checkout++;
        const d = _diaBR(x.ini); const pd = v.porDia[d] || (v.porDia[d] = { pessoas: 0, vendas: 0 }); pd.pessoas++;
      });
    const ids = Object.keys(quem);
    for (let i = 0; i < ids.length; i += 500) {
      const lote = ids.slice(i, i + 500);
      _q('SELECT visitante, valor, liquido, dia FROM pedidos WHERE pago=1 AND estorno=0 AND renovacao=0 AND em BETWEEN ? AND ? AND visitante IN (' + _ph(lote.length) + ')')
        .all(per.ini, per.fim, ...lote).forEach(o => {
          const v = porId[quem[o.visitante]]; if (!v) return;
          v.vendas++; v.receita += liq(o); v.receitas.push(liq(o));
          const pd = v.porDia[o.dia] || (v.porDia[o.dia] = { pessoas: 0, vendas: 0 }); pd.vendas++;
        });
    }
  }
  vars.forEach(v => { v.metas = meta === 'compra' ? v.vendas : (v.metasEtapa || 0); });

  // ── veredito ──
  const ctrl = vars[0];
  const bayes = _abBayes(vars.map((v, i) => Object.assign({}, v, { usaVendas: meta === 'compra', controle: i === 0 })),
                         { diasRodando: Math.max(1, (Date.now() - (inicioTeste || per.ini)) / 86400000), minVendas: Number(r.minVendas) || 40 });
  const B = 2000;
  const boots = vars.map(v => _bootRpp(v.pessoas, v.receitas, B));
  const rpp = v => v.pessoas ? v.receita / v.pessoas : 0;
  const ordem = vars.filter(v => v.pessoas).slice().sort((a, b) => rpp(b) - rpp(a));
  const lider = ordem[0] || null;
  let veredito = null;
  if (lider && ctrl && vars.length >= 2) {
    // o desafiante: o líder, ou (se o controle lidera) o melhor dos outros
    const desafiante = lider === ctrl ? (ordem[1] || null) : lider;
    if (desafiante) {
      const ia = vars.indexOf(ctrl), ib = vars.indexOf(desafiante);
      const razoes = [];
      let perda = 0, melhor = 0;
      for (let b = 0; b < B; b++) {
        const a = boots[ia][b], x = boots[ib][b];
        if (a > 0) razoes.push(x / a - 1);
        perda += Math.max(0, a - x);
        if (x > a) melhor++; else if (x === a) melhor += 0.5;
      }
      razoes.sort((p, q) => p - q);
      // A chance mostrada é no mesmo critério do "na frente" e do lift: R$ por
      // pessoa. Com ticket diferente entre as variantes, a conversão sozinha
      // aponta uma e o dinheiro outra — a tela dizia as duas coisas ao mesmo tempo.
      const bv = (bayes.variantes || []).find(x => x.id === desafiante.id) || {};
      const chanceConversao = bv.chanceMelhorQueControle != null ? bv.chanceMelhorQueControle : null;
      const chance = (ctrl.vendas + desafiante.vendas) > 0 ? melhor / B : chanceConversao;
      const minLado = Math.min(ctrl.vendas, desafiante.vendas), minV = Number(r.minVendas) || 40;
      // quantas vendas faltam: o que falta pro mínimo por lado, ou pro tamanho
      // que a diferença atual pede pra chegar a 95% — o que for maior
      const pa = ctrl.pessoas ? ctrl.vendas / ctrl.pessoas : 0, pb = desafiante.pessoas ? desafiante.vendas / desafiante.pessoas : 0;
      let faltaVendas = Math.max(0, minV - minLado) * 2;
      if (pa !== pb && (pa + pb) > 0) {
        const nAlvo = Math.ceil(Math.pow(1.645 + 0.84, 2) * (pa * (1 - pa) + pb * (1 - pb)) / Math.pow(pb - pa, 2));
        const faltaPessoas = Math.max(0, nAlvo - Math.min(ctrl.pessoas, desafiante.pessoas));
        faltaVendas = Math.max(faltaVendas, Math.round(faltaPessoas * (pa + pb)));
      }
      // 95% pros dois lados: o controle também pode ser o vencedor claro
      const pode = chance != null && Math.max(chance, 1 - chance) >= 0.95 && minLado >= minV;
      veredito = {
        controle: ctrl.id, desafiante: desafiante.id, chance, chanceConversao, liftRpp: razoes.length ? razoes[Math.floor(razoes.length / 2)] : null,
        perda: rpp(ctrl) ? (perda / B) / rpp(ctrl) : null, faltaVendas: pode ? 0 : faltaVendas,
        minPorLado: minV, vendasMenorLado: minLado, podeDeclarar: pode,
        sugerida: chance != null && chance < 0.5 ? ctrl.id : desafiante.id,
        leitura: _abLeitura(ctrl, desafiante, chance, pode, minV)
      };
    }
  }

  // ── divisão real x configurada, perda clique → página ──
  const totS = vars.reduce((a, v) => a + v.sorteios, 0), totP = vars.reduce((a, v) => a + v.peso, 0);
  vars.forEach(v => { v.fatiaReal = totS ? v.sorteios / totS * 100 : null; v.fatiaAlvo = totP ? v.peso / totP * 100 : null; });
  const divisao = { total: totS, torta: totS > 200 && vars.some(v => v.fatiaReal != null && Math.abs(v.fatiaReal - v.fatiaAlvo) > 5) };
  const chegaram = vars.reduce((a, v) => a + v.pessoas, 0);
  const perdaClique = totS ? Math.max(0, 1 - chegaram / totS) : null;

  // ── fora do teste: gente do funil que não passou pelo link ──
  let fora = null;
  const funil = (Array.isArray(dbj.store[KEY_FUNIS]) ? dbj.store[KEY_FUNIS] : []).find(f => f && (f.id === r.funil ||
    (f.projeto === r.projeto && (f.etapas || []).some(e => (r.destinos || []).some(d => _normPg(d.url) && _normPg(d.url) === _normPg(e.url))))));
  if (db && funil) {
    const esc = _escopoFunil(dbj, funil.id);
    if (esc) {
      const esq = _escopoSql(esc, 'p');
      const lista = _q(`SELECT DISTINCT p.visitante FROM paginas p WHERE p.dia BETWEEN ? AND ? AND p.interno=0 AND ` + esq.where)
        .all(per.de, per.ate, ...esq.args).map(x => x.visitante).filter(x => !quem[x]);
      let vendas = 0, receita = 0;
      const fontes = {}, anuncios = {};
      for (let i = 0; i < lista.length; i += 500) {
        const lote = lista.slice(i, i + 500);
        _q('SELECT valor, liquido FROM pedidos WHERE pago=1 AND estorno=0 AND renovacao=0 AND em BETWEEN ? AND ? AND visitante IN (' + _ph(lote.length) + ')')
          .all(per.ini, per.fim, ...lote).forEach(o => { vendas++; receita += liq(o); });
        _q('SELECT fonte, cont FROM sessoes WHERE inicio BETWEEN ? AND ? AND (teste IS NULL OR teste=\'\') AND visitante IN (' + _ph(lote.length) + ')')
          .all(per.ini, per.fim, ...lote).forEach(s => {
            const f = s.fonte || 'direto'; fontes[f] = (fontes[f] || 0) + 1;
            const c = _canalDe(s.fonte, _canaisCache());
            if (c && c.anuncios && s.cont) { const k = String(s.cont).split('|')[0].slice(0, 60); anuncios[k] = (anuncios[k] || 0) + 1; }
          });
      }
      fora = { visitas: lista.length, vendas, receita, rpp: lista.length ? receita / lista.length : 0,
               fontes: Object.entries(fontes).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([fonte, n]) => ({ fonte, n })),
               anunciosDiretos: Object.entries(anuncios).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([anuncio, n]) => ({ anuncio, n })) };
    }
  }

  // ── conversão por dia ──
  // Sempre do teste inteiro (até 60 dias), não só do período escolhido: com
  // "Ontem" o gráfico viraria um ponto só, e o que ele responde é a evolução.
  const iniSerie = Math.max(inicioTeste || per.ini, Date.now() - 60 * 86400000);
  const porDiaT = {}; vars.forEach(v => { porDiaT[v.id] = {}; });
  if (db) {
    const quemT = {};
    _q(`SELECT visitante, variante, MIN(inicio) ini FROM sessoes WHERE lower(teste)=? AND interno=0 AND inicio >= ? GROUP BY visitante`)
      .all(slug, iniSerie).forEach(x => {
        const vid = String(x.variante || ''); if (!porDiaT[vid]) return;
        quemT[x.visitante] = vid;
        const d = _diaBR(x.ini); const pd = porDiaT[vid][d] || (porDiaT[vid][d] = { pessoas: 0, vendas: 0 }); pd.pessoas++;
      });
    const idsT = Object.keys(quemT);
    for (let i = 0; i < idsT.length; i += 500) {
      const lote = idsT.slice(i, i + 500);
      _q('SELECT visitante, dia FROM pedidos WHERE pago=1 AND estorno=0 AND renovacao=0 AND em >= ? AND visitante IN (' + _ph(lote.length) + ')')
        .all(iniSerie, ...lote).forEach(o => {
          const vid = quemT[o.visitante]; const pd = porDiaT[vid][o.dia] || (porDiaT[vid][o.dia] = { pessoas: 0, vendas: 0 }); pd.vendas++;
        });
    }
  }
  const dias = [];
  for (let t = Date.parse(_diaBR(iniSerie) + 'T12:00:00Z'); dias.length < 61; t += 86400000) {
    const d = new Date(t).toISOString().slice(0, 10); if (d > _diaBR(Date.now())) break; dias.push(d);
  }
  const serie = vars.map(v => ({ id: v.id, nome: v.nome, pontos: dias.map(d => { const x = porDiaT[v.id][d] || { pessoas: 0, vendas: 0 }; return { dia: d, pessoas: x.pessoas, vendas: x.vendas, conv: x.pessoas ? x.vendas / x.pessoas : null, noPeriodo: d >= per.de && d <= per.ate }; }) }));

  // ── histórico: os testes que já acabaram neste projeto ──
  const historico = (Array.isArray(dbj.store[KEY_REDIRS]) ? dbj.store[KEY_REDIRS] : [])
    .filter(x => x && x.slug !== r.slug && (x.projeto || '') === (r.projeto || '') && (x.vencedora || x.estado === 'encerrado'))
    .map(x => {
      const v = (x.destinos || []).find((d, i) => String(d.id || ('v' + i)) === String(x.vencedora));
      return { nome: x.nome || x.slug, de: x.criadoEm || null, ate: x.encerradoEm || null,
               vencedora: v ? (v.nome || x.vencedora) : (x.vencedora ? String(x.vencedora) : 'empate'),
               ganho: x.resultado && x.resultado.liftRpp != null ? x.resultado.liftRpp : null };
    }).sort((a, b) => String(b.ate || '').localeCompare(String(a.ate || ''))).slice(0, 12);

  return { ok: true, teste: slug, nome: r.nome || slug, hipotese: r.hipotese || '', meta, metaNome: meta === 'compra' ? 'Compra (webhook)' : 'etapa do funil',
    link: r.dominio ? ('https://' + r.dominio + '/r/' + slug) : ('/r/' + slug), estado: r.estado || (r.ativo === false ? 'pausado' : 'rodando'),
    criadoEm: r.criadoEm || null, diaDoTeste: inicioTeste ? Math.max(1, Math.ceil((Date.now() - inicioTeste) / 86400000)) : null,
    vencedora: r.vencedora || null, de: per.de, ate: per.ate, testeInteiro: !(de || ate),
    inicioTeste: inicioTeste ? _diaBR(inicioTeste) : null,
    variantes: vars.map(v => ({ id: v.id, nome: v.nome, url: v.url, peso: v.peso, sorteios: v.sorteios, pessoas: v.pessoas,
      pitch: v.pitch, checkout: v.checkout, vendas: v.vendas, receita: v.receita, metas: v.metas,
      pctPitch: v.pessoas ? v.pitch / v.pessoas : 0, taxaCheckout: v.pessoas ? v.checkout / v.pessoas : 0,
      conversao: v.pessoas ? v.vendas / v.pessoas : 0, ticket: v.vendas ? v.receita / v.vendas : 0, rpp: rpp(v),
      fatiaReal: v.fatiaReal, fatiaAlvo: v.fatiaAlvo, controle: v === ctrl })),
    lider: lider ? lider.id : null, veredito, bayes: { chanceLider: bayes.chanceLider, lider: bayes.lider },
    divisao, perdaClique, chegaram, fora, serie, historico };
}
function _abLeitura(a, b, chance, pode, minV) {
  const nome = v => v.nome || v.id;
  const partes = [];
  const pa = a.pessoas ? a.pitch / a.pessoas : 0, pb = b.pessoas ? b.pitch / b.pessoas : 0;
  const ra = a.pessoas ? a.receita / a.pessoas : 0, rb = b.pessoas ? b.receita / b.pessoas : 0;
  if (pb > pa * 1.05) partes.push('A ' + nome(b) + ' segura mais gente até o pitch');
  else if (pa > pb * 1.05) partes.push('A ' + nome(a) + ' segura mais gente até o pitch');
  if (rb > ra) partes.push((partes.length ? 'e ' : 'A ' + nome(b) + ' ') + 'vende mais por pessoa');
  else if (ra > rb) partes.push((partes.length ? 'mas a ' + nome(a) + ' ' : 'A ' + nome(a) + ' ') + 'vende mais por pessoa');
  const ta = a.vendas ? a.receita / a.vendas : 0, tb = b.vendas ? b.receita / b.vendas : 0;
  let s = partes.join(' ') + (partes.length ? '.' : '');
  if (ta && tb && Math.abs(ta - tb) / Math.min(ta, tb) > 0.1) s += ' A ' + nome(ta > tb ? a : b) + ' vende mais caro por venda.';
  s += pode ? ' Já dá pra declarar.' : ' Mantenha a divisão até 95% ou ' + minV + ' vendas por lado.';
  return s.trim();
}

app.get('/api/ab/v2', authUsuario, (req, res) => {
  try {
    const slug = String(req.query.teste || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!slug) return res.status(400).json({ error: 'Informe o teste.' });
    const out = _abV2(slug, String(req.query.de || '').slice(0, 10), String(req.query.ate || '').slice(0, 10));
    if (!out) return res.status(404).json({ error: 'Teste não encontrado.' });
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Dados pra tela ──
// Os numeros do funil. Vive fora da rota porque o MCP responde as MESMAS
// perguntas: se cada um fizesse a propria conta, a tela e o chat diriam numeros
// diferentes pro mesmo funil — que foi o problema que a Jornada ja teve.
function _funilStats(de, ate, funil) {
    const db = readDB();
    const ado = _mapaAdocao(db, funil);
    let linhas = Array.isArray(db.store[KEY_FSTATS]) ? db.store[KEY_FSTATS] : [];
    if (funil) linhas = linhas.filter(ado.aceita);
    if (de)    linhas = linhas.filter(l => l.data >= de);
    if (ate)   linhas = linhas.filter(l => l.data <= ate);
    // soma o que ainda nao foi gravado, senao a tela fica pra tras
    const extra = Object.values(_fBuffer).filter(l =>
      (!funil || ado.aceita(l)) && (!de || l.data >= de) && (!ate || l.data <= ate));
    const porEtapa = {};
    linhas.concat(extra).forEach(l0 => {
      const l = funil ? Object.assign({}, l0, { etapa: ado.etapaDe(l0) }) : l0;
      if (!porEtapa[l.etapa]) porEtapa[l.etapa] = { etapa: l.etapa, entradas: 0, unicos: 0, saidas: 0, segundos: 0, eventos: {} };
      const v = porEtapa[l.etapa];
      v.entradas += l.entradas || 0; v.unicos += l.unicos || 0;
      v.saidas   += l.saidas   || 0; v.segundos += l.segundos || 0;
      Object.keys(l.eventos || {}).forEach(t => { v.eventos[t] = (v.eventos[t] || 0) + l.eventos[t]; });
    });
    // ── Unicos de verdade, contados da jornada ──────────────────────────────
    // _fVistos (o Set que decide quem ja foi contado) vive so na memoria. Todo
    // restart ele volta vazio e quem voltou ao site depois disso e contado de
    // novo como unico — e o merge SOMA no banco. Num dia com varios deploys o
    // numero infla feio: 1.200 pessoas viraram 2.218.
    // A jornada nao tem esse problema: e um registro por visitante, gravado no
    // banco. Quando o periodo cabe na janela dela, ela e a fonte melhor.
    // Fora da janela (>7 dias) nao ha jornada e o contador antigo e o que tem.
    const dentroDaJanela = (() => {
      if (!de) return false;                       // sem inicio nao da pra saber
      const limite = new Date(Date.now() - JORNADA_DIAS * 86400000).toISOString().slice(0, 10);
      return de >= limite;
    })();

    // ── Quantas paginas reportam sob a MESMA etapa ──────────────────────────
    // A chave de contagem e funil|etapa|dia: a pagina nao entra nela. Duas VSLs
    // coladas com o mesmo data-e somam no mesmo bloco, e o bloco mostra a URL
    // cadastrada na etapa como se fosse a unica. Com teste A/B isso e o caso
    // normal, nao a excecao — entao a tela tem de mostrar a divisao.
    // A jornada guarda a pagina em cada evento; e de la que ela sai.
    const porPagina = {};
    const jn = (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
      .concat(Object.values(_jBuffer));
    // ── Aceitar tambem pela PAGINA, nao so pelo id do funil ─────────────────
    // Existe um comentario no /api/funil/jornadas dizendo exatamente isto: o
    // pixel pode reportar sob um id de funil velho e a pagina continua sendo a
    // mesma pagina. Filtrar so por funil fazia a tela vir vazia. Eu reintroduzi
    // esse bug ao consertar outro — o numero caiu de 3.298 pra 1.300.
    // Agora: vale se o funil bate (ou foi adotado) OU se a pagina do evento e
    // uma das URLs cadastradas nas etapas DESTE funil.
    const _norm = u => String(u || '').trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[?#].*$/, '').replace(/\/+$/, '');
    const urlsDoFunil = new Set();
    const etapaPorUrl = {};
    const etapaTemUrl = {};       // etapa que mostra um link na tela
    if (funil) {
      const fu = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : [])
        .find(x => x && x.id === funil);
      ((fu && fu.etapas) || []).forEach(e => {
        if (!e.url) return;
        const k = _norm(e.url);
        urlsDoFunil.add(k); etapaPorUrl[k] = e.id; etapaTemUrl[e.id] = true;
      });
    }
    const valeAqui = (j, e) => {
      if (!funil) return true;
      if (ado.aceita({ funil: j.funil, etapa: e.etapa })) return true;
      return e.pg && urlsDoFunil.has(_norm(e.pg));
    };
    // ── Em que etapa o evento cai: a URL cadastrada ganha do data-e ─────────
    // Estava ao contrario, e isso apagava o teste A/B inteiro da tela. O data-e
    // vai junto com o script quando voce duplica a pagina, entao /segredo e
    // /segredo2 chegam com o MESMO data-e: o servidor jogava as duas na mesma
    // etapa, um bloco somava tudo (3.886) e o outro ficava zerado — parecia que
    // uma variante nao recebia trafego, quando na verdade tinha 2.412 pessoas.
    // A URL o usuario cadastrou de proposito, uma em cada etapa, e e ela que o
    // mapa desenha em cada bloco. Entao ela e a intencao mais forte das duas.
    // ── So exclui pagina estranha de etapa que se sustenta sozinha ──────────
    // Se a URL cadastrada na etapa nunca aparece nos eventos (link digitado com
    // erro, pagina que mudou de endereco, /index.html no fim), excluir as outras
    // paginas zeraria o bloco — regressao pior que o problema que estou
    // consertando. Nesse caso vale o comportamento antigo, e o aviso que ja
    // existe ('mostra X mas quem traz gente e Y') continua sendo quem resolve.
    const urlVista = new Set();
    jn.forEach(j => (j.eventos || []).forEach(e => {
      if (e && e.pg) urlVista.add(_norm(e.pg));
    }));
    const etapaSeSustenta = {};
    Object.keys(etapaPorUrl).forEach(u => {
      if (urlVista.has(u)) etapaSeSustenta[etapaPorUrl[u]] = true;
    });

    // Paginas que declaram uma etapa mas nao sao a URL dela. Nao somem: viram
    // lista, pra dar pra ver e decidir (cadastrar como etapa, ou arrumar o pixel).
    const foraDoMapa = {};
    const etapaDaqui = (j, e) => {
      if (!funil) return e.etapa;
      const dona = etapaPorUrl[_norm(e.pg)];
      if (dona) return dona;
      const decl = ado.aceita({ funil: j.funil, etapa: e.etapa })
        ? ado.etapaDe({ funil: j.funil, etapa: e.etapa })
        : e.etapa;
      // ── Um bloco que mostra uma URL tem de contar AQUELA URL ───────────────
      // O data-e e copiado junto com o script: /bio, /aula, /assinatura e mais
      // oito paginas chegavam com o data-e da VSL e entravam no bloco dela. O
      // bloco entao exibia 'apostilai.ai/segredo' e somava onze paginas que nao
      // sao aquela. Se a etapa tem link cadastrado, pagina que nao e o link fica
      // de fora — e aparece na lista de fora do mapa.
      // Etapa sem link cadastrado continua aceitando pelo data-e: e o unico
      // sinal que ela tem, e tirar isso zeraria funil que ainda nao foi montado.
      if (decl && etapaTemUrl[decl] && etapaSeSustenta[decl] && e.pg) {
        const k = String(e.pg).slice(0, 160);
        (foraDoMapa[k] = foraDoMapa[k] || new Set()).add(j.id);
        return null;
      }
      return decl;
    };

    const unicosJn = {};       // etapa -> Set(visitante)
    jn.forEach(j => {
      const chaves = new Set();
      (j.eventos || []).forEach(e => {
        if (!e.etapa && !e.pg) return;
        if (!valeAqui(j, e)) return;
        const dia = String(e.em || '').slice(0, 10);
        if (de && dia < de) return;
        if (ate && dia > ate) return;
        const et = etapaDaqui(j, e);
        if (!et) return;
        (unicosJn[et] = unicosJn[et] || new Set()).add(j.id);
        if (!e.pg) return;
        chaves.add(et + '|' + e.pg);
      });
      // um visitante conta uma vez por (etapa,pagina), nao uma por evento
      chaves.forEach(k => {
        const corte = k.indexOf('|');
        const et = k.slice(0, corte), pg = k.slice(corte + 1);
        if (!porPagina[et]) porPagina[et] = {};
        porPagina[et][pg] = (porPagina[et][pg] || 0) + 1;
      });
    });

    // ── Etapa que so a jornada conhece tambem entra na lista ────────────────
    // porEtapa nasce dos contadores, e contador e chaveado pelo data-e. Num
    // teste A/B as duas paginas chegam com o MESMO data-e: existe uma linha de
    // contador so, e a segunda etapa nunca era criada — o bloco dela mostrava 0
    // pra sempre, como se aquela variante nao recebesse ninguem. A jornada sabe
    // quem esteve em cada URL; se ela viu gente numa etapa, a etapa existe.
    Object.keys(unicosJn).forEach(et => {
      if (!porEtapa[et]) {
        porEtapa[et] = { etapa: et, entradas: 0, unicos: 0, saidas: 0, segundos: 0, eventos: {} };
      }
    });

    return { ok: true, funil, de, ate,
      // 'jornada' quando o numero veio da fonte confiavel; 'contador' quando
      // sobrou o acumulado antigo. A tela precisa poder dizer qual e qual.
      fonteUnicos: dentroDaJanela ? 'jornada' : 'contador',
      // Paginas com pixel que nao correspondem a nenhuma etapa deste funil.
      // Antes elas engordavam o bloco da etapa que copiaram; agora ficam aqui.
      foraDoMapa: Object.entries(foraDoMapa)
        .map(([pg, quem]) => ({ pg, pessoas: quem.size }))
        .sort((a, b) => b.pessoas - a.pessoas).slice(0, 40),
      etapas: Object.values(porEtapa).map(e => {
        const real = dentroDaJanela && unicosJn[e.etapa] ? unicosJn[e.etapa].size : null;
        return Object.assign(e, {
          tempoMedio: e.saidas > 0 ? Math.round(e.segundos / e.saidas) : 0,
          unicosContador: e.unicos,
          unicos: real != null ? real : e.unicos,
          paginas: Object.entries(porPagina[e.etapa] || {})
            .map(([pg, pessoas]) => ({ pg, pessoas }))
            .sort((a, b) => b.pessoas - a.pessoas)
        });
      }),
      feed: _fFeed.filter(f => !funil || ado.aceita(f)).slice(0, 40) };
}

app.get('/api/funil/stats', authUsuario, (req, res) => {
  try {
    res.json(_funilStats(String(req.query.de || '').slice(0, 10),
                         String(req.query.ate || '').slice(0, 10),
                         String(req.query.funil || '').slice(0, 80)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── O PIXEL, SERVIDO DAQUI ──
// Antes o codigo inteiro era colado em cada pagina: ~40 linhas, com um
// comentario em cima dizendo o nome do funil e a URL — que qualquer um lia no
// "ver codigo fonte" do site. E, pior: corrigir qualquer coisa no pixel exigia
// recolar em TODAS as paginas. Agora a pagina carrega este arquivo e passa so
// os dois ids; o que muda aqui vale pra todo mundo no proximo carregamento.
// ══════════════════════════════════════════════════════
// Muda a cada deploy. Serve pra responder "essa pagina esta rodando qual pixel?"
// sem adivinhar — basta olhar window.TMXOrigem.versao no console.
const TMX_VERSAO = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');

// ── Versao do app ───────────────────────────────────────────────────────────
// O ScaleLab.html e um SPA de arquivo unico: a aba que ficou aberta continua
// rodando o JavaScript de antes do deploy pra sempre. Passei tres rodadas
// subindo mudanca com o usuario olhando pra tela velha sem que nenhum dos dois
// percebesse. A marca e o mtime do arquivo servido — muda a cada 'railway up'.
let _versaoApp = '';
function versaoApp() {
  if (_versaoApp) return _versaoApp;
  try {
    // Os DOIS arquivos, nao so o HTML. Correcao que mexe so no servidor nao
    // movia o numero, e a tela dizia 'voce esta atualizado' com codigo velho —
    // exatamente o que o carimbo existe pra evitar.
    const mt = f => { try { return fs.statSync(f).mtimeMs; } catch (e) { return 0; } };
    const maior = Math.max(mt(path.join(__dirname, 'public', 'ScaleLab.html')),
                           mt(path.join(__dirname, 'server.js')));
    // Math.round, nao '| 0': o '| 0' forca inteiro de 32 bits e um timestamp em
    // milissegundos estoura isso — dava a volta e virava numero negativo.
    _versaoApp = maior ? String(Math.round(maior)) : TMX_VERSAO;
  } catch (e) { _versaoApp = TMX_VERSAO; }
  return _versaoApp;
}

// Sem login: e so um numero de build, e a tela precisa dele antes de autenticar.
app.get('/api/versao', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true, versao: versaoApp() });
});

const PIXEL_JS = `(function(w,d){
  var TMX_VERSAO = '${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')}';
  var eu = d.currentScript;
  if(!eu) { var ts = d.getElementsByTagName('script'); eu = ts[ts.length-1]; }
  var FUNIL = eu.getAttribute('data-f') || '';
  var ETAPA = eu.getAttribute('data-e') || '';
  var VERSAO = eu.getAttribute('data-v') || '';
  var API   = eu.src.replace(/\\/px\\.js.*$/, '') + '/api/funil/evento';
  if(!FUNIL) return;

  // ── O id tem que valer no dominio inteiro, nao so no host ────────────────
  // Cookie gravado sem 'domain=' e host-only: quem entra em apostilai.ai e vai
  // pra go.apostilai.ai recebe DOIS ids e conta como duas pessoas. Com o funil
  // atravessando subdominio (landing num, VSL noutro) o numero da etapa inflava
  // sozinho — foi assim que uma etapa mostrou 3.380 pessoas vindas de 2.056
  // cliques. Aqui a gente sobe ate o dominio mais largo que o navegador aceita.
  //
  // O teste e empirico de proposito: navegador recusa cookie em sufixo publico,
  // entao 'com.br' falha e '.apostilai.com.br' passa, sem precisar carregar uma
  // lista de sufixos aqui dentro.
  function _raiz(){
    try{
      var h = location.hostname;
      if(/^[\\d.]+$/.test(h) || h.indexOf('.') < 0) return '';   // IP ou localhost
      var partes = h.split('.');
      for(var i = partes.length - 2; i >= 0; i--){
        var cand = '.' + partes.slice(i).join('.');
        var sonda = 'tmxp' + Math.random().toString(36).slice(2, 7);
        d.cookie = sonda + '=1;path=/;domain=' + cand + ';SameSite=Lax';
        if(d.cookie.indexOf(sonda + '=1') >= 0){
          d.cookie = sonda + '=;path=/;domain=' + cand + ';max-age=0';
          return cand;
        }
      }
    }catch(e){}
    return '';
  }
  function _gravaId(v, dom){
    var base = 'tmx_id=' + v + ';path=/;max-age=7776000;SameSite=Lax' +
               (location.protocol === 'https:' ? ';Secure' : '');
    try{ d.cookie = base + (dom ? ';domain=' + dom : ''); }catch(e){}
  }
  var RAIZ = _raiz();
  var id = (d.cookie.match(/tmx_id=([^;]+)/)||[])[1];
  if(!id){
    id = 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2,8);
    _gravaId(id, RAIZ);
  } else if(RAIZ){
    // Ja existia, mas talvez preso a este host. Regrava largo e apaga a copia
    // host-only — duas linhas com o mesmo nome deixariam a leitura instavel.
    _gravaId(id, RAIZ);
    try{ d.cookie = 'tmx_id=;path=/;max-age=0'; }catch(e){}
    _gravaId(id, RAIZ);
  }

  var q = new URLSearchParams(location.search), utm = {};
  // Veio de um quiz do Central TMX: o quiz manda o id dele no link. Guardado
  // pra seguir junto mesmo depois que a pessoa navegar sem o parametro.
  var QID = '';
  try{
    var qidUrl = q.get('tmx_qid') || '';
    if(/^[a-z0-9_-]{4,40}$/i.test(qidUrl)) localStorage.setItem('tmx_qid', qidUrl);
    QID = localStorage.getItem('tmx_qid') || '';
  }catch(e){ QID = q.get('tmx_qid') || ''; }
  ['source','medium','campaign','content','term'].forEach(function(k){
    var v = q.get('utm_'+k);
    try{ if(v) localStorage.setItem('tmx_utm_'+k, v);
         utm[k] = v || localStorage.getItem('tmx_utm_'+k) || ''; }catch(e){ utm[k] = v || ''; }
  });

  // ── First-touch: a origem VERDADEIRA, gravada uma vez e nunca sobrescrita ──
  // O bloco acima ja fazia a UTM sobreviver ao retorno sem parametro (e o que
  // salva o caminho anuncio > perfil > bio). Mas ele e last-touch-com-UTM: um
  // segundo clique em outro anuncio apaga o primeiro. Aqui fica o registro que
  // nao muda, que e o que vai pro checkout.
  var MARCAS = ['utm_source','utm_medium','utm_campaign','utm_content','utm_term',
                'utm_id','fbclid','gclid','ttclid','src','sck','xcod'];
  function bisc(n){
    var m = d.cookie.match('(^|;)\\\\s*' + n + '\\\\s*=\\\\s*([^;]+)');
    return m ? decodeURIComponent(m.pop()) : '';
  }
  function guarda(k, v){
    try{ localStorage.setItem(k, v); }catch(e){}
    // cookie tambem: no iOS o localStorage do WebView as vezes some antes
    try{
      d.cookie = k + '=' + encodeURIComponent(v) + ';path=/;max-age=7776000;SameSite=Lax' +
                 (location.protocol === 'https:' ? ';Secure' : '');
    }catch(e){}
  }
  function le(k){
    var v = '';
    try{ v = localStorage.getItem(k) || ''; }catch(e){}
    return v || bisc(k);
  }

  var agora = {};
  MARCAS.forEach(function(k){
    var v = q.get(k);
    // Macro do gerenciador que nao foi substituida ("{{campaign.name}}" chegando
    // ao pe da letra) nao e origem — e defeito de configuracao do anuncio.
    // Guardar isso no first-touch e pior que nao guardar nada: depois nao ha o
    // que colocar no lugar, porque o proprio "melhor valor" esta quebrado.
    if(v && !/^\\{\\{.*\\}\\}$/.test(v.trim())) agora[k] = v;
  });
  // _fbp e _fbc vem do pixel da Meta, se ele estiver na pagina
  var _fbp = bisc('_fbp'), _fbc = bisc('_fbc');
  if(_fbp) agora.fbp = _fbp;
  if(_fbc) agora.fbc = _fbc;

  if(Object.keys(agora).length){
    agora.em = Date.now();
    agora.pg = location.pathname;
    agora.ref = d.referrer || '';
    var txt = JSON.stringify(agora);
    if(!le('tmx_first')) guarda('tmx_first', txt);   // uma vez, e so
    guarda('tmx_last', txt);
  }
  var primeiro = {};
  try{ primeiro = JSON.parse(le('tmx_first') || '{}'); }catch(e){ primeiro = {}; }
  // pra quem quiser ler de fora (pixel da Meta, por exemplo)
  // Versao visivel: sem isso nao da pra saber se a pagina esta rodando o pixel
  // novo ou uma copia velha em cache — e isso ja custou uma investigacao inteira.
  w.TMXOrigem = { vid: id, primeiro: primeiro, versao: TMX_VERSAO };
  ['t','v'].forEach(function(k){
    var v = q.get('tmx_'+k);
    try{ if(v) localStorage.setItem('tmx_ab_'+k, v); }catch(e){}
  });
  var teste = '', variante = '';
  try{ teste = localStorage.getItem('tmx_ab_t') || ''; variante = localStorage.getItem('tmx_ab_v') || ''; }catch(e){}

  // A pagina, sem query nem hash: com ela da pra comparar 5 VSLs que usam a
  // MESMA etapa do mapa. Query fora de proposito — leva utm e as vezes dado
  // pessoal, e viraria uma chave diferente por visitante.
  // Sem tirar o www aqui, a pagina medida ("www.site.com/x") nunca casaria com o
  // link cadastrado no teste ("https://site.com/x/") — e o seletor mostraria as
  // duas como se fossem paginas diferentes. Minuscula tambem: /697 e /697/ e
  // /VSL e /vsl viravam linhas separadas na mesma tela.
  var PAGINA = (location.host + location.pathname).toLowerCase()
                 .replace(/^www\\./, '').replace(/\\/+$/, '').slice(0, 160);

  // ── Trafego interno ──────────────────────────────────────────────────────
  // Quem e do time abre a pagina uma vez com ?tmx_interno=1 e fica marcado por
  // um ano neste aparelho: continua aparecendo nos Leads, mas sai das metricas
  // e do teste A/B. ?tmx_interno=0 desfaz.
  try{
    var qi = q.get('tmx_interno');
    if(qi === '1' || qi === '0'){
      var bi = 'tmx_int=' + (qi === '1' ? '1;max-age=31536000' : ';max-age=0') + ';path=/;SameSite=Lax' +
               (location.protocol === 'https:' ? ';Secure' : '');
      d.cookie = bi + (RAIZ ? ';domain=' + RAIZ : '');
    }
  }catch(e){}
  var INTERNO = bisc('tmx_int') === '1';

  // ── Sessao: 30 min sem nada fecha ────────────────────────────────────────
  // Sem isso uma aba esquecida aberta a noite inteira virava "saiu depois de
  // 600 min", e cada volta ao site era a mesma visita. A sessao vale entre
  // abas (fica no localStorage) e so a atividade de verdade a mantem viva:
  // rolar, clicar, digitar, voltar pra aba ou o video tocando.
  var SESS_MS = 30 * 60 * 1000;
  function novoSid(){ return 's' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
  var SID = '';
  try{
    var s0 = JSON.parse(localStorage.getItem('tmx_sess') || 'null');
    if(s0 && s0.id && Date.now() - s0.ult < SESS_MS) SID = s0.id;
  }catch(e){}
  if(!SID) SID = novoSid();
  var inicioPagina = Date.now(), inicioSessao = Date.now(), ativoEm = Date.now(), saiuSessao = false;
  function marcaSessao(){ try{ localStorage.setItem('tmx_sess', JSON.stringify({ id: SID, ult: ativoEm })); }catch(e){} }
  marcaSessao();

  function manda(tipo, extra){
    var dados = Object.assign({ id:id, funil:FUNIL, etapa:ETAPA, tipo:tipo, utm:utm,
                                pg:PAGINA, primeiro:primeiro, sid:SID, interno:INTERNO ? 1 : 0,
                                teste:teste, variante:variante, versao:VERSAO, ref:d.referrer, qid:QID }, extra||{});
    var corpo = JSON.stringify(dados);
    try{
      navigator.sendBeacon
        ? navigator.sendBeacon(API, new Blob([corpo],{type:'text/plain;charset=UTF-8'}))
        : fetch(API,{method:'POST',headers:{'Content-Type':'text/plain;charset=UTF-8'},body:corpo,keepalive:true});
    }catch(e){}
  }
  // A origem DESTE acesso (so o que veio na URL agora). O 'utm' acima e o
  // ultimo com UTM guardado; sem separar, voltar direto ao site parecia mais
  // um clique no anuncio antigo.
  var aqui = {};
  MARCAS.forEach(function(k){ if(agora[k]) aqui[k] = agora[k]; });
  function mandaSaiu(){
    if(saiuSessao) return;
    saiuSessao = true;
    // Ate o ultimo sinal de vida, nunca ate agora: se a pessoa largou a aba,
    // o tempo parado nao entra na conta.
    var fim = (Date.now() - ativoEm < SESS_MS) ? Date.now() : ativoEm;
    // tempo NESTA pagina (a Atencao compara paginas), dentro desta visita
    manda('saiu', {
      segundos: Math.max(0, Math.round((fim - Math.max(inicioPagina, inicioSessao)) / 1000)),
      atencao:  Math.round(atencao/1000),
      rolagem:  Math.round(Math.max(fundo, fracaoVista())),
      lcp: lcp, cls: Math.round(cls*1000)/1000, fcp: fcp, erros: errosJs,
      // até que segundo do vídeo foi: o aviso é de minuto em minuto, e quem
      // passa do pitch e sai antes do próximo aviso ficava sem marcar
      vmax: (typeof VID === 'object' && VID.max) ? VID.max : 0, player: (typeof VID === 'object' && VID.player) || ''
    });
  }
  function mexeu(){
    var t = Date.now();
    if(t - ativoEm >= SESS_MS){
      // voltou depois de 30 min parado: a visita anterior acabou onde parou
      mandaSaiu();
      SID = novoSid(); inicioSessao = t; saiuSessao = false; ativoEm = t;
      marcaSessao();
      manda('entrou', { retorno: 1 });
      return;
    }
    ativoEm = t;
    marcaSessao();
  }
  var fundo = 0, atencao = 0, lcp = 0, cls = 0, fcp = 0, errosJs = 0;
  manda('entrou', { aqui: aqui, tela: (screen.width||0) + 'x' + (screen.height||0) });

  // ── rolagem ──
  // So o evento de scroll alimentava isto, entao quem NAO rolava ficava com 0 —
  // e numa VSL quase ninguem rola, a pessoa assiste. O numero dizia que 12 de 13
  // nao passaram do topo quando na verdade tinham visto a pagina inteira.
  // Agora tambem se mede na saida, com a altura final: se a pagina cabe na tela,
  // quem nao rolou viu 100%; se e longa, viu a fracao que coube.
  function fracaoVista(){
    var alt = d.body.scrollHeight || d.documentElement.scrollHeight || 0;
    if(!alt) return 0;
    return Math.min(100, (scrollY + innerHeight) / alt * 100);
  }
  var mexeuScroll = 0;
  w.addEventListener('scroll', function(){
    var p = fracaoVista();
    if(p>fundo) fundo = p;
    if(Date.now() - mexeuScroll > 5000){ mexeuScroll = Date.now(); mexeu(); }
  },{passive:true});
  d.addEventListener('keydown', function(){ mexeu(); }, true);
  var mexeuPonteiro = 0;
  d.addEventListener('pointermove', function(){
    if(Date.now() - mexeuPonteiro > 10000){ mexeuPonteiro = Date.now(); mexeu(); }
  }, { passive:true, capture:true });

  // ── atencao: so conta o tempo com a aba VISIVEL. Tempo de parede contava
  //    quem abriu numa aba de fundo e esqueceu como se estivesse assistindo. ──
  // Comeca contando: se o navegador nunca disparar visibilitychange, a atencao
  // vira o tempo de parede — que e o melhor palpite honesto. Comecar em zero
  // fazia a atencao ser sempre 0 quando o evento nao vinha.
  var visivelDesde = Date.now();
  function fechaJanela(){ if(visivelDesde){ atencao += Date.now()-visivelDesde; visivelDesde = 0; } }
  d.addEventListener('visibilitychange', function(){
    if(d.visibilityState === 'visible'){ if(!visivelDesde) visivelDesde = Date.now(); mexeu(); }
    else fechaJanela();
  });

  // ── Web Vitals de campo: mede o aparelho do lead, nao o laboratorio ──
  try{
    new PerformanceObserver(function(l){
      var e = l.getEntries(); if(e.length) lcp = Math.round(e[e.length-1].startTime);
    }).observe({type:'largest-contentful-paint', buffered:true});
    new PerformanceObserver(function(l){
      l.getEntries().forEach(function(e){ if(!e.hadRecentInput) cls += e.value; });
    }).observe({type:'layout-shift', buffered:true});
    new PerformanceObserver(function(l){
      l.getEntries().forEach(function(e){ if(e.name === 'first-contentful-paint') fcp = Math.round(e.startTime); });
    }).observe({type:'paint', buffered:true});
  }catch(e){}
  w.addEventListener('error', function(){ errosJs++; });

  // ── friccao: clique morto e rage click ──
  var ultimos = [];
  function rotuloDe(el){
    var r = (el.getAttribute && el.getAttribute('aria-label')) || el.innerText || el.alt || el.value || el.tagName || '';
    return String(r).replace(/\\s+/g,' ').trim().slice(0,70) || (el.tagName || '?');
  }
  function acionavel(el){
    return !!(el.closest && el.closest('a[href],button,input,select,textarea,label,[onclick],[role=button],[type=submit]'));
  }
  // Onde o clique nunca e "morto": o player (Vturb e qualquer video), iframes,
  // FAQ (summary/details e sanfonas com aria), campos de formulario e
  // componentes proprios (tag com hifen, como VTURB-SMARTPLAYER). Eram 738
  // "cliques que nao funcionam" num dia — quase todos no play do video.
  var IGNORAR = 'vturb-smartplayer,iframe,video,summary,details,[aria-expanded],[aria-controls],label,input,select,textarea,[contenteditable]';
  function ignoravel(el){
    try{
      if(el.closest(IGNORAR)) return true;
      for(var n = el, i = 0; n && i < 6; n = n.parentElement, i++){
        if(n.tagName && n.tagName.indexOf('-') > 0) return true;
      }
    }catch(e){}
    return false;
  }
  // So conta como morto o que PARECE clicavel: cursor de mao, ou cara de botao
  // e de card de plano. Clique em texto corrido nao e defeito da pagina.
  function pareceClicavel(el){
    try{
      if(getComputedStyle(el).cursor === 'pointer') return true;
      if(el.tagName === 'IMG') return true;
      for(var n = el, i = 0; n && i < 4; n = n.parentElement, i++){
        var c = (typeof n.className === 'string' ? n.className : '') + ' ' + (n.id || '');
        if(/btn|button|botao|bot[aã]o|cta|card|plano|plan|price|preco|comprar|oferta/i.test(c)) return true;
      }
    }catch(e){}
    return false;
  }
  d.addEventListener('click', function(ev){
    mexeu();
    var el = ev.target && ev.target.closest ? ev.target.closest('a,button,[role=button],input[type=submit],img,video') : null;
    if(!el) el = ev.target;
    if(!el || !el.getBoundingClientRect) return;
    var rot = rotuloDe(el);
    var alt = d.body.scrollHeight || 1;
    var y = el.getBoundingClientRect().top + scrollY;
    var noPlayer = ignoravel(el);
    manda('clique', { rotulo: rot, posicao: Math.round(y/alt*100), player: noPlayer ? 1 : 0 });

    // rage click: 3+ no mesmo ponto em ~1s
    var agora = Date.now();
    ultimos = ultimos.filter(function(c){ return agora - c.t < 1000; });
    ultimos.push({ t:agora, x:ev.clientX, y:ev.clientY });
    var perto = ultimos.filter(function(c){
      return Math.abs(c.x-ev.clientX) < 35 && Math.abs(c.y-ev.clientY) < 35; });
    if(perto.length >= 3){
      ultimos = [];
      manda('friccao', { rotulo: rot, motivo: 'raiva' });
      return;
    }

    // clique morto: parece clicavel, nao e acionavel, nao e player nem FAQ,
    // e NADA na pagina mudou logo depois (nem classe, nem atributo, nem texto
    // — contar so filhos do body marcava como morto a sanfona que abriu)
    if(acionavel(el) || noPlayer || !pareceClicavel(el)) return;
    var urlAntes = location.href, focoAntes = d.activeElement, mudou = false, obsM = null;
    try{
      obsM = new MutationObserver(function(){ mudou = true; });
      obsM.observe(d.body, { subtree:true, childList:true, attributes:true, characterData:true });
    }catch(e){}
    setTimeout(function(){
      try{ if(obsM) obsM.disconnect(); }catch(e){}
      if(!mudou && location.href === urlAntes && d.activeElement === focoAntes)
        manda('friccao', { rotulo: rot, motivo: 'morto', posicao: Math.round(y/alt*100) });
    }, 450);
  }, true);

  // ── Video (Vturb ou qualquer <video>) ────────────────────────────────────
  // O pitch e o que separa quem assistiu de quem so abriu a pagina. O player
  // da Vturb vive dentro de um componente proprio; aqui a gente procura o
  // <video> na pagina, dentro do componente (quando ele deixa) e na API antiga
  // smartplayer.instances. A cada minuto tocando, manda em que segundo esta:
  // o servidor sabe onde fica o pitch de cada VSL e marca quem passou.
  var VID = { tocou: false, max: 0, env: 0, player: '' };
  function idDoPlayer(){
    try{
      var el = d.querySelector('vturb-smartplayer,[id^="vid_"],[id^="vid-"]');
      var m = el && String(el.id || '').match(/vid[-_]([a-z0-9]{12,40})/i);
      if(m) return m[1];
      var sc = d.querySelector('script[src*="/players/"]');
      m = sc && String(sc.src).match(/\\/players\\/([a-z0-9]{12,40})/i);
      if(m) return m[1];
    }catch(e){}
    return '';
  }
  function acharVideo(){
    try{
      var v = d.querySelector('video'); if(v) return v;
      var hs = d.querySelectorAll('vturb-smartplayer,[id^="vid_"],[id^="vid-"]');
      for(var i=0;i<hs.length;i++){
        var sr = hs[i].shadowRoot; if(sr){ var x = sr.querySelector('video'); if(x) return x; }
      }
      var ins = w.smartplayer && w.smartplayer.instances;
      if(ins && ins[0] && ins[0].video) return ins[0].video;
    }catch(e){}
    return null;
  }
  setInterval(function(){
    var v = acharVideo(); if(!v) return;
    var t = Math.floor(v.currentTime || 0), tocando = !v.paused && !v.ended;
    if(tocando) mexeu();
    if(t > VID.max) VID.max = t;
    if(!VID.player) VID.player = idDoPlayer();
    var dur = Math.floor(v.duration || 0);
    if(!VID.tocou && t > 0){
      VID.tocou = true; VID.env = Date.now();
      manda('video', { seg: t, max: VID.max, dur: dur, player: VID.player, marco: 'play' });
      return;
    }
    if(VID.tocou && tocando && Date.now() - VID.env >= 60000){
      VID.env = Date.now();
      manda('video', { seg: t, max: VID.max, dur: dur, player: VID.player });
    }
  }, 5000);

  // Sem nada acontecendo por 30 min a visita fecha ali, com o tempo ate o
  // ultimo sinal de vida — nao ate a hora em que a aba for fechada.
  setInterval(function(){
    if(!saiuSessao && Date.now() - ativoEm >= SESS_MS) mandaSaiu();
  }, 60000);

  // Voltou pela memoria do navegador (botao voltar): a pagina nao recarrega,
  // entao e aqui que a visita continua — ou comeca outra, se passou de 30 min.
  w.addEventListener('pageshow', function(ev){
    if(!ev.persisted) return;
    if(Date.now() - ativoEm >= SESS_MS) mexeu();
    else saiuSessao = false;
  });

  w.addEventListener('pagehide', function(){
    fechaJanela();
    // O observador as vezes ainda nao entregou nada quando a pessoa sai rapido.
    // Ler a lista de entradas aqui pega o que ja foi medido de qualquer jeito.
    try{
      if(!lcp){
        var e1 = performance.getEntriesByType('largest-contentful-paint');
        if(e1 && e1.length) lcp = Math.round(e1[e1.length-1].startTime);
      }
      if(!fcp){
        var e2 = performance.getEntriesByName('first-contentful-paint');
        if(e2 && e2.length) fcp = Math.round(e2[0].startTime);
      }
      if(!lcp){
        var nav = performance.getEntriesByType('navigation')[0];
        if(nav && nav.domContentLoadedEventEnd) lcp = Math.round(nav.domContentLoadedEventEnd);
      }
    }catch(e){}
    mandaSaiu();
  });

  // Marca uma etapa no clique de um botao — serve pro checkout do gateway,
  // onde o nosso codigo nao entra mas o clique acontece numa pagina sua.
  w.TMX = function(nome, extra){ manda(nome, extra); };
  // ── Levar o first-touch ate o checkout ──────────────────────────────────
  // localStorage e por dominio: quando a pessoa clica em comprar e vai pro
  // gateway, a UTM fica pra tras e a venda chega sem origem. Aqui a gente
  // reescreve o link de saida com o first-touch antes do clique acontecer.
  //
  // So mexe em host de checkout conhecido — sair anexando UTM em todo link
  // externo vazaria dado de campanha pra qualquer site que voce linkar.
  // Gateways por dominio, mais palavras que aparecem no caminho da URL de compra.
  // A lista cresceu comparando com a de uma ferramenta concorrente: faltavam
  // vindi, adoorei, octuspay, buygoods, guru, iexperience e as palavras genericas
  // (pagamento, carrinho, pedido, finalizar). Link de compra que nao casa aqui
  // nao recebe a UTM — e a venda chega sem origem.
  var CHECKOUTS = new RegExp([
    'payt','kiwify','hotmart','monetizze','eduzz','braip','perfectpay','cakto','ticto',
    'kirvano','greenn','lastlink','pepper','yampi','appmax','doppus','vindi','adoorei',
    'octuspay','buygoods','iexperience','guru','vega',
    'checkout','pagamento','payment','pague','pedido','carrinho','cart','order',
    'finalizar','confirmacao','confirmation','pay\\\\.'
  ].join('|'), 'i');
  var extraCheckout = eu.getAttribute('data-checkout') || '';
  if(extraCheckout){
    try{ CHECKOUTS = new RegExp(CHECKOUTS.source + '|' + extraCheckout, 'i'); }catch(e){}
  }
  var LEVAR = ['utm_source','utm_medium','utm_campaign','utm_content','utm_term',
               'utm_id','fbclid','gclid','ttclid','src','sck','xcod'];

  function enriquecer(href){
    try{
      var u = new URL(href, location.href);
      if(!CHECKOUTS.test(u.host + u.pathname)) return href;
      // Valor que o proprio site cravou no link e que NAO e informacao: a pagina
      // do apostilai.ai sai com utm_source=organic fixo em todo botao de compra,
      // e era isso que fazia venda de anuncio chegar na Utmify como organica.
      // Se a gente sabe de onde a pessoa veio, isso ganha do padrao do site.
      var VAZIO = /^(|organic|organico|orgânico|direct|direto|none|null|undefined|nao-informado|n\\/a)$/i;
      // First-touch vence, ponto. Foi por ser conservador demais aqui que o
      // utm_content do anuncio chegou no checkout como "link_in_bio::...": o
      // link da bio tem utm propria, o script da pagina faz last-touch e
      // sobrescreve, e eu so preenchia campo vazio. Se a pessoa veio de um
      // anuncio, o anuncio e a origem — mesmo que ela tenha passado por outro
      // lugar no meio. E o que "first-touch" quer dizer.
      var MANDA = ['utm_campaign','utm_content','utm_term','utm_id','utm_medium','fbclid','gclid','ttclid'];
      LEVAR.forEach(function(k){
        if(!primeiro[k]) return;
        var atual = (u.searchParams.get(k) || '').trim();
        var ehLixo = VAZIO.test(atual) || /^\\{\\{.*\\}\\}$/.test(atual);
        // utm_source fica de fora do atropelo: a pagina cola o id do lead nele
        // (ig + id) e sobrescrever quebraria o rastreio deles.
        if(ehLixo || MANDA.indexOf(k) >= 0){
          if(atual && !ehLixo && atual !== primeiro[k]){
            // nao joga fora o que estava la — guarda pra conferencia
            u.searchParams.set('tmx_ult_' + k.replace(/^utm_/, ''), atual.slice(0, 120));
          }
          u.searchParams.set(k, primeiro[k]);
        }
      });
      if(!u.searchParams.get('tmx_vid')) u.searchParams.set('tmx_vid', id);
      // ── O gateway so devolve o que ele conhece ──────────────────────────
      // tmx_vid chega na Payt e MORRE ali: no postback ela repassa utm_*, src e
      // sck, e descarta parametro inventado por terceiro. Sem isso a venda
      // chega sem dono e nao da pra dizer de que pagina ou variante veio.
      // 'sck' e o campo que Payt, Kiwify, Hotmart e Monetizze repassam.
      var sck = (u.searchParams.get('sck') || '').trim();
      if(!/tmx_[a-z0-9]/i.test(sck)){
        // nao joga fora o que a pagina ja pos ali — anexa depois de um til
        u.searchParams.set('sck', (sck && !VAZIO.test(sck) ? sck + '~' : '') + 'tmx_' + id);
      }
      return u.toString();
    }catch(e){ return href; }
  }

  // Reescreve os links de checkout ASSIM QUE A PAGINA CARREGA, nao no clique.
  //
  // Esperar o clique so funciona quando o botao e um <a> e quando o codigo da
  // pagina le o href DEPOIS de mim. Se o botao for um <button> com handler
  // proprio, ou se a pagina navegar com location.href = ... (que nao da pra
  // interceptar — a propriedade nao e configuravel), o conserto nunca acontecia.
  // Deixando o href ja corrigido no DOM, qualquer codigo que o leia pega a
  // versao certa, independente de como a navegacao acontece.
  var MARCA = 'data-tmx-ok';
  function arrumarLinks(raiz){
    var as;
    try{ as = (raiz || d).querySelectorAll ? (raiz || d).querySelectorAll('a[href]') : []; }
    catch(e){ return; }
    for(var i=0;i<as.length;i++){
      var a = as[i];
      var atual = a.getAttribute('href') || '';
      if(!atual) continue;
      if(a.getAttribute(MARCA) === atual) continue;   // ja arrumado, e ninguem mexeu depois
      var novo = enriquecer(atual);
      if(novo && novo !== atual){
        a.setAttribute('href', novo);
        a.setAttribute(MARCA, novo);                  // guarda pra nao entrar em loop
      } else {
        a.setAttribute(MARCA, atual);
      }
    }
  }
  arrumarLinks(d);
  if(d.readyState === 'loading') d.addEventListener('DOMContentLoaded', function(){ arrumarLinks(d); });
  w.addEventListener('load', function(){ arrumarLinks(d); });

  // O script da pagina reescreve esses mesmos links depois de carregar. Sem
  // observar, a versao dela venceria a nossa por ser a ultima a escrever.
  try{
    if(w.MutationObserver){
      var obs = new w.MutationObserver(function(muts){
        var mexeu = false;
        for(var i=0;i<muts.length && !mexeu;i++){
          var m = muts[i];
          if(m.type === 'attributes' || (m.addedNodes && m.addedNodes.length)) mexeu = true;
        }
        if(mexeu) arrumarLinks(d);
      });
      obs.observe(d.documentElement, { childList:true, subtree:true,
                                       attributes:true, attributeFilter:['href'] });
    }
  }catch(e){}

  // Rede de seguranca: se algo escapou, corrige no clique — antes de qualquer
  // handler da pagina, porque esta na fase de captura.
  // "Abriu o checkout" sai sozinho do clique no botao de compra: o checkout e
  // do gateway e o nosso codigo nao entra la, mas o clique acontece aqui.
  // Uma vez por pagina; o servidor tambem so conta uma por visita.
  var foiCheckout = false;
  function marcaCheckout(href, rot){
    if(foiCheckout) return;
    try{
      var u = new URL(href, location.href);
      if(!CHECKOUTS.test(u.host + u.pathname)) return;
      foiCheckout = true;
      manda('checkout', { rotulo: String(rot || '').slice(0, 70), destino: u.host });
    }catch(e){}
  }
  d.addEventListener('click', function(ev){
    var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    if(!a) return;
    var novo = enriquecer(a.getAttribute('href') || a.href);
    if(novo && novo !== a.href){ a.href = novo; a.setAttribute(MARCA, novo); }
    marcaCheckout(a.href, rotuloDe(a));
  }, true);

  // Botao que navega por JS (player de VSL costuma fazer isso) nao passa pelo
  // <a>, entao os dois caminhos de navegacao tambem sao cobertos.
  try{
    var _assign = w.location.assign.bind(w.location);
    w.location.assign = function(u){ marcaCheckout(String(u), 'botão'); return _assign(enriquecer(String(u))); };
    var _replace = w.location.replace.bind(w.location);
    w.location.replace = function(u){ marcaCheckout(String(u), 'botão'); return _replace(enriquecer(String(u))); };
  }catch(e){}
  try{
    var _open = w.open;
    w.open = function(u){
      var args = Array.prototype.slice.call(arguments);
      if(u){ marcaCheckout(String(u), 'botão'); args[0] = enriquecer(String(u)); }
      return _open.apply(w, args);
    };
  }catch(e){}

  w.TMXBotao = function(seletor, etapa){
    d.addEventListener('click', function(ev){
      var alvo = ev.target && ev.target.closest ? ev.target.closest(seletor) : null;
      if(alvo) manda('entrou', { etapa: etapa });
    }, true);
  };
})(window, document);`;

app.get('/px.js', (req, res) => {
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.set('Access-Control-Allow-Origin', '*');
  // 5min. Era 1h, e durante um ajuste de atribuicao isso significou testar o
  // conserto contra uma copia velha em cache e nao entender por que nao pegava.
  // 5min ainda poupa o download a cada acesso e deixa o conserto chegar rapido.
  res.set('Cache-Control', 'public, max-age=300');
  res.set('X-TMX-Versao', TMX_VERSAO);
  // sem isto o cabecalho existe mas o navegador esconde de quem le de outro
  // dominio — e o diagnostico de cache nao serviria pra nada
  res.set('Access-Control-Expose-Headers', 'X-TMX-Versao');
  res.send(PIXEL_JS);
});

// ── Redirecionador: divide o trafego entre destinos por peso ──
app.get('/r/:slug', (req, res) => {
  try {
    const slug = String(req.params.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
    const db = readDB();
    const lista = Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : [];
    const r = lista.find(x => String(x.slug || '').toLowerCase() === slug && x.ativo !== false);
    if (!r || !Array.isArray(r.destinos) || !r.destinos.length) {
      return res.status(404).send('Link não encontrado.');
    }
    // Quem ja foi sorteado antes recebe a MESMA variante. Sortear de novo a cada
    // acesso deixa a mesma pessoa ver as duas paginas — ela compara, e o
    // comportamento dela entra na conta da variante errada. Um teste em que o
    // sujeito ve os dois lados nao mede o que diz medir.
    const bisc = String(req.headers.cookie || '')
      .split(';').map(c => c.trim()).find(c => c.startsWith('tmx_ab_' + slug + '='));
    const jaFoi = bisc ? decodeURIComponent(bisc.split('=')[1] || '') : '';
    let escolhido = jaFoi ? r.destinos.find((d, i) => String(d.id || ('v' + i)) === jaFoi) : null;
    // teste encerrado com vencedora: todo mundo vai pra ela, inclusive quem ja
    // tinha caido na outra — o anuncio continua com o mesmo link
    if (r.vencedora) {
      const v = r.destinos.find((d, i) => String(d.id || ('v' + i)) === String(r.vencedora));
      if (v) escolhido = v;
    }
    const repetido = !!escolhido;

    if (!escolhido) {
      const total = r.destinos.reduce((s, d) => s + (Number(d.peso) || 1), 0);
      let x = Math.random() * total;
      escolhido = r.destinos[0];
      for (const d of r.destinos) { x -= (Number(d.peso) || 1); if (x <= 0) { escolhido = d; break; } }
    }
    // Cada destino precisa de um id estavel: sem ele nao da pra dizer quem levou
    // qual depois. Slug de link antigo nao tem, entao cai na posicao.
    const vid = String(escolhido.id || ('v' + r.destinos.indexOf(escolhido)));
    // 90 dias, igual ao tmx_id — teste que dura semanas nao pode perder a
    // atribuicao no meio do caminho
    if (!repetido) {
      res.setHeader('Set-Cookie',
        'tmx_ab_' + slug + '=' + encodeURIComponent(vid) +
        ';Path=/;Max-Age=7776000;SameSite=Lax' +
        (req.headers['x-forwarded-proto'] === 'https' ? ';Secure' : ''));
    }

    let destino = String(escolhido.url || '');
    const qs = req.originalUrl.split('?')[1];
    // repassa a query (utm_*) pro destino, senao o rastreamento se perde aqui
    if (qs) destino += (destino.includes('?') ? '&' : '?') + qs;
    // A variante viaja na URL, nao em cookie: o cookie seria de app.centraltmx.com
    // e a pagina de destino e outro dominio — nunca chegaria la.
    destino += (destino.includes('?') ? '&' : '?') +
               'tmx_t=' + encodeURIComponent(slug) + '&tmx_v=' + encodeURIComponent(vid);

    _fContar('redir:' + slug, escolhido.url, 'entrou', null, null);
    _abContar(slug, vid, 'sorteio');      // denominador do teste
    res.redirect(302, destino);
  } catch (e) { res.status(500).send('Erro no redirecionamento.'); }
});

// ══════════════════════════════════════════════════════
// ── QUIZ DE FUNIL ──
// O quiz é montado no Central TMX (sl_quizzes, sincronizado) e servido aqui em
// /q/:slug. Quem desenha as telas é public/quiz-motor.js, o MESMO arquivo da
// prévia no painel — se fossem dois códigos, a prévia mostraria uma coisa e o
// anúncio outra. Aqui ficam a página pública, os eventos de cada visitante, as
// imagens, e a conta de onde abandonam e qual resposta compra mais.
// ══════════════════════════════════════════════════════
const KEY_QUIZZES   = 'sl_quizzes';

// ══════════════════════════════════════════════════════
// ── DOMÍNIOS ──
// Testes A/B e Quiz guardavam dominio cada um no seu campo de texto livre, sem
// saber um do outro. O Quiz nem validava: 'editalhackeado', sem .com, virou o
// link https://editalhackeado/q/... que nao abre em lugar nenhum.
// Aqui fica a lista unica — o que ja esta em uso nos testes e quizzes, mais o
// que for cadastrado — e a checagem de que o DNS aponta mesmo pra ca.
// ══════════════════════════════════════════════════════
const KEY_DOMINIOS = 'sl_dominios';
const DOMINIO_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

function _dominioLimpo(v) {
  return String(v || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
}

// Todos os dominios conhecidos, e onde cada um esta sendo usado.
function _dominiosConhecidos(db) {
  const mapa = {};
  const add = (d, origem, nome) => {
    d = _dominioLimpo(d);
    if (!d || !DOMINIO_RE.test(d)) return;
    mapa[d] = mapa[d] || { dominio: d, usos: [], cadastrado: false };
    if (origem) mapa[d].usos.push({ origem, nome: String(nome || '').slice(0, 60) });
  };
  (Array.isArray(db.store[KEY_DOMINIOS]) ? db.store[KEY_DOMINIOS] : []).forEach(x => {
    add(x.dominio);
    const k = _dominioLimpo(x.dominio);
    if (mapa[k]) { mapa[k].cadastrado = true; mapa[k].checado = x.checado; mapa[k].ok = x.ok; mapa[k].erro = x.erro; }
  });
  (Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : [])
    .forEach(r => r && r.dominio && add(r.dominio, 'Teste A/B', r.nome || r.slug));
  (Array.isArray(db.store[KEY_QUIZZES]) ? db.store[KEY_QUIZZES] : [])
    .forEach(q => q && q.dominio && add(q.dominio, 'Quiz', q.nome || q.slug));
  return Object.values(mapa).sort((a, b) => a.dominio.localeCompare(b.dominio));
}

// Pergunta pro proprio dominio qual versao ele serve. Se bater com a nossa, o
// DNS esta apontando pra ca — nao basta resolver, tem de cair NESTE servidor.
// Um dominio que resolve pra outro lugar passaria num teste de DNS simples e
// mesmo assim o link quebraria.
async function _checarDominio(dominio) {
  const d = _dominioLimpo(dominio);
  if (!DOMINIO_RE.test(d)) return { ok: false, erro: 'endereço inválido' };
  const corta = new AbortController();
  const t = setTimeout(() => corta.abort(), 6000);
  try {
    const r = await fetch('https://' + d + '/api/versao', { signal: corta.signal, redirect: 'manual' });
    if (!r.ok) return { ok: false, erro: 'respondeu ' + r.status + ' — o DNS aponta pra outro servidor' };
    const j = await r.json().catch(() => null);
    if (!j || j.versao !== versaoApp()) return { ok: false, erro: 'aponta pra outro servidor, não pro Central TMX' };
    return { ok: true };
  } catch (e) {
    const m = e.name === 'AbortError' ? 'não respondeu em 6s'
      : /ENOTFOUND|getaddrinfo/i.test(e.message) ? 'o DNS ainda não existe'
      : /certificate|SSL|TLS/i.test(e.message) ? 'sem certificado HTTPS ainda — o Railway leva alguns minutos'
      : e.message;
    return { ok: false, erro: m };
  } finally { clearTimeout(t); }
}

app.get('/api/dominios', authUsuario, (req, res) => {
  try { res.json({ ok: true, proprio: req.headers.host || '', dominios: _dominiosConhecidos(readDB()) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Cadastra e ja checa. Cadastrar sem checar deixava o usuario descobrir que o
// DNS nao aponta so quando o anuncio ja estivesse rodando.
app.post('/api/dominios', authUsuario, async (req, res) => {
  try {
    const d = _dominioLimpo(req.body && req.body.dominio);
    if (!DOMINIO_RE.test(d)) {
      return res.status(400).json({ error: 'Isso não é um domínio. Use algo como ir.seudominio.com.br — com o ponto e a terminação.' });
    }
    const chk = await _checarDominio(d);
    const db = readDB();
    const l = Array.isArray(db.store[KEY_DOMINIOS]) ? db.store[KEY_DOMINIOS] : [];
    const i = l.findIndex(x => _dominioLimpo(x.dominio) === d);
    const reg = { dominio: d, checado: new Date().toISOString(), ok: chk.ok, erro: chk.erro || '',
                  porQuem: (req.user && req.user.nome) || '' };
    if (i >= 0) l[i] = Object.assign(l[i], reg); else l.push(reg);
    db.store[KEY_DOMINIOS] = l;
    db.timestamps[KEY_DOMINIOS] = now();
    audit(db, 'dominio_cadastrado', { dominio: d }, chk.ok ? 'apontado' : ('pendente: ' + chk.erro), req.user);
    writeDB(db);
    res.json(Object.assign({ ok: true, dominio: d }, { apontado: chk.ok, erro: chk.erro || '' }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Rechecar um que ja existe — o DNS leva de minutos a horas pra propagar.
app.post('/api/dominios/checar', authUsuario, async (req, res) => {
  try {
    const d = _dominioLimpo(req.body && req.body.dominio);
    const chk = await _checarDominio(d);
    const db = readDB();
    const l = Array.isArray(db.store[KEY_DOMINIOS]) ? db.store[KEY_DOMINIOS] : [];
    const i = l.findIndex(x => _dominioLimpo(x.dominio) === d);
    const reg = { dominio: d, checado: new Date().toISOString(), ok: chk.ok, erro: chk.erro || '' };
    if (i >= 0) l[i] = Object.assign(l[i], reg); else l.push(reg);
    db.store[KEY_DOMINIOS] = l;
    db.timestamps[KEY_DOMINIOS] = now();
    writeDB(db);
    res.json({ ok: true, dominio: d, apontado: chk.ok, erro: chk.erro || '' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
const KEY_QUIZ_RESP = 'sl_quiz_resp';   // uma linha por visitante por dia: o caminho dele no quiz
const KEY_QUIZ_DIA  = 'sl_quiz_dia';    // contagem agregada por quiz por dia (sobrevive ao teto das linhas)
const QUIZ_RESP_TETO = 12000, QUIZ_RESP_DIAS = 30, QUIZ_DIA_DIAS = 180;
const QUIZ_IMG_DIR = path.join(DATA_DIR, 'quiz_img');
try { if (!fs.existsSync(QUIZ_IMG_DIR)) fs.mkdirSync(QUIZ_IMG_DIR, { recursive: true }); } catch (e) {}

// readDB lê e parseia o banco inteiro. A página do quiz recebe tráfego pago:
// ler o banco por visitante derrubaria o servidor num pico de campanha. Os
// quizzes ficam num cache de 5s — editar no painel aparece em segundos.
let _qzCache = { em: 0, porSlug: {}, porId: {} };
function _qzQuizzes(forcar) {
  if (!forcar && Date.now() - _qzCache.em < 5000) return _qzCache;
  try {
    const db = readDB();
    const porSlug = {}, porId = {};
    (Array.isArray(db.store[KEY_QUIZZES]) ? db.store[KEY_QUIZZES] : []).forEach(q => {
      if (!q || !q.id) return;
      porId[q.id] = q;
      if (q.slug) porSlug[String(q.slug).toLowerCase()] = q;
    });
    _qzCache = { em: Date.now(), porSlug, porId };
  } catch (e) { /* banco ilegível agora: segue com o cache anterior */ }
  return _qzCache;
}

let _qzResp = new Map();    // "quiz|vid|dia" -> registro
let _qzDia = {};            // "quiz|dia"     -> agregado
let _qzPorVid = new Map();  // vid -> Set(chave), pra ligar o id que a VSL usa
let _qzSujo = false;

function _qzIndexar(vid, k) {
  if (!_qzPorVid.has(vid)) _qzPorVid.set(vid, new Set());
  _qzPorVid.get(vid).add(k);
}
function _qzCarregar() {
  try {
    const db = readDB();
    (Array.isArray(db.store[KEY_QUIZ_RESP]) ? db.store[KEY_QUIZ_RESP] : []).forEach(r => {
      if (!r || !r.q || !r.v || !r.d) return;
      const k = r.q + '|' + r.v + '|' + r.d;
      _qzResp.set(k, r); _qzIndexar(r.v, k);
    });
    (Array.isArray(db.store[KEY_QUIZ_DIA]) ? db.store[KEY_QUIZ_DIA] : []).forEach(a => {
      if (a && a.q && a.d) _qzDia[a.q + '|' + a.d] = a;
    });
    if (_qzResp.size) console.log('[QUIZ] ' + _qzResp.size + ' respostas recuperadas do disco.');
  } catch (e) { console.error('[QUIZ] não consegui recuperar as respostas:', e.message); }
}
function _qzAgregado(q, d) {
  const k = q + '|' + d;
  return _qzDia[k] || (_qzDia[k] = { q, d, ab: 0, tel: {}, resp: {}, num: {}, perf: {}, fim: 0, cl: 0 });
}

// Cada evento mexe no registro do visitante E no agregado do dia. O registro é
// o que impede contar duas vezes: quem recarrega a tela não soma de novo, e
// quem volta e troca a resposta tira a antiga da conta antes de somar a nova.
function _qzEvento(ev) {
  const q = String(ev.q || '').slice(0, 60), v = String(ev.v || '').slice(0, 40), e = String(ev.e || '');
  if (!q || !v || !/^[a-z0-9_-]+$/i.test(v)) return false;
  if (!_qzQuizzes().porId[q]) return false;          // evento de quiz que não existe não entra
  const d = _hojeBR(), k = q + '|' + v + '|' + d, ag = _qzAgregado(q, d);
  let r = _qzResp.get(k);
  if (!r) {
    const u = (ev.u && typeof ev.u === 'object') ? ev.u : {};
    r = { q, v, d, em: Date.now(), at: Date.now(), tel: [], r: {}, p: '', fim: 0, cl: 0, vd: '',
          u: { s: String(u.utm_source || '').slice(0, 60), c: String(u.utm_campaign || '').slice(0, 80), ct: String(u.utm_content || '').slice(0, 80) } };
    _qzResp.set(k, r); _qzIndexar(v, k);
    ag.ab++;
    // teto de memória: um ataque com milhares de ids falsos não pode crescer sem fim
    if (_qzResp.size > QUIZ_RESP_TETO * 1.5) _qzPodar();
  }
  r.at = Date.now();
  if (e === 'tela') {
    const t = String(ev.t || '').slice(0, 40);
    if (t && r.tel.indexOf(t) < 0 && r.tel.length < 80) { r.tel.push(t); ag.tel[t] = (ag.tel[t] || 0) + 1; }
  }
  if (e === 'resp') {
    const b = String(ev.b || '').slice(0, 40);
    if (b) {
      const antes = r.r[b];
      if (Array.isArray(ev.ops)) {
        const ops = ev.ops.map(x => String(x).slice(0, 40)).slice(0, 20);
        const m = ag.resp[b] = ag.resp[b] || {};
        if (Array.isArray(antes)) antes.forEach(o => { if (m[o] > 0) m[o]--; });
        ops.forEach(o => { m[o] = (m[o] || 0) + 1; });
        r.r[b] = ops;
      } else if (ev.valor != null && isFinite(Number(ev.valor))) {
        const val = Math.round(Number(ev.valor) * 100) / 100;
        const m = ag.num[b] = ag.num[b] || {};
        if (antes != null && !Array.isArray(antes) && m[String(antes)] > 0) m[String(antes)]--;
        m[String(val)] = (m[String(val)] || 0) + 1;
        r.r[b] = val;
      }
    }
  }
  if (e === 'fim' && !r.fim) {
    r.fim = 1; ag.fim++;
    const p = String(ev.p || '').slice(0, 40);
    if (p) { r.p = p; ag.perf[p] = (ag.perf[p] || 0) + 1; }
  }
  if (e === 'clique' && !r.cl) {
    r.cl = 1; ag.cl++;
    if (ev.p && !r.p) r.p = String(ev.p).slice(0, 40);
  }
  _qzSujo = true;
  return true;
}

// O quiz fica no domínio do app e a VSL no da oferta: o pixel de lá cria outro
// id, e a venda chega com ESSE id. O quiz manda o dele na URL (tmx_qid), o pixel
// devolve em todo evento, e aqui a gente anota: este visitante do quiz é aquele
// da VSL. É o que faz "qual resposta compra mais" ter resposta.
function _qzLigarDestino(qid, visitante) {
  if (!qid || !visitante || qid === visitante) return;
  const ks = _qzPorVid.get(String(qid)); if (!ks) return;
  ks.forEach(k => {
    const r = _qzResp.get(k);
    if (r && r.vd !== visitante) { r.vd = String(visitante).slice(0, 40); _qzSujo = true; }
  });
}

function _qzPodar() {
  const corte = new Date(Date.now() - QUIZ_RESP_DIAS * 86400000).toISOString().slice(0, 10);
  let lista = Array.from(_qzResp.values()).filter(r => r.d >= corte).sort((a, b) => b.at - a.at);
  if (lista.length > QUIZ_RESP_TETO) lista = lista.slice(0, QUIZ_RESP_TETO);
  _qzResp = new Map(); _qzPorVid = new Map();
  lista.forEach(r => { const k = r.q + '|' + r.v + '|' + r.d; _qzResp.set(k, r); _qzIndexar(r.v, k); });
  const corteDia = new Date(Date.now() - QUIZ_DIA_DIAS * 86400000).toISOString().slice(0, 10);
  Object.keys(_qzDia).forEach(k => { if (_qzDia[k].d < corteDia) delete _qzDia[k]; });
  return lista;
}
function _qzGravar() {
  if (!_qzSujo) return;
  _qzSujo = false;
  try {
    const lista = _qzPodar();
    const db = readDB();
    db.store[KEY_QUIZ_RESP] = lista;
    db.store[KEY_QUIZ_DIA] = Object.values(_qzDia);
    db.timestamps[KEY_QUIZ_RESP] = now();
    db.timestamps[KEY_QUIZ_DIA] = now();
    writeDB(db);
  } catch (e) { _qzSujo = true; console.error('[QUIZ] falhou ao gravar:', e.message); }
}
setInterval(_qzGravar, 45 * 1000);
_qzCarregar();

// ── eventos do visitante ──
app.post('/api/quiz/evento', express.text({ type: '*/*', limit: '8kb' }), (req, res) => {
  try {
    let ev = req.body;
    if (typeof ev === 'string') { try { ev = JSON.parse(ev); } catch (e) { ev = null; } }
    if (ev && typeof ev === 'object') _qzEvento(ev);
  } catch (e) {}
  res.sendStatus(204);
});

// ── imagens do quiz ──
// Ficam no volume, fora do db.json (imagem em base64 no banco foi o que já
// inchou o disco uma vez). Servidas sem ler o banco: o nome do arquivo já diz
// o tipo, e o id aleatório não dá pra adivinhar.
const QUIZ_IMG_TIPOS = { 'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
app.post('/api/quiz/imagem', authUsuario, express.raw({ type: () => true, limit: '6mb' }), (req, res) => {
  try {
    const buf = req.body;
    if (!Buffer.isBuffer(buf) || !buf.length) return res.status(400).json({ error: 'Arquivo vazio.' });
    const mime = String(req.headers['x-mime'] || req.headers['content-type'] || '').toLowerCase().split(';')[0].trim();
    const ext = QUIZ_IMG_TIPOS[mime];
    if (!ext) return res.status(400).json({ error: 'Envie a imagem em JPG, PNG, WEBP ou GIF.' });
    // A imagem só pode entrar se, depois dela, ainda couber regravar o db.json
    // (a mesma folga de 3x que o writeDB pede) com margem. O corte fixo de 150 MB
    // barrava imagem de 200 KB num volume de 433 MB com 140 MB livres e 27 MB de banco.
    const livre = _espacoLivreMB(DATA_DIR);
    let dbMB = 0; try { dbMB = fs.statSync(DB_FILE).size / (1024 * 1024); } catch (e) {}
    const precisa = buf.length / (1024 * 1024) + Math.max(60, Math.ceil(dbMB) * 3) + 10;
    if (livre != null && livre < precisa) {
      return res.status(507).json({ error: 'O disco do servidor está quase cheio (' + Math.round(livre) + ' MB livres). Use o link de uma imagem hospedada em outro lugar por enquanto.' });
    }
    const arquivo = 'qi' + Date.now().toString(36) + crypto.randomBytes(6).toString('hex') + '.' + ext;
    fs.writeFileSync(path.join(QUIZ_IMG_DIR, arquivo), buf);
    res.json({ ok: true, url: '/qi/' + arquivo, tamanho: buf.length });
  } catch (e) { res.status(500).json({ error: 'Não consegui salvar a imagem.' }); }
});
app.get('/qi/:arquivo', (req, res) => {
  const a = String(req.params.arquivo || '');
  if (!/^qi[a-z0-9]+\.(jpg|png|webp|gif)$/.test(a)) return res.status(404).end();
  const fp = path.join(QUIZ_IMG_DIR, a);
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Content-Type', { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif' }[a.split('.').pop()]);
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  // o editor do quiz lê o peso da imagem por aqui (HEAD), sem baixar ela de novo
  try { res.setHeader('Content-Length', fs.statSync(fp).size); } catch (e) {}
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(fp).on('error', () => { try { res.status(500).end(); } catch (e) {} }).pipe(res);
});

// ── a página pública ──
function _qzEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function _qzConcluiramSemana(id) {
  const corte = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
  let n = 0;
  Object.values(_qzDia).forEach(a => { if (a.q === id && a.d >= corte) n += a.fim || 0; });
  return n;
}
// Link do último botão que abre link: é pra onde vai quem chega num quiz pausado
function _qzDestinoFinal(q) {
  let url = '';
  (q.telas || []).forEach(t => (t.blocos || []).forEach(b => {
    if (b && b.tipo === 'botao' && b.acao === 'link') {
      const u = b.porPerfil ? ((q.perfis || [])[0] || {}).url : b.url;
      if (u) url = String(u).trim();
    }
  }));
  if (url && !/^https?:\/\//i.test(url)) url = 'https://' + url;
  return url;
}
function _qzPagina404() {
  return '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>Página indisponível</title><meta name="robots" content="noindex"><style>body{margin:0;min-height:100vh;display:grid;place-items:center;' +
    'font-family:system-ui,-apple-system,sans-serif;background:#F4F6FA;color:#0F172A;padding:24px;text-align:center}p{color:#475569;max-width:32ch;margin:8px auto 0}</style></head>' +
    '<body><div><h1 style="font-size:22px;margin:0">Esta página não está disponível</h1><p>O link pode ter mudado. Volte ao anúncio e tente de novo.</p></div></body></html>';
}

app.get('/q/:slug', (req, res) => {
  try {
    const slug = String(req.params.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 80);
    const q = _qzQuizzes().porSlug[slug];
    res.set('Cache-Control', 'no-store');
    if (!q) return res.status(404).send(_qzPagina404());

    // Pausado: quem clicou no anúncio vai direto pra oferta, nunca pra página morta
    if (q.ativo === false) {
      const dest = _qzDestinoFinal(q);
      if (!dest) return res.status(404).send(_qzPagina404());
      const qs = req.originalUrl.split('?')[1];
      return res.redirect(302, dest + (qs ? (dest.includes('?') ? '&' : '?') + qs : ''));
    }

    const publico = { id: q.id, slug: q.slug, nome: q.nome, tema: q.tema || {}, telas: q.telas || [], perfis: q.perfis || [] };
    const dados = JSON.stringify(publico).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
    const fundo = /^#[0-9a-f]{3,6}$/i.test(String((q.tema || {}).fundo || '')) ? q.tema.fundo : '#FFFFFF';
    const px = q.pixels || {};
    const meta = /^\d{6,20}$/.test(String(px.meta || '').trim()) ? String(px.meta).trim() : '';
    const tiktok = /^[A-Z0-9]{10,30}$/i.test(String(px.tiktok || '').trim()) ? String(px.tiktok).trim() : '';
    const funil = (q.mapa && q.mapa.funil) ? q.mapa : null;

    const scriptMeta = meta ? ('<script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};' +
      'if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version="2.0";n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];' +
      's.parentNode.insertBefore(t,s)}(window,document,"script","https://connect.facebook.net/en_US/fbevents.js");fbq("init","' + meta + '");fbq("track","PageView");</script>') : '';
    const scriptTiktok = tiktok ? ('<script>!function(w,d,t){w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie"],' +
      'ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);' +
      'ttq.instance=function(t){for(var e=ttq._i[t]||[],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e};ttq.load=function(e,n){var i="https://analytics.tiktok.com/i18n/pixel/events.js";' +
      'ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=i,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};var o=document.createElement("script");o.type="text/javascript",o.async=!0,o.src=i+"?sdkid="+e+"&lib="+t;' +
      'var a=document.getElementsByTagName("script")[0];a.parentNode.insertBefore(o,a)};ttq.load("' + tiktok + '");ttq.page()}(window,document,"ttq");</script>') : '';

    const html = '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
      '<title>' + _qzEsc(q.titulo || q.nome || 'Quiz') + '</title><meta name="robots" content="noindex,nofollow">' +
      '<meta name="theme-color" content="' + fundo + '">' +
      '<style>html,body{margin:0;background:' + fundo + '}#qz{min-height:100vh;min-height:100dvh}</style>' +
      scriptMeta + scriptTiktok + '</head><body><div id="qz"></div>' +
      '<script src="/quiz-motor.js?v=' + TMX_VERSAO + '"></script>' +
      '<script>(function(){var Q=' + dados + ';' +
        'var vid=(document.cookie.match(/(?:^|;\\s*)tmx_id=([^;]+)/)||[])[1];' +
        'if(!vid||!/^[a-z0-9_-]+$/i.test(vid)){vid="v"+Date.now().toString(36)+Math.random().toString(36).slice(2,8);' +
        'document.cookie="tmx_id="+vid+";path=/;max-age=7776000;SameSite=Lax"+(location.protocol==="https:"?";Secure":"");}' +
        'var U={};new URLSearchParams(location.search).forEach(function(v,k){if(/^utm_/.test(k))U[k]=v.slice(0,120);});' +
        'function envia(tipo,d){var c=JSON.stringify(Object.assign({q:Q.id,v:vid,e:tipo,u:U},d||{}));' +
          'try{if(!(navigator.sendBeacon&&navigator.sendBeacon("/api/quiz/evento",new Blob([c],{type:"text/plain"}))))' +
          'fetch("/api/quiz/evento",{method:"POST",body:c,keepalive:true,headers:{"Content-Type":"text/plain"}});}catch(e){}' +
          'try{if(window.fbq){if(tipo==="tela")fbq("trackCustom","QuizTela",{quiz:Q.slug,tela:(d.i||0)+1});' +
          'if(tipo==="fim")fbq("trackCustom","QuizConcluido",{quiz:Q.slug,perfil:d.p||""});' +
          'if(tipo==="clique")fbq("trackCustom","QuizFoiParaOferta",{quiz:Q.slug});}' +
          'if(window.ttq){if(tipo==="fim")ttq.track("CompleteRegistration");if(tipo==="clique")ttq.track("ClickButton");}}catch(e){}}' +
        'QuizMotor.montar(document.getElementById("qz"),Q,{modo:"vivo",vid:vid,n:' + _qzConcluiramSemana(q.id) + ',parametros:location.search.slice(1),enviar:envia});' +
      '})();</script>' +
      (funil ? '<script src="/px.js" data-f="' + _qzEsc(funil.funil) + '" data-e="' + _qzEsc(funil.etapa || '') + '" async></script>' : '') +
      '</body></html>';
    res.type('html').send(html);
  } catch (e) {
    console.error('[QUIZ] página falhou:', e.message);
    res.status(500).send(_qzPagina404());
  }
});

// ── números pro painel ──
// Mesma ideia do funil: a conta do quiz mora aqui, e tanto a tela quanto o MCP
// chamam esta funcao. Uma pergunta, uma resposta.
function _quizStats(id, de, ate) {
    let q = _qzQuizzes().porId[id];
    if (!q) q = _qzQuizzes(true).porId[id];     // acabou de ser criado: o cache ainda não viu
    if (!q) return { ok: false, erro: 'Quiz não encontrado.' };
    const noPeriodo = d => (!de || d >= de) && (!ate || d <= ate);

    const tot = { ab: 0, fim: 0, cl: 0, tel: {}, resp: {}, num: {}, perf: {} };
    const somar = (dst, src) => Object.keys(src || {}).forEach(k => { dst[k] = (dst[k] || 0) + (src[k] || 0); });
    Object.values(_qzDia).forEach(a => {
      if (a.q !== id || !noPeriodo(a.d)) return;
      tot.ab += a.ab || 0; tot.fim += a.fim || 0; tot.cl += a.cl || 0;
      somar(tot.tel, a.tel); somar(tot.perf, a.perf);
      Object.keys(a.resp || {}).forEach(b => { somar(tot.resp[b] = tot.resp[b] || {}, a.resp[b]); });
      Object.keys(a.num || {}).forEach(b => { somar(tot.num[b] = tot.num[b] || {}, a.num[b]); });
    });

    // Venda entra pela mesma regra do teste A/B: toda venda com id de visitante no período
    const db = readDB();
    const compra = {};
    (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : []).forEach(v => {
      if (!v || !v.vid || !_vendaPaga(v)) return;
      const dia = String(v.recebidoEm || '').slice(0, 10);
      if (dia && !noPeriodo(dia)) return;
      const c = compra[v.vid] = compra[v.vid] || { n: 0, valor: 0, cliente: '' };
      c.n++; c.valor += Number(v.valor) || 0;
      if (!c.cliente && v.cliente) c.cliente = String(v.cliente).slice(0, 60);
    });
    const regs = [];
    _qzResp.forEach(r => { if (r.q === id && noPeriodo(r.d)) regs.push(r); });
    const comprou = r => compra[r.v] || (r.vd ? compra[r.vd] : null) || null;

    let compraram = 0, receita = 0, ligados = 0;
    const porOp = {}, porPerfil = {};
    regs.forEach(r => {
      const c = comprou(r);
      if (r.vd) ligados++;
      if (c) { compraram++; receita += c.valor; }
      Object.keys(r.r || {}).forEach(b => {
        const val = r.r[b];
        if (!Array.isArray(val)) return;
        val.forEach(o => {
          const x = porOp[b + '|' + o] = porOp[b + '|' + o] || { base: 0, compras: 0, receita: 0, cliques: 0 };
          x.base++; if (r.cl) x.cliques++; if (c) { x.compras++; x.receita += c.valor; }
        });
      });
      if (r.p) {
        const x = porPerfil[r.p] = porPerfil[r.p] || { base: 0, cliques: 0, compras: 0, receita: 0 };
        x.base++; if (r.cl) x.cliques++; if (c) { x.compras++; x.receita += c.valor; }
      }
    });

    const telas = [], opcoes = [], numeros = [];
    (q.telas || []).forEach((t, i) => {
      telas.push({ id: t.id, nome: t.nome || ('Tela ' + (i + 1)), chegaram: tot.tel[t.id] || 0 });
      (t.blocos || []).forEach(b => {
        if (b.tipo === 'opcoes') {
          const titulo = (t.blocos || []).filter(x => x.tipo === 'titulo').map(x => String(x.txt || '').replace(/\*/g, '')).pop() || t.nome;
          opcoes.push({ bloco: b.id, tela: t.id, pergunta: titulo, varias: b.modo === 'varias',
            ops: (b.ops || []).map(o => {
              const x = porOp[b.id + '|' + o.id] || { base: 0, compras: 0, receita: 0, cliques: 0 };
              return { id: o.id, t: o.t, emoji: o.emoji || '', pessoas: (tot.resp[b.id] || {})[o.id] || 0, base: x.base, compras: x.compras, receita: x.receita, cliques: x.cliques };
            }) });
        }
        if (b.tipo === 'numero') {
          const m = tot.num[b.id] || {};
          numeros.push({ bloco: b.id, tela: t.id, unidade: b.unidade || '',
            valores: Object.keys(m).map(k => [Number(k), m[k]]).filter(x => x[1] > 0).sort((a, c) => a[0] - c[0]) });
        }
      });
    });
    // ══ Depois do botao: o quiz ate a venda ══════════════════════════════════
    // O quiz passa o id do visitante pra VSL (tmx_qid) e o pixel de la devolve,
    // entao r.vd e o id DELE na jornada da VSL. Com isso da pra responder o que
    // o quiz sozinho nao responde: quantos clicaram e nao chegaram, quanto quem
    // chegou assistiu, e se abriu o checkout.
    const EH_CHECKOUT_Q = /checkout|pagamento|pay\.|carrinho|payt|kiwify|hotmart|monetizze|eduzz|cakto|ticto|kirvano|perfectpay/i;
    const tipoEtapa = {};
    (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : [])
      .forEach(f => ((f && f.etapas) || []).forEach(e => { if (e && e.id) tipoEtapa[e.id] = e.tipo; }));

    // so as jornadas que interessam: as dos visitantes deste quiz no periodo
    const quero = new Set(regs.filter(r => r.vd).map(r => String(r.vd)));
    const vsl = {};                                  // vd -> { atencao, checkout }
    if (quero.size) {
      const jn = (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
        .concat(Object.values(typeof _jBuffer === 'object' && _jBuffer ? _jBuffer : {}));
      jn.forEach(j => {
        if (!j || !quero.has(String(j.id))) return;
        const x = vsl[j.id] = vsl[j.id] || { atencao: 0, checkout: false };
        (j.eventos || []).forEach(e => {
          x.atencao = Math.max(x.atencao, Number(e.atencao) || 0);
          if (tipoEtapa[e.etapa] === 'checkout' || (e.pg && EH_CHECKOUT_Q.test(e.pg))) x.checkout = true;
        });
      });
    }
    // A jornada da VSL guarda 7 dias; a linha do quiz, 30. Quem chegou na VSL ha
    // mais de 7 dias ainda tem o vd, mas o quanto assistiu ja nao existe. Tratar
    // isso como 'assistiu 0' criaria uma queda falsa na escada — entao essa
    // pessoa sai da conta de atencao e vira um numero a parte.
    const naVsl = r => (r.vd && vsl[r.vd]) ? vsl[r.vd] : null;

    // ── a escada por etapas, toda tirada das MESMAS linhas ────────────────────
    // Misturar contagem agregada (180 dias) com linha por pessoa (30 dias) faria
    // uma etapa posterior ter mais gente que a anterior. Aqui e tudo de regs.
    const escada = [];
    (q.telas || []).forEach((t, i) => {
      escada.push({ id: t.id, nome: t.nome || ('Tela ' + (i + 1)), grupo: 'quiz',
                    n: regs.filter(r => (r.tel || []).indexOf(t.id) >= 0).length });
    });
    const clicou   = regs.filter(r => r.cl);
    const chegou   = clicou.filter(r => r.vd);
    const comDado  = chegou.filter(r => naVsl(r));            // jornada ainda guardada
    const um       = comDado.filter(r => naVsl(r).atencao >= 60);
    const cinco    = comDado.filter(r => naVsl(r).atencao >= 300);
    const checkout = comDado.filter(r => naVsl(r).checkout);
    const vslSemDetalhe = chegou.length - comDado.length;
    escada.push({ id: '_clique',   nome: 'Clicou na oferta',   grupo: 'quiz', n: clicou.length });
    escada.push({ id: '_vsl',      nome: 'Chegou na VSL',      grupo: 'vsl',  n: chegou.length, dica: 'a página carregou e o pixel viu' });
    escada.push({ id: '_1min',     nome: 'Assistiu +1 min',    grupo: 'vsl',  n: um.length,     dica: 'atenção real, aba visível' });
    escada.push({ id: '_5min',     nome: 'Assistiu +5 min',    grupo: 'vsl',  n: cinco.length,  dica: 'atenção real, aba visível' });
    escada.push({ id: '_checkout', nome: 'Abriu o checkout',   grupo: 'vsl',  n: checkout.length });
    // venda nao e aninhada no checkout: se a deteccao do checkout falhar, uma
    // venda real sumiria da escada. Melhor aparecer fora de ordem que sumir.
    escada.push({ id: '_compra',   nome: 'Comprou',            grupo: 'vsl',  n: regs.filter(r => comprou(r)).length });

    // ── tempo no quiz ─────────────────────────────────────────────────────────
    // Mediana, nao media: quem deixa a aba aberta uma hora puxaria a media pra
    // cima e o numero mentiria sobre o visitante tipico.
    const dur = r => Math.max(0, Math.round(((r.at || 0) - (r.em || 0)) / 1000));
    const tempos = regs.filter(r => r.fim).map(dur).sort((a, b) => a - b);
    const mediana = l => !l.length ? 0 : (l.length % 2 ? l[(l.length - 1) / 2] : Math.round((l[l.length/2 - 1] + l[l.length/2]) / 2));
    const faixas = [['<30s', 0, 30], ['30s–1m', 30, 60], ['1–2m', 60, 120], ['2–3m', 120, 180], ['+3m', 180, Infinity]];
    const tempo = { mediana: mediana(tempos), base: tempos.length,
      faixas: faixas.map(f => ({ rot: f[0], n: tempos.filter(x => x >= f[1] && x < f[2]).length })) };

    // ── por criativo ──────────────────────────────────────────────────────────
    const segunda = (q.telas || [])[1] ? q.telas[1].id : null;
    const porCri = {};
    regs.forEach(r => {
      const k = (r.u && r.u.ct) || '(sem criativo)';
      const x = porCri[k] = porCri[k] || { criativo: k, fonte: (r.u && r.u.s) || '', abriram: 0, comecaram: 0, concluiram: 0, clicaram: 0, vsl: 0, compraram: 0 };
      x.abriram++;
      if (segunda ? (r.tel || []).indexOf(segunda) >= 0 : (r.tel || []).length > 1) x.comecaram++;
      if (r.fim) x.concluiram++;
      if (r.cl) x.clicaram++;
      if (r.cl && r.vd) x.vsl++;
      if (comprou(r)) x.compraram++;
    });
    const criativos = Object.values(porCri).sort((a, b) => b.abriram - a.abriram).slice(0, 30);

    // ── horario (Brasilia) ────────────────────────────────────────────────────
    const horas = new Array(24).fill(0);
    regs.forEach(r => { if (r.em) horas[new Date(r.em - 3 * 3600000).getUTCHours()]++; });

    // ── cada pessoa, uma linha ────────────────────────────────────────────────
    const blocos = {};
    (q.telas || []).forEach(t => {
      const pergunta = (t.blocos || []).filter(x => x.tipo === 'titulo').map(x => String(x.txt || '').replace(/\*/g, '')).pop() || t.nome || '';
      (t.blocos || []).forEach(b => {
        if (b.tipo === 'opcoes') blocos[b.id] = { pergunta, tipo: 'opcoes', ops: Object.fromEntries((b.ops || []).map(o => [o.id, o.t])) };
        if (b.tipo === 'numero') blocos[b.id] = { pergunta, tipo: 'numero', unidade: b.unidade || '' };
      });
    });
    const nomePerfil = Object.fromEntries((q.perfis || []).map(p => [p.id, p.nome]));
    const pessoas = regs.slice().sort((a, b) => (b.em || 0) - (a.em || 0)).slice(0, 150).map(r => {
      const c = comprou(r), v = naVsl(r);
      const respostas = Object.keys(r.r || {}).map(bid => {
        const bl = blocos[bid]; if (!bl) return null;
        const val = r.r[bid];
        const txt = bl.tipo === 'opcoes'
          ? (Array.isArray(val) ? val.map(o => bl.ops[o]).filter(Boolean).join(', ') : '')
          : (val != null ? (val + (bl.unidade ? ' ' + bl.unidade : '')) : '');
        return txt ? { pergunta: String(bl.pergunta).slice(0, 70), resposta: String(txt).slice(0, 80) } : null;
      }).filter(Boolean);
      return {
        em: r.em, visitante: String(r.v).slice(0, 10),
        criativo: (r.u && r.u.ct) || '', fonte: (r.u && r.u.s) || '', campanha: (r.u && r.u.c) || '',
        perfil: r.p ? (nomePerfil[r.p] || '') : '', respostas,
        telas: (r.tel || []).length, concluiu: !!r.fim, clicou: !!r.cl, tempo: dur(r),
        // null = chegou na VSL mas a jornada expirou; a tela mostra '—', nao '0:00'
        chegouVsl: !!(r.cl && r.vd), atencao: v ? v.atencao : null, checkout: !!(v && v.checkout),
        comprou: c ? { valor: c.valor, cliente: c.cliente || '' } : null
      };
    });

    const perfis = (q.perfis || []).map(p => {
      const x = porPerfil[p.id] || { base: 0, cliques: 0, compras: 0, receita: 0 };
      const doPerfil = regs.filter(r => r.p === p.id && r.cl && r.vd);
      const comAt = doPerfil.filter(r => naVsl(r));
      return { id: p.id, nome: p.nome, url: p.url || '', concluiram: tot.perf[p.id] || 0, base: x.base, cliques: x.cliques, compras: x.compras, receita: x.receita,
               chegaramVsl: doPerfil.length,
               atencaoMediana: comAt.length ? mediana(comAt.map(r => naVsl(r).atencao).sort((a, b) => a - b)) : null };
    });

    return { ok: true, quiz: { id: q.id, nome: q.nome }, de, ate,
      abriram: tot.ab, concluiram: tot.fim, clicaram: tot.cl, compraram, receita,
      telas, opcoes, numeros, perfis,
      escada, vslSemDetalhe, tempo, criativos, horas, pessoas,
      // quanto da conta de venda tem base: registros guardados e quantos já foram ligados a um id da VSL
      base: { registros: regs.length, ligados, retencaoDias: QUIZ_RESP_DIAS }  };
}

app.get('/api/quiz/stats', authUsuario, (req, res) => {
  try {
    const d = _quizStats(String(req.query.quiz || '').slice(0, 60),
                         String(req.query.de || '').slice(0, 10),
                         String(req.query.ate || '').slice(0, 10));
    if (!d.ok) return res.status(404).json({ error: d.erro });
    res.json(d);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── slug livre? ──
app.get('/api/quiz/slug-livre', authUsuario, (req, res) => {
  const slug = String(req.query.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 80);
  const dono = String(req.query.quiz || '');
  const q = _qzQuizzes(true).porSlug[slug];
  res.json({ ok: true, slug, livre: !!slug && (!q || q.id === dono) });
});

// ══════════════════════════════════════════════════════
// ── MCP DO CENTRAL TMX (somente leitura) ──
// O sistema já consome o MCP da Utmify; isto é o outro lado: expõe as respostas
// do Central TMX pra um assistente (Claude no celular, por exemplo) perguntar
// direto, sem abrir o painel.
//
// Só leitura, de propósito: se o token vazar, o estrago máximo é alguém ler
// número — ninguém pausa campanha nem apaga demanda por aqui.
//
// O valor não é "mais uma integração": é que aqui os dados já estão CRUZADOS.
// A VTurb sabe até onde a pessoa assistiu mas não sabe se comprou; a Utmify sabe
// da venda mas não sabe a retenção nem o que ela respondeu no quiz. Só este
// servidor junta as três pontas — e as contas são as MESMAS funções que as telas
// usam (_funilStats, _quizStats, _utmifyPanorama), pra chat e tela nunca darem
// números diferentes pra mesma pergunta.
//
// Conectar: https://SEU-DOMINIO/mcp?token=<token da API>
// O token sai em Configurações → API (POST /api/tokens/generate).
// ══════════════════════════════════════════════════════
const MCP_PROTOCOLO = '2024-11-05';
const _mcpUso = {};   // hash -> quando marcamos uso pela última vez

function _mcpAutenticar(req) {
  let t = String(req.query.token || '').trim();
  const h = String(req.headers.authorization || '');
  if (!t && h.startsWith('Bearer ')) t = h.slice(7).trim();
  if (!t) return null;
  const hash = crypto.createHash('sha256').update(t).digest('hex');
  let db;
  try { db = readDB(); } catch (e) { return null; }
  const achado = (db.api_tokens || []).find(x => x.hash === hash && x.ativo);
  if (!achado) return null;
  // Uma conversa dispara várias chamadas. Gravar o banco inteiro em cada uma
  // seria caro à toa, então o carimbo de uso é no máximo 1x por minuto.
  const agora = Date.now();
  if (!_mcpUso[hash] || agora - _mcpUso[hash] > 60000) {
    _mcpUso[hash] = agora;
    achado.ultimoUso = new Date().toISOString();
    achado.totalReqs = (achado.totalReqs || 0) + 1;
    try { writeDB(db); } catch (e) {}
  }
  return achado;
}

const _mcpDia = v => new Date(Date.now() - 3 * 3600000 - v * 86400000).toISOString().slice(0, 10);
function _mcpPeriodo(a) {
  a = a || {};
  const dt = /^\d{4}-\d{2}-\d{2}$/;
  if (dt.test(String(a.de || ''))) {
    const ate = dt.test(String(a.ate || '')) ? a.ate : a.de;
    return { de: a.de, ate, rotulo: a.de === ate ? a.de : 'de ' + a.de + ' a ' + ate };
  }
  const p = String(a.periodo || 'hoje');
  if (p === 'ontem') return { de: _mcpDia(1), ate: _mcpDia(1), rotulo: 'ontem' };
  if (p === '7d')    return { de: _mcpDia(6), ate: _mcpDia(0), rotulo: 'últimos 7 dias' };
  if (p === '30d')   return { de: _mcpDia(29), ate: _mcpDia(0), rotulo: 'últimos 30 dias' };
  return { de: _mcpDia(0), ate: _mcpDia(0), rotulo: 'hoje' };
}
const _mcpBrl = n => (Number(n) || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL', maximumFractionDigits: 2 });
const _mcpNum = n => Math.round(Number(n) || 0).toLocaleString('pt-BR');
const _mcpPct = (x, c) => ((Number(x) || 0) * 100).toFixed(c == null ? 1 : c).replace('.', ',') + '%';

const MCP_FERRAMENTAS = [
  { name: 'listar_projetos',
    description: 'Lista os projetos (dashboards), funis, quizzes e VSLs disponíveis, com os ids. Use antes das outras ferramentas quando precisar de um id.',
    inputSchema: { type: 'object', properties: {} } },
  { name: 'como_esta_hoje',
    description: 'Visão geral do negócio no período: investimento, faturamento, vendas aprovadas, ROAS, ticket, CPA e lucro, por projeto e por produto.',
    inputSchema: { type: 'object', properties: {
      periodo: { type: 'string', enum: ['hoje', 'ontem', '7d', '30d'], description: 'Padrão: hoje' },
      de: { type: 'string', description: 'Data inicial AAAA-MM-DD (opcional, no lugar de periodo)' },
      ate: { type: 'string', description: 'Data final AAAA-MM-DD' },
      projeto: { type: 'string', description: 'Id do projeto (opcional; sem ele, todos)' } } } },
  { name: 'criativos_que_vendem',
    description: 'Ranking dos anúncios por faturamento no período, com vendas, gasto, ROAS e CPA. Mostra também os que gastaram e não venderam.',
    inputSchema: { type: 'object', properties: {
      periodo: { type: 'string', enum: ['hoje', 'ontem', '7d', '30d'] },
      de: { type: 'string' }, ate: { type: 'string' },
      projeto: { type: 'string', description: 'Id do projeto (opcional)' },
      limite: { type: 'number', description: 'Quantos anúncios mostrar. Padrão 12' } } } },
  { name: 'onde_perco_gente',
    description: 'Onde as pessoas abandonam: as etapas de um funil ou as telas de um quiz, com a maior queda apontada. Sem id, lista o que existe.',
    inputSchema: { type: 'object', properties: {
      funil: { type: 'string', description: 'Id do funil' },
      quiz: { type: 'string', description: 'Id do quiz' },
      periodo: { type: 'string', enum: ['hoje', 'ontem', '7d', '30d'] },
      de: { type: 'string' }, ate: { type: 'string' } } } },
  { name: 'respostas_que_compram',
    description: 'Num quiz: qual resposta de cada pergunta traz mais compra, e como os perfis se saem. Liga a resposta à venda mesmo com a oferta em outro domínio.',
    inputSchema: { type: 'object', properties: {
      quiz: { type: 'string', description: 'Id do quiz' },
      periodo: { type: 'string', enum: ['hoje', 'ontem', '7d', '30d'] },
      de: { type: 'string' }, ate: { type: 'string' } }, required: ['quiz'] } },
  { name: 'retencao_da_vsl',
    description: 'Números de uma VSL na VTurb: views, views únicas, plays, plays únicos, play rate, quem chegou no pitch, cliques e vendas — mais a curva de retenção minuto a minuto e a maior queda. Sem o id do player, lista as VSLs disponíveis.',
    inputSchema: { type: 'object', properties: {
      player: { type: 'string', description: 'Id do player na VTurb' },
      duracao: { type: 'number', description: 'Duração do vídeo em segundos. Só precisa se a VTurb não informar.' },
      periodo: { type: 'string', enum: ['hoje', 'ontem', '7d', '30d'] },
      de: { type: 'string' }, ate: { type: 'string' } } } },
  { name: 'vendas_recentes',
    description: 'As últimas vendas e checkouts registrados, com anúncio e horário. É o mesmo feed "Acontecendo agora" do painel.',
    inputSchema: { type: 'object', properties: {
      projeto: { type: 'string', description: 'Nome do projeto (opcional)' },
      limite: { type: 'number', description: 'Quantos eventos. Padrão 20' } } } }
];

async function _mcpExecutar(nome, a) {
  a = a || {};
  const per = _mcpPeriodo(a);

  if (nome === 'listar_projetos') {
    const db = readDB();
    let dashboards = [];
    try { dashboards = (await _utmifyDashboardsAtivos()).lista || []; } catch (e) {}
    const funis = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : []);
    const quizzes = (Array.isArray(db.store[KEY_QUIZZES]) ? db.store[KEY_QUIZZES] : []);
    const vturb = (_vturbCfg() || {}).players || [];
    let t = 'PROJETOS (use o id em projeto:)\n';
    t += dashboards.length ? dashboards.map(d => '· ' + d.nome + '  —  id: ' + d.id).join('\n') : '· nenhum projeto conectado na Utmify';
    t += '\n\nFUNIS (use em funil:)\n' + (funis.length ? funis.map(f => '· ' + f.nome + (f.projeto ? ' [' + f.projeto + ']' : '') + '  —  id: ' + f.id + '  ·  ' + (f.etapas || []).length + ' etapas').join('\n') : '· nenhum funil');
    t += '\n\nQUIZZES (use em quiz:)\n' + (quizzes.length ? quizzes.map(q => '· ' + q.nome + '  —  id: ' + q.id + '  ·  ' + (q.ativo ? 'no ar em /q/' + q.slug : 'rascunho')).join('\n') : '· nenhum quiz');
    t += '\n\nVSLs NA VTURB (use em player:)\n' + (vturb.length ? vturb.slice(0, 40).map(p => '· ' + (p.nome || p.name || p.id) + '  —  id: ' + p.id).join('\n') : '· nenhuma VSL salva (use retencao_da_vsl sem player pra buscar na VTurb)');
    return t;
  }

  if (nome === 'como_esta_hoje') {
    const d = await _utmifyPanorama(per.de, per.ate, String(a.projeto || ''));
    const k = d.kpis || {}, p = k.pedidos || {};
    let t = 'COMO ESTÁ ' + per.rotulo.toUpperCase() + '\n\n' +
      'Investido:    ' + _mcpBrl(k.investimento) + '\n' +
      'Faturamento:  ' + _mcpBrl(k.receita) + '\n' +
      'Vendas:       ' + _mcpNum(p.aprovadas) + ' aprovadas' + (p.pendentes ? '  (' + _mcpNum(p.pendentes) + ' pendentes)' : '') + '\n' +
      'ROAS:         ' + (Number(k.roas) || 0).toFixed(2).replace('.', ',') + 'x\n' +
      'Ticket médio: ' + _mcpBrl(k.ticket) + '\n' +
      'CPA:          ' + _mcpBrl(k.cpa) + '\n';
    // olha o mesmo campo que imprime: antes conferia 'liquido' e mostrava 'margem',
    // entao bastava um faltar pra linha do lucro sumir sem motivo
    const lucro = d.margem && (d.margem.margem != null ? d.margem.margem : d.margem.liquido);
    if (typeof lucro === 'number') t += 'Lucro:        ' + _mcpBrl(lucro) + '\n';
    const dash = (d.porDashboard || []).filter(x => x.investimento || x.receita);
    if (dash.length > 1) {
      t += '\nPOR PROJETO\n' + dash.map(x => '· ' + (x.nome || x.id) + ': ' + _mcpBrl(x.receita) + ' de faturamento, ' + _mcpBrl(x.investimento) + ' investido' +
        (x.investimento > 0 ? ' (ROAS ' + (x.receita / x.investimento).toFixed(2).replace('.', ',') + 'x)' : '')).join('\n') + '\n';
    }
    const prod = (d.produtos || []).slice(0, 5);
    if (prod.length) t += '\nPRODUTOS\n' + prod.map(x => '· ' + (x.nome || x.produto || '(sem nome)') + ': ' + _mcpBrl(x.receita) + (x.vendas ? ' em ' + _mcpNum(x.vendas) + ' vendas' : '')).join('\n') + '\n';
    if ((d.erros || []).length) t += '\nAvisos: ' + d.erros.slice(0, 3).map(e => e.motivo || e.erro || String(e)).join(' · ') + '\n';
    return t;
  }

  if (nome === 'criativos_que_vendem') {
    const achado = await _utmifyDashboardsAtivos();
    const cfg = achado.cfg, lista = _filtrarProjeto(achado.lista, String(a.projeto || ''));
    const porNome = {};
    for (const d of lista) {
      const tz = (d.tz === undefined || d.tz === null) ? -3 : d.tz;
      const off = (tz < 0 ? '-' : '+') + String(Math.abs(tz)).padStart(2, '0') + ':00';
      let r;
      try {
        r = await _utmifyChamarTool(cfg.token, 'get_meta_ad_objects', { dashboardId: d.id, level: 'ad',
          dateRange: { from: per.de + 'T00:00:00' + off, to: per.ate + 'T23:59:59' + off } });
      } catch (e) { continue; }
      // O mesmo criativo roda em várias contas e conjuntos: junta pelo NOME,
      // que é como a equipe fala dele ("o AD64.3"), não por id de anúncio.
      ((r && r.results) || []).forEach(x => {
        const n = String(x.name || '(sem nome)').trim();
        const k = (d.nome || d.id) + ' | ' + n;
        if (!porNome[k]) porNome[k] = { nome: n, projeto: d.nome || d.id, vendas: 0, receita: 0, gasto: 0 };
        porNome[k].vendas += Number(x.approvedOrdersCount) || 0;
        porNome[k].receita += (Number(x.grossRevenue) || 0) / 100;
        porNome[k].gasto += (Number(x.spend) || 0) / 100;
      });
    }
    const todos = Object.values(porNome);
    if (!todos.length) return 'Nenhum anúncio com dados ' + per.rotulo + '.';
    const lim = Math.min(40, Math.max(3, Number(a.limite) || 12));
    const vendem = todos.filter(x => x.vendas > 0).sort((x, y) => y.receita - x.receita).slice(0, lim);
    const queimam = todos.filter(x => !x.vendas && x.gasto > 0).sort((x, y) => y.gasto - x.gasto).slice(0, 8);
    const tg = todos.reduce((s, x) => s + x.gasto, 0), tr = todos.reduce((s, x) => s + x.receita, 0), tv = todos.reduce((s, x) => s + x.vendas, 0);
    let t = 'CRIATIVOS ' + per.rotulo.toUpperCase() + '\n' +
      'Total: ' + _mcpNum(tv) + ' vendas · ' + _mcpBrl(tr) + ' faturado · ' + _mcpBrl(tg) + ' investido' + (tg > 0 ? ' · ROAS ' + (tr / tg).toFixed(2).replace('.', ',') + 'x' : '') + '\n\n';
    t += 'QUEM VENDE\n' + (vendem.length ? vendem.map(x =>
      '· ' + x.nome + ' [' + x.projeto + ']: ' + _mcpNum(x.vendas) + ' venda(s) · ' + _mcpBrl(x.receita) +
      ' · gasto ' + _mcpBrl(x.gasto) + (x.gasto > 0 ? ' · ROAS ' + (x.receita / x.gasto).toFixed(2).replace('.', ',') + 'x' : '') +
      (x.vendas ? ' · CPA ' + _mcpBrl(x.gasto / x.vendas) : '')).join('\n') : '· nenhum anúncio vendeu no período') + '\n';
    if (queimam.length) t += '\nGASTOU E NÃO VENDEU\n' + queimam.map(x => '· ' + x.nome + ' [' + x.projeto + ']: ' + _mcpBrl(x.gasto)).join('\n') + '\n';
    return t;
  }

  if (nome === 'onde_perco_gente') {
    const db = readDB();
    if (!a.funil && !a.quiz) {
      const funis = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : []).map(f => '· funil: ' + f.nome + ' — id ' + f.id);
      const quizzes = (Array.isArray(db.store[KEY_QUIZZES]) ? db.store[KEY_QUIZZES] : []).map(q => '· quiz: ' + q.nome + ' — id ' + q.id);
      return 'Diga qual funil ou quiz olhar:\n' + funis.concat(quizzes).join('\n');
    }
    let t = '';
    if (a.funil) {
      const d = _funilStats(per.de, per.ate, String(a.funil));
      const f = (Array.isArray(db.store[KEY_FUNIS]) ? db.store[KEY_FUNIS] : []).find(x => x.id === String(a.funil));
      const nome = e => ((f && (f.etapas || []).find(x => x.id === e.etapa)) || {}).nome || e.etapa;
      const etapas = (d.etapas || []).slice().sort((x, y) => y.unicos - x.unicos);
      t += 'FUNIL ' + ((f && f.nome) || a.funil) + ' · ' + per.rotulo + '\n' +
        'Contagem vinda de: ' + (d.fonteUnicos === 'jornada' ? 'jornada (cada pessoa uma vez)' : 'contador acumulado') + '\n\n';
      t += etapas.length ? etapas.map(e => '· ' + nome(e) + ': ' + _mcpNum(e.unicos) + ' pessoas' +
        ((e.paginas || []).length > 1 ? '  (' + e.paginas.length + ' páginas somadas)' : '')).join('\n') : '· sem dado no período';
      if ((d.foraDoMapa || []).length) {
        const somaFora = d.foraDoMapa.reduce((s, x) => s + x.pessoas, 0);
        t += '\n\nAtenção: ' + d.foraDoMapa.length + ' página(s) com pixel fora do mapa (' + _mcpNum(somaFora) + ' pessoas). Cadastre a URL numa etapa pra elas entrarem na conta.';
      }
      t += '\n\n';
    }
    if (a.quiz) {
      const d = _quizStats(String(a.quiz), per.de, per.ate);
      if (!d.ok) return t + d.erro;
      t += 'QUIZ ' + d.quiz.nome + ' · ' + per.rotulo + '\n' +
        _mcpNum(d.abriram) + ' abriram · ' + _mcpNum(d.concluiram) + ' concluíram · ' + _mcpNum(d.clicaram) + ' foram pra oferta · ' + _mcpNum(d.compraram) + ' compraram (' + _mcpBrl(d.receita) + ')\n\n';
      const passos = (d.telas || []).map(x => ({ nome: x.nome, n: x.chegaram }));
      passos.push({ nome: 'Tocaram no botão da oferta', n: d.clicaram });
      let pior = -1, maior = 0;
      if (d.abriram >= 30) for (let i = 1; i < passos.length - 1; i++) {
        if (!passos[i].n) continue;
        const s = (passos[i].n - passos[i + 1].n) / passos[i].n;
        if (s > maior) { maior = s; pior = i; }
      }
      t += passos.map((p, i) => {
        const saem = i < passos.length - 1 ? Math.max(0, p.n - passos[i + 1].n) : null;
        return '· ' + p.nome + ': ' + _mcpNum(p.n) + (saem != null && p.n ? '  (saem ' + _mcpPct(saem / p.n) + ')' : '') + (i === pior ? '   ← MAIOR ABANDONO' : '');
      }).join('\n');
      if (pior < 0 && d.abriram < 30) t += '\n\nCom ' + _mcpNum(d.abriram) + ' pessoas ainda não dá pra apontar a maior queda: pode ser acaso.';
    }
    return t;
  }

  if (nome === 'respostas_que_compram') {
    const d = _quizStats(String(a.quiz || ''), per.de, per.ate);
    if (!d.ok) return d.erro;
    let t = 'QUIZ ' + d.quiz.nome + ' · ' + per.rotulo + '\n' +
      _mcpNum(d.compraram) + ' compras ligadas a respostas, ' + _mcpBrl(d.receita) + '\n';
    if (!d.base || !d.base.ligados) {
      t += '\nNenhuma venda ligada ainda. Pra isso funcionar, a oferta precisa do pixel do Central TMX e do webhook de vendas ligado.\n';
    }
    (d.opcoes || []).forEach(o => {
      const linhas = (o.ops || []).filter(x => x.base > 0).map(x => ({ t: x.t, base: x.base, compras: x.compras, taxa: x.compras / x.base, rpp: x.receita / x.base }))
        .sort((x, y) => y.taxa - x.taxa);
      if (!linhas.length) return;
      t += '\n' + o.pergunta.replace(/\*/g, '') + '\n' +
        linhas.map((x, i) => '   ' + (i === 0 && x.compras > 0 ? '▲ ' : '  ') + x.t + ': ' + _mcpNum(x.base) + ' pessoas · ' + _mcpNum(x.compras) + ' compraram · ' + _mcpPct(x.taxa) + ' · ' + _mcpBrl(x.rpp) + ' por pessoa').join('\n') + '\n';
    });
    const perfis = (d.perfis || []).filter(p => p.base > 0);
    if (perfis.length) t += '\nPERFIS\n' + perfis.map(p => '· ' + p.nome + ': ' + _mcpNum(p.concluiram) + ' concluíram · compra ' + _mcpPct(p.base ? p.compras / p.base : 0) + ' · ' + _mcpBrl(p.receita)).join('\n') + '\n';
    return t;
  }

  if (nome === 'retencao_da_vsl') {
    const cfg = _vturbExige();
    if (!a.player) {
      const ps = await _vturbPlayers(cfg.token).catch(() => (cfg.players || []));
      return 'VSLs NA VTURB (use o id em player:)\n' + (ps.length ? ps.slice(0, 60).map(p => '· ' + (p.nome || p.name || '(sem nome)') + ' — id: ' + p.id).join('\n') : '· nenhuma VSL encontrada');
    }
    const pr = _vturbPeriodo({ query: { de: per.de, ate: per.ate } });
    // A VTurb EXIGE a duracao do video e recusa zero. Ela pode vir da pergunta,
    // do cadastro local ou da lista da propria VTurb — e se nao vier de lugar
    // nenhum, o erro precisa dizer o que fazer, nao repassar o texto deles.
    let meta = (cfg.players || []).find(p => String(p.id) === String(a.player)) || {};
    let dur = Number(a.duracao) || Number(meta.duracao) || 0;
    if (dur <= 0) {
      const daApi = (await _vturbPlayers(cfg.token).catch(() => [])).find(p => String(p.id) === String(a.player));
      if (daApi) { meta = Object.assign({}, daApi, meta); dur = Number(daApi.duracao) || 0; }
    }
    if (dur <= 0) {
      return 'A VTurb não informou a duração dessa VSL, e ela é obrigatória pra montar a curva.\n' +
             'Pergunte de novo dizendo a duração em segundos (ex.: "retenção dessa VSL, duração 2280"), ' +
             'ou cadastre a duração da VSL em Criativos & VSL.';
    }
    // A curva sozinha nao responde "quantas pessoas". views, plays e play rate
    // vem de /sessions/stats — a MESMA chamada que a tela de VSL ja usa — entao
    // quem pergunta pela retencao recebe o tamanho da amostra junto.
    const [bruto, stats] = await Promise.all([
      _vturbApiData(cfg.token, '/times/user_engagement',
        { player_id: String(a.player), start_date: pr.ini, end_date: pr.fim, timezone: 'America/Sao_Paulo', video_duration: dur }, pr),
      _vturbApiData(cfg.token, '/sessions/stats',
        { player_id: String(a.player), start_date: pr.ini, end_date: pr.fim, timezone: 'America/Sao_Paulo',
          video_duration: dur, pitch_time: Number(meta.pitch) || 0 }, pr).catch(e => ({ _erro: e.message }))
    ]);
    // A lista vem em 'grouped_timed' — e o mesmo campo que a tela de VSL usa.
    // Eu tinha chutado 'data' e a resposta voltava sempre vazia.
    const lista = Array.isArray(bruto) ? bruto
      : ((bruto && (bruto.grouped_timed || bruto.timed || bruto.data || bruto.results)) || []);
    const pts = lista.map(x => ({ t: Number(x.timed) || 0, n: Number(x.total_users) || 0 })).sort((x, y) => x.t - y.t);
    if (!pts.length) return 'Sem dados de retenção pra essa VSL ' + per.rotulo + '.';
    // Mesma regra da tela: curva de sobrevivência NUNCA sobe. Se subir, o que
    // veio é histograma de abandono e precisa ser somado de trás pra frente.
    let ehSobrevivencia = true;
    for (let i = 1; i < pts.length; i++) if (pts[i].n > pts[i - 1].n * 1.02 + 1) { ehSobrevivencia = false; break; }
    let curva;
    if (ehSobrevivencia) {
      const topo = pts[0].n || 1;
      curva = pts.map(p => ({ t: p.t, y: Math.min(100, p.n / topo * 100) }));
    } else {
      let acum = 0; const saida = [];
      for (let j = pts.length - 1; j >= 0; j--) { acum += pts[j].n; saida.unshift({ t: pts[j].t, n: acum }); }
      const total = saida[0].n || 1;
      curva = saida.map(p => ({ t: p.t, y: p.n / total * 100 }));
    }
    const em = seg => { let melhor = null; curva.forEach(p => { if (p.t <= seg && (!melhor || p.t > melhor.t)) melhor = p; }); return melhor; };
    let queda = null;
    for (let i = 1; i < curva.length; i++) {
      const perdeu = curva[i - 1].y > 0 ? (curva[i - 1].y - curva[i].y) / curva[i - 1].y : 0;
      if (!queda || perdeu > queda.perdeu) queda = { perdeu, de: curva[i - 1], para: curva[i] };
    }
    const mmss = s => Math.floor(s / 60) + 'min' + String(Math.round(s % 60)).padStart(2, '0');
    const nomeVsl = String(meta.nome || a.player);
    let t = (/^vsl\b/i.test(nomeVsl) ? '' : 'VSL ') + nomeVsl + ' · ' + per.rotulo + '\n\n';
    // taxas da VTurb ja vem em 0-100; multiplicar de novo daria 5.510%
    const taxa = (v, c) => (Number(v) || 0).toFixed(c == null ? 1 : c).replace('.', ',') + '%';
    if (stats && !stats._erro) {
      const views  = Number(stats.total_viewed) || 0,  viewsU = Number(stats.total_viewed_device_uniq) || 0;
      const plays  = Number(stats.total_started) || 0, playsU = Number(stats.total_started_device_uniq) || 0;
      const pitch  = Number(stats.total_over_pitch) || 0;
      const cliq   = Number(stats.total_clicked_device_uniq || stats.total_clicked) || 0;
      const vendas = Number(stats.total_conversions) || 0;
      t += 'NÚMEROS DO PERÍODO\n';
      t += 'views ' + _mcpNum(views) + ' · views únicas ' + _mcpNum(viewsU) + '\n';
      t += 'plays ' + _mcpNum(plays) + ' · plays únicos ' + _mcpNum(playsU) + ' · play rate ' + taxa(stats.play_rate) + '\n';
      t += 'chegaram no pitch ' + _mcpNum(pitch) + (Number(stats.over_pitch_rate) ? ' (' + taxa(stats.over_pitch_rate) + ' de quem deu play)' : '') +
           ' · terminaram ' + _mcpNum(stats.total_finished_device_uniq || stats.total_finished) +
           ' · engajamento ' + taxa(stats.engagement_rate) + '\n';
      t += 'cliques ' + _mcpNum(cliq) + ' · vendas ' + _mcpNum(vendas) +
           (Number(stats.overall_conversion_rate) ? ' (' + taxa(stats.overall_conversion_rate, 2) + ' de conversão)' : '') + '\n\n';
    } else if (stats && stats._erro) {
      t += '(não consegui buscar views e plays agora: ' + stats._erro + ')\n\n';
    }
    t += 'RETENÇÃO\n';
    [60, 300, 600, 1200].forEach(s => { const p = em(s); if (p) t += 'aos ' + mmss(s) + ': ' + _mcpPct(p.y / 100, 0) + ' ainda assistindo\n'; });
    if (queda && queda.perdeu > 0) t += '\nMaior queda: entre ' + mmss(queda.de.t) + ' e ' + mmss(queda.para.t) + ', perde ' + _mcpPct(queda.perdeu) + ' de quem estava assistindo.';
    if (meta.pitch) t += '\nO pitch está marcado em ' + mmss(Number(meta.pitch)) + '.';
    return t;
  }

  if (nome === 'vendas_recentes') {
    const proj = String(a.projeto || '').trim().toLowerCase();
    const lim = Math.min(60, Math.max(5, Number(a.limite) || 20));
    const evs = _evFeed.filter(e => !proj || String(e.dashboard || '').trim().toLowerCase() === proj).slice(0, lim);
    if (!evs.length) return 'Nenhum evento registrado ainda' + (proj ? ' nesse projeto' : '') + '.';
    return 'ACONTECENDO AGORA\n\n' + evs.map(e => {
      const h = new Date(e.momento).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' });
      const q = e.qtd > 1 ? ' x' + e.qtd : '';
      const tipo = e.tipo === 'venda' ? 'Venda aprovada' + q : e.tipo === 'receita' ? 'Receita a mais' : 'Checkout iniciado' + q;
      return '· ' + h + '  ' + tipo + (e.valor ? ' · ' + _mcpBrl(e.valor) : '') + '  —  ' + e.anuncio + ' [' + e.dashboard + ']' +
        (e.atrasada ? ' (pedido de ' + String(e.diaOriginal || '').split('-').reverse().slice(0, 2).join('/') + ', Pix/boleto)' : '');
    }).join('\n');
  }

  throw new Error('Ferramenta desconhecida: ' + nome);
}

// O protocolo é JSON-RPC 2.0 por HTTP, igual ao servidor MCP da Utmify que a
// gente consome — é o formato que os assistentes esperam.
app.post('/mcp', express.json({ limit: '1mb' }), async (req, res) => {
  const corpo = req.body || {};
  const id = corpo.id !== undefined ? corpo.id : null;
  const erro = (codigo, msg) => res.json({ jsonrpc: '2.0', id, error: { code: codigo, message: msg } });
  if (!_mcpAutenticar(req)) {
    return res.status(401).json({ jsonrpc: '2.0', id,
      error: { code: -32001, message: 'Token inválido ou não informado. Gere um token da API no Central TMX e use ?token= no fim da URL.' } });
  }
  const metodo = String(corpo.method || '');
  try {
    if (metodo === 'initialize') {
      return res.json({ jsonrpc: '2.0', id, result: { protocolVersion: MCP_PROTOCOLO,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'Central TMX', version: '1.0.0' },
        instructions: 'Dados da operação do Central TMX: vendas, anúncios, funis, quizzes e VSLs. Somente leitura. Todos os valores em reais e as datas no fuso de Brasília.' } });
    }
    if (metodo.indexOf('notifications/') === 0) return res.status(202).end();
    if (metodo === 'ping') return res.json({ jsonrpc: '2.0', id, result: {} });
    if (metodo === 'tools/list') return res.json({ jsonrpc: '2.0', id, result: { tools: MCP_FERRAMENTAS } });
    if (metodo === 'tools/call') {
      const nome = String((corpo.params || {}).name || '');
      if (!MCP_FERRAMENTAS.some(f => f.name === nome)) return erro(-32602, 'Ferramenta desconhecida: ' + nome);
      try {
        const texto = await _mcpExecutar(nome, (corpo.params || {}).arguments || {});
        return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: String(texto) }] } });
      } catch (e) {
        // erro da ferramenta volta como resultado, não como falha do protocolo:
        // assim o assistente lê o motivo e explica, em vez de só dizer que quebrou
        return res.json({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: 'Não consegui responder: ' + e.message }] } });
      }
    }
    return erro(-32601, 'Método não suportado: ' + metodo);
  } catch (e) {
    console.error('[MCP]', metodo, e.message);
    return erro(-32603, e.message);
  }
});
app.get('/mcp', (req, res) => {
  res.json({ ok: true, servidor: 'Central TMX', protocolo: MCP_PROTOCOLO, somenteLeitura: true,
    ferramentas: MCP_FERRAMENTAS.map(f => f.name),
    comoConectar: 'Use esta mesma URL com ?token=SEU_TOKEN no seu assistente. O token sai em Configurações → API.' });
});

// ── Não perder métrica no deploy ────────────────────────────────────────────
// Os contadores ficam em buffer na memória e só descem pro disco a cada 30–45s.
// Numa atualização o Railway manda SIGTERM e mata o processo: sem isto aqui, o
// que estava no buffer nesse instante ia embora — e é justamente o pico da hora
// do deploy. Grava tudo antes de sair.
let _saindo = false;
function _gravarTudoESair(sinal) {
  if (_saindo) return;
  _saindo = true;
  console.log(`[${sinal}] gravando métricas pendentes antes de encerrar…`);
  const passos = [
    ['funil',   _fGravar],  ['atencao', _atGravar],
    ['ab',      _abGravar], ['jornada', _jGravar],
    // _abVistosGravar faltava aqui: um deploy perdia ate 60s de "quem ja foi contado"
    ['ab_vistos', _abVistosGravar], ['quiz', _qzGravar]
  ];
  for (const [nome, fn] of passos) {
    try { fn(); } catch (e) { console.error(`[${sinal}] ${nome} falhou:`, e.message); }
  }
  console.log(`[${sinal}] métricas gravadas.`);
  process.exit(0);
}
['SIGTERM', 'SIGINT'].forEach(s => process.on(s, () => _gravarTudoESair(s)));

app.listen(PORT, () => {
  console.log('');
  console.log('  ✅  ScaleLab Backend v2.0 rodando!');
  console.log('');
  console.log(`  📌  App:  http://localhost:${PORT}/ScaleLab.html`);
  console.log(`  📖  API Docs: http://localhost:${PORT}/api/v1/docs`);
  console.log(`  🔑  Tokens:   POST /api/tokens/generate`);
  console.log(`  💾  Backup:   Time Machine — 1h/48h + 1/dia/90d + 1/sem/12m + 1/mês forever`);
  const remoteOk = !!(process.env.GITHUB_BACKUP_TOKEN && process.env.GITHUB_BACKUP_REPO);
  console.log(`  ☁️   Remoto:   ${remoteOk ? 'ATIVO → ' + process.env.GITHUB_BACKUP_REPO : 'DESATIVADO (falta GITHUB_BACKUP_TOKEN / GITHUB_BACKUP_REPO)'}`);
  console.log('');
});
