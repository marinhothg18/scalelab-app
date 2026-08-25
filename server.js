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
  // o pixel tem limite proprio: um visitante dispara varios eventos por pagina
  skip: (req) => req.path === '/api/sync/stream' || req.path === '/api/funil/evento'
});
// Continua limitado, so que com folga pra trafego real (e por IP do visitante)
const pixelLimiter = rateLimit({ windowMs: 60*1000, max: 120,
  message: { error: 'limite' }, standardHeaders: false, legacyHeaders: false });
app.use('/api/funil/evento', pixelLimiter);
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
app.post('/api/tokens/generate', (req, res) => {
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
    res.json({
      ok: true,
      configurado: !!(cfg && cfg.token),
      urlWebhook: cfg && cfg.token ? `/api/webhook/vendas/${cfg.token}` : null,
      totalVendas: vendas.length,
      ultimaVenda: vendas.length ? vendas[vendas.length - 1].recebidoEm : null,
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

function _normalizarVenda(p) {
  const achado = _pegaCom(p, [
    'commission.totalPriceInCents','totalPriceInCents','amount_in_cents','price_in_cents',
    'valor','value','amount','total','price','transaction.amount','data.amount','order.total'
  ]);
  let valor = _num(achado.valor);
  // Gateways que mandam em centavos deixam isso explícito no nome do campo
  if (valor !== null && /cents/i.test(achado.caminho)) valor = valor / 100;
  return {
    id: 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    pedidoId: String(_pega(p, ['orderId','order_id','id','transaction_id','codigo','code']) || ''),
    status: String(_pega(p, ['status','order_status','payment_status','situacao']) || '').toLowerCase(),
    valor: valor,
    moeda: String(_pega(p, ['currency','moeda']) || 'BRL'),
    produto: String(_pega(p, ['products.0.name','product.name','produto','product_name','plan_name']) || ''),
    cliente: String(_pega(p, ['customer.name','cliente.nome','customer_name','buyer.name']) || ''),
    email: String(_pega(p, ['customer.email','cliente.email','customer_email','buyer.email']) || ''),
    utmSource:   String(_pega(p, ['trackingParameters.utm_source','utm_source','tracking.utm_source','src']) || ''),
    utmMedium:   String(_pega(p, ['trackingParameters.utm_medium','utm_medium','tracking.utm_medium']) || ''),
    utmCampaign: String(_pega(p, ['trackingParameters.utm_campaign','utm_campaign','tracking.utm_campaign','campaign']) || ''),
    utmContent:  String(_pega(p, ['trackingParameters.utm_content','utm_content','tracking.utm_content']) || ''),
    utmTerm:     String(_pega(p, ['trackingParameters.utm_term','utm_term','tracking.utm_term']) || ''),
    // o visitante que o pixel anexou no link do checkout — e o que liga a venda
    // a jornada inteira, mesmo quando a UTM se perdeu no caminho
    vid: String(_pega(p, ['tmx_vid','trackingParameters.tmx_vid','tracking.tmx_vid',
                          'metadata.tmx_vid','custom.tmx_vid']) || ''),
    recebidoEm: new Date().toISOString()
  };
}

// Como esta venda foi ligada a uma origem. Sem isso voce troca um numero ruim
// por outro numero ruim sem saber qual e qual: 'vid' e confianca dura (o proprio
// visitante), 'utm' e o parametro que sobreviveu, 'nenhum' e venda orfa.
function _comoCasou(v) {
  if (v.vid)       return 'vid';
  if (v.utmContent || v.utmCampaign || v.utmSource) return 'utm';
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
    if (!jaTem) vendas.push(venda);
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
app.get('/api/metricas/utmify/anuncios', authUsuario, async (req, res) => {
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
    res.json(saida);
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
    const foto = {};
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
        } catch (e) { continue; }
        const porNome = {};
        ((r && r.results) || []).forEach(a => {
          const nome = String(a.name || '(sem nome)').trim();
          const k = d.id + '|' + dia + '|' + nome.toLowerCase().replace(/\s+/g, ' ');
          if (!porNome[k]) porNome[k] = { nome, dashboard: d.nome || d.id, dia,
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
        // so venda que entrou de fato; pendente e reembolso nao sao faturamento
        return !/reembols|refund|charge|recus|cancel|estorn/i.test(String(v.status || ''));
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
  'sl_ab_stats',            // contagem do teste A/B; a tela le por /api/ab/stats
  'sl_funil_jornada',       // caminho por visitante; a tela le por /api/funil/jornadas
  'sl_funil_atencao',       // rolagem e cliques; a tela le por /api/funil/atencao
  'sl_funil_adocoes'        // so o servidor decide; o navegador sobrescreveria
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
    duracao: Number(x.duration) || 0, pitch: Number(x.pitch_time) || 0,
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
    b.segundos += Number(extra && extra.segundos) || 0;
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
    _fContar(funil, etapa, tipo, visitante, c);

    // Teste A/B: a variante chegou pela URL do redirecionador e o pixel a devolve
    // em todo evento. 'entrou' na 1a pagina conta pessoa; alcancar a etapa que e
    // a meta conta conversao — e a mesma pessoa nunca conta duas vezes.
    const teste = String(c.teste || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 60);
    const variante = String(c.variante || '').slice(0, 40);
    if (teste && variante && visitante && tipo === 'entrou') {
      _abContar(teste, variante, 'entrou', visitante);
      try {
        const db = readDB();
        const r = (Array.isArray(db.store[KEY_REDIRS]) ? db.store[KEY_REDIRS] : [])
          .find(x => String(x.slug || '').toLowerCase() === teste);
        // meta e uma etapa do funil: chegar nela e a conversao do teste
        if (r && r.meta && String(r.meta) === etapa) _abContar(teste, variante, 'meta', visitante);
      } catch (e) {}
    }

    // so na entrada: os outros eventos sao da mesma pessoa, no mesmo aparelho
    if (tipo === 'entrou') c.quem = _quemE(req);
    _jRegistrar(visitante, funil, etapa, tipo, c);
    const pg = String(c.pg || '').slice(0, 160);
    if (tipo === 'saiu')    _atSaida(etapa, c, pg);
    if (tipo === 'clique')  _atClique(etapa, c.rotulo, c.posicao, pg);
    if (tipo === 'friccao') _atFriccao(etapa, c.rotulo, c.motivo, pg);

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
  if (extra && Number(extra.segundos)) ev.segundos = Number(extra.segundos);
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

    const vendas = (Array.isArray(db.store[KEY_VENDAS]) ? db.store[KEY_VENDAS] : [])
      .filter(v => v && noDia(v.recebidoEm));

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

    const lista = Object.values(paginas)
      .filter(p => !EH_CHECKOUT.test(p.pg))
      .filter(p => p.visitantes || p.entrada.vendas || p.venda.vendas)
      .map(p => Object.assign({}, p, {
        conversao: p.visitantes ? (p.venda.vendas / p.visitantes) * 100 : 0,
        ticket: p.venda.vendas ? p.venda.receita / p.venda.vendas : 0
      }))
      .sort((a, b) => b.venda.receita - a.venda.receita || b.visitantes - a.visitantes);

    res.json({ ok: true, de, ate, paginas: lista,
      // sem isto a tela mostra zero e voce nao sabe se e "nao vendeu" ou
      // "nao consegui ligar a venda a ninguem"
      diagnostico: { vendasNoPeriodo: vendas.length, aprovadas: vendas.filter(aprovada).length,
                     casadas, semVid, semJornada,
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
    let lista = (Array.isArray(db.store[KEY_JORNADA]) ? db.store[KEY_JORNADA] : [])
      .filter(porFunil)
      .concat(Object.values(_jBuffer).filter(porFunil))
      .map(trazer);

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
    if (pg) lista = lista.filter(j => (j.eventos || []).some(e => (e.pg || '') === pg));

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
      if (!v || !v.vid) return;
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

    res.json({ ok: true, funil, filtro, contagem, de, ate, pg, oferta,
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
      const k = l.pg || '';
      if (!paginas[k]) paginas[k] = { pg: k, saidas: 0 };
      paginas[k].saidas += l.saidas || 0;
    });
    if (pg) linhas = linhas.filter(l => (l.pg || '') === pg);
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
        if (!cl[r]) cl[r] = { rotulo: r, n: 0, pos: l.cliques[r].pos };
        cl[r].n += l.cliques[r].n;
        if (l.cliques[r].pos) cl[r].pos = l.cliques[r].pos;
      });
      Object.keys(l.friccao || {}).forEach(r => {
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
const _abVistos = new Map();          // por chave: quem ja foi contado como unico

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
      set.add(visitante);
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
      if (!v || !v.vid) return;
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

    res.json({
      ok: true, teste: slug, nome: r.nome || slug, hipotese: r.hipotese || '',
      meta: r.meta || null, estado: r.estado || (r.ativo === false ? 'pausado' : 'rodando'),
      criadoEm: r.criadoEm || null, variantes,
      lider: ord[0] ? ord[0].id : null, segundo: ord[1] ? ord[1].id : null,
      precoVaria, julgamento, divisao, vendasSemVariante,
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

// ── Dados pra tela ──
app.get('/api/funil/stats', authUsuario, (req, res) => {
  try {
    const de  = String(req.query.de  || '').slice(0, 10);
    const ate = String(req.query.ate || '').slice(0, 10);
    const funil = String(req.query.funil || '').slice(0, 80);
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

    res.json({ ok: true, funil, de, ate,
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
      feed: _fFeed.filter(f => !funil || ado.aceita(f)).slice(0, 40) });
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
    _versaoApp = maior ? String(maior | 0) : TMX_VERSAO;
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

  var entrou = Date.now();
  // A pagina, sem query nem hash: com ela da pra comparar 5 VSLs que usam a
  // MESMA etapa do mapa. Query fora de proposito — leva utm e as vezes dado
  // pessoal, e viraria uma chave diferente por visitante.
  // Sem tirar o www aqui, a pagina medida ("www.site.com/x") nunca casaria com o
  // link cadastrado no teste ("https://site.com/x/") — e o seletor mostraria as
  // duas como se fossem paginas diferentes.
  var PAGINA = (location.host + location.pathname)
                 .replace(/^www\\./i, '').replace(/\\/+$/, '').slice(0, 160);
  function manda(tipo, extra){
    var dados = Object.assign({ id:id, funil:FUNIL, etapa:ETAPA, tipo:tipo, utm:utm,
                                pg:PAGINA, primeiro:primeiro,
                                teste:teste, variante:variante, versao:VERSAO, ref:d.referrer }, extra||{});
    var corpo = JSON.stringify(dados);
    try{
      navigator.sendBeacon
        ? navigator.sendBeacon(API, new Blob([corpo],{type:'text/plain;charset=UTF-8'}))
        : fetch(API,{method:'POST',headers:{'Content-Type':'text/plain;charset=UTF-8'},body:corpo,keepalive:true});
    }catch(e){}
  }
  manda('entrou');

  // ── rolagem ──
  // So o evento de scroll alimentava isto, entao quem NAO rolava ficava com 0 —
  // e numa VSL quase ninguem rola, a pessoa assiste. O numero dizia que 12 de 13
  // nao passaram do topo quando na verdade tinham visto a pagina inteira.
  // Agora tambem se mede na saida, com a altura final: se a pagina cabe na tela,
  // quem nao rolou viu 100%; se e longa, viu a fracao que coube.
  var fundo = 0;
  function fracaoVista(){
    var alt = d.body.scrollHeight || d.documentElement.scrollHeight || 0;
    if(!alt) return 0;
    return Math.min(100, (scrollY + innerHeight) / alt * 100);
  }
  w.addEventListener('scroll', function(){
    var p = fracaoVista();
    if(p>fundo) fundo = p;
  },{passive:true});

  // ── atencao: so conta o tempo com a aba VISIVEL. Tempo de parede contava
  //    quem abriu numa aba de fundo e esqueceu como se estivesse assistindo. ──
  // Comeca contando: se o navegador nunca disparar visibilitychange, a atencao
  // vira o tempo de parede — que e o melhor palpite honesto. Comecar em zero
  // fazia a atencao ser sempre 0 quando o evento nao vinha.
  var visivelDesde = Date.now();
  var atencao = 0;
  function fechaJanela(){ if(visivelDesde){ atencao += Date.now()-visivelDesde; visivelDesde = 0; } }
  d.addEventListener('visibilitychange', function(){
    if(d.visibilityState === 'visible'){ if(!visivelDesde) visivelDesde = Date.now(); }
    else fechaJanela();
  });

  // ── Web Vitals de campo: mede o aparelho do lead, nao o laboratorio ──
  var lcp = 0, cls = 0, fcp = 0;
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
  var errosJs = 0;
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
  d.addEventListener('click', function(ev){
    var el = ev.target && ev.target.closest ? ev.target.closest('a,button,[role=button],input[type=submit],img,video') : null;
    if(!el) el = ev.target;
    if(!el || !el.getBoundingClientRect) return;
    var rot = rotuloDe(el);
    var alt = d.body.scrollHeight || 1;
    var y = el.getBoundingClientRect().top + scrollY;
    manda('clique', { rotulo: rot, posicao: Math.round(y/alt*100) });

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

    // clique morto: elemento nao acionavel e nada mudou logo depois
    if(acionavel(el)) return;
    var urlAntes = location.href, focoAntes = d.activeElement, htmlAntes = d.body.childElementCount;
    setTimeout(function(){
      if(location.href === urlAntes && d.activeElement === focoAntes && d.body.childElementCount === htmlAntes)
        manda('friccao', { rotulo: rot, motivo: 'morto', posicao: Math.round(y/alt*100) });
    }, 450);
  }, true);

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
    manda('saiu',{
      segundos: Math.round((Date.now()-entrou)/1000),
      atencao:  Math.round(atencao/1000),
      rolagem:  Math.round(Math.max(fundo, fracaoVista())),
      lcp: lcp, cls: Math.round(cls*1000)/1000, fcp: fcp, erros: errosJs
    });
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
  d.addEventListener('click', function(ev){
    var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    if(!a) return;
    var novo = enriquecer(a.getAttribute('href') || a.href);
    if(novo && novo !== a.href){ a.href = novo; a.setAttribute(MARCA, novo); }
  }, true);

  // Botao que navega por JS (player de VSL costuma fazer isso) nao passa pelo
  // <a>, entao os dois caminhos de navegacao tambem sao cobertos.
  try{
    var _assign = w.location.assign.bind(w.location);
    w.location.assign = function(u){ return _assign(enriquecer(String(u))); };
    var _replace = w.location.replace.bind(w.location);
    w.location.replace = function(u){ return _replace(enriquecer(String(u))); };
  }catch(e){}
  try{
    var _open = w.open;
    w.open = function(u){
      var args = Array.prototype.slice.call(arguments);
      if(u) args[0] = enriquecer(String(u));
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
    ['ab',      _abGravar], ['jornada', _jGravar]
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
