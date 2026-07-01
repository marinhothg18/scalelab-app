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
const PORT = process.env.PORT || 3001;
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const DB_FILE = path.join(DATA_DIR, 'db.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
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
  skip: (req) => req.path === '/api/sync/stream'
});
app.use('/api/', globalLimiter);

// Rate limiting mais agressivo pra API v1
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 60, message: { error: 'Limite da API atingido. Máximo 60 req/min.' } });
app.use('/api/v1/', apiLimiter);

// Rate limiting crítico para login: 5 tentativas por 10min por IP
const loginLimiter = rateLimit({
  windowMs: 10*60*1000,
  max: 5,
  message: { error: 'Muitas tentativas de login. Aguarde 10 minutos.' },
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

// ── BANCO DE DADOS ──
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { store: {}, timestamps: {}, api_tokens: [], api_logs: [] }; }
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
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
  writeDB(db);
}
initDB();
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
app.post('/api/integracoes/utmify/config', (req, res) => {
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
app.get('/api/integracoes/utmify/me', (req, res) => {
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
app.post('/api/integracoes/utmify/test', async (req, res) => {
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

app.get('/api/store', (req, res) => {
  const db = readDB();
  // Multi-tenancy: filtra o store pelo tenant da request.
  // Super-admin com ?_super=1 vê tudo (pro painel SaaS poder consultar
  // dados de qualquer tenant quando precisar).
  const bypass = req.query._super === '1' && _isSuperAdmin(req);
  const baseStore = bypass ? db.store : _aplicarFiltroTenant(db.store, req.tenantId);
  const safe = Object.assign({}, baseStore);
  if (safe['sl_usuarios']) safe['sl_usuarios'] = _stripSenhas(safe['sl_usuarios']);
  res.json(safe);
});

app.get('/api/updates/:since', (req, res) => {
  const since = parseInt(req.params.since) || 0;
  const db = readDB();
  const bypass = req.query._super === '1' && _isSuperAdmin(req);
  const isInterno = req.tenantId === TENANT_INTERNO_ID;
  const data = {};
  Object.entries(db.timestamps || {}).forEach(([k, ts]) => {
    if (ts > since) {
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

app.put('/api/store/:key', (req, res) => {
  const db = readDB();
  const key = req.params.key;
  let incoming = req.body;
  const existing = db.store[key];

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
app.post('/api/lixeira/soft-delete', (req, res) => {
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
app.post('/api/lixeira/restore/:lixeiraId', (req, res) => {
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
app.delete('/api/lixeira/:lixeiraId', (req, res) => {
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

app.post('/api/auth/login', loginLimiter, (req, res) => {
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
        writeDB(db); // persiste lastActivity
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
      .filter(f => f.endsWith('.json'))
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

// Grava snapshot e aplica retenção
function criarSnapshotBackup(motivo) {
  try {
    const agora = new Date();
    const pad = n => String(n).padStart(2,'0');
    const stamp = `${agora.getUTCFullYear()}${pad(agora.getUTCMonth()+1)}${pad(agora.getUTCDate())}-${pad(agora.getUTCHours())}${pad(agora.getUTCMinutes())}${pad(agora.getUTCSeconds())}`;
    const fname = `db-${stamp}${motivo ? '-' + motivo : ''}.json`;
    const fpath = path.join(BACKUP_DIR, fname);
    const conteudo = fs.readFileSync(DB_FILE, 'utf8');
    fs.writeFileSync(fpath, conteudo);
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
      .filter(f => f.endsWith('.json'))
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
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${nome}"`);
  res.send(fs.readFileSync(fpath, 'utf8'));
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
    fs.writeFileSync(DB_FILE, JSON.stringify(dados, null, 2));
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
    const conteudo = fs.readFileSync(fpath, 'utf8');
    fs.writeFileSync(DB_FILE, conteudo);
    try { const ndb = readDB(); audit(ndb, 'backup_restore_snap', { snapshot: nome }, null, { id: req.user.id, nome: req.user.nome, cargo: req.user.cargo }); writeDB(ndb); } catch {}
    console.log(`[BACKUP] ${req.user.nome} restaurou a partir de ${nome}.`);
    res.json({ ok: true, message: `Banco restaurado de ${nome}.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── INICIA ──
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
