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
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// Rate limiting global
const globalLimiter = rateLimit({ windowMs: 60*1000, max: 200, message: { error: 'Muitas requisições. Tente novamente em 1 minuto.' } });
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

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));
// URL raiz serve o app
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'ScaleLab.html')));

// ── BANCO DE DADOS ──
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { store: {}, timestamps: {}, api_tokens: [], api_logs: [] }; }
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function now() { return Math.floor(Date.now() / 1000); }

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
  const { nome, userId } = req.body || {};
  if (!nome) return res.status(400).json({ error: 'Nome do token obrigatório.' });

  const token = 'sk_live_' + crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const db = readDB();
  const tokenMeta = {
    id: Date.now(),
    nome,
    hash: tokenHash,
    preview: token.substring(0, 16) + '...',
    criado: new Date().toISOString(),
    criadoPor: userId || 'sistema',
    ativo: true,
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
// ── ROTAS INTERNAS (frontend sync) ──
// ══════════════════════════════════════════════

app.get('/api/store', (req, res) => {
  const db = readDB();
  const safe = Object.assign({}, db.store);
  if (safe['sl_usuarios']) safe['sl_usuarios'] = _stripSenhas(safe['sl_usuarios']);
  res.json(safe);
});

app.get('/api/updates/:since', (req, res) => {
  const since = parseInt(req.params.since) || 0;
  const db = readDB();
  const data = {};
  Object.entries(db.timestamps || {}).forEach(([k, ts]) => {
    if (ts > since) data[k] = (k === 'sl_usuarios') ? _stripSenhas(db.store[k]) : db.store[k];
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

  // Aplica merge inteligente por ID quando faz sentido
  db.store[key] = _mergeArrayById(existing, incoming);

  if (!db.timestamps) db.timestamps = {};
  db.timestamps[key] = now();
  writeDB(db);
  res.json({ ok: true, merged: Array.isArray(db.store[key]) ? db.store[key].length : undefined });
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
  res.json({ ok: true });
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
  const user = usuarios.find(u => u.email && u.email.toLowerCase() === String(email).toLowerCase() && u.ativo !== false);
  if (!user) {
    audit(db, 'login_falhou', { email }, { ip: req.ip }, null);
    writeDB(db);
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
    audit(db, 'login_falhou', { email, userId: user.id }, { motivo: 'senha_incorreta', ip: req.ip }, null);
    writeDB(db);
    return res.status(401).json({ error: 'Email ou senha inválidos' });
  }

  const token = criarSessao(db, user.id);
  audit(db, 'login', { userId: user.id, email: user.email }, { ip: req.ip }, { id: user.id, nome: user.nome, cargo: user.cargo });
  writeDB(db);

  const { senha: _s, senhaHash: _h, ...safeUser } = user;
  res.json({ user: safeUser, token, expiraEm: new Date(Date.now() + SESSION_TTL_MS).toISOString() });
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
    // Regras padrão = ativas, exceto explicitamente false
    const regras = {
      prazo24h:     cfgLemb.prazo24h     !== false,
      atrasada1d:   cfgLemb.atrasada1d   !== false,
      atrasada3d:   cfgLemb.atrasada3d   !== false,
      alertaDir2d:  cfgLemb.alertaDir2d  !== false,
      ritualHoje:   cfgLemb.ritualHoje   !== false,
      backlog3d:    cfgLemb.backlog3d    !== false,
    };
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
// Roda a cada 1h + primeira em 30s após boot
setInterval(_lembretesRodar, 60 * 60 * 1000);
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
// WHATSAPP + AGENTE IA (Z-API + Claude/OpenAI)
// ══════════════════════════════════════════════

// Limpa número de telefone pro formato Z-API (55+DDD+numero, só dígitos)
function _waCleanPhone(phone) {
  if (!phone) return '';
  let p = String(phone).replace(/\D/g, '');
  // Remove 9 extra do Brasil se tiver 14 digitos (55 + DDD + 9 + 8 dig)
  if (p.length === 13 && p.startsWith('55')) {
    // está ok
  } else if (p.length === 11) {
    p = '55' + p; // DDD + 9 digitos → adiciona 55
  } else if (p.length === 10) {
    p = '55' + p; // DDD + 8 digitos (sem 9)
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
  const r = await sendWhatsAppMessage(to, message || '🤖 Teste do Axcend! Está funcionando.');
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
      await sendWhatsAppMessage(phone, '👋 Olá! Este número não está cadastrado no Axcend. Peça ao admin pra cadastrar seu WhatsApp no perfil.');
      return res.json({ ok: true, skipped: 'user-nao-encontrado' });
    }

    // Processa com IA (se configurada)
    let resposta = '';
    if (cfg.ai_provider && cfg.ai_key) {
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
  const tools = _agentTools();
  const systemPrompt = `Você é o assistente do Axcend (sistema de gestão de tráfego pago em centralaxcend.com).
Usuário: ${user.nome} (${user.cargo}).
Responde em português, tom natural e direto. Sem emojis demais.
Use as ferramentas disponíveis quando o usuário pedir dados reais.
Se o usuário pedir algo que não tem ferramenta, responda do que sabe sem inventar dados.`;

  const body = {
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    system: systemPrompt,
    messages: [{ role: 'user', content: texto }],
    tools
  };

  let r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': cfg.ai_key,
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
      headers: { 'x-api-key': cfg.ai_key, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
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
  // Simplificação: usa chat completion sem tool (pra suportar OpenAI precisaria traduzir tools)
  const body = {
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: `Você é o assistente do Axcend. Usuário: ${user.nome} (${user.cargo}). Responda em português.` },
      { role: 'user', content: texto }
    ]
  };
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + cfg.ai_key, 'Content-Type': 'application/json' },
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
      description: 'Cria uma nova demanda no sistema',
      input_schema: {
        type: 'object',
        required: ['nome'],
        properties: {
          nome: { type: 'string' },
          responsavel: { type: 'string', description: 'Nome do responsável' },
          prazo: { type: 'string', description: 'Data YYYY-MM-DD' },
          descricao: { type: 'string' }
        }
      }
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
          nome: t.nome, responsavel: t.resp, dias_atraso: Math.floor((new Date(hojeStr).getTime() - new Date(t.data).getTime())/(24*60*60*1000))
        }))
      };
    }
    return { erro: 'tool desconhecida' };
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
  await _notificarViaWhatsApp(destId, titulo || 'Notificação Axcend', texto);
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
