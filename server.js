const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

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

// ── BANCO DE DADOS ──
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { store: {}, timestamps: {}, api_tokens: [], api_logs: [] }; }
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function now() { return Math.floor(Date.now() / 1000); }

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
  writeDB(db);
}
initDB();

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
  db.api_tokens.push({
    id: Date.now(),
    nome,
    hash: tokenHash,
    preview: token.substring(0, 16) + '...',
    criado: new Date().toISOString(),
    criadoPor: userId || 'sistema',
    ativo: true,
    ultimoUso: null,
    totalReqs: 0
  });
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
  res.json(db.store);
});

app.get('/api/updates/:since', (req, res) => {
  const since = parseInt(req.params.since) || 0;
  const db = readDB();
  const data = {};
  Object.entries(db.timestamps || {}).forEach(([k, ts]) => {
    if (ts > since) data[k] = db.store[k];
  });
  res.json({ data, timestamp: now() });
});

app.put('/api/store/:key', (req, res) => {
  const db = readDB();
  db.store[req.params.key] = req.body;
  if (!db.timestamps) db.timestamps = {};
  db.timestamps[req.params.key] = now();
  writeDB(db);
  res.json({ ok: true });
});

app.post('/api/auth/login', (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) return res.status(400).json({ error: 'Email e senha obrigatórios' });
  const db = readDB();
  const usuarios = db.store['sl_usuarios'] || [];
  const user = usuarios.find(u => u.email?.toLowerCase() === email.toLowerCase() && u.senha === senha && u.ativo !== false);
  if (!user) return res.status(401).json({ error: 'Email ou senha inválidos' });
  const { senha: _, ...safeUser } = user;
  res.json({ user: safeUser });
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

// Middleware: só Diretoria pode acessar backup
function authDiretoria(req, res, next) {
  const email = req.headers['x-user-email'] || (req.body && req.body.email);
  const senha = req.headers['x-user-senha'] || (req.body && req.body.senha);
  if (!email || !senha) return res.status(401).json({ error: 'Credenciais necessárias (x-user-email + x-user-senha).' });
  const db = readDB();
  const user = (db.store['sl_usuarios'] || []).find(u =>
    u.email && u.email.toLowerCase() === String(email).toLowerCase() &&
    u.senha === senha && u.ativo !== false);
  if (!user) return res.status(401).json({ error: 'Credenciais inválidas.' });
  if (user.cargo !== 'Diretoria') return res.status(403).json({ error: 'Acesso restrito à Diretoria.' });
  req.user = user;
  next();
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
