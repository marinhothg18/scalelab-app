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

// ── INICIA ──
app.listen(PORT, () => {
  console.log('');
  console.log('  ✅  ScaleLab Backend v2.0 rodando!');
  console.log('');
  console.log(`  📌  App:  http://localhost:${PORT}/ScaleLab.html`);
  console.log(`  📖  API Docs: http://localhost:${PORT}/api/v1/docs`);
  console.log(`  🔑  Tokens:   POST /api/tokens/generate`);
  console.log('');
});
