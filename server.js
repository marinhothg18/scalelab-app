const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
// Usa /data se existir (volume persistente Railway), senão usa __dirname
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const DB_FILE = path.join(DATA_DIR, 'db.json');

// ── CORS: permite file://, localhost, etc. ──
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '20mb' }));

// Serve ScaleLab.html e arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// ── BANCO DE DADOS (JSON em arquivo) ──
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { store: {}, timestamps: {} }; }
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Init: seed usuários padrão se o banco estiver vazio
function initDB() {
  const db = readDB();
  if (!db.store['sl_usuarios']) {
    db.store['sl_usuarios'] = [
      { id:'u1', nome:'Thiago', email:'thiago@axcend.com', senha:'axcend2026', cargo:'Diretoria',         ativo:true },
      { id:'u2', nome:'Rafael', email:'rafael@axcend.com', senha:'axcend2026', cargo:'Gestor de Tráfego', ativo:true },
      { id:'u3', nome:'Ana',    email:'copy@axcend.com',   senha:'axcend2026', cargo:'Copy',              ativo:true },
      { id:'u4', nome:'Carlos', email:'editor@axcend.com', senha:'axcend2026', cargo:'Editor',            ativo:true },
      { id:'u5', nome:'Felipe', email:'infra@axcend.com',  senha:'axcend2026', cargo:'Infra',             ativo:true },
      { id:'u6', nome:'Lucas',  email:'spy@axcend.com',    senha:'axcend2026', cargo:'Spy',               ativo:true }
    ];
    db.timestamps['sl_usuarios'] = now();
    writeDB(db);
  }
}

function now() { return Math.floor(Date.now() / 1000); }

initDB();

// ── ROTAS ──

// GET /api/store — todos os dados (sync inicial)
app.get('/api/store', (req, res) => {
  const db = readDB();
  res.json(db.store);
});

// GET /api/updates/:since — apenas chaves alteradas desde o timestamp
app.get('/api/updates/:since', (req, res) => {
  const since = parseInt(req.params.since) || 0;
  const db = readDB();
  const data = {};
  Object.entries(db.timestamps || {}).forEach(([k, ts]) => {
    if (ts > since) data[k] = db.store[k];
  });
  res.json({ data, timestamp: now() });
});

// PUT /api/store/:key — salva uma chave
app.put('/api/store/:key', (req, res) => {
  const db = readDB();
  db.store[req.params.key] = req.body;
  if (!db.timestamps) db.timestamps = {};
  db.timestamps[req.params.key] = now();
  writeDB(db);
  res.json({ ok: true });
});

// POST /api/auth/login — autentica contra sl_usuarios
app.post('/api/auth/login', (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) return res.status(400).json({ error: 'Email e senha obrigatórios' });

  const db = readDB();
  const usuarios = db.store['sl_usuarios'] || [];
  const user = usuarios.find(
    u => u.email?.toLowerCase() === email.toLowerCase() && u.senha === senha && u.ativo !== false
  );
  if (!user) return res.status(401).json({ error: 'Email ou senha inválidos' });

  const { senha: _, ...safeUser } = user;
  res.json({ user: safeUser });
});

// GET /api/ping
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// ── INICIA ──
app.listen(PORT, () => {
  console.log('');
  console.log('  ✅  ScaleLab Backend rodando!');
  console.log('');
  console.log(`  📌  Abra: http://localhost:${PORT}/ScaleLab.html`);
  console.log('');
  console.log('  Credenciais:');
  console.log('    Diretoria:  thiago@axcend.com / axcend2026');
  console.log('    Tráfego:    rafael@axcend.com / axcend2026');
  console.log('');
});
