// Acessos por cargo (decisão do Thiago em 07/11/2026).
// 1. A regra do menu e da navegação (_podeVerPagina, no ScaleLab.html), cargo por cargo.
// 2. O servidor: o Sócio lê e grava o RH mas não o Financeiro; Meu Protocolo só a conta do Thiago.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');

const RAIZ = path.join(__dirname, '..');

// ── 1. regra da tela ──
function regraDaTela(rituais) {
  const html = fs.readFileSync(path.join(RAIZ, 'public', 'ScaleLab.html'), 'utf8');
  const ini = html.indexOf('var PROTOCOLO_DONO_EMAIL');
  const fim = html.indexOf('function goTo(', ini);
  assert.ok(ini > 0 && fim > ini, 'achei a regra no ScaleLab.html');
  const ctx = { g: (k, d) => (k === 'rituais' ? rituais : d), tmxEhTmx: () => true, currentUser: null };
  vm.createContext(ctx);
  vm.runInContext(html.slice(ini, fim), ctx);
  return ctx;
}
const PAGINAS = ['dashboard', 'task', 'criativos', 'rituais', 'arquivos', 'metricas', 'adsmetrics', 'funis', 'adlibrary', 'chat',
  'gestao', 'financeiro', 'configuracoes', 'protocolo'];
const ve = (r, u) => PAGINAS.filter(p => r._podeVerPagina(p, u));

test('menu e navegação seguem o cargo', () => {
  const r = regraDaTela([{ id: 'r1', participantes: ['Ana Editora'] }]);
  const todos = ['dashboard', 'task', 'criativos', 'rituais', 'arquivos', 'adlibrary', 'chat'];
  assert.deepStrictEqual(ve(r, { cargo: 'Diretoria', email: 'thiago@axcend.com' }), PAGINAS, 'o Thiago vê tudo');
  assert.deepStrictEqual(ve(r, { cargo: 'Diretoria', email: 'outro@tmx.com' }), PAGINAS.filter(p => p !== 'protocolo'), 'outro Dono não vê o Meu Protocolo');
  assert.deepStrictEqual(ve(r, { cargo: 'Sócio' }), PAGINAS.filter(p => !['financeiro', 'configuracoes', 'protocolo'].includes(p)), 'Sócio: tudo menos Financeiro, Configurações e Protocolo');
  assert.deepStrictEqual(ve(r, { cargo: 'Gestor de Tráfego' }), [...todos, 'metricas', 'adsmetrics', 'funis'].sort((a, b) => PAGINAS.indexOf(a) - PAGINAS.indexOf(b)));
  assert.deepStrictEqual(ve(r, { cargo: 'Copy' }), [...todos, 'funis'].sort((a, b) => PAGINAS.indexOf(a) - PAGINAS.indexOf(b)), 'Copy: sem Tráfego e Análise, com Projetos');
  assert.deepStrictEqual(ve(r, { cargo: 'Editor', nome: 'Ana Editora' }), todos, 'Editor num ritual: vê Rituais, sem Projetos');
  assert.deepStrictEqual(ve(r, { cargo: 'Editor', nome: 'Beto' }), todos.filter(p => p !== 'rituais'), 'Editor em nenhum ritual: sem Rituais');
  assert.strictEqual(r._nomeCargo('Diretoria'), 'Dono');
  assert.strictEqual(r._nomeCargo('Copy'), 'Copy');
  // fora da TMX o Meu Protocolo não existe, nem pro Thiago
  const cliente = regraDaTela([]);
  cliente.tmxEhTmx = () => false;
  assert.strictEqual(cliente._podeVerPagina('protocolo', { cargo: 'Diretoria', email: 'thiago@axcend.com' }), false);
});

// ── 2. servidor ──
let dir, srv, base, log = '';
const espera = ms => new Promise(r => setTimeout(r, ms));
async function ate(cond, ms, oQue) {
  const fim = Date.now() + ms;
  for (;;) {
    try { if (await cond()) return; } catch (e) {}
    if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-3000));
    await espera(150);
  }
}
async function chamar(metodo, caminho, { token, corpo } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null;
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-cargos-'));
  const porta = 45000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe']
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('o servidor guarda RH, Financeiro e Meu Protocolo pelo cargo', async () => {
  const tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.ok(tmx, log.slice(-1500));
  const agora = Date.now();
  const novos = [
    { id: 'u-socio', nome: 'Sócio Teste', email: 'socio@tmx.test', senha: 'senha-socio-1', cargo: 'Sócio', ativo: true, _updatedAt: agora },
    { id: 'u-copy', nome: 'Copy Teste', email: 'copy@tmx.test', senha: 'senha-copy-1', cargo: 'Copy', ativo: true, _updatedAt: agora },
    { id: 'u-dono2', nome: 'Outro Dono', email: 'dono2@tmx.test', senha: 'senha-dono-1', cargo: 'Diretoria', ativo: true, _updatedAt: agora }
  ];
  assert.strictEqual((await chamar('PUT', '/api/store/sl_usuarios', { token: tmx, corpo: novos })).status, 200);
  assert.strictEqual((await chamar('PUT', '/api/store/sl_rh_colaboradores', { token: tmx, corpo: [{ id: 'c1', nome: 'Fulano', salario: 5000, _updatedAt: agora }] })).status, 200);
  assert.strictEqual((await chamar('PUT', '/api/store/sl_fin_contas', { token: tmx, corpo: [{ id: 'f1', nome: 'Conta', _updatedAt: agora }] })).status, 200);
  assert.strictEqual((await chamar('PUT', '/api/store/sl_protocolo', { token: tmx, corpo: { dia: 'teste' } })).status, 200);
  const entrar = async (email, senha) => (await chamar('POST', '/api/auth/login', { corpo: { email, senha } })).dados.token;
  const socio = await entrar('socio@tmx.test', 'senha-socio-1');
  const copy = await entrar('copy@tmx.test', 'senha-copy-1');
  const dono2 = await entrar('dono2@tmx.test', 'senha-dono-1');
  assert.ok(socio && copy && dono2, 'os três entram');

  const s = (await chamar('GET', '/api/store', { token: socio })).dados;
  assert.ok(Array.isArray(s.sl_rh_colaboradores), 'Sócio vê o RH');
  assert.ok(!('sl_fin_contas' in s), 'Sócio não vê o Financeiro');
  assert.ok(!('sl_protocolo' in s), 'Sócio não vê o Meu Protocolo');
  assert.strictEqual((await chamar('PUT', '/api/store/sl_rh_feedbacks', { token: socio, corpo: [{ id: 'fb1', _updatedAt: agora }] })).status, 200, 'Sócio grava no RH');
  assert.strictEqual((await chamar('PUT', '/api/store/sl_fin_contas', { token: socio, corpo: [{ id: 'f2', _updatedAt: agora }] })).status, 403, 'Sócio não grava no Financeiro');

  const c = (await chamar('GET', '/api/store', { token: copy })).dados;
  assert.ok(!('sl_rh_colaboradores' in c) && !('sl_fin_contas' in c) && !('sl_protocolo' in c), 'Copy não vê RH, Financeiro nem Protocolo');
  assert.strictEqual((await chamar('PUT', '/api/store/sl_rh_feedbacks', { token: copy, corpo: [{ id: 'fb2', _updatedAt: agora }] })).status, 403);

  const d2 = (await chamar('GET', '/api/store', { token: dono2 })).dados;
  assert.ok(Array.isArray(d2.sl_fin_contas) && Array.isArray(d2.sl_rh_colaboradores), 'outro Dono vê Financeiro e RH');
  assert.ok(!('sl_protocolo' in d2), 'outro Dono não vê o Meu Protocolo');
  assert.strictEqual((await chamar('PUT', '/api/store/sl_protocolo', { token: dono2, corpo: { dia: 'x' } })).status, 403);

  const t = (await chamar('GET', '/api/store', { token: tmx })).dados;
  assert.ok(t.sl_protocolo && Array.isArray(t.sl_fin_contas), 'o Thiago vê tudo, inclusive o Meu Protocolo');
  const up = (await chamar('GET', '/api/updates/0', { token: socio })).dados;
  assert.ok(up.data && !('sl_fin_contas' in up.data) && 'sl_rh_colaboradores' in up.data, 'a sincronização segue a mesma regra');
});
