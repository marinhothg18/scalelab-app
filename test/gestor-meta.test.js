// Gestor de Tráfego na Meta (09/11/2026): conecta pelo Facebook, puxa, desconecta, pausa, muda orçamento e
// escolhe as contas de cada projeto. Token colado, destinos e envio de compras continuam só com o Dono, o
// token não chega ao gestor e quem mexeu fica registrado com o nome.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const TOKEN = 'EAAtokenDoGestorDeTeste1234567890abcdefghijklmnopqrstuvwxyz';
const APP_ID = '1234567890';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

let meta, srv, dir, base, log = '', dono, gestor, copy, socio, gravacoes = [];
const objetos = {
  '100': { id: '100', name: 'CBO real', status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '50000', account_id: '111' },
  '101': { id: '101', name: 'Conjunto', campaign_id: '100', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '102': { id: '102', name: 'AD245.1', campaign_id: '100', adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' }
};
function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/v[\d.]+\//, '');
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.method === 'POST') {
    let corpo = '';
    req.on('data', b => { corpo += b; });
    req.on('end', () => {
      const { access_token, ...campos } = Object.fromEntries(new URLSearchParams(corpo));
      gravacoes.push({ id: p, campos });
      if (objetos[p]) { Object.assign(objetos[p], campos); if (campos.status) objetos[p].effective_status = campos.status; }
      ok({ success: true });
    });
    return;
  }
  if (p === 'oauth/access_token') return ok({ access_token: TOKEN, token_type: 'bearer', expires_in: 5184000 });
  if (p === 'debug_token') return ok({ data: { app_id: APP_ID, type: 'USER', expires_at: Math.floor(Date.now() / 1000) + 5184000 } });
  if (p === 'me/permissions') return ok({ data: ['ads_read', 'ads_management'].map(permission => ({ permission, status: 'granted' })) });
  if (p === 'me/adaccounts') return ok({ data: [{ id: 'act_111', account_id: '111', name: 'Conta real', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' }] });
  if (p === 'me') return ok({ id: '77', name: 'Pessoa Exemplo' });
  let m = p.match(/^(\d+)\/adsets$/);
  if (m) return ok({ data: Object.values(objetos).filter(o => o.campaign_id === m[1] && !o.adset_id) });
  m = p.match(/^(\d+)\/ads$/);
  if (m) return ok({ data: Object.values(objetos).filter(o => o.campaign_id === m[1] && o.adset_id) });
  if (objetos[p]) return ok(objetos[p]);
  ok({ data: [] });
}
async function chamar(metodo, caminho, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
const entrar = async (email, senha) => (await chamar('POST', '/api/auth/login', { corpo: { email, senha } })).dados.token;
const conta = (id, nome, email, senha, cargo) => ({ id, nome, email, senha, cargo, ativo: true, _updatedAt: Date.now() });

before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-gestormeta-'));
  const porta = 57000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0', META_APP_ID: APP_ID, META_APP_SECRET: 'segredo-de-teste', META_LOGIN_CONFIG_ID: '999' }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = await entrar('thiago@axcend.com', 'axcend2026');
  assert.ok(dono, log.slice(-1500));
  await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [
    conta('u-gestor', 'Gestor Teste', 'gestor@tmx.test', 'senha-gestor-1', 'Gestor de Tráfego'),
    conta('u-copy', 'Copy Teste', 'copy@tmx.test', 'senha-copy-1', 'Copy'),
    conta('u-socio', 'Socio Teste', 'socio@tmx.test', 'senha-socio-1', 'Sócio')
  ] });
  gestor = await entrar('gestor@tmx.test', 'senha-gestor-1');
  copy = await entrar('copy@tmx.test', 'senha-copy-1');
  socio = await entrar('socio@tmx.test', 'senha-socio-1');
  assert.ok(gestor && copy && socio, log.slice(-1500));
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('os outros cargos não conectam nem mexem', async () => {
  for (const token of [copy, socio]) {
    for (const [m, c, corpo] of [
      ['GET', '/api/meta/conexao'], ['GET', '/api/meta/historico'], ['GET', '/api/meta/campanha/100/estrutura'],
      ['POST', '/api/meta/login', { accessToken: 'curto' }], ['POST', '/api/meta/conexao/atualizar', {}],
      ['POST', '/api/meta/conexao/desconectar', {}], ['POST', '/api/meta/puxar', {}],
      ['POST', '/api/meta/status', { nivel: 'anuncio', id: '102', ativo: false }],
      ['POST', '/api/meta/orcamento', { nivel: 'campanha', id: '100', valor: 600 }],
      ['POST', '/api/projeto/config', { projeto: 'Teste', contas: ['111'] }]
    ]) assert.strictEqual((await chamar(m, c, { token, corpo })).status, 403, c);
  }
  assert.strictEqual(gravacoes.length, 0);
  assert.strictEqual((await chamar('GET', '/api/projeto/config?projeto=Teste', { token: copy })).dados.podeContas, false);
});

test('o gestor conecta pelo Facebook e o token não chega nele', async () => {
  const r = await chamar('POST', '/api/meta/login', { token: gestor, corpo: { accessToken: 'curto-do-facebook' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-800));
  assert.ok(!JSON.stringify(r.dados).includes(TOKEN));
  const v = await chamar('GET', '/api/meta/conexao', { token: gestor });
  assert.strictEqual(v.status, 200);
  assert.strictEqual(v.dados.conectado, true);
  assert.strictEqual(v.dados.via, 'facebook');
  assert.strictEqual(v.dados.contas.length, 1);
  assert.ok(!v.dados.tokenFim, 'o fim do token é só do Dono');
  assert.ok(!JSON.stringify(v.dados).includes(TOKEN));
  assert.ok((await chamar('GET', '/api/meta/conexao', { token: dono })).dados.tokenFim, 'o Dono continua vendo o fim do token');
});

test('o que continua só com o Dono', async () => {
  assert.strictEqual((await chamar('POST', '/api/meta/conexao', { token: gestor, corpo: { token: TOKEN } })).status, 403, 'token colado');
  assert.strictEqual((await chamar('POST', '/api/meta/capi/config', { token: gestor, corpo: { modo: 'enviando' } })).status, 403, 'envio de compras');
});

test('o gestor atualiza e puxa os números', async () => {
  assert.strictEqual((await chamar('POST', '/api/meta/conexao/atualizar', { token: gestor, corpo: {} })).status, 200);
  // a conexão já dispara uma puxada; enquanto ela roda, a rota responde "já está puxando"
  await ate(async () => (await chamar('POST', '/api/meta/puxar', { token: gestor, corpo: {} })).status === 200, 20000, 'puxar', () => log);
});

test('o gestor pausa e muda o orçamento', async () => {
  gravacoes = [];
  assert.strictEqual((await chamar('GET', '/api/meta/campanha/100/estrutura', { token: gestor })).status, 200);
  const p = await chamar('POST', '/api/meta/status', { token: gestor, corpo: { nivel: 'anuncio', id: '102', camp: '100', ativo: false, nome: 'AD245.1' } });
  assert.strictEqual(p.status, 200, JSON.stringify(p.dados));
  const o = await chamar('POST', '/api/meta/orcamento', { token: gestor, corpo: { nivel: 'campanha', id: '100', camp: '100', valor: 650, de: 500, nome: 'CBO real' } });
  assert.strictEqual(o.status, 200, JSON.stringify(o.dados));
  assert.deepStrictEqual(gravacoes, [{ id: '102', campos: { status: 'PAUSED' } }, { id: '100', campos: { daily_budget: '65000' } }]);
});

test('quem mexeu fica registrado com o nome', async () => {
  const h = await chamar('GET', '/api/meta/historico', { token: gestor });
  assert.strictEqual(h.status, 200);
  const achou = re => assert.ok(h.dados.itens.some(i => i.quem === 'Gestor Teste' && re.test(i.texto) && i.em > 0), re + ' em ' + JSON.stringify(h.dados.itens));
  achou(/conectou a Meta pelo Facebook/);
  achou(/atualizou as contas/);
  achou(/puxou os números/);
  achou(/pausou o anúncio AD245\.1/);
  achou(/mudou o orçamento da campanha CBO real de R\$.500,00 para R\$.650,00/);
});

test('o gestor escolhe as contas do projeto e não muda o envio de compras', async () => {
  const antes = await chamar('GET', '/api/projeto/config?projeto=Teste', { token: gestor });
  assert.strictEqual(antes.dados.podeContas, true);
  const r = await chamar('POST', '/api/projeto/config', { token: gestor, corpo: { projeto: 'Teste', contas: ['111'], regra: 'curso', destinos: ['qualquer'], modo: 'enviando', confirmar: 'SIM_ENVIAR_PRA_META', antecipar: true } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = (await chamar('GET', '/api/projeto/config?projeto=Teste', { token: dono })).dados;
  assert.deepStrictEqual(d.sel, ['111']);
  assert.strictEqual(d.regra, 'curso');
  assert.strictEqual(d.modo, antes.dados.modo, 'o modo das compras não muda');
  assert.deepStrictEqual(d.destinosSel, antes.dados.destinosSel, 'os destinos não mudam');
});

test('o gestor desconecta', async () => {
  assert.strictEqual((await chamar('POST', '/api/meta/conexao/desconectar', { token: gestor, corpo: {} })).status, 200);
  assert.strictEqual((await chamar('GET', '/api/meta/conexao', { token: dono })).dados.conectado, false);
  const h = await chamar('GET', '/api/meta/historico', { token: dono });
  assert.ok(h.dados.itens.some(i => i.quem === 'Gestor Teste' && /desconectou a Meta/.test(i.texto)));
});
