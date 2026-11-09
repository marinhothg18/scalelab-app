// Mexer nas campanhas pelo TMX (09/11/2026): ativar, pausar e orçamento de campanha, conjunto e anúncio.
// Sobe o servidor com uma Meta falsa e confere: só a Diretoria muda, o valor vai em centavos na moeda
// da conta, ninguém passa por cima de um valor que mudou, e tudo fica na auditoria e no histórico.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const TOKEN = 'EAAtokenDeControleDeTeste1234567890abcdefghijklmnopqrstuvwxyz';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

let meta, srv, dir, base, log = '', dono, permissoes = ['ads_read', 'ads_management'], gravacoes = [], recusarProxima = null;
const objetos = {};
function resetar() {
  Object.keys(objetos).forEach(k => delete objetos[k]);
  Object.assign(objetos, {
    '100': { id: '100', name: 'CBO real | 100', status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '50000', account_id: '111' },
    '200': { id: '200', name: 'ABO dolar | 200', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '222' },
    '300': { id: '300', name: 'Conta em euro', status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '10000', account_id: '333' },
    '400': { id: '400', name: 'Vitalicio', status: 'ACTIVE', effective_status: 'ACTIVE', lifetime_budget: '900000', account_id: '111' },
    '101': { id: '101', name: 'Conjunto sem orcamento', campaign_id: '100', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
    '201': { id: '201', name: 'Conjunto ABO', campaign_id: '200', status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '2500', account_id: '222' },
    '102': { id: '102', name: 'AD245.1', campaign_id: '100', adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
    '103': { id: '103', name: 'AD216.2', campaign_id: '100', adset_id: '101', status: 'PAUSED', effective_status: 'PAUSED', account_id: '111' }
  });
}
const CONTAS = [
  { id: 'act_111', account_id: '111', name: 'Conta real', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' },
  { id: 'act_222', account_id: '222', name: 'Conta dolar', account_status: 1, currency: 'USD', timezone_name: 'America/Sao_Paulo' },
  { id: 'act_333', account_id: '333', name: 'Conta euro', account_status: 1, currency: 'EUR', timezone_name: 'America/Sao_Paulo' }
];
function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/v[\d.]+\//, ''), q = Object.fromEntries(u.searchParams);
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.method === 'POST') {
    let corpo = '';
    req.on('data', b => { corpo += b; });
    req.on('end', () => {
      const f = Object.fromEntries(new URLSearchParams(corpo));
      if (recusarProxima) { const m = recusarProxima; recusarProxima = null; res.statusCode = 400; return ok({ error: { code: 100, error_user_msg: m } }); }
      const { access_token, ...campos } = f;
      gravacoes.push({ id: p, campos });
      if (objetos[p]) { Object.assign(objetos[p], campos); if (campos.status) objetos[p].effective_status = campos.status; }
      ok({ success: true });
    });
    return;
  }
  if (p === 'me/permissions') return ok({ data: permissoes.map(permission => ({ permission, status: 'granted' })) });
  if (p === 'me/adaccounts') return ok({ data: CONTAS });
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
const conectar = () => chamar('POST', '/api/meta/conexao', { token: dono, corpo: { token: TOKEN } });
before(async () => {
  resetar();
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-metactrl-'));
  const porta = 55000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.ok(dono, log.slice(-1500));
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('sem a Meta conectada nada muda', async () => {
  const r = await chamar('POST', '/api/meta/status', { token: dono, corpo: { nivel: 'anuncio', id: '102', camp: '100', ativo: false } });
  assert.strictEqual(r.status, 400);
  assert.match(r.dados.error, /Conecte a Meta/);
  assert.strictEqual(gravacoes.length, 0);
});

test('só a Diretoria mexe, e nunca sem ads_management', async (t) => {
  await t.test('sem login é recusado', async () => {
    for (const [m, c] of [['GET', '/api/meta/campanha/100/estrutura'], ['POST', '/api/meta/status'], ['POST', '/api/meta/orcamento']])
      assert.strictEqual((await chamar(m, c, m === 'POST' ? { corpo: { id: '100', valor: 1 } } : {})).status, 401, c);
  });
  await t.test('conexão sem ads_management não grava', async () => {
    permissoes = ['ads_read'];
    assert.strictEqual((await conectar()).status, 200, log.slice(-800));
    const r = await chamar('POST', '/api/meta/orcamento', { token: dono, corpo: { nivel: 'campanha', id: '100', valor: 600 } });
    assert.strictEqual(r.status, 400);
    assert.match(r.dados.error, /ads_management/);
    assert.strictEqual(gravacoes.length, 0);
  });
  await t.test('quem não é Diretoria é recusado', async () => {
    permissoes = ['ads_read', 'ads_management'];
    assert.strictEqual((await conectar()).status, 200);
    await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [{ id: 'u-gestor', nome: 'Gestor', email: 'gestor@tmx.test', senha: 'senha-gestor-1', cargo: 'Gestor de Tráfego', ativo: true, _updatedAt: Date.now() }] });
    const outro = (await chamar('POST', '/api/auth/login', { corpo: { email: 'gestor@tmx.test', senha: 'senha-gestor-1' } })).dados.token;
    assert.ok(outro);
    assert.strictEqual((await chamar('POST', '/api/meta/orcamento', { token: outro, corpo: { nivel: 'campanha', id: '100', valor: 600 } })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/meta/status', { token: outro, corpo: { nivel: 'anuncio', id: '102', ativo: false } })).status, 403);
    assert.strictEqual(gravacoes.length, 0);
  });
});

test('a tela recebe conjuntos e anúncios como estão na Meta, sem o token', async () => {
  const r = await chamar('GET', '/api/meta/campanha/100/estrutura', { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.ok(!JSON.stringify(r.dados).includes(TOKEN));
  assert.strictEqual(r.dados.moeda, 'BRL');
  assert.deepStrictEqual(r.dados.campanha.orc, { valor: 500, tipo: 'dia' });
  assert.strictEqual(r.dados.conjuntos.length, 1);
  assert.strictEqual(r.dados.conjuntos[0].orc, null);
  assert.deepStrictEqual(r.dados.conjuntos[0].anuncios.map(a => [a.nome, a.status]), [['AD245.1', 'ACTIVE'], ['AD216.2', 'PAUSED']]);
  const d = await chamar('GET', '/api/meta/campanha/200/estrutura', { token: dono });
  assert.strictEqual(d.dados.moeda, 'USD');
  assert.strictEqual(d.dados.campanha.orc, null);
  assert.deepStrictEqual(d.dados.conjuntos[0].orc, { valor: 25, tipo: 'dia' });
  assert.strictEqual((await chamar('GET', '/api/meta/campanha/300/estrutura', { token: dono })).dados.podeOrcamento, false);
});

test('pausar e ativar nos três níveis', async (t) => {
  for (const [nivel, id, camp, acao] of [['anuncio', '102', '100', 'meta_anuncio_pausado'], ['conjunto', '101', '100', 'meta_conjunto_pausado'], ['campanha', '100', '100', 'meta_campanha_pausada']]) {
    await t.test(nivel, async () => {
      gravacoes = [];
      const r = await chamar('POST', '/api/meta/status', { token: dono, corpo: { nivel, id, camp, ativo: false, nome: 'Item ' + id } });
      assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
      assert.deepStrictEqual(gravacoes, [{ id, campos: { status: 'PAUSED' } }]);
      assert.strictEqual(r.dados.mudanca.para, 'PAUSED');
      const au = (await chamar('GET', '/api/auditoria/list', { token: dono })).dados;
      assert.ok(JSON.stringify(au).includes(acao), acao + ' na auditoria');
    });
  }
  await t.test('o endereço antigo continua pausando campanha', async () => {
    gravacoes = [];
    const r = await chamar('POST', '/api/meta/campanha/status', { token: dono, corpo: { id: '100', ativo: true, nome: 'CBO' } });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(gravacoes, [{ id: '100', campos: { status: 'ACTIVE' } }]);
  });
  await t.test('erro da Meta chega na tela e não anota nada', async () => {
    recusarProxima = 'A conta está restrita';
    const r = await chamar('POST', '/api/meta/status', { token: dono, corpo: { nivel: 'anuncio', id: '103', camp: '100', ativo: true } });
    assert.strictEqual(r.status, 400);
    assert.match(r.dados.error, /restrita/);
  });
});

test('orçamento', async (t) => {
  await t.test('vai em centavos no campo certo', async () => {
    resetar(); gravacoes = [];
    const r = await chamar('POST', '/api/meta/orcamento', { token: dono, corpo: { nivel: 'campanha', id: '100', camp: '100', valor: 650.5, de: 500, nome: 'CBO' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.deepStrictEqual(gravacoes, [{ id: '100', campos: { daily_budget: '65050' } }]);
    assert.strictEqual(r.dados.valorReal, 650.5);
    const au = (await chamar('GET', '/api/auditoria/list', { token: dono })).dados;
    assert.ok(JSON.stringify(au).includes('meta_campanha_orcamento'));
  });
  await t.test('orçamento total continua total', async () => {
    gravacoes = [];
    const r = await chamar('POST', '/api/meta/orcamento', { token: dono, corpo: { nivel: 'campanha', id: '400', valor: 12000 } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.deepStrictEqual(gravacoes, [{ id: '400', campos: { lifetime_budget: '1200000' } }]);
    assert.strictEqual(r.dados.tipo, 'total');
  });
  await t.test('conjunto em conta de dólar vai em dólar', async () => {
    gravacoes = [];
    const r = await chamar('POST', '/api/meta/orcamento', { token: dono, corpo: { nivel: 'conjunto', id: '201', camp: '200', valor: 30, de: 25 } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.deepStrictEqual(gravacoes, [{ id: '201', campos: { daily_budget: '3000' } }]);
    assert.strictEqual(r.dados.moeda, 'USD');
  });
  await t.test('não passa por cima de valor que mudou na Meta', async () => {
    gravacoes = [];
    const r = await chamar('POST', '/api/meta/orcamento', { token: dono, corpo: { nivel: 'campanha', id: '100', valor: 900, de: 500 } });
    assert.strictEqual(r.status, 409);
    assert.strictEqual(gravacoes.length, 0);
  });
  await t.test('recusa o que não dá pra mudar', async () => {
    gravacoes = [];
    const caso = async corpo => (await chamar('POST', '/api/meta/orcamento', { token: dono, corpo })).status;
    assert.strictEqual(await caso({ nivel: 'conjunto', id: '101', valor: 100 }), 400, 'conjunto de campanha com orçamento próprio');
    assert.strictEqual(await caso({ nivel: 'campanha', id: '200', valor: 100 }), 400, 'campanha com orçamento nos conjuntos');
    assert.strictEqual(await caso({ nivel: 'campanha', id: '300', valor: 100 }), 400, 'moeda fora da lista');
    assert.strictEqual(await caso({ nivel: 'campanha', id: '100', valor: 0 }), 400, 'zero');
    assert.strictEqual(await caso({ nivel: 'campanha', id: '100', valor: 'abc' }), 400, 'texto');
    assert.strictEqual(await caso({ nivel: 'anuncio', id: '102', valor: 100 }), 400, 'anúncio não tem orçamento');
    assert.strictEqual(gravacoes.length, 0);
  });
});
