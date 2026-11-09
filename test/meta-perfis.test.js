// Vários perfis na Meta (09/11/2026): cada perfil soma contas e pixels, conta repetida aparece uma vez, cada conta sai pelo
// perfil que a enxerga, desconectar tira só o que era dele e a conexão de antes continua funcionando sem migração.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const APP_ID = '1234567890';
const T = n => 'EAAtokenDoPerfil' + n + 'DeTeste1234567890abcdefghijklmnopqrstuvwxyz';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

// cada token é um perfil: A enxerga 111 e 222; B enxerga 222 e 333
const PERFIS = {
  [T('A')]: { id: '7001', name: 'Perfil A', contas: ['111', '222'], pixels: ['900100000000001'] },
  [T('B')]: { id: '7002', name: 'Perfil B', contas: ['222', '333'], pixels: ['900200000000002'] }
};
const mortos = new Set(), semPermissao = new Set();
const curtos = { 'curto-a': T('A'), 'curto-b': T('B') };
let meta, srv, dir, base, log = '', dono, gestor, chamadas = [];
function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/v[\d.]+\//, '');
  let corpo = '';
  req.on('data', b => { corpo += b; });
  req.on('end', () => {
    const q = req.method === 'POST' ? new URLSearchParams(corpo) : u.searchParams, tk = q.get('access_token') || '', pf = PERFIS[tk];
    const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
    const erro = (code, message) => { res.statusCode = 400; ok({ error: { code, message } }); };
    if (p === 'oauth/access_token') return ok({ access_token: curtos[q.get('fb_exchange_token')] || T('A'), token_type: 'bearer', expires_in: 5184000 });
    if (p === 'debug_token') return ok({ data: { app_id: APP_ID, type: 'USER', expires_at: Math.floor(Date.now() / 1000) + 5184000 } });
    chamadas.push({ metodo: req.method, p, tk, quebra: u.searchParams.get('breakdowns') || '', periodo: u.searchParams.get('time_range') || '' });
    if (!pf || mortos.has(tk)) return erro(190, 'token recusado');
    if (p === 'me/permissions') return ok({ data: ['ads_read', 'ads_management'].map(permission => ({ permission, status: 'granted' })) });
    if (p === 'me/adaccounts') return ok({ data: pf.contas.map(c => ({ id: 'act_' + c, account_id: c, name: 'Conta ' + c, account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' })) });
    if (p === 'me') return ok({ id: pf.id, name: pf.name });
    const c = /^act_(\d+)\//.exec(p);
    if (c && (pf.contas.indexOf(c[1]) < 0 || semPermissao.has(tk + c[1]))) return erro(200, 'sem permissão nesta conta');
    if (c && /adspixels$/.test(p)) return ok({ data: c[1] === pf.contas[0] ? pf.pixels.map(id => ({ id, name: 'Pixel ' + id })) : [] });
    if (c && /campaigns$/.test(p)) return ok({ data: [{ id: '5' + c[1], name: 'Campanha ' + c[1], status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '5000' }] });
    if (c && /insights$/.test(p) && u.searchParams.get('time_increment') && !u.searchParams.get('breakdowns')) return ok({ data: [{ campaign_id: '5' + c[1], campaign_name: 'Campanha ' + c[1], date_start: new Date().toISOString().slice(0, 10), spend: '10.00', impressions: '100' }] });
    if (req.method === 'POST') return /^5333$/.test(p) && pf.contas.indexOf('333') < 0 ? erro(100, 'objeto não encontrado') : ok({ success: true });
    if (/^900\d{12}$/.test(p)) return ok({ id: p, name: 'Pixel ' + p });
    ok({ data: [] });
  });
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.clone().json(); } catch (e) {}
  return { status: r.status, dados, texto: await r.text() };
}
const entrar = async (email, senha) => (await chamar('POST', '/api/auth/login', { corpo: { email, senha } })).dados.token;
const conexao = async () => (await chamar('GET', '/api/meta/conexao', { token: dono })).dados;
const banco = () => JSON.parse(fs.readFileSync(path.join(dir, 'db.json'), 'utf8'));
const conectar = (curto, token = gestor) => chamar('POST', '/api/meta/login', { token, corpo: { accessToken: curto } });
const puxar = async () => { await ate(async () => { const r = await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 2 } }); if (r.status === 200) { puxar.ultimo = r.dados.resultado; return true; } return false; }, 20000, 'puxada', () => log); return puxar.ultimo; };
const usouEm = conta => chamadas.filter(x => x.p === 'act_' + conta + '/campaigns').map(x => x.tk);

before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-metaperfis-'));
  const porta = 63100 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
    META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0', META_APP_ID: APP_ID, META_APP_SECRET: 'segredo-de-teste', META_LOGIN_CONFIG_ID: '555' } });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = await entrar('thiago@axcend.com', 'axcend2026');
  await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [{ id: 'u-gestor', nome: 'Gestor Teste', email: 'gestor@tmx.test', senha: 'senha-gestor-1', cargo: 'Gestor de Tráfego', ativo: true, _updatedAt: Date.now() }] });
  gestor = await entrar('gestor@tmx.test', 'senha-gestor-1');
  assert.ok(dono && gestor, log.slice(-1500));
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('a conexão de antes vira um perfil, sem migrar nada', async () => {
  const d = banco();
  d.store.sl_integracoes_meta = { accessToken: T('A'), tipo: 'sistema', via: 'facebook', conectadoEm: '2026-11-09T16:36:05.384Z', quem: { id: '7001', nome: 'Perfil A' }, permissoes: ['ads_read', 'ads_management'],
    expiraEm: Date.now() + 86400000 * 50, listasEm: '2026-11-09T16:36:05.384Z',
    contas: [{ id: 'act_111', conta: '111', nome: 'Conta 111', status: 1, moeda: 'BRL' }, { id: 'act_222', conta: '222', nome: 'Conta 222', status: 1, moeda: 'BRL' }],
    pixels: [{ id: '900100000000001', nome: 'Pixel 1', contas: ['111'] }] };
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify(d));
  const c = await conexao();
  assert.strictEqual(c.conectado, true);
  assert.deepStrictEqual(c.perfis.map(p => [p.id, p.nome, p.contas, p.pixels, p.caiu]), [['7001', 'Perfil A', 2, 1, false]]);
  assert.deepStrictEqual(c.contas.map(x => x.perfis), [['7001'], ['7001']]);
  assert.strictEqual(c.conectadoEm, '2026-11-09T16:36:05.384Z');
  chamadas = [];
  const r = await puxar();
  assert.strictEqual(r.contas, 2, JSON.stringify(r));
  assert.deepStrictEqual(usouEm('111'), [T('A')]);
});

test('outro perfil soma, sem repetir conta e sem recomeçar a semana de comparação', async (t) => {
  const r = await conectar('curto-b');
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-600));
  assert.deepStrictEqual(r.dados.novo, { nome: 'Perfil B', contas: 2, pixels: 1 });
  assert.ok(!r.texto.includes(T('B')) && !r.texto.includes(T('A')), 'token nenhum sai do servidor');
  const c = await conexao();
  await t.test('dois perfis, na ordem em que conectaram', () => assert.deepStrictEqual(c.perfis.map(p => p.nome), ['Perfil A', 'Perfil B']));
  await t.test('conta que os dois enxergam aparece uma vez', () => {
    assert.deepStrictEqual(c.contas.map(x => x.conta).sort(), ['111', '222', '333']);
    assert.deepStrictEqual(c.contas.find(x => x.conta === '222').perfis, ['7001', '7002']);
  });
  await t.test('os pixels somam', () => assert.deepStrictEqual(c.pixels.map(x => x.id).sort(), ['900100000000001', '900200000000002']));
  await t.test('a semana de comparação não recomeça', () => assert.strictEqual(c.conectadoEm, '2026-11-09T16:36:05.384Z'));
  await t.test('o aviso de conexão nova muda, para o link saber que chegou', () => assert.notStrictEqual(c.ultimaConexaoEm, c.conectadoEm));
  await t.test('o projeto mostra por qual perfil vem a conta, só para quem mexe na Meta', async () => {
    const p = (await chamar('GET', '/api/projeto/config?projeto=Teste', { token: gestor })).dados;
    assert.deepStrictEqual(p.contas.find(x => x.conta === '222').por, ['Perfil A', 'Perfil B']);
  });
});

test('o mesmo perfil entrando de novo só renova', async () => {
  assert.strictEqual((await conectar('curto-a')).status, 200);
  const c = await conexao();
  assert.deepStrictEqual(c.perfis.map(p => p.nome), ['Perfil A', 'Perfil B']);
});

test('o token nunca sai pela sincronização nem pela conexão', async () => {
  const a = await chamar('GET', '/api/meta/conexao', { token: gestor }), b = await chamar('GET', '/api/store', { token: dono });
  [a.texto, b.texto].forEach(x => { assert.ok(!x.includes(T('A')) && !x.includes(T('B'))); });
  assert.strictEqual(a.dados.tokenFim, '', 'gestor não vê nem o fim do token');
});

test('cada conta sai pelo perfil que a enxerga', async () => {
  await espera(900);
  chamadas = [];
  const r = await puxar();
  assert.strictEqual(r.contas, 3, JSON.stringify(r));
  assert.deepStrictEqual(usouEm('111'), [T('A')]);
  assert.deepStrictEqual(usouEm('222'), [T('A')], 'conta repetida usa quem conectou primeiro');
  assert.deepStrictEqual(usouEm('333'), [T('B')]);
});

test('a puxada de 15 em 15 minutos traz só o gasto de hoje', async () => {
  const antes = banco().store.sl_integracoes_meta.sync.atividadesAte;
  assert.ok(antes, 'a puxada completa marcou até onde viu o histórico');
  chamadas = [];
  await espera(5);
  await ate(async () => (await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { leve: true } })).status === 200, 20000, 'puxada leve', () => log);
  const de111 = chamadas.filter(x => x.p.startsWith('act_111/'));
  assert.ok(de111.some(x => x.p === 'act_111/campaigns'), 'campanhas e orçamento vêm');
  assert.ok(de111.some(x => x.p === 'act_111/insights' && /hourly/.test(x.quebra)), 'hora a hora vem');
  assert.ok(!de111.some(x => /publisher_platform/.test(x.quebra)), 'posicionamento fica para a completa');
  assert.ok(!de111.some(x => x.p === 'act_111/activities'), 'histórico fica para a completa');
  const hoje = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
  assert.ok(de111.filter(x => x.periodo).every(x => JSON.parse(x.periodo).since === hoje), 'só hoje: ' + JSON.stringify(de111.map(x => x.periodo)));
  const s = banco().store.sl_integracoes_meta.sync;
  assert.strictEqual(s.leve, true);
  assert.strictEqual(s.atividadesAte, antes, 'a leve não marca o histórico como visto');
  chamadas = [];
  await puxar();
  const c = chamadas.filter(x => x.p.startsWith('act_111/'));
  assert.ok(c.some(x => x.p === 'act_111/activities') && c.some(x => /publisher_platform/.test(x.quebra)), 'a completa continua trazendo tudo');
  assert.notStrictEqual(banco().store.sl_integracoes_meta.sync.atividadesAte, antes);
});

test('pausar sai pelo perfil da conta daquela campanha', async () => {
  chamadas = [];
  const r = await chamar('POST', '/api/meta/status', { token: gestor, corpo: { nivel: 'campanha', id: '5333', ativo: false, nome: 'Campanha 333' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.deepStrictEqual(chamadas.filter(x => x.metodo === 'POST').map(x => x.tk), [T('B')]);
});

test('o pixel confere com o perfil que enxerga ele', async () => {
  chamadas = [];
  const r = await chamar('POST', '/api/destinos', { token: dono, corpo: { nome: 'Destino B', pixel: '900200000000002' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.deepStrictEqual(chamadas.filter(x => x.p === '900200000000002').map(x => x.tk), [T('B')]);
});

test('sem permissão numa conta, passa para o outro perfil e não dá o perfil por caído', async () => {
  semPermissao.add(T('A') + '222');
  chamadas = [];
  const r = await puxar();
  semPermissao.clear();
  assert.strictEqual(r.contas, 3, JSON.stringify(r));
  assert.deepStrictEqual(r.erros, []);
  assert.deepStrictEqual(usouEm('222'), [T('A'), T('B')]);
  assert.strictEqual(r.campanhas, 3, 'a tentativa que falhou não conta em dobro');
  assert.deepStrictEqual((await conexao()).perfis.map(p => p.caiu), [false, false]);
});

test('perfil que caiu passa as contas para o outro e fica marcado', async (t) => {
  mortos.add(T('A'));
  chamadas = [];
  const r = await puxar();
  await t.test('a conta dos dois continua, pelo outro perfil', () => {
    assert.deepStrictEqual(usouEm('111'), [T('A')]);
    assert.deepStrictEqual(usouEm('222'), [T('B')], 'caiu na primeira conta, nas outras nem tenta');
    assert.strictEqual(r.contas, 2, JSON.stringify(r));
  });
  await t.test('a conta só dele aparece como erro', () => assert.ok(r.erros.some(e => /Conta 111/.test(e)), JSON.stringify(r.erros)));
  const c = await conexao();
  await t.test('o perfil fica para reconectar e a Meta segue conectada', () => {
    assert.strictEqual(c.conectado, true);
    assert.deepStrictEqual(c.perfis.map(p => p.caiu), [true, false]);
    assert.ok(c.perfis[0].erro);
  });
  await t.test('a próxima puxada nem tenta com ele', async () => {
    chamadas = [];
    const r2 = await puxar();
    assert.deepStrictEqual(usouEm('222'), [T('B')]);
    assert.deepStrictEqual(usouEm('111'), []);
    assert.ok(r2.erros.some(e => /sem perfil com acesso/.test(e)), JSON.stringify(r2.erros));
  });
  await t.test('o projeto avisa a conta sem acesso', async () => {
    const p = (await chamar('GET', '/api/projeto/config?projeto=Teste', { token: gestor })).dados;
    assert.strictEqual(p.contas.find(x => x.conta === '111').semAcesso, true);
    assert.strictEqual(p.contas.find(x => x.conta === '222').semAcesso, false);
  });
  await t.test('voltou a responder, volta sozinho', async () => {
    mortos.delete(T('A'));
    await puxar();
    assert.deepStrictEqual((await conexao()).perfis.map(p => p.caiu), [false, false]);
  });
});

test('atualizar um perfil não mexe no outro', async () => {
  chamadas = [];
  const r = await chamar('POST', '/api/meta/conexao/atualizar', { token: gestor, corpo: { perfil: '7002' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.ok(chamadas.length && chamadas.every(x => x.tk === T('B')));
  assert.strictEqual((await chamar('POST', '/api/meta/conexao/atualizar', { token: gestor, corpo: { perfil: '999' } })).status, 404);
});

test('desconectar tira só o que era dele', async (t) => {
  const r = await chamar('POST', '/api/meta/conexao/desconectar', { token: gestor, corpo: { perfil: '7002' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const c = await conexao();
  await t.test('o outro perfil continua', () => assert.deepStrictEqual(c.perfis.map(p => p.nome), ['Perfil A']));
  await t.test('sai a conta só dele e fica a dos dois', () => assert.deepStrictEqual(c.contas.map(x => x.conta).sort(), ['111', '222']));
  await t.test('o histórico diz qual perfil', async () => {
    const h = (await chamar('GET', '/api/meta/historico', { token: dono })).dados.itens;
    assert.ok(h.some(i => i.quem === 'Gestor Teste' && i.texto === 'desconectou o perfil Perfil B da Meta'), JSON.stringify(h));
  });
  await t.test('perfil que não está conectado dá erro', async () => assert.strictEqual((await chamar('POST', '/api/meta/conexao/desconectar', { token: gestor, corpo: { perfil: '7002' } })).status, 404));
  await t.test('o token dele sai do banco', () => assert.ok(!fs.readFileSync(path.join(dir, 'db.json'), 'utf8').includes(T('B'))));
  await t.test('o último desconecta a Meta', async () => {
    assert.strictEqual((await chamar('POST', '/api/meta/conexao/desconectar', { token: gestor, corpo: { perfil: '7001' } })).status, 200);
    const v = await conexao();
    assert.strictEqual(v.conectado, false);
    assert.deepStrictEqual(v.perfis, []);
    assert.ok(!fs.readFileSync(path.join(dir, 'db.json'), 'utf8').includes(T('A')));
  });
});

test('o link diz quem entrou e quantas contas são dele', async () => {
  assert.strictEqual((await conectar('curto-a')).status, 200);
  const g = (await chamar('POST', '/api/meta/login/link', { token: gestor, corpo: {} })).dados;
  const api = '/api/meta/login/link/' + g.caminho.split('/').pop();
  assert.strictEqual((await chamar('GET', api)).dados.jaTem, 1);
  const r = await chamar('POST', api, { corpo: { accessToken: 'curto-b' } });
  assert.deepStrictEqual(r.dados, { ok: true, contas: 2, perfil: 'Perfil B' });
  assert.strictEqual((await conexao()).perfis.length, 2);
});
