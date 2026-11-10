// Regras de tráfego (10/11/2026). Sobe o servidor com uma Meta falsa e confere: a puxada grava os números por
// anúncio; o rascunho e a simulação não mexem em nada; com a execução automática desligada a regra só registra
// "seria"; ligada, pausa uma vez só (não repete no mesmo item); "só avisar" não mexe; orçamento sobe pela
// porcentagem com teto; campanha fixada fica de fora; sem o dado da Meta o item é "sem dado"; e a venda do TMX
// ligada ao anúncio pelo utm_content entra na conta.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const TOKEN = 'EAAtokenDasRegrasDeTrafegoDeTeste1234567890abcdefghijklmnopqrstuv';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };
const hoje = () => new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);

let meta, srv, dir, base, log = '', dono, gravacoes = [], falharPorAnuncio = false, bloqueada = false;
const C = { '100': '1000000000100', '200': '1000000000200' };
const objetos = {
  [C['100']]: { id: C['100'], name: 'CBO 1-1-3 | TESTE | CONCURSO | ' + C['100'], status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '50000', account_id: '111' },
  [C['200']]: { id: C['200'], name: 'ABO | RENDA | ' + C['200'], status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '101': { id: '101', name: 'Aberto', campaign_id: C['100'], status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '201': { id: '201', name: 'Conjunto ABO', campaign_id: C['200'], status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '3000', account_id: '111' },
  '102': { id: '102', name: 'AD226.1 | TESTE', campaign_id: C['100'], adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '103': { id: '103', name: 'AD231.3 | TESTE', campaign_id: C['100'], adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '202': { id: '202', name: 'AD88.1', campaign_id: C['200'], adset_id: '201', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' }
};
const GASTO_AD = { '102': '62.10', '103': '10.00', '202': '40.00' };
function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/v[\d.]+\//, ''), q = u.searchParams;
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.method === 'POST') {
    let corpo = ''; req.on('data', b => { corpo += b; });
    req.on('end', () => { const { access_token, ...campos } = Object.fromEntries(new URLSearchParams(corpo)); gravacoes.push({ id: p, campos }); if (objetos[p]) Object.assign(objetos[p], campos, campos.status ? { effective_status: campos.status } : {}); ok({ success: true }); });
    return;
  }
  if (bloqueada && p === 'act_111/campaigns') { res.statusCode = 400;
    return ok({ error: { message: '(#200) API access blocked.', type: 'OAuthException', code: 200, error_subcode: 2859013, fbtrace_id: 'AbCdEfTraceDeTeste' } }); }
  if (p === 'me/permissions') return ok({ data: ['ads_read', 'ads_management'].map(permission => ({ permission, status: 'granted' })) });
  if (p === 'me/adaccounts') return ok({ data: [{ id: 'act_111', account_id: '111', name: 'ca 2', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' }] });
  if (p === 'me') return ok({ id: '77', name: 'Pessoa Exemplo' });
  const lista = f => Object.values(objetos).filter(f);
  if (p === 'act_111/campaigns') return ok({ data: lista(o => !o.campaign_id) });
  if (p === 'act_111/adsets') return ok({ data: lista(o => o.campaign_id && !o.adset_id) });
  if (p === 'act_111/ads') return ok({ data: lista(o => o.adset_id).map(a => Object.assign({ created_time: '2026-10-01T10:00:00-0300' }, a)) });
  if (p === 'act_111/insights' && q.get('level') === 'ad') {
    if (falharPorAnuncio) { res.statusCode = 400; return ok({ error: { code: 1, message: 'erro temporário' } }); }
    return ok({ data: Object.keys(GASTO_AD).map(id => ({ ad_id: id, ad_name: objetos[id].name, adset_id: objetos[id].adset_id, campaign_id: objetos[id].campaign_id, date_start: hoje(), spend: GASTO_AD[id], impressions: '1000', inline_link_clicks: '20' })) });
  }
  if (p === 'act_111/insights' && q.get('time_increment') && !q.get('breakdowns')) return ok({ data: [
    { campaign_id: C['100'], campaign_name: objetos[C['100']].name, date_start: hoje(), spend: '72.10', impressions: '2000' },
    { campaign_id: C['200'], campaign_name: objetos[C['200']].name, date_start: hoje(), spend: '40.00', impressions: '1000' }] });
  if (objetos[p]) return ok(objetos[p]);
  ok({ data: [] });
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
const regra = extra => Object.assign({ nome: 'Gastou sem vender', sit: 'rascunho', contas: ['111'], alvo: 'anuncio', statusItem: 'ativos', nomeOp: 'tem', termo: 'TESTE', fixas: true,
  junta: 'todas', conds: [{ m: 'gasto', de: 'item', op: '>=', v: 50 }, { m: 'vendas', de: 'item', op: '=', v: 0 }], acao: 'pausar', religar: true, per: 'hoje', freq: 15,
  de: '00:00', ate: '23:59', lim: 10, esp: 6, novoH: 0, zap: false }, extra || {});
const salvar = async r => { const x = await chamar('POST', '/api/regras-trafego', { token: dono, corpo: { regra: r } }); assert.strictEqual(x.status, 200, JSON.stringify(x.dados)); return x.dados.regra; };
const simular = async (r, modo) => { const x = await chamar('POST', '/api/regras-trafego/simular', { token: dono, corpo: { regra: r, modo } }); assert.strictEqual(x.status, 200, JSON.stringify(x.dados)); return x.dados; };
const rodar = async () => { const x = await chamar('POST', '/api/regras-trafego/rodar', { token: dono, corpo: {} }); assert.strictEqual(x.status, 200, JSON.stringify(x.dados)); return x.dados.resumo; };
const historico = async id => (await chamar('GET', '/api/regras-trafego/' + id + '/historico', { token: dono })).dados.itens;

before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-regras-'));
  const porta = 59000 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0' } });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.strictEqual((await chamar('POST', '/api/meta/conexao', { token: dono, corpo: { token: TOKEN } })).status, 200);
  await ate(async () => (await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 2 } })).status === 200, 20000, 'puxada', () => log);
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('a tela recebe as contas, os projetos e desde quando há número por anúncio', async () => {
  const d = (await chamar('GET', '/api/regras-trafego', { token: dono })).dados;
  assert.strictEqual(d.auto, false, 'a execução automática nasce desligada');
  assert.strictEqual(d.podeLigar, true);
  assert.deepStrictEqual(d.opcoes.contas.map(c => c.conta), ['111']);
  assert.strictEqual(d.opcoes.porAnuncioDesde, new Date(Date.now() - 27 * 3600000).toISOString().slice(0, 10));
});

let principal;
test('rascunho e simulação não mexem em nada', async (t) => {
  await t.test('regra sem condição ou orçamento em anúncio é recusada', async () => {
    assert.strictEqual((await chamar('POST', '/api/regras-trafego', { token: dono, corpo: { regra: regra({ conds: [] }) } })).status, 400);
    assert.strictEqual((await chamar('POST', '/api/regras-trafego', { token: dono, corpo: { regra: regra({ acao: 'orcamento', orcLimite: 100 }) } })).status, 400);
  });
  principal = await salvar(regra());
  assert.strictEqual(principal.sit, 'rascunho');
  const s = await simular(principal, 'agora');
  const porNome = Object.fromEntries(s.itens.map(x => [x.nome, x]));
  assert.strictEqual(porNome['AD226.1 | TESTE'].resultado, 'bateu');
  assert.strictEqual(porNome['AD226.1 | TESTE'].valores.Gasto, 'R$ 62,10');
  assert.strictEqual(porNome['AD231.3 | TESTE'].resultado, 'nao');
  assert.ok(!porNome['AD88.1'], 'fora do nome');
  const s7 = await simular(principal, '7d');
  assert.strictEqual(s7.dias.length, 7);
  assert.strictEqual(s7.dias[6].n, 1);
  assert.ok(s7.dias[0].semDado >= 1, 'dia sem números por anúncio aparece como sem dado');
  await rodar();
  assert.strictEqual(gravacoes.length, 0, 'rascunho não roda');
});

test('com a execução automática desligada, a regra ativa só registra', async () => {
  assert.strictEqual((await chamar('POST', '/api/regras-trafego/' + principal.id + '/situacao', { token: dono, corpo: { sit: 'ativa' } })).status, 200);
  const r = await rodar();
  assert.strictEqual(r.find(x => x.regra === principal.id).seria, 1);
  assert.strictEqual(gravacoes.length, 0);
  const h = await historico(principal.id);
  assert.ok(h.some(x => x.resultado === 'seria' && x.nome === 'AD226.1 | TESTE' && x.valores.Gasto === 'R$ 62,10'), JSON.stringify(h));
});

test('ligada, pausa uma vez e não repete no mesmo item', async () => {
  assert.strictEqual((await chamar('POST', '/api/regras-trafego/auto', { token: dono, corpo: { ligado: true } })).status, 200);
  await rodar();
  assert.deepStrictEqual(gravacoes, [{ id: '102', campos: { status: 'PAUSED' } }]);
  gravacoes = [];
  await rodar();
  assert.deepStrictEqual(gravacoes, [], 'na segunda volta já está pausado');
  const hist = (await chamar('GET', '/api/meta/historico', { token: dono })).dados.itens;
  assert.ok(hist.some(i => i.quem === 'Regra · Gastou sem vender' && /pausou o anúncio AD226\.1/.test(i.texto)), JSON.stringify(hist));
  assert.ok((await historico(principal.id)).some(x => x.resultado === 'agiu'));
});

test('só avisar não mexe e manda a notificação', async () => {
  const r = await salvar(regra({ nome: 'Avisa gasto', sit: 'ativa', alvo: 'campanha', nomeOp: '', termo: '', conds: [{ m: 'gasto', de: 'item', op: '>=', v: 1 }], acao: 'avisar' }));
  gravacoes = [];
  const res = await rodar();
  assert.strictEqual(res.find(x => x.regra === r.id).avisou, 2);
  assert.deepStrictEqual(gravacoes, []);
  const notifs = (await chamar('GET', '/api/store', { token: dono })).dados;
  assert.ok(JSON.stringify(notifs).includes('Avisa gasto'), JSON.stringify(notifs).slice(0, 600));
  await chamar('POST', '/api/regras-trafego/' + r.id + '/situacao', { token: dono, corpo: { sit: 'pausada' } });
});

test('orçamento sobe pela porcentagem com teto', async () => {
  const r = await salvar(regra({ nome: 'Escala', sit: 'ativa', alvo: 'campanha', nomeOp: 'tem', termo: 'CBO', conds: [{ m: 'gasto', de: 'item', op: '>=', v: 50 }], acao: 'orcamento', orcDir: 'subir', orcPct: 20, orcLimite: 550 }));
  const s = await simular(r, 'agora');
  assert.deepStrictEqual(s.itens[0].orcamento, { de: 500, para: 550 });
  gravacoes = [];
  await rodar();
  assert.deepStrictEqual(gravacoes, [{ id: C['100'], campos: { daily_budget: '55000' } }]);
  await chamar('POST', '/api/regras-trafego/' + r.id + '/situacao', { token: dono, corpo: { sit: 'pausada' } });
});

test('campanha fixada fica de fora', async () => {
  assert.strictEqual((await chamar('POST', '/api/metricas/campanhas/marca', { token: dono, corpo: { id: C['200'], fixa: true } })).status, 200);
  const s = await simular(regra({ alvo: 'campanha', nomeOp: '', termo: '', conds: [{ m: 'gasto', de: 'item', op: '>=', v: 1 }] }), 'agora');
  assert.ok(s.fora.some(x => x.motivo === 'campanha fixada no topo' && /ABO \| RENDA/.test(x.nome)));
  assert.ok(!s.itens.some(x => /ABO \| RENDA/.test(x.nome)));
});

test('regra de uma campanha só (botão ⚡ da tabela): fica só nela e a tela recebe o nome dela', async () => {
  const r = await salvar(regra({ nome: 'Só a AD226', alvo: 'anuncio', campanhas: [C['100']], nomeOp: '', termo: '', conds: [{ m: 'gasto', de: 'item', op: '>=', v: 1 }] }));
  assert.deepStrictEqual(r.campanhas, [C['100']]);
  const s = await simular(r, 'agora');
  assert.ok(s.itens.length && s.itens.every(x => /CONCURSO/.test(x.campNome)), JSON.stringify(s.itens));
  const d = (await chamar('GET', '/api/regras-trafego', { token: dono })).dados;
  assert.match(d.opcoes.campNomes[C['100']], /CBO 1-1-3 \| TESTE \| CONCURSO/);
});

test('sem o número da Meta, o item é sem dado', async () => {
  const s = await simular(regra({ per: '7d' }), 'agora');
  assert.ok(s.itens.every(x => x.resultado === 'sem_dado'), JSON.stringify(s.itens));
  assert.match(s.itens[0].motivo, /ainda não chegaram por anúncio/);
});

test('a venda do TMX entra no anúncio pelo utm_content', async () => {
  const aviso = new URL((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: dono })).dados.urlWebhook, base).pathname;
  const venda = { id: 'V1', status: 'paid', product: { name: 'Curso', code: 'P1' }, customer: { name: 'Ana', email: 'ana@exemplo.com', phone: '11988887777' },
    transaction: { total_price: 69700, payment_method: 'pix', payment_status: 'paid' },
    utm_source: 'FB', utm_campaign: objetos[C['100']].name, utm_content: 'AD231.3 | TESTE' };   // sem o id: casa pelo nome do anúncio
  assert.strictEqual((await chamar('POST', aviso, { corpo: venda })).status, 200);
  await espera(400);
  const s = await simular(regra({ nomeOp: '', termo: '', statusItem: 'todos', conds: [{ m: 'vendas', de: 'item', op: '>=', v: 1 }] }), 'agora');
  const ad = s.itens.find(x => x.nome === 'AD231.3 | TESTE');
  assert.strictEqual(ad.resultado, 'bateu', JSON.stringify(s.itens));
  assert.strictEqual(ad.valores.Vendas, '1');
});

test('sem permissão de Meta não entra; ligar a chave é só do Dono', async () => {
  assert.strictEqual((await chamar('GET', '/api/regras-trafego')).status, 401);
  await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [{ id: 'u-copy', nome: 'Copy', email: 'copy@tmx.test', senha: 'senha-copy-1', cargo: 'Copy', ativo: true, _updatedAt: Date.now() },
    { id: 'u-gestor', nome: 'Gestor', email: 'gestor@tmx.test', senha: 'senha-gestor-1', cargo: 'Gestor de Tráfego', ativo: true, _updatedAt: Date.now() }] });
  const copy = (await chamar('POST', '/api/auth/login', { corpo: { email: 'copy@tmx.test', senha: 'senha-copy-1' } })).dados.token;
  const gestor = (await chamar('POST', '/api/auth/login', { corpo: { email: 'gestor@tmx.test', senha: 'senha-gestor-1' } })).dados.token;
  assert.strictEqual((await chamar('GET', '/api/regras-trafego', { token: copy })).status, 403);
  assert.strictEqual((await chamar('GET', '/api/regras-trafego', { token: gestor })).status, 200);
  assert.strictEqual((await chamar('POST', '/api/regras-trafego/auto', { token: gestor, corpo: { ligado: false } })).status, 403);
});

test('falha da Meta por anúncio não derruba a puxada da campanha', async () => {
  falharPorAnuncio = true;
  let r; await ate(async () => (r = await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 1 } })).status === 200, 20000, 'puxada', () => log);
  falharPorAnuncio = false;
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.dados.resultado.contas, 1);
  assert.ok(r.dados.resultado.erros.some(e => /por anúncio/.test(e)), JSON.stringify(r.dados.resultado.erros));
});

test('erro da Meta: a tela recebe o código, o subcódigo e o fbtrace_id exatos, não um palpite', async () => {
  bloqueada = true;
  let r; await ate(async () => (r = await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 1 } })).status === 200, 20000, 'puxada', () => log);
  bloqueada = false;
  const erro = r.dados.resultado.erros.find(e => /API access blocked/.test(e));
  assert.ok(erro, JSON.stringify(r.dados.resultado.erros));
  assert.match(erro, /\[Meta: código 200, subcódigo 2859013, OAuthException, «\(#200\) API access blocked\.»\]/);
  assert.doesNotMatch(erro, /bloqueou o app/, 'sem o palpite de que o bloqueio é do app');
  const con = (await chamar('GET', '/api/meta/conexao', { token: dono })).dados;
  assert.deepStrictEqual({ codigo: con.sync.cru.codigo, sub: con.sync.cru.sub, tipo: con.sync.cru.tipo, trace: con.sync.cru.trace },
    { codigo: 200, sub: 2859013, tipo: 'OAuthException', trace: 'AbCdEfTraceDeTeste' });
  assert.match(con.ultimoErro || '', /API access blocked/);
  await ate(async () => (await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 1 } })).status === 200, 20000, 'puxada de volta', () => log);
  const depois = (await chamar('GET', '/api/meta/conexao', { token: dono })).dados;
  assert.strictEqual(depois.ultimoErro, null, 'a Meta voltou: o aviso velho sai do cartão');
  assert.strictEqual(depois.sync.cru, null);
});
