// Conjuntos e anúncios da tabela Por Campanha (11/11/2026). Sobe o servidor com uma Utmify falsa e confere:
// os dois níveis vêm numa resposta só, com orçamento, status e vídeo da Utmify; as vendas são as do TMX (pelo id
// do anúncio no utm_content e, sem id, pelo nome dentro da campanha); a venda sem anúncio conta à parte; o
// conjunto soma as vendas dos anúncios dele; e a segunda consulta não volta na Utmify.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
let dir, srv, base, log = '', utmify, tmx, chamadas = 0;
async function ate(cond, ms, oQue) {
  const fim = Date.now() + ms;
  for (;;) {
    try { if (await cond()) return; } catch (e) {}
    if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-3000));
    await espera(150);
  }
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null;
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
const HOJE = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
const CAMP = '1000000000100', CAMP_NOME = 'CBO 1.3.1 | CONCURSO | AD226.HK1 | ca2 | 05/11';
const obj = over => Object.assign({ accountId: '840757715420067', campaignId: CAMP, ca: 'ca 2', status: 'ACTIVE', effectiveStatus: 'ACTIVE', spend: 10000, grossRevenue: 0,
  approvedOrdersCount: 0, pendingOrdersCount: 0, impressions: 1000, inlineLinkClicks: 20, landingPageViews: 15, initiateCheckout: 2,
  videoViews: 900, videoViews3Seconds: 200, video75Watched: 10, frequency: 1.2, dailyBudget: null, lifetimeBudget: null }, over);
const CONJUNTOS = [
  obj({ id: '1000000000201', adsetId: '1000000000201', name: '01', spend: 12581, grossRevenue: 156818, approvedOrdersCount: 2 }),
  obj({ id: '1000000000202', adsetId: '1000000000202', name: '01 — Cópia', spend: 22342, status: 'PAUSED', effectiveStatus: 'PAUSED' }),
  obj({ id: '1000000000203', adsetId: '1000000000203', campaignId: '1000000000900', name: 'ABO 08', dailyBudget: 4020.5, lifetimeBudget: 0, spend: 0, impressions: 0, videoViews3Seconds: null })
];
const ANUNCIOS = [
  obj({ id: '1000000000301', adId: '1000000000301', adsetId: '1000000000201', name: 'AD226.HK1', spend: 12581, grossRevenue: 156818, approvedOrdersCount: 2 }),
  obj({ id: '1000000000302', adId: '1000000000302', adsetId: '1000000000202', name: 'AD226.HK1', spend: 22342 }),
  obj({ id: '1000000000303', adId: '1000000000303', adsetId: '1000000000201', name: 'AD231.3 | TESTE', spend: 500, status: 'ACTIVE', effectiveStatus: 'DISAPPROVED' })
];
function servidorUtmify(req, res) {
  let b = '';
  req.on('data', c => { b += c; });
  req.on('end', () => {
    const c = JSON.parse(b || '{}'), ok = result => { res.setHeader('Content-Type', 'application/json'); res.setHeader('Mcp-Session-Id', 'sessao'); res.end(JSON.stringify({ jsonrpc: '2.0', id: c.id, result })); };
    if (c.method !== 'tools/call') return ok({});
    const a = c.params.arguments || {};
    let dados = { results: [] };
    if (c.params.name === 'get_meta_ad_objects' && a.level === 'adset') { chamadas++; dados = { results: CONJUNTOS }; }
    else if (c.params.name === 'get_meta_ad_objects' && a.level === 'ad') { chamadas++; dados = { results: ANUNCIOS }; }
    ok({ content: [{ type: 'text', text: JSON.stringify(dados) }] });
  });
}
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-niveis-'));
  utmify = await new Promise(r => { const s = http.createServer(servidorUtmify).listen(0, '127.0.0.1', () => r(s)); });
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_integracoes_utmify_mcp: { token: 'tk', modo: 'mcp', dashboards: [{ id: 'dash-teste', nome: 'CONCURSO', tz: -3 }] } }, timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 49000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
    TMX_UTMIFY_URL: 'http://127.0.0.1:' + utmify.address().port + '/mcp?resources=gs' }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
  tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  // três vendas pagas hoje: uma com o id do anúncio, uma só com o nome, uma com anúncio que não existe
  const aviso = new URL((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: tmx })).dados.urlWebhook, base).pathname;
  const venda = (id, cont) => ({ id, status: 'paid', product: { name: 'Apostilai Foco', code: 'P1' }, customer: { name: 'Pessoa', email: id + '@exemplo.com', phone: '11988887777' },
    transaction: { total_price: 83976, payment_method: 'pix', payment_status: 'paid' }, utm_source: 'FB', utm_campaign: CAMP_NOME + ' | ' + CAMP, utm_content: cont });
  for (const v of [venda('V1', 'AD226.HK1 | 1000000000301'), venda('V2', 'AD231.3 | TESTE'), venda('V3', 'AD999 sumiu')]) {
    assert.strictEqual((await chamar('POST', aviso, { corpo: v })).status, 200);
  }
  await espera(400);
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (utmify) utmify.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('sem sessão não entra', async () => {
  assert.strictEqual((await chamar('GET', '/api/metricas/utmify/niveis?de=' + HOJE + '&ate=' + HOJE)).status, 401);
});

test('conjuntos e anúncios com as vendas do TMX', async () => {
  const r = await chamar('GET', '/api/metricas/utmify/niveis?de=' + HOJE + '&ate=' + HOJE, { token: tmx });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados, ad = id => d.anuncios.find(x => x.id === id), cj = id => d.conjuntos.find(x => x.id === id);
  assert.strictEqual(d.fonteReceita, 'tmx');
  assert.deepStrictEqual([d.conjuntos.length, d.anuncios.length], [3, 3]);
  // pelo id: AD226.HK1 do conjunto 01
  assert.deepStrictEqual([ad('1000000000301').aprovadas, ad('1000000000301').faturamento], [1, 839.76]);
  // só o nome: AD231.3 | TESTE, o único com esse nome na campanha
  assert.deepStrictEqual([ad('1000000000303').aprovadas, ad('1000000000303').conjuntoId], [1, '1000000000201']);
  assert.strictEqual(ad('1000000000302').aprovadas, 0);
  // o conjunto soma os anúncios dele
  assert.deepStrictEqual([cj('1000000000201').aprovadas, cj('1000000000201').faturamento], [2, 1679.52]);
  assert.strictEqual(cj('1000000000202').aprovadas, 0);
  // a venda de anúncio que não existe conta à parte, na campanha
  assert.deepStrictEqual(d.semAnuncio, { [CAMP]: 1 });
  // o que vem da Utmify continua lá
  const a1 = ad('1000000000301');
  assert.deepStrictEqual([a1.investimento, a1.fatUtmify, a1.vendasUtmify, a1.conta, a1.contaId, a1.campanhaId], [125.81, 1568.18, 2, 'ca 2', '840757715420067', CAMP]);
  assert.strictEqual(a1.hook, 0.2);
  assert.strictEqual(Math.round(a1.lucro * 100) / 100, Math.round((839.76 - 125.81) * 100) / 100);
  assert.deepStrictEqual([ad('1000000000303').status, ad('1000000000303').efetivo], ['ACTIVE', 'DISAPPROVED']);
  // orçamento: o do conjunto ABO aparece; o do CBO fica na campanha (null); sem vídeo, sem hook
  assert.deepStrictEqual([cj('1000000000203').orc, cj('1000000000201').orc, cj('1000000000203').hook], [40.205, null, null]);
});

test('a segunda consulta usa o que já veio da Utmify', async () => {
  const antes = chamadas;
  const r = await chamar('GET', '/api/metricas/utmify/niveis?de=' + HOJE + '&ate=' + HOJE, { token: tmx });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(chamadas, antes);
  assert.strictEqual(r.dados.anuncios.find(x => x.id === '1000000000301').aprovadas, 1, 'a cópia guardada não acumula venda');
});
