// Auditoria IA do projeto (08/11/2026).
// Sobe o servidor numa pasta temporária com uma Utmify falsa e uma Anthropic falsa. Confere quem pode
// rodar, que os números chegam somados dia a dia (hoje, 3 e 7 dias, histórico, cópias, metas), que o
// relatório fica guardado, que a segunda rodada leva as recomendações da primeira e que resposta ruim vira erro.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const PROJETO = 'dash-teste';
let dir, srv, base, log = '', utmify, anthropic;
const pedidosIA = [];
let respostaIA = null, chamadasUtmify = 0, semAnuncios = false;
const espera = ms => new Promise(r => setTimeout(r, ms));
async function ate(cond, ms, oQue) {
  const fim = Date.now() + ms;
  for (;;) {
    try { if (await cond()) return; } catch (e) {}
    if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-3000));
    await espera(120);
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
const diaBR = n => new Date(Date.now() - 3 * 3600000 - n * 86400000).toISOString().slice(0, 10);
const HOJE = diaBR(0), ONTEM = diaBR(1);

// Duas cópias do AD232.HK1 hoje; uma cópia por dia antes. Um teste 1.1.3 e uma campanha de lance.
function linhasAd(dia) {
  if (semAnuncios) return [];
  const idade = [0, 1, 2, 3, 4, 5, 6].find(n => diaBR(n) === dia);
  const ad = (over) => Object.assign({ ca: 'ca 2', status: 'ACTIVE', effectiveStatus: 'ACTIVE', spend: 10000, grossRevenue: 0, approvedOrdersCount: 0, salesFromFacebook: 0, pendingOrdersCount: 0,
    initiateCheckout: 2, landingPageViews: 20, inlineLinkClicks: 25, impressions: 1000, videoViews3Seconds: 300, video75Watched: 30 }, over);
  const l = [ad({ id: 'a1', name: 'AD232.HK1', campaignId: 'c1', spend: 20000, grossRevenue: 70000, approvedOrdersCount: 1, salesFromFacebook: 2 })];
  if (idade === 0) l.push(ad({ id: 'a2', name: 'AD232.HK1', campaignId: 'c2', spend: 30000, initiateCheckout: 0 }));
  if (idade <= 1) l.push(ad({ id: 'a3', name: 'AD300.1', campaignId: 'c3', spend: 15000, status: idade === 0 ? 'PAUSED' : 'ACTIVE', effectiveStatus: idade === 0 ? 'PAUSED' : 'ACTIVE' }));
  if (idade === 0) l.push(ad({ id: 'a4', name: 'AD400.2', campaignId: 'c4', spend: 8000, grossRevenue: 69700, approvedOrdersCount: 1 }));
  return l;
}
function linhasCamp(dia) {
  const c = (id, name, status) => ({ id, name, ca: 'ca 2', status: status || 'ACTIVE', effectiveStatus: status || 'ACTIVE', dailyBudget: 15000, createdTime: ONTEM + 'T10:00:00', spend: 10000 });
  return [c('c1', 'CBO 1.3.1 ca2 04/11'), c('c2', 'CBO 1.3.1 P03 05/11'), c('c3', 'CBO 1.1.3 TESTE AD300', dia === HOJE ? 'PAUSED' : 'ACTIVE'), c('c4', 'BIDCAP principal')];
}
const resumo = (dia) => ({ ads: { spent: dia === HOJE ? 73000 : 50000, clicks: 200, pageViews: 160, initiateCheckouts: 8 }, analytics: { profit: 66700, roas: dia === HOJE ? 1.91 : 1.4 },
  ordersCount: { total: 5, approved: 2, pending: 1, refunded: 0, refusedCreditCard: 2, approvedCreditCard: 2, totalCreditCard: 4, byHour: [{ hour: 8, count: 2 }], byProductName: [{ productName: 'Foco', count: 2, revenue: 139700 }] },
  comissions: { pendingGrossRevenue: 19700, refundedGrossRevenue: 0 }, statistics: {},
  hourlyCumulative: { investmentByHourCumulative: [{ hour: 8, cents: 30000 }, { hour: 19, cents: 73000 }, { hour: 20, cents: 73000 }] } });
function servidorUtmify(req, res) {
  let b = '';
  req.on('data', c => { b += c; });
  req.on('end', () => {
    const c = JSON.parse(b || '{}'), ok = result => { res.setHeader('Content-Type', 'application/json'); res.setHeader('Mcp-Session-Id', 'sessao'); res.end(JSON.stringify({ jsonrpc: '2.0', id: c.id, result })); };
    if (c.method !== 'tools/call') return ok({});
    chamadasUtmify++;
    const a = c.params.arguments || {}, dia = String((a.dateRange || {}).from || '').slice(0, 10);
    let dados = {};
    if (c.params.name === 'get_dashboard_summary') dados = resumo(dia);
    else if (a.level === 'ad') dados = { results: linhasAd(dia) };
    else if (a.level === 'campaign') dados = { results: semAnuncios ? [] : linhasCamp(dia) };
    else if (a.level === 'account') dados = { results: [{ name: 'ca 2', spend: 73000, grossRevenue: 139700, approvedOrdersCount: 2, initiateCheckout: 8 }, { name: 'ca 3', spend: 0 }] };
    ok({ content: [{ type: 'text', text: JSON.stringify(dados) }] });
  });
}
function servidorAnthropic(req, res) {
  let b = '';
  req.on('data', c => { b += c; });
  req.on('end', () => {
    pedidosIA.push({ url: req.url, headers: req.headers, corpo: JSON.parse(b) });
    const texto = respostaIA, usage = { input_tokens: 1000, output_tokens: 500 };
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    const ev = (t, d) => res.write('event: ' + t + '\ndata: ' + JSON.stringify(Object.assign({ type: t }, d)) + '\n\n');
    ev('message_start', { message: { id: 'msg_1', type: 'message', role: 'assistant', model: 'claude-opus-5-5', content: [], stop_reason: null, stop_sequence: null, usage } });
    ev('content_block_start', { index: 0, content_block: { type: 'text', text: '' } });
    ev('content_block_delta', { index: 0, delta: { type: 'text_delta', text: texto } });
    ev('content_block_stop', { index: 0 });
    ev('message_delta', { delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 500 } });
    ev('message_stop', {});
    res.end();
  });
}
const escutar = (fn) => new Promise(r => { const s = http.createServer(fn).listen(0, '127.0.0.1', () => r(s)); });

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-auditoria-'));
  utmify = await escutar(servidorUtmify);
  anthropic = await escutar(servidorAnthropic);
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_integracoes_utmify_mcp: { token: 'tk', modo: 'mcp', dashboards: [{ id: PROJETO, nome: 'CONCURSO', tz: -3 }] } }, timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 51000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
    ANTHROPIC_API_KEY: 'chave-de-teste', ANTHROPIC_BASE_URL: 'http://127.0.0.1:' + anthropic.address().port,
    TMX_UTMIFY_URL: 'http://127.0.0.1:' + utmify.address().port + '/mcp?resources=gs' }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  // numa base nova o servidor derruba as sessões uma vez, 20 s depois de subir (_derrubarSessoesUmaVez)
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (utmify) utmify.close();
  if (anthropic) anthropic.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const pronta = async (token, id) => {
  // devagar: o limite geral da API é 200 pedidos por minuto
  for (let i = 0; i < 90; i++) {
    const r = await chamar('GET', '/api/ia/auditoria/' + id, { token });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-1800));
    if (r.dados.status !== 'rodando') return r.dados;
    await espera(500);
  }
  throw new Error('a análise não terminou\n' + log.slice(-2000));
};
const celulas = (texto, nome) => {
  const l = texto.split('\n').find(x => x.startsWith('| ' + nome + ' |'));
  assert.ok(l, 'achei a linha ' + nome);
  return l.split('|').slice(1, -1).map(c => c.trim());
};

test('auditoria IA', async (t) => {
  const ctx = {};
  ctx.dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.ok(ctx.dono, log.slice(-1500));
  respostaIA = JSON.stringify({ manchete: 'Dia abaixo da meta', markdown: '# Relatório\n\n## 1. Resumo\n\n| A | B |\n|---|---|\n| 1 | 2 |', acoes: [{ prioridade: 'alta', acao: 'Pausar AD300.1', detalhe: 'sem venda' }] });

  await t.test('só quem vê a Análise de tráfego roda', async () => {
    assert.strictEqual((await chamar('POST', '/api/ia/auditoria', { corpo: { projeto: PROJETO } })).status, 401);
    const agora = Date.now();
    await chamar('PUT', '/api/store/sl_usuarios', { token: ctx.dono, corpo: [{ id: 'u-copy', nome: 'Copy', email: 'copy@tmx.test', senha: 'senha-copy-1', cargo: 'Copy', ativo: true, _updatedAt: agora }] });
    const copy = (await chamar('POST', '/api/auth/login', { corpo: { email: 'copy@tmx.test', senha: 'senha-copy-1' } })).dados.token;
    assert.strictEqual((await chamar('POST', '/api/ia/auditoria', { token: copy, corpo: { projeto: PROJETO } })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/ia/auditorias?projeto=' + PROJETO, { token: copy })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/ia/auditoria-metas', { token: copy, corpo: { projeto: PROJETO, metas: { cpa: 1 } } })).status, 403);
  });

  await t.test('sem projeto escolhido não roda', async () => {
    assert.strictEqual((await chamar('POST', '/api/ia/auditoria', { token: ctx.dono, corpo: {} })).status, 400);
    assert.strictEqual(pedidosIA.length, 0);
  });

  await t.test('as metas ficam guardadas por projeto', async () => {
    const s = await chamar('POST', '/api/ia/auditoria-metas', { token: ctx.dono, corpo: { projeto: PROJETO, metas: { fatDia: 3000, lucroDia: 1700, investDia: 1300, cpa: 175, roiMin: 1.5, roiMax: 1.6, principal: 'Foco' } } });
    assert.strictEqual(s.status, 200);
    assert.strictEqual((await chamar('GET', '/api/ia/auditoria-metas?projeto=' + PROJETO, { token: ctx.dono })).dados.metas.fatDia, 3000);
  });

  await t.test('o Claude recebe os números somados e o relatório fica guardado', async () => {
    const r = await chamar('POST', '/api/ia/auditoria', { token: ctx.dono, corpo: { projeto: PROJETO, projetoNome: 'CONCURSO', dia: 'hoje' } });
    assert.strictEqual(r.status, 200);
    const s = await pronta(ctx.dono, r.dados.id);
    assert.strictEqual(s.status, 'pronta', s.erro + log.slice(-1500));
    const p = pedidosIA[0].corpo, dados = p.messages[0].content;
    ctx.dados = dados;
    assert.strictEqual(p.model, 'claude-opus-5-5');
    assert.strictEqual(p.output_config.effort, 'high');
    assert.strictEqual(p.output_config.format.type, 'json_schema');
    assert.strictEqual(p.fallbacks, 'default');
    assert.match(p.system, /Duplicação do fim do dia/);
    assert.match(String(pedidosIA[0].headers['anthropic-beta']), /server-side-fallback-2026-07-01/);

    // AD232.HK1: hoje R$ 200 + R$ 300 em 2 campanhas; 3 dias = 500 + 200 + 200; 7 dias = 500 + 6 x 200
    const c = celulas(dados, 'AD232.HK1');
    assert.strictEqual(c[1], 'ativo');
    assert.strictEqual(c[2], '2', 'duas campanhas no dia');
    assert.strictEqual(c[3], 'R$ 500');
    assert.strictEqual(c[4], '0 / 1 / 2', 'vendas TMX / Utmify / pixel');
    assert.strictEqual(c[8], '900 · 0 / 3 / 6 · 2,33', '3 dias');
    assert.strictEqual(c[9], '1.700 · 0 / 7 / 14 · 2,88', '7 dias');
    assert.strictEqual(c[14].replace('%', ''), '30', 'hook = 3s / impressões');
    assert.strictEqual(celulas(dados, 'AD300.1')[1], 'pausado', 'o status é o de agora');

    assert.match(dados, /\| AD232\.HK1 \| 1 \/ 200 \/ 1 \| 1 \/ 200 \/ 1 \| 1 \/ 200 \/ 1 \| 1 \/ 200 \/ 1 \| 1 \/ 200 \/ 1 \| 1 \/ 200 \/ 1 \| 2 \/ 500 \/ 1 \|/, 'histórico de 7 dias');
    assert.match(dados, /\| AD232\.HK1 \| CBO 1\.3\.1 P03 05\/11 \| ca 2 \|/, 'uma linha por cópia');
    assert.match(dados, /=== BIDCAP[^\n]*\n\| Campanha[^\n]*\n[^\n]*\n\| BIDCAP principal \| ativa \| R\$ 150 \| R\$ 100 \|/);
    assert.match(dados, /=== TESTES CRIATIVOS[\s\S]*\| AD300\.1 \| R\$ 300 \|/);
    assert.ok(!dados.split('=== TESTES CRIATIVOS')[1].split('===')[1].includes('AD232.HK1'), 'CBO 1.3.1 não é teste 1.1.3');
    assert.match(dados, /\| ca 3 \| R\$ 0 \|/, 'conta reserva aparece');

    // meta do dia e fator de escala (CPA 175 = metade da referência)
    assert.match(dados, /Fator de escala das regras em R\$: 0,50/);
    assert.match(dados, /\| Investimento \| R\$ 730 \| até R\$ 1\.300 \| 56% \| R\$ 570 de espaço \|/);
    assert.match(dados, /Receita ligada a anúncio: R\$ 1\.397\. Não rastreada \(orgânico, bio, renovação\): R\$ 0/, 'sem venda no TMX, a receita dos anúncios vem da Utmify');
    assert.match(dados, /parcial até ~20h \(último gasto registrado às 19h\)/);
    assert.match(dados, /\| Cartão recusado \| 2 de 4 \(50%\)/);
    assert.match(dados, /retenção da VSL \(VTurb ainda não conectada/, 'o que não veio é dito');

    const lista = (await chamar('GET', '/api/ia/auditorias?projeto=' + PROJETO, { token: ctx.dono })).dados;
    assert.strictEqual(lista.lista.length, 1);
    assert.strictEqual(lista.lista[0].manchete, 'Dia abaixo da meta');
    assert.strictEqual(lista.lista[0].dia, HOJE);
    assert.strictEqual(lista.rodando, null);
    const a = (await chamar('GET', '/api/ia/auditorias/' + r.dados.id, { token: ctx.dono })).dados;
    assert.match(a.relatorio.markdown, /## 1\. Resumo/);
    assert.ok(a.relatorio.faltou.some(x => /VSL/.test(x)));
    assert.strictEqual(a.custoUS, 0.014, '1000 de entrada a US$ 4 + 500 de saída a US$ 20, por milhão');
    assert.strictEqual(a.n, 1);
  });

  await t.test('analisar ontem usa o dia fechado', async () => {
    const r = await chamar('POST', '/api/ia/auditoria', { token: ctx.dono, corpo: { projeto: PROJETO, projetoNome: 'CONCURSO', dia: 'ontem' } });
    assert.strictEqual((await pronta(ctx.dono, r.dados.id)).status, 'pronta');
    const dados = pedidosIA[1].corpo.messages[0].content;
    assert.match(dados, new RegExp('Dia analisado \\(D\\): ' + ONTEM.slice(8, 10) + '/' + ONTEM.slice(5, 7) + '/\\d{4} · dia fechado'));
    assert.strictEqual(celulas(dados, 'AD300.1')[1], 'ativo', 'ontem o teste ainda estava ativo');
  });

  await t.test('a rodada seguinte cobra as recomendações da anterior', async () => {
    assert.ok(!/AUDITORIA ANTERIOR/.test(ctx.dados), 'a primeira não tem anterior');
    assert.match(pedidosIA[1].corpo.messages[0].content, /RECOMENDAÇÕES DA AUDITORIA ANTERIOR[^\n]*\n- \[alta\] Pausar AD300\.1: sem venda/);
  });

  await t.test('resposta que não dá pra ler vira erro e não fica salva', async () => {
    const antes = (await chamar('GET', '/api/ia/auditorias?projeto=' + PROJETO, { token: ctx.dono })).dados.lista.length;
    respostaIA = 'isso não é JSON';
    const r = await chamar('POST', '/api/ia/auditoria', { token: ctx.dono, corpo: { projeto: PROJETO, projetoNome: 'CONCURSO' } });
    const s = await pronta(ctx.dono, r.dados.id);
    assert.strictEqual(s.status, 'erro');
    assert.match(s.erro, /não deu pra ler/);
    assert.strictEqual((await chamar('GET', '/api/ia/auditorias?projeto=' + PROJETO, { token: ctx.dono })).dados.lista.length, antes);
  });

  await t.test('sem anúncio na Utmify não gasta a chave', async () => {
    semAnuncios = true;
    const n = pedidosIA.length;
    const r = await chamar('POST', '/api/ia/auditoria', { token: ctx.dono, corpo: { projeto: PROJETO, projetoNome: 'CONCURSO' } });
    const s = await pronta(ctx.dono, r.dados.id);
    semAnuncios = false;
    assert.strictEqual(s.status, 'erro');
    assert.match(s.erro, /nenhum anúncio/);
    assert.strictEqual(pedidosIA.length, n);
  });

  await t.test('projeto que não está na Utmify é recusado, nunca vira outro projeto', async () => {
    const n = pedidosIA.length;
    const r = await chamar('POST', '/api/ia/auditoria', { token: ctx.dono, corpo: { projeto: 'outro-projeto', projetoNome: 'X' } });
    const s = await pronta(ctx.dono, r.dados.id);
    assert.strictEqual(s.status, 'erro');
    assert.match(s.erro, /não está ligado na Utmify/);
    assert.strictEqual(pedidosIA.length, n);
  });
});
