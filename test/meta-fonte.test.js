// Fonte "Meta" na Análise de tráfego › Por Campanha (12/11/2026). Empresa sem Utmify (e quem revisa o app na Meta) via
// a tabela vazia. Sobe o servidor com uma Meta falsa, puxa os números e confere: as campanhas vêm do que a SCALROI
// guardou da Meta, com orçamento (CBO e ABO), status e conta; a campanha sem gasto aparece se é recente, a antiga
// pausada não; as vendas são as da SCALROI, reconhecidas pelo id da campanha mesmo com o nome mudado; o projeto de
// Projetos › Integrações corta campanhas e vendas; conjuntos e anúncios vêm no formato da Utmify, com a venda no
// anúncio do utm_content; e pausar daqui aparece na hora.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const TOKEN = 'EAAtokenDaFonteMetaDeTesteNaAnaliseDeTrafego1234567890abcdefghijkl';
const espera = ms => new Promise(r => setTimeout(r, ms));
const hoje = () => new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
let meta, srv, dir, base, log = '', dono, ia;
const pedidosIA = [];   // o que a Auditoria IA mandaria pro Claude (uma Anthropic de mentira guarda e recusa)
const ate = async (cond, ms, oQue) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-2000)); await espera(150); } };

const C = { cbo: '1000000000100', abo: '1000000000200', nova: '1000000000300', velha: '1000000000400', recente: '1000000000500' };
const agoraIso = new Date().toISOString().replace('Z', '+0000');
const ha10dias = new Date(Date.now() - 10 * 86400000).toISOString().replace('Z', '+0000');
const objetos = {
  [C.cbo]: { id: C.cbo, name: 'CBO 1-1-3 | CONCURSO | ' + C.cbo, status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '50000', created_time: '2026-11-01T10:00:00-0300', account_id: '111' },
  [C.abo]: { id: C.abo, name: 'ABO | RENDA | ' + C.abo, status: 'ACTIVE', effective_status: 'ACTIVE', created_time: '2026-11-01T10:00:00-0300', account_id: '111' },
  [C.nova]: { id: C.nova, name: 'TESTE NOVA | CONCURSO', status: 'PAUSED', effective_status: 'PAUSED', created_time: agoraIso, account_id: '111' },
  [C.velha]: { id: C.velha, name: 'VELHA PAUSADA | CONCURSO', status: 'PAUSED', effective_status: 'PAUSED', created_time: '2025-01-10T10:00:00-0300', account_id: '111' },
  [C.recente]: { id: C.recente, name: 'PAUSADA HA 10 DIAS | CONCURSO', status: 'PAUSED', effective_status: 'PAUSED', created_time: ha10dias, account_id: '111' },
  '101': { id: '101', name: 'Aberto', campaign_id: C.cbo, status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '201': { id: '201', name: 'Conjunto ABO', campaign_id: C.abo, status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '3000', account_id: '111' },
  '102': { id: '102', name: 'AD226.1 | TESTE', campaign_id: C.cbo, adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '103': { id: '103', name: 'AD231.3 | TESTE', campaign_id: C.cbo, adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '202': { id: '202', name: 'AD88.1', campaign_id: C.abo, adset_id: '201', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' }
};
const GASTO_AD = { '102': '62.10', '103': '10.00', '202': '40.00' };
function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/v[\d.]+\//, ''), q = u.searchParams;
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.method === 'POST') {
    let corpo = ''; req.on('data', b => { corpo += b; });
    req.on('end', () => { const { access_token, ...campos } = Object.fromEntries(new URLSearchParams(corpo)); if (objetos[p]) Object.assign(objetos[p], campos, campos.status ? { effective_status: campos.status } : {}); ok({ success: true }); });
    return;
  }
  if (p === 'me/permissions') return ok({ data: ['ads_read', 'ads_management'].map(permission => ({ permission, status: 'granted' })) });
  if (p === 'me/adaccounts') return ok({ data: [{ id: 'act_111', account_id: '111', name: 'ca 2', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' }] });
  if (p === 'me') return ok({ id: '77', name: 'Pessoa Exemplo' });
  const lista = f => Object.values(objetos).filter(f);
  if (p === 'act_111/campaigns') return ok({ data: lista(o => !o.campaign_id) });
  if (p === 'act_111/adsets') return ok({ data: lista(o => o.campaign_id && !o.adset_id) });
  if (p === 'act_111/ads') return ok({ data: lista(o => o.adset_id).map(a => Object.assign({ created_time: '2026-10-01T10:00:00-0300' }, a)) });
  if (p === 'act_111/insights' && q.get('level') === 'ad') return ok({ data: Object.keys(GASTO_AD).map(id => ({ ad_id: id, ad_name: objetos[id].name, adset_id: objetos[id].adset_id,
    campaign_id: objetos[id].campaign_id, date_start: hoje(), spend: GASTO_AD[id], impressions: '1000', inline_link_clicks: '20' })) });
  if (p === 'act_111/insights' && /^hourly/.test(q.get('breakdowns') || '')) return ok({ data: [
    { campaign_id: C.cbo, spend: '30.00', impressions: '800', inline_link_clicks: '15', hourly_stats_aggregated_by_advertiser_time_zone: '09:00:00 - 09:59:59' },
    { campaign_id: C.cbo, spend: '42.10', impressions: '1200', inline_link_clicks: '25', hourly_stats_aggregated_by_advertiser_time_zone: '10:00:00 - 10:59:59' },
    { campaign_id: C.abo, spend: '40.00', impressions: '1000', inline_link_clicks: '10', hourly_stats_aggregated_by_advertiser_time_zone: '11:00:00 - 11:59:59' }] });
  if (p === 'act_111/insights' && q.get('time_increment') && !q.get('breakdowns')) return ok({ data: [
    { campaign_id: C.cbo, campaign_name: objetos[C.cbo].name, date_start: hoje(), spend: '72.10', impressions: '2000', inline_link_clicks: '40', frequency: '1.5',
      actions: [{ action_type: 'landing_page_view', value: '30' }, { action_type: 'video_view', value: '600' }], video_play_actions: [{ action_type: 'video_view', value: '900' }],
      video_p75_watched_actions: [{ action_type: 'video_view', value: '50' }] },
    { campaign_id: C.abo, campaign_name: objetos[C.abo].name, date_start: hoje(), spend: '40.00', impressions: '1000', inline_link_clicks: '10' }] });
  if (objetos[p]) return ok(objetos[p]);
  ok({ data: [] });
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
const per = () => '?de=' + hoje() + '&ate=' + hoje();

before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  ia = await new Promise(r => { const s = http.createServer((req, res) => { let b = ''; req.on('data', x => { b += x; }); req.on('end', () => {
    try { pedidosIA.push(JSON.parse(b)); } catch (e) {}
    res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'teste' } })); }); }).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-meta-fonte-'));
  // os dois projetos dividem a conta 111 pela palavra no nome da campanha
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_projetos_meta: { CONCURSO: { contas: ['111'], regra: 'CONCURSO' }, RENDA: { contas: ['111'], regra: 'RENDA' } } },
    timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 47000 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
    META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0',
    ANTHROPIC_API_KEY: 'chave-de-teste', ANTHROPIC_BASE_URL: 'http://127.0.0.1:' + ia.address().port }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.strictEqual((await chamar('POST', '/api/meta/conexao', { token: dono, corpo: { token: TOKEN } })).status, 200);
  await ate(async () => (await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 2 } })).status === 200, 20000, 'puxada');
  // duas vendas pagas hoje: uma da campanha CBO (com o nome antigo na UTM e o nome do anúncio 102 no utm_content), uma sem campanha
  const aviso = new URL((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: dono })).dados.urlWebhook, base).pathname;
  const venda = (id, extra) => Object.assign({ id, status: 'paid', product: { name: 'Apostilai Foco', code: 'P1' }, customer: { name: 'Pessoa', email: id + '@exemplo.com', phone: '11988887777' },
    transaction: { total_price: 83976, payment_method: 'pix', payment_status: 'paid' } }, extra);
  assert.strictEqual((await chamar('POST', aviso, { corpo: venda('M1', { utm_source: 'FB', utm_campaign: 'NOME ANTIGO CONCURSO | ' + C.cbo, utm_content: 'AD226.1 | TESTE' }) })).status, 200);
  assert.strictEqual((await chamar('POST', aviso, { corpo: venda('M2', {}) })).status, 200);
  // visitas pelo pixel da SCALROI (antes de qualquer tela pedir: a conta fica guardada 1 min)
  const visita = (id, camp, cont, extra) => chamar('POST', '/api/funil/evento', { corpo: Object.assign({ id, funil: 'f1', etapa: 'e1', tipo: 'entrou', pg: 'site.com/a', sid: 's' + id,
    aqui: { utm_source: 'FB', utm_campaign: camp, utm_content: cont } }, extra || {}) });
  await visita('v1', 'CBO 1-1-3 | CONCURSO | ' + C.cbo, 'AD231.3 | TESTE');
  await visita('v1', 'CBO 1-1-3 | CONCURSO | ' + C.cbo, 'AD231.3 | TESTE');   // a mesma pessoa de novo: conta uma
  await visita('v2', 'NOME ANTIGO | ' + C.cbo, 'AD226.1 | TESTE');
  await visita('v3', 'CBO 1-1-3 | CONCURSO | ' + C.cbo, 'AD226.1 | TESTE', { interno: 1 });   // a equipe não conta
  await visita('v4', 'ABO | RENDA', 'AD88.1');   // sem o id da campanha: entra pelo nome
  await espera(400);
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
  if (ia) ia.close();
});

test('sem sessão não entra', async () => {
  for (const r of ['painel', 'niveis', 'projetos', 'panorama', 'filtros', 'anuncios', 'tempo-real']) assert.strictEqual((await chamar('GET', '/api/metricas/meta/' + r + per())).status, 401, r);
});

test('campanhas da Meta com as vendas da SCALROI', async () => {
  const r = await chamar('GET', '/api/metricas/meta/painel' + per(), { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados, c = id => d.porCampanha.find(x => x.campanhaId === id);
  assert.strictEqual(d.conectada, true);
  assert.ok(c(C.cbo) && c(C.abo) && c(C.nova), 'as duas que gastaram e a nova sem gasto');
  assert.ok(!c(C.velha), 'a pausada antiga sem gasto fica de fora');
  assert.ok(!c(C.recente), 'pausada há 10 dias, sem gasto e sem mudança: fora, como na Utmify (antes entrava por ser dos últimos 30 dias)');
  const k = c(C.cbo);
  assert.deepStrictEqual([k.investimento, k.impressoes, k.cliques, k.lpv, k.status, k.conta, k.contaId, k.orc, k.orcVida], [72.1, 2000, 40, 30, 'ACTIVE', 'ca 2', '111', 500, false]);
  // a venda veio com o nome antigo na UTM: entra pela id da campanha
  assert.deepStrictEqual([k.aprovadas, k.faturamento], [1, 839.76]);
  assert.strictEqual(Math.round(k.lucro * 100) / 100, Math.round((839.76 - 72.1) * 100) / 100);
  assert.deepStrictEqual([k.vv, k.v3, k.v75, k.hook], [900, 600, 50, 0.3]);
  assert.strictEqual(k.fatUtmify, undefined, 'não finge número da Utmify');
  // ABO: o orçamento é a soma dos conjuntos no ar
  assert.deepStrictEqual([c(C.abo).orc, c(C.abo).aprovadas, c(C.abo).hook], [30, 0, null]);
  assert.deepStrictEqual([c(C.nova).investimento, c(C.nova).status], [0, 'PAUSED']);
  // os totais contam também a venda sem campanha
  assert.deepStrictEqual([d.kpis.vendas, Math.round(d.kpis.faturamento * 100) / 100, Math.round(d.kpis.investimento * 100) / 100], [2, 1679.52, 112.1]);
  assert.deepStrictEqual(d.porConta.map(x => [x.nome, x.campanhas]), [['ca 2', 3]]);
});

test('a análise da campanha pela Meta: os números da Meta e as vendas da SCALROI (20/11)', async () => {
  assert.strictEqual((await chamar('GET', '/api/metricas/meta/campanha' + per() + '&id=' + C.cbo)).status, 401);
  const r = await chamar('GET', '/api/metricas/meta/campanha' + per() + '&id=' + C.cbo + '&nome=x', { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados, m = d.campanha, cent = v => Math.round(v * 100) / 100;
  assert.deepStrictEqual([m.fonte, m.id, m.nome, m.conta, m.status, m.orc, m.orcVida], ['meta', C.cbo, objetos[C.cbo].name, 'ca 2', 'ACTIVE', 500, false]);
  assert.deepStrictEqual([cent(m.gasto), m.imp, m.cliques, m.freq, m.vv, m.v3, m.v75], [72.1, 2000, 40, 1.5, 900, 600, 50]);
  // do clique em diante, pela SCALROI: v1 e v2 (com o nome antigo e o id no fim); a visita da equipe não conta
  assert.deepStrictEqual([d.tmx.visitas, d.tmx.vendas, cent(d.tmx.faturamento)], [2, 1, 839.76]);
  assert.strictEqual(d.porDia.length, 7);
  assert.deepStrictEqual([d.porDia[6].dia, cent(d.porDia[6].gasto), d.porDia[6].vendasTmx], [hoje(), 72.1, 1]);
  assert.strictEqual(d.erroAoVivo, null);
  // os anúncios: gasto da Meta, a venda no anúncio pelo nome, hook sem dado (a Meta não manda vídeo por anúncio)
  const ad = id => d.anuncios.find(a => a.id === id);
  assert.deepStrictEqual([cent(ad('102').gasto), ad('102').vendasTmx, ad('102').ctr, ad('102').hook, ad('102').status], [62.1, 1, 0.02, null, 'ACTIVE']);
  assert.deepStrictEqual([cent(ad('103').gasto), ad('103').vendasTmx], [10, 0]);
  assert.ok(!ad('202'), 'o anúncio de outra campanha fica de fora');
  // só a tabela de anúncios, pra trocar o período dela
  const so = await chamar('GET', '/api/metricas/meta/campanha' + per() + '&id=' + C.cbo + '&so=anuncios', { token: dono });
  assert.deepStrictEqual(so.dados.anuncios.map(a => a.id).sort(), ['102', '103']);
  // ABO sem vídeo: o orçamento é a soma dos conjuntos no ar e o vídeo vai vazio (não zero)
  const abo = (await chamar('GET', '/api/metricas/meta/campanha' + per() + '&id=' + C.abo, { token: dono })).dados.campanha;
  assert.deepStrictEqual([abo.orc, abo.v3, abo.vv, cent(abo.gasto)], [30, null, null, 40]);
  assert.strictEqual((await chamar('GET', '/api/metricas/meta/campanha' + per() + '&nome=sem-id', { token: dono })).status, 400);
});

test('o Sócio de um projeto abre a análise das campanhas dele pela Meta, e só delas (20/11)', async () => {
  const agora = Date.now();
  assert.strictEqual((await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [{ id: 'u-socio', nome: 'Sócia', email: 'socia@tmx.test', senha: 'senha-socia-1',
    cargo: 'Sócio', ativo: true, projetos: ['CONCURSO'], _updatedAt: agora }] })).status, 200);
  const socia = (await chamar('POST', '/api/auth/login', { corpo: { email: 'socia@tmx.test', senha: 'senha-socia-1' } })).dados.token;
  assert.ok(socia);
  const r = await chamar('GET', '/api/metricas/meta/campanha' + per() + '&id=' + C.cbo, { token: socia });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.strictEqual(r.dados.campanha.nome, objetos[C.cbo].name);
  assert.strictEqual(r.dados.tmx.vendas, 1);
  assert.strictEqual((await chamar('GET', '/api/metricas/campanha/agora?id=' + C.cbo, { token: socia })).status, 200, 'o "ao vivo" da análise também');
  // a campanha do outro projeto (RENDA, mesma conta) fica fechada
  assert.strictEqual((await chamar('GET', '/api/metricas/meta/campanha' + per() + '&id=' + C.abo, { token: socia })).status, 403);
  assert.strictEqual((await chamar('GET', '/api/metricas/campanha/agora?id=' + C.abo, { token: socia })).status, 403);
});

test('o projeto de Projetos › Integrações corta campanhas e vendas', async () => {
  const lp = await chamar('GET', '/api/metricas/meta/projetos', { token: dono });
  assert.deepStrictEqual(lp.dados.projetos.map(p => p.id), ['CONCURSO', 'RENDA']);
  const r = await chamar('GET', '/api/metricas/meta/painel' + per() + '&projeto=CONCURSO', { token: dono });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.dados.porCampanha.map(x => x.campanhaId).sort(), [C.cbo, C.nova]);
  assert.strictEqual(r.dados.kpis.vendas, 1, 'só a venda do projeto');
  const renda = await chamar('GET', '/api/metricas/meta/painel' + per() + '&projeto=RENDA', { token: dono });
  assert.deepStrictEqual(renda.dados.porCampanha.map(x => x.campanhaId), [C.abo]);
  // as vendas por campanha da tela (fonte=meta) reconhecem o id que só a Meta conhece
  const t = await chamar('GET', '/api/metricas/tmx-campanhas' + per() + '&projeto=CONCURSO&fonte=meta', { token: dono });
  assert.strictEqual(t.status, 200);
  assert.deepStrictEqual(Object.keys(t.dados.porCampanha), ['id:' + C.cbo]);
});

test('conjuntos e anúncios no formato da tabela', async () => {
  const r = await chamar('GET', '/api/metricas/meta/niveis' + per(), { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados, ad = id => d.anuncios.find(x => x.id === id), cj = id => d.conjuntos.find(x => x.id === id);
  assert.strictEqual(d.fonteReceita, 'tmx');
  // o conjunto soma os anúncios dele
  assert.deepStrictEqual([cj('101').investimento, cj('101').impressoes, cj('101').aprovadas, cj('101').orc, cj('101').campanhaId], [72.1, 2000, 1, null, C.cbo]);
  assert.deepStrictEqual([cj('201').orc, cj('201').orcVida, cj('201').investimento], [30, false, 40]);
  // a venda cai no anúncio pelo nome dele dentro da campanha (o id curto da Meta falsa não passa por id de anúncio)
  assert.deepStrictEqual([ad('102').aprovadas, ad('102').faturamento, ad('102').conjuntoId, ad('102').conta], [1, 839.76, '101', 'ca 2']);
  assert.deepStrictEqual([ad('103').aprovadas, ad('103').investimento, ad('103').status], [0, 10, 'ACTIVE']);
  const so = await chamar('GET', '/api/metricas/meta/niveis' + per() + '&projeto=RENDA', { token: dono });
  assert.deepStrictEqual([so.dados.conjuntos.map(x => x.id), so.dados.anuncios.map(x => x.id)], [['201'], ['202']]);
});

test('visitas da SCALROI por campanha, conjunto e anúncio (18/11)', async () => {
  const p = await chamar('GET', '/api/metricas/meta/painel' + per(), { token: dono });
  const c = id => p.dados.porCampanha.find(x => x.campanhaId === id);
  // pelo id da campanha (mesmo com o nome antigo na UTM) e, sem id, pelo nome
  assert.deepStrictEqual([c(C.cbo).visitas, c(C.abo).visitas, c(C.nova).visitas], [2, 1, 0]);
  const n = await chamar('GET', '/api/metricas/meta/niveis' + per(), { token: dono });
  const ad = id => n.dados.anuncios.find(x => x.id === id), cj = id => n.dados.conjuntos.find(x => x.id === id);
  // o anúncio pelo nome dentro da campanha; o conjunto soma os anúncios; sem o id da campanha não chega no anúncio
  assert.deepStrictEqual([ad('102').visitas, ad('103').visitas, cj('101').visitas, ad('202').visitas, cj('201').visitas], [1, 1, 2, 0, 0]);
});

test('Resumo pela Meta no formato da Utmify, com o faturamento da SCALROI (19/11)', async () => {
  const r = await chamar('GET', '/api/metricas/meta/panorama' + per(), { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados, k = d.kpis, cent = v => Math.round(v * 100) / 100;
  assert.strictEqual(d.fonteReceita, 'tmx');
  assert.deepStrictEqual([cent(k.investimento), k.cliques, k.visitas, k.pedidos.aprovadas, cent(k.receita), cent(k.lucro)], [112.1, 50, 30, 2, 1679.52, cent(1679.52 - 112.1)]);
  // o gasto hora a hora fecha com o do dia: os gráficos do Resumo aparecem
  assert.deepStrictEqual([d.acum.tem, d.acum.inv[8], d.acum.inv[9], cent(d.acum.inv[10]), cent(d.acum.inv[23])], [true, 0, 30, 72.1, 112.1]);
  assert.deepStrictEqual(d.porDashboard.map(x => [x.nome, cent(x.investimento)]), [['CONCURSO', 72.1], ['RENDA', 40]]);
  assert.ok(d.produtos.some(x => x.produto === 'Apostilai Foco' && x.vendas === 2));
  assert.ok(Array.isArray(d.planos) && Array.isArray(d.porUtm));
  const renda = await chamar('GET', '/api/metricas/meta/panorama' + per() + '&projeto=RENDA', { token: dono });
  assert.deepStrictEqual([cent(renda.dados.kpis.investimento), renda.dados.porDashboard.map(x => x.nome)], [40, ['RENDA']]);
  // os filtros: contas dos projetos (Projetos › Integrações) e produtos das vendas
  const f = await chamar('GET', '/api/metricas/meta/filtros', { token: dono });
  assert.strictEqual(f.status, 200, JSON.stringify(f.dados));
  assert.deepStrictEqual(f.dados.contas, [{ id: '111', nome: 'ca 2' }]);
  assert.ok(f.dados.produtos.includes('Apostilai Foco'));
  // filtro de conta: o gasto é o da conta, e a venda vai pra conta pela campanha que a Meta conhece
  const pc = await chamar('GET', '/api/metricas/meta/panorama' + per() + '&conta=111', { token: dono });
  assert.deepStrictEqual([cent(pc.dados.kpis.investimento), pc.dados.kpis.pedidos.aprovadas], [112.1, 1]);
  const outra = await chamar('GET', '/api/metricas/meta/panorama' + per() + '&conta=999', { token: dono });
  assert.deepStrictEqual([outra.dados.kpis.investimento, outra.dados.kpis.pedidos.aprovadas], [0, 0]);
});

test('Por Anúncio pela Meta: junta pelo nome, com as vendas da SCALROI e sem fingir hook (19/11)', async () => {
  const r = await chamar('GET', '/api/metricas/meta/anuncios' + per(), { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const ad = n => r.dados.anuncios.find(x => x.nome === n);
  assert.deepStrictEqual(r.dados.anuncios.map(x => x.nome), ['AD226.1 | TESTE', 'AD88.1', 'AD231.3 | TESTE']);
  const a = ad('AD226.1 | TESTE');
  assert.deepStrictEqual([a.investimento, a.vendas, a.receita, a.dashboard, a.veiculacoes, a.ctr, a.semVideo], [62.1, 1, 839.76, 'CONCURSO', 1, 2, true]);
  assert.deepStrictEqual(Object.keys(a.porConta), ['ca 2']);
  assert.deepStrictEqual([r.dados.conciliacao.vendasConta, r.dados.conciliacao.vendasAnuncios, r.dados.conciliacao.vendasSemAnuncio], [2, 1, 1]);
  const so = await chamar('GET', '/api/metricas/meta/anuncios' + per() + '&projeto=RENDA', { token: dono });
  assert.deepStrictEqual(so.dados.anuncios.map(x => [x.nome, x.dashboard]), [['AD88.1', 'RENDA']]);
  // o detalhe (3 e 7 dias)
  const det = await chamar('GET', '/api/metricas/meta/anuncio?nome=' + encodeURIComponent('AD226.1 | TESTE') + '&de=' + hoje() + '&ate=' + hoje(), { token: dono });
  assert.strictEqual(det.status, 200, JSON.stringify(det.dados));
  const t = det.dados.periodos.tela;
  assert.deepStrictEqual([t.inv, t.v, t.rec, t.veic, t.ativos, t.cl, t.imp, t.semVideo], [62.1, 1, 839.76, 1, 1, 20, 1000, true]);
  assert.deepStrictEqual(det.dados.ids, ['102']);
  assert.ok(det.dados.pixel.d7 && det.dados.periodos.d7.inv === 62.1);
});

test('Tempo Real pela Meta: cada venda e cada checkout de hoje viram um evento (19/11)', async () => {
  // uma pessoa chega no checkout vinda do AD226.1, duas vezes (conta uma), pelo pixel da SCALROI
  const ck = () => chamar('POST', '/api/funil/evento', { corpo: { id: 'ck1', funil: 'f1', etapa: 'e1', tipo: 'checkout', pg: 'site.com/checkout', sid: 'sck1',
    aqui: { utm_source: 'FB', utm_campaign: 'CBO 1-1-3 | CONCURSO | ' + C.cbo, utm_content: 'AD226.1 | TESTE' } } });
  await ck(); await ck(); await espera(300);
  const r = await chamar('GET', '/api/metricas/meta/tempo-real?x=1', { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.deepStrictEqual([r.dados.kpis.pedidos.aprovadas, Math.round(r.dados.kpis.investimento * 100) / 100, r.dados.eventos.length], [2, 112.1, 3]);
  assert.deepStrictEqual(r.dados.eventos.map(e => e.tipo).sort(), ['ic', 'venda', 'venda']);
  assert.ok(r.dados.eventos.some(e => e.tipo === 'ic' && e.anuncio === 'AD226.1 | TESTE' && e.momento));
  // a Meta falsa não conta IC: o número de cima vem do pixel da SCALROI
  assert.deepStrictEqual([r.dados.kpis.ics, r.dados.kpis.icsDoPixel], [1, true]);
  assert.ok(r.dados.eventos.some(e => e.anuncio === 'AD226.1 | TESTE' && Math.round(e.valor * 100) === 83976));
  assert.ok(r.dados.eventos.some(e => e.anuncio === 'sem anúncio'));
});

test('tudo pela Meta: funil, vendas por canal, cobertura de UTM e as perguntas ao Claude (19/11)', async () => {
  assert.strictEqual((await chamar('GET', '/api/metricas/fonte', { token: dono })).dados.fonte, 'meta');
  // cliques do funil
  const f = await chamar('GET', '/api/funil/cliques' + per(), { token: dono });
  assert.strictEqual(f.status, 200, JSON.stringify(f.dados));
  assert.deepStrictEqual([f.dados.total, f.dados.visitas, f.dados.vendas], [50, 30, 2]);
  assert.ok(f.dados.campanhas.some(c => c.nome === objetos[C.cbo].name && c.cliques === 40));
  // o gasto das campanhas de cada dia (Resultados, Canais, vendas por canal) sai da Meta
  const vc = await chamar('GET', '/api/vendas/por-canal' + per(), { token: dono });
  assert.strictEqual(vc.status, 200, JSON.stringify(vc.dados));
  assert.strictEqual(Math.round(vc.dados.gasto * 100) / 100, 112.1);
  // cobertura de UTM: os três anúncios tiveram visita com o anúncio na UTM; no projeto RENDA, só o dele
  const cb = await chamar('GET', '/api/metricas/meta/cobertura-utm' + per(), { token: dono });
  assert.strictEqual(cb.status, 200, JSON.stringify(cb.dados));
  assert.deepStrictEqual([Math.round(cb.dados.gastoTotal * 100) / 100, Math.round(cb.dados.cobertura), cb.dados.semUtm.length], [112.1, 100, 0]);
  assert.strictEqual((await chamar('GET', '/api/metricas/meta/cobertura-utm' + per() + '&projeto=RENDA', { token: dono })).dados.gastoTotal, 40);
  // as ferramentas do Claude
  const tk = (await chamar('POST', '/api/tokens/generate', { token: dono, corpo: { nome: 'teste da Meta' } })).dados.token;
  const mcp = async (name, args) => { const r = await (await fetch(base + '/mcp?token=' + tk, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args || {} } }) })).json(); return r.result.content[0].text; };
  const como = await mcp('como_esta_hoje');
  assert.match(como, /Investido:\s+R\$\s*112,10/);
  assert.match(como, /Faturamento:\s+R\$\s*1\.679,52/);
  assert.match(como, /Vendas:\s+2 aprovadas/);
  const cri = await mcp('criativos_que_vendem');
  assert.match(cri, /QUEM VENDE[\s\S]*AD226\.1 \| TESTE/);
  assert.match(cri, /Total: 1 vendas?/);
});

test('Auditoria IA pela Meta: o texto pro Claude leva os números da Meta e não fala da Utmify (19/11)', async () => {
  const r = await chamar('POST', '/api/ia/auditoria', { token: dono, corpo: { projeto: 'CONCURSO', projetoNome: 'CONCURSO', dia: 'hoje' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  await ate(() => pedidosIA.length > 0, 30000, 'a Auditoria montar o texto e chamar o Claude');
  const corpo = pedidosIA[0], texto = corpo.messages[0].content, sistema = JSON.stringify(corpo.system);
  assert.match(texto, /Fonte do gasto: Meta/);
  { const i = texto.indexOf('Utmify'); assert.ok(i < 0, 'o texto não cita a Utmify: …' + texto.slice(Math.max(0, i - 200), i + 100)); }
  assert.ok(!/Utmify/.test(sistema), 'as regras também não');
  assert.match(texto, /AD226\.1/);
  assert.ok(!/AD88\.1/.test(texto), 'o anúncio do outro projeto (RENDA) fica de fora');
  assert.match(texto, /\| Investimento \| R\$ 72 \|/);
  assert.match(texto, /vêm de: TMX/, 'a Meta não tem faturamento: o resumo é sempre o da SCALROI');
  assert.match(texto, /\| AD226\.1 \/ TESTE \|[^\n]*\| - \| - \| R\$ 62 \|/, 'hook e body sem dado, não 0%');
});

test('pausar pela tela aparece na hora, sem esperar a próxima puxada', async () => {
  const x = await chamar('POST', '/api/meta/status', { token: dono, corpo: { nivel: 'campanha', id: C.cbo, ativo: false, nome: objetos[C.cbo].name } });
  assert.strictEqual(x.status, 200, JSON.stringify(x.dados));
  const r = await chamar('GET', '/api/metricas/meta/painel' + per(), { token: dono });
  assert.strictEqual(r.dados.porCampanha.find(c => c.campanhaId === C.cbo).status, 'PAUSED');
  const y = await chamar('POST', '/api/meta/status', { token: dono, corpo: { nivel: 'anuncio', id: '103', camp: C.cbo, ativo: false, nome: 'AD231.3 | TESTE' } });
  assert.strictEqual(y.status, 200, JSON.stringify(y.dados));
  const n = await chamar('GET', '/api/metricas/meta/niveis' + per(), { token: dono });
  assert.strictEqual(n.dados.anuncios.find(a => a.id === '103').status, 'PAUSED');
});

test('a lista igual à da Utmify: a pausada sem gasto entra quando mudou no período (19/11)', async () => {
  const lista = async () => (await chamar('GET', '/api/metricas/meta/painel' + per(), { token: dono })).dados.porCampanha.map(x => x.campanhaId);
  assert.ok(!(await lista()).includes(C.recente));
  for (const ativo of [true, false]) {
    const x = await chamar('POST', '/api/meta/status', { token: dono, corpo: { nivel: 'campanha', id: C.recente, ativo, nome: objetos[C.recente].name } });
    assert.strictEqual(x.status, 200, JSON.stringify(x.dados));
  }
  assert.ok((await lista()).includes(C.recente), 'ligou e pausou hoje: aparece, com a mudança');
});
