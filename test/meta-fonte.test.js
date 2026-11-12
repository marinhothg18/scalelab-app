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
let meta, srv, dir, base, log = '', dono;
const ate = async (cond, ms, oQue) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-2000)); await espera(150); } };

const C = { cbo: '1000000000100', abo: '1000000000200', nova: '1000000000300', velha: '1000000000400' };
const agoraIso = new Date().toISOString().replace('Z', '+0000');
const objetos = {
  [C.cbo]: { id: C.cbo, name: 'CBO 1-1-3 | CONCURSO | ' + C.cbo, status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '50000', created_time: '2026-11-01T10:00:00-0300', account_id: '111' },
  [C.abo]: { id: C.abo, name: 'ABO | RENDA | ' + C.abo, status: 'ACTIVE', effective_status: 'ACTIVE', created_time: '2026-11-01T10:00:00-0300', account_id: '111' },
  [C.nova]: { id: C.nova, name: 'TESTE NOVA | CONCURSO', status: 'PAUSED', effective_status: 'PAUSED', created_time: agoraIso, account_id: '111' },
  [C.velha]: { id: C.velha, name: 'VELHA PAUSADA | CONCURSO', status: 'PAUSED', effective_status: 'PAUSED', created_time: '2025-01-10T10:00:00-0300', account_id: '111' },
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
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-meta-fonte-'));
  // os dois projetos dividem a conta 111 pela palavra no nome da campanha
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_projetos_meta: { CONCURSO: { contas: ['111'], regra: 'CONCURSO' }, RENDA: { contas: ['111'], regra: 'RENDA' } } },
    timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 47000 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
    META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0' }, stdio: ['ignore', 'pipe', 'pipe'] });
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
  await espera(400);
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('sem sessão não entra', async () => {
  for (const r of ['painel', 'niveis', 'projetos']) assert.strictEqual((await chamar('GET', '/api/metricas/meta/' + r + per())).status, 401, r);
});

test('campanhas da Meta com as vendas da SCALROI', async () => {
  const r = await chamar('GET', '/api/metricas/meta/painel' + per(), { token: dono });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados, c = id => d.porCampanha.find(x => x.campanhaId === id);
  assert.strictEqual(d.conectada, true);
  assert.ok(c(C.cbo) && c(C.abo) && c(C.nova), 'as duas que gastaram e a nova sem gasto');
  assert.ok(!c(C.velha), 'a pausada antiga sem gasto fica de fora');
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
