// Claude mexendo na Meta pelo MCP (10/11/2026): o token só lê até a Diretoria ligar "Pode mexer na Meta". Com a
// permissão, o Claude lê as campanhas, a estrutura, pausa, ativa e muda orçamento (até o dobro ou a metade), sem passar
// por cima de valor que mudou, e cada mudança fica em "Quem mexeu" com o nome do token.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const TOKEN = 'EAAtokenDoClaudeNaMetaDeTeste1234567890abcdefghijklmnopqrstuvwxyz';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

let meta, srv, dir, base, log = '', dono, gravacoes = [];
const objetos = {
  '100': { id: '100', name: 'CBO CONCURSO | AD245', status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '50000', account_id: '111' },
  '101': { id: '101', name: 'Aberto 25-55', campaign_id: '100', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '102': { id: '102', name: 'AD245.1', campaign_id: '100', adset_id: '101', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '200': { id: '200', name: 'ABO RENDA', status: 'ACTIVE', effective_status: 'ACTIVE', account_id: '111' },
  '201': { id: '201', name: 'Conjunto ABO', campaign_id: '200', status: 'ACTIVE', effective_status: 'ACTIVE', daily_budget: '3000', account_id: '111' }
};
function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname.replace(/^\/v[\d.]+\//, '');
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.method === 'POST') {
    let corpo = ''; req.on('data', b => { corpo += b; });
    req.on('end', () => { const { access_token, ...campos } = Object.fromEntries(new URLSearchParams(corpo)); gravacoes.push({ id: p, campos }); if (objetos[p]) Object.assign(objetos[p], campos, campos.status ? { effective_status: campos.status } : {}); ok({ success: true }); });
    return;
  }
  if (p === 'me/permissions') return ok({ data: ['ads_read', 'ads_management'].map(permission => ({ permission, status: 'granted' })) });
  if (p === 'me/adaccounts') return ok({ data: [{ id: 'act_111', account_id: '111', name: 'Conta real', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' }] });
  if (p === 'me') return ok({ id: '77', name: 'Pessoa Exemplo' });
  if (p === 'act_111/campaigns') return ok({ data: [objetos['100'], objetos['200']] });
  if (p === 'act_111/adsets') return ok({ data: [objetos['101'], objetos['201']] });
  if (p === 'act_111/insights' && u.searchParams.get('time_increment') && !u.searchParams.get('breakdowns')) {
    const dia = new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
    return ok({ data: [{ campaign_id: '100', campaign_name: objetos['100'].name, date_start: dia, spend: '321.50', impressions: '1000' }, { campaign_id: '200', campaign_name: 'ABO RENDA', date_start: dia, spend: '45.00', impressions: '200' }] });
  }
  let m = p.match(/^(\d+)\/adsets$/); if (m) return ok({ data: Object.values(objetos).filter(o => o.campaign_id === m[1] && !o.adset_id) });
  m = p.match(/^(\d+)\/ads$/); if (m) return ok({ data: Object.values(objetos).filter(o => o.campaign_id === m[1] && o.adset_id) });
  if (objetos[p]) return ok(objetos[p]);
  ok({ data: [] });
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
let api, apiId;
const mcp = async (method, params) => (await chamar('POST', '/mcp?token=' + api, { corpo: { jsonrpc: '2.0', id: 1, method, params } }));
const ferramenta = async (name, args) => { const r = (await mcp('tools/call', { name, arguments: args })).dados; return r.result ? { erro: !!r.result.isError, texto: r.result.content[0].text } : { erro: true, texto: r.error.message }; };
const nomes = async () => (await mcp('tools/list')).dados.result.tools.map(t => t.name);

before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-mcpmeta-'));
  const porta = 57000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0' } });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.strictEqual((await chamar('POST', '/api/meta/conexao', { token: dono, corpo: { token: TOKEN } })).status, 200);
  await ate(async () => (await chamar('POST', '/api/meta/puxar', { token: dono, corpo: { dias: 2 } })).status === 200, 20000, 'puxada', () => log);
  const g = await chamar('POST', '/api/tokens/generate', { token: dono, corpo: { nome: 'Claude do Thiago' } });
  api = g.dados.token;
  apiId = (await chamar('GET', '/api/tokens/list', { token: dono })).dados.find(t => t.nome === 'Claude do Thiago').id;
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('sem a permissão, o token só lê', async (t) => {
  const n = await nomes();
  assert.ok(n.includes('campanhas_da_meta'));
  for (const x of ['estrutura_da_campanha', 'pausar_ou_ativar', 'mudar_orcamento']) assert.ok(!n.includes(x), x);
  await t.test('a lista das campanhas sai com id, gasto e o aviso de que só lê', async () => {
    const r = await ferramenta('campanhas_da_meta', {});
    assert.ok(!r.erro, r.texto);
    assert.match(r.texto, /CBO CONCURSO \| AD245 \(id 100\)/);
    assert.match(r.texto, /gasto hoje R\$\s?321,50/);
    assert.match(r.texto, /Este token só lê/);
  });
  await t.test('pedir para pausar é recusado', async () => {
    const r = await ferramenta('pausar_ou_ativar', { nivel: 'campanha', id: '100', ativo: false });
    assert.ok(r.erro); assert.match(r.texto, /desconhecida/);
    assert.strictEqual(gravacoes.length, 0);
  });
  await t.test('o token aparece como só lê', async () => {
    assert.strictEqual((await chamar('GET', '/api/tokens/list', { token: dono })).dados.find(x => x.id === apiId).podeMeta, false);
  });
});

test('ligar a permissão é da Diretoria e fica na auditoria', async () => {
  assert.strictEqual((await chamar('POST', '/api/tokens/permissao/' + apiId, { corpo: { meta: true } })).status, 401);
  assert.strictEqual((await chamar('POST', '/api/tokens/permissao/999', { token: dono, corpo: { meta: true } })).status, 404);
  const r = await chamar('POST', '/api/tokens/permissao/' + apiId, { token: dono, corpo: { meta: true } });
  assert.deepStrictEqual(r.dados, { ok: true, podeMeta: true });
  const n = await nomes();
  for (const x of ['estrutura_da_campanha', 'pausar_ou_ativar', 'mudar_orcamento']) assert.ok(n.includes(x), x);
  const ini = (await mcp('initialize', {})).dados.result.instructions;
  assert.match(ini, /confirme com a pessoa/);
});

test('com a permissão, o Claude lê a estrutura, pausa e muda orçamento', async (t) => {
  await t.test('estrutura', async () => {
    const r = await ferramenta('estrutura_da_campanha', { campanha: '100' });
    assert.ok(!r.erro, r.texto);
    assert.match(r.texto, /Campanha CBO CONCURSO \| AD245 \(id 100\) · ativa · R\$\s?500,00 por dia/);
    assert.match(r.texto, /Anúncio AD245\.1 \(id 102\)/);
  });
  await t.test('conjunto ou anúncio sem a campanha não vai', async () => {
    const r = await ferramenta('pausar_ou_ativar', { nivel: 'anuncio', id: '102', ativo: false });
    assert.ok(r.erro); assert.match(r.texto, /id da campanha/);
  });
  await t.test('pausa o anúncio e fica em Quem mexeu com o nome do token', async () => {
    const r = await ferramenta('pausar_ou_ativar', { nivel: 'anuncio', id: '102', ativo: false, campanha: '100', nome: 'AD245.1' });
    assert.ok(!r.erro, r.texto);
    assert.deepStrictEqual(gravacoes.pop(), { id: '102', campos: { status: 'PAUSED' } });
    const h = (await chamar('GET', '/api/meta/historico', { token: dono })).dados.itens;
    assert.ok(h.some(i => i.quem === 'Claude · token Claude do Thiago' && /pausou o anúncio AD245\.1/.test(i.texto)), JSON.stringify(h));
  });
  await t.test('pausar a campanha já aparece na lista', async () => {
    assert.ok(!(await ferramenta('pausar_ou_ativar', { nivel: 'campanha', id: '100', ativo: false, nome: 'CBO CONCURSO' })).erro);
    assert.match((await ferramenta('campanhas_da_meta', { busca: 'concurso' })).texto, /\(id 100\) · conta [^·]+ · pausada/);
  });
  await t.test('orçamento: mais que o dobro não vai', async () => {
    const r = await ferramenta('mudar_orcamento', { nivel: 'campanha', id: '100', valor: 1200, valor_atual: 500 });
    assert.ok(r.erro); assert.match(r.texto, /até o dobro/);
    assert.strictEqual(gravacoes.length, 1, 'só a pausa da campanha');
  });
  await t.test('orçamento: valor atual errado não passa por cima', async () => {
    const r = await ferramenta('mudar_orcamento', { nivel: 'campanha', id: '100', valor: 600, valor_atual: 400 });
    assert.ok(r.erro); assert.match(r.texto, /mudou na Meta/);
  });
  await t.test('orçamento: sem o valor atual não vai', async () => {
    assert.match((await ferramenta('mudar_orcamento', { nivel: 'campanha', id: '100', valor: 600 })).texto, /valor_atual/);
  });
  await t.test('orçamento certo vai em centavos', async () => {
    const r = await ferramenta('mudar_orcamento', { nivel: 'campanha', id: '100', valor: 900, valor_atual: 500, nome: 'CBO CONCURSO' });
    assert.ok(!r.erro, r.texto);
    assert.deepStrictEqual(gravacoes.pop(), { id: '100', campos: { daily_budget: '90000' } });
    assert.match(r.texto, /de R\$\s?500,00 para R\$\s?900,00 por dia/);
  });
  await t.test('conjunto ABO', async () => {
    const r = await ferramenta('mudar_orcamento', { nivel: 'conjunto', id: '201', valor: 45, valor_atual: 30, campanha: '200' });
    assert.ok(!r.erro, r.texto);
    assert.deepStrictEqual(gravacoes.pop(), { id: '201', campos: { daily_budget: '4500' } });
  });
});

test('desligar a permissão e revogar o token cortam na hora', async () => {
  await chamar('POST', '/api/tokens/permissao/' + apiId, { token: dono, corpo: { meta: false } });
  assert.ok(!(await nomes()).includes('pausar_ou_ativar'));
  await chamar('POST', '/api/tokens/revoke/' + apiId, { token: dono });
  assert.strictEqual((await mcp('tools/list')).status, 401);
});
