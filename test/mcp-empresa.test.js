// MCP e API v1 de cada empresa (07/11/2026).
// Sobe o servidor numa pasta temporária (a TMX vazia + as empresas A e B) e confere que o
// token gerado pela Diretoria de uma empresa abre só o MCP e a API dela: recusado na outra
// empresa e na TMX, e o da TMX recusado na empresa. O que é só da TMX não aparece.
// Nada toca o banco de verdade: tudo vive numa pasta que é apagada no fim.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
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
  let body;
  if (corpo !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(corpo); }
  const r = await fetch(base + caminho, { method: metodo, headers, body });
  let dados = null;
  const tipo = r.headers.get('content-type') || '';
  if (tipo.includes('json')) { try { dados = await r.json(); } catch (e) {} } else { try { dados = await r.text(); } catch (e) {} }
  return { status: r.status, dados, headers: r.headers };
}
const login = (email, senha) => chamar('POST', '/api/auth/login', { corpo: { email, senha } });
// Chamada ao MCP como o Claude faz: token no fim da URL (ou no cabeçalho, se pedir)
async function mcp(caminho, token, metodo, params, { cabecalho } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  let url = base + caminho;
  if (token && cabecalho) headers.Authorization = 'Bearer ' + token;
  else if (token) url += '?token=' + encodeURIComponent(token);
  const r = await fetch(url, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: metodo, params: params || {} }) });
  let dados = null;
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados, headers: r.headers };
}
const textoDe = r => ((r.dados && r.dados.result && r.dados.result.content) || []).map(c => c.text).join('\n');

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-mcp-empresa-'));
  const porta = 41000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ,
    // ambiente limpo: nenhuma chave de verdade (Utmify, VTurb, IA...) entra no teste
    env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});

after(async () => {
  if (srv && srv.exitCode === null) {
    srv.kill('SIGTERM');
    await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]);
  }
  if (process.env.TMX_TESTE_LOG) fs.writeFileSync(process.env.TMX_TESTE_LOG, log);
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('cada empresa tem o próprio MCP e a própria API v1', async (t) => {
  const ctx = {};
  // um funil e um arquivo da Central de Arquivos com o nome de quem é dono
  const funil = nome => [{ id: 'f-' + nome, nome: 'Funil da ' + nome, etapas: [], _updatedAt: Date.now() }];
  const arquivos = nome => [{ id: 'p-' + nome, nome: 'Projeto da ' + nome, _updatedAt: Date.now(),
    items: { copywriting: [{ id: 'a-' + nome, nome: 'Roteiros AD10 a AD20 da ' + nome, url: 'https://docs.exemplo/' + nome, ad_inicio: 10, ad_fim: 20 }] } }];

  await t.test('prepara a TMX e as empresas A e B, cada uma com os dados dela', async () => {
    const r = await login('thiago@axcend.com', 'axcend2026');
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    ctx.tmx = r.dados.token;
    for (const k of ['A', 'B']) {
      const c = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx,
        corpo: { nome: 'Empresa ' + k, usuario: { nome: 'Dona ' + k, email: 'dona@empresa-' + k.toLowerCase() + '.com', senha: 'senha-da-' + k + '-123' } } });
      assert.strictEqual(c.status, 200, JSON.stringify(c.dados) + log.slice(-2000));
      ctx['id' + k] = c.dados.empresa.id;
      const l = await login('dona@empresa-' + k.toLowerCase() + '.com', 'senha-da-' + k + '-123');
      assert.strictEqual(l.status, 200, JSON.stringify(l.dados));
      ctx['tok' + k] = l.dados.token;
    }
    for (const [tok, nome] of [[ctx.tokA, 'A'], [ctx.tokB, 'B'], [ctx.tmx, 'TMX']]) {
      const tarefa = [{ id: 't-' + nome, nome: 'Tarefa da ' + nome, status: 'A_FAZER', _updatedAt: Date.now() }];
      assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: tok, corpo: tarefa })).status, 200);
      assert.strictEqual((await chamar('PUT', '/api/store/sl_funis', { token: tok, corpo: funil(nome) })).status, 200);
      assert.strictEqual((await chamar('PUT', '/api/store/sl_arq_projetos', { token: tok, corpo: arquivos(nome) })).status, 200);
    }
  });

  await t.test('a Diretoria de cada empresa gera o token dela, com o endereço dela', async () => {
    assert.strictEqual((await chamar('POST', '/e/' + ctx.idA + '/api/tokens/generate', { corpo: { nome: 'x' } })).status, 401, 'sem login não gera');
    for (const [k, tok] of [['A', ctx.tokA], ['B', ctx.tokB], ['Tmx', ctx.tmx]]) {
      const r = await chamar('POST', '/api/tokens/generate', { token: tok, corpo: { nome: 'Claude ' + k, master: true } });
      assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
      assert.match(r.dados.token, /^sk_live_[0-9a-f]{64}$/);
      ctx['api' + k] = r.dados.token;
      ctx['end' + k] = r.dados.enderecos;
    }
    assert.deepStrictEqual(ctx.endA, { mcp: '/e/' + ctx.idA + '/mcp', api: '/e/' + ctx.idA + '/api/v1', docs: '/e/' + ctx.idA + '/api/v1/docs' });
    assert.strictEqual(ctx.endTmx.mcp, '/mcp');
    // a lista de A tem só o token de A, sem o hash; e o banco de A guarda só o sha256
    const lista = await chamar('GET', '/api/tokens/list', { token: ctx.tokA });
    assert.strictEqual(lista.status, 200);
    assert.deepStrictEqual(lista.dados.map(x => x.nome), ['Claude A']);
    assert.ok(!('hash' in lista.dados[0]));
    const dbA = JSON.parse(fs.readFileSync(path.join(dir, 'empresas', ctx.idA, 'db.json'), 'utf8'));
    assert.strictEqual(dbA.api_tokens.length, 1);
    assert.ok(!JSON.stringify(dbA).includes(ctx.apiA), 'o token em si nunca fica gravado');
    assert.strictEqual(dbA.api_tokens[0].master, false, 'numa empresa não existe token master');
    const dbTmx = JSON.parse(fs.readFileSync(path.join(dir, 'db.json'), 'utf8'));
    assert.deepStrictEqual(dbTmx.api_tokens.map(x => x.nome), ['Claude Tmx'], 'o token da A não vai pro banco da TMX');
  });

  await t.test('o token de A abre o MCP de A', async () => {
    const ini = await mcp(ctx.endA.mcp, ctx.apiA, 'initialize');
    assert.strictEqual(ini.status, 200, JSON.stringify(ini.dados));
    assert.strictEqual(ini.dados.result.serverInfo.name, 'TMX · Empresa A');
    assert.match(ini.dados.result.instructions, /Empresa A/);
    // pelo cabeçalho também
    assert.strictEqual((await mcp(ctx.endA.mcp, ctx.apiA, 'ping', {}, { cabecalho: true })).status, 200);
    const info = await chamar('GET', ctx.endA.mcp);
    assert.strictEqual(info.dados.servidor, 'TMX · Empresa A');
  });

  await t.test('tools/list da empresa não tem o que é da TMX', async () => {
    const daA = (await mcp(ctx.endA.mcp, ctx.apiA, 'tools/list')).dados.result.tools;
    const daTmx = (await mcp('/mcp', ctx.apiTmx, 'tools/list')).dados.result.tools;
    assert.ok(daA.length >= 10, 'as ferramentas do produto continuam lá: ' + daA.map(f => f.name).join(', '));
    assert.ok(daA.every(f => daTmx.some(x => x.name === f.name)), 'nenhuma ferramenta nova só da empresa');
    const txtA = JSON.stringify(daA);
    assert.doesNotMatch(txtA, /KALEB|Kalebe|CONCURSO|Protocolo|soTmx/i, 'nada de nome de projeto da TMX nem de Meu Protocolo');
    assert.ok(daA.every(f => Object.keys(f).sort().join() === 'description,inputSchema,name'));
    // a TMX continua igual, com os exemplos dela
    assert.match(JSON.stringify(daTmx), /CONCURSO/);
    // ferramenta que não está na lista não roda
    const fora = await mcp(ctx.endA.mcp, ctx.apiA, 'tools/call', { name: 'meu_protocolo', arguments: {} });
    assert.strictEqual(fora.dados.error.code, -32602);
  });

  await t.test('tools/call devolve só os dados de A', async () => {
    const proj = textoDe(await mcp(ctx.endA.mcp, ctx.apiA, 'tools/call', { name: 'listar_projetos', arguments: {} }));
    assert.match(proj, /Funil da A/);
    assert.doesNotMatch(proj, /Funil da (B|TMX)/);
    const arqs = textoDe(await mcp(ctx.endA.mcp, ctx.apiA, 'tools/call', { name: 'listar_arquivos', arguments: {} }));
    assert.match(arqs, /Roteiros AD10 a AD20 da A/);
    assert.doesNotMatch(arqs, /da (B|TMX)/);
    const copy = textoDe(await mcp(ctx.endA.mcp, ctx.apiA, 'tools/call', { name: 'buscar_copy_por_ad', arguments: { numero: 'AD15' } }));
    assert.match(copy, /docs\.exemplo\/A/);
    assert.doesNotMatch(copy, /docs\.exemplo\/(B|TMX)/);
    // e a TMX, pelo endereço dela, continua vendo só o dela
    const daTmx = textoDe(await mcp('/mcp', ctx.apiTmx, 'tools/call', { name: 'listar_projetos', arguments: {} }));
    assert.match(daTmx, /Funil da TMX/);
    assert.doesNotMatch(daTmx, /Funil da (A|B)/);
  });

  await t.test('o token de A é recusado em B e na TMX; o da TMX é recusado em A', async () => {
    assert.strictEqual((await mcp(ctx.endB.mcp, ctx.apiA, 'tools/list')).status, 401);
    assert.strictEqual((await mcp('/mcp', ctx.apiA, 'tools/list')).status, 401);
    assert.strictEqual((await mcp('/mcp', ctx.apiA, 'tools/list', {}, { cabecalho: true })).status, 401);
    assert.strictEqual((await mcp(ctx.endA.mcp, ctx.apiTmx, 'tools/list')).status, 401);
    assert.strictEqual((await mcp(ctx.endA.mcp, ctx.apiB, 'tools/list')).status, 401);
    assert.strictEqual((await mcp(ctx.endA.mcp, '', 'tools/list')).status, 401);
    // API v1
    assert.strictEqual((await chamar('GET', ctx.endB.api + '/demandas', { token: ctx.apiA })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/v1/demandas', { token: ctx.apiA })).status, 403);
    assert.strictEqual((await chamar('GET', ctx.endA.api + '/demandas', { token: ctx.apiTmx })).status, 403);
    // a sessão do app também não serve de token da API
    assert.strictEqual((await chamar('GET', ctx.endA.api + '/demandas', { token: ctx.tokA })).status, 403);
  });

  await t.test('a API v1 de A lê só A e deixa fora o que é da TMX e os segredos', async () => {
    const dem = await chamar('GET', ctx.endA.api + '/demandas', { token: ctx.apiA });
    assert.strictEqual(dem.status, 200, JSON.stringify(dem.dados));
    assert.deepStrictEqual(dem.dados.demandas.map(x => x.id), ['t-A']);
    const tmx = await chamar('GET', '/api/v1/demandas', { token: ctx.apiTmx });
    assert.deepStrictEqual(tmx.dados.demandas.map(x => x.id), ['t-TMX']);
    const us = await chamar('GET', ctx.endA.api + '/dados/sl_usuarios', { token: ctx.apiA });
    assert.strictEqual(us.status, 200);
    assert.deepStrictEqual(us.dados.map(u => u.email), ['dona@empresa-a.com']);
    assert.ok(us.dados.every(u => !('senha' in u) && !('senhaHash' in u)), 'senha nunca sai');
    // módulo arquivado (IA) e segredo do webhook de vendas: existem no banco de A, mas não saem
    assert.strictEqual((await chamar('PUT', '/api/store/sl_ia_copy', { token: ctx.tokA, corpo: [{ id: 'ia1', texto: 'x', _updatedAt: Date.now() }] })).status, 200);
    assert.strictEqual((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: ctx.tokA })).status, 200);
    for (const chave of ['sl_ia_copy', 'sl_integracoes_vendas', 'sl_protocolo', 'constructor']) {
      assert.strictEqual((await chamar('GET', ctx.endA.api + '/dados/' + chave, { token: ctx.apiA })).status, 404, chave);
    }
    const docs = await chamar('GET', ctx.endA.docs);
    assert.strictEqual(docs.dados.base, '/e/' + ctx.idA + '/api/v1');
    assert.ok(docs.dados.endpoints.every(e => e.path.startsWith('/e/' + ctx.idA + '/api/v1/')));
  });

  await t.test('o suporte da TMX vê a lista, mas não gera nem revoga token do cliente', async () => {
    const r = await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/suporte', { token: ctx.tmx,
      corpo: { motivo: 'ajudar com o conector', modo: 'mexer', minutos: 15, avisar: false } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const sup = r.dados.token;
    assert.strictEqual((await chamar('GET', '/api/tokens/list', { token: sup })).status, 200);
    const gera = await chamar('POST', '/api/tokens/generate', { token: sup, corpo: { nome: 'da TMX' } });
    assert.strictEqual(gera.status, 403);
    assert.strictEqual(gera.dados.codigo, 'SUPORTE_SEM_TOKEN');
    const id = (await chamar('GET', '/api/tokens/list', { token: ctx.tokA })).dados[0].id;
    assert.strictEqual((await chamar('POST', '/api/tokens/revoke/' + id, { token: sup })).status, 403);
  });

  await t.test('empresa suspensa: MCP e API fecham junto com o app, o pixel continua', async () => {
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/bloquear', { token: ctx.tmx, corpo: { motivo: 'teste' } })).status, 200);
    const m = await mcp(ctx.endA.mcp, ctx.apiA, 'tools/list');
    assert.strictEqual(m.status, 403);
    assert.strictEqual(m.headers.get('x-tmx-bloqueada'), '1');
    assert.strictEqual((await chamar('GET', ctx.endA.api + '/demandas', { token: ctx.apiA })).status, 403);
    assert.strictEqual((await chamar('GET', '/e/' + ctx.idA + '/px.js')).status, 200, 'o pixel não para');
    assert.strictEqual((await mcp(ctx.endB.mcp, ctx.apiB, 'tools/list')).status, 200, 'a B segue normal');
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/desbloquear', { token: ctx.tmx })).status, 200);
    assert.strictEqual((await mcp(ctx.endA.mcp, ctx.apiA, 'tools/list')).status, 200);
  });

  await t.test('revogado pela Diretoria de A, o token para na hora', async () => {
    const lista = (await chamar('GET', '/api/tokens/list', { token: ctx.tokA })).dados;
    // a B não revoga o token da A
    assert.strictEqual((await chamar('POST', '/api/tokens/revoke/' + lista[0].id, { token: ctx.tokB })).status, 404);
    assert.strictEqual((await chamar('POST', '/api/tokens/revoke/' + lista[0].id, { token: ctx.tokA })).status, 200);
    assert.strictEqual((await mcp(ctx.endA.mcp, ctx.apiA, 'tools/list')).status, 401);
    assert.strictEqual((await chamar('GET', ctx.endA.api + '/demandas', { token: ctx.apiA })).status, 403);
    // os registros de acesso de A são de A
    const logs = await chamar('GET', '/api/tokens/logs', { token: ctx.tokA });
    assert.strictEqual(logs.status, 200);
    assert.ok(logs.dados.length > 0 && logs.dados.every(l => l.path.startsWith('/api/v1/')));
    assert.ok(logs.dados.some(l => l.path === '/api/v1/dados/sl_usuarios'));
    // na TMX ficou só a chamada do token da TMX; a B não chamou a API
    const logsTmx = (await chamar('GET', '/api/tokens/logs', { token: ctx.tmx })).dados;
    assert.deepStrictEqual(logsTmx.map(l => l.path), ['/api/v1/demandas']);
    assert.deepStrictEqual((await chamar('GET', '/api/tokens/logs', { token: ctx.tokB })).dados, []);
  });
});
