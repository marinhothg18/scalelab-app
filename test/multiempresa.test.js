// Prova de isolamento entre empresas (07/11/2026).
// Sobe o servidor numa pasta temporária (a TMX vazia + duas empresas de teste, A e B)
// e confere que nada de uma aparece na outra: sessão, login, sincronização, webhook
// de vendas, pixel, rotinas (lembretes e backup) e o que é só da TMX.
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
async function chamar(metodo, caminho, { token, corpo, texto } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  let body;
  if (texto !== undefined) { headers['Content-Type'] = 'text/plain'; body = texto; }
  else if (corpo !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(corpo); }
  const r = await fetch(base + caminho, { method: metodo, headers, body });
  let dados = null;
  const tipo = r.headers.get('content-type') || '';
  if (tipo.includes('json')) { try { dados = await r.json(); } catch (e) {} } else { try { dados = await r.text(); } catch (e) {} }
  return { status: r.status, dados, headers: r.headers };
}
const login = (email, senha) => chamar('POST', '/api/auth/login', { corpo: { email, senha } });
function lerSqlite(arq, sql, ...args) {
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(arq, { readOnly: true });
  try { return db.prepare(sql).all(...args); } finally { db.close(); }
}

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-multiempresa-'));
  const porta = 39000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ,
    // ambiente limpo: nenhuma chave de verdade (GitHub, IA, Utmify...) entra no teste
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
  // TMX_TESTE_LOG=<arquivo> guarda o log do servidor pra conferir depois
  if (process.env.TMX_TESTE_LOG) fs.writeFileSync(process.env.TMX_TESTE_LOG, log);
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('duas empresas e a TMX não enxergam nada uma da outra', async (t) => {
  const ctx = {};

  await t.test('TMX: login continua sem marca de empresa', async () => {
    const r = await login('thiago@axcend.com', 'axcend2026');
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.match(r.dados.token, /^ses_[0-9a-f]{64}$/);
    assert.strictEqual(r.dados.empresa.id, 'tmx');
    assert.strictEqual(r.dados.empresa.base, '');
    ctx.tmx = r.dados.token;
    ctx.tmxUser = r.dados.user.id;
  });

  await t.test('cria as empresas A e B (só a Diretoria da TMX)', async () => {
    const semLogin = await chamar('POST', '/api/plataforma/empresas', { corpo: { nome: 'X' } });
    assert.strictEqual(semLogin.status, 401);
    const conflito = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx,
      corpo: { nome: 'Conflito', usuario: { email: 'thiago@axcend.com', senha: 'umasenha123' } } });
    assert.strictEqual(conflito.status, 409, 'e-mail da TMX não pode virar de outra empresa');
    for (const [chave, nome, email, senha] of [['A', 'Empresa A', 'dona@empresa-a.com', 'senha-da-A-123'], ['B', 'Empresa B', 'dona@empresa-b.com', 'senha-da-B-123']]) {
      const r = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx,
        corpo: { nome, usuario: { nome: 'Dona ' + chave, email, senha } } });
      assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-2000));
      assert.match(r.dados.empresa.id, /^[a-z][a-z0-9]{5,15}$/);
      ctx['id' + chave] = r.dados.empresa.id;
      ctx['email' + chave] = email; ctx['senha' + chave] = senha;
    }
    const lista = await chamar('GET', '/api/plataforma/empresas', { token: ctx.tmx });
    assert.strictEqual(lista.status, 200);
    assert.strictEqual(lista.dados.empresas.length, 2);
  });

  await t.test('login de cada empresa vai para o motor dela', async () => {
    for (const k of ['A', 'B']) {
      const r = await login(ctx['email' + k], ctx['senha' + k]);
      assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
      assert.ok(r.dados.token.startsWith('ses_' + ctx['id' + k] + '.'), 'sessão leva a marca da empresa');
      assert.strictEqual(r.dados.empresa.id, ctx['id' + k]);
      assert.strictEqual(r.dados.empresa.base, '/e/' + ctx['id' + k]);
      ctx['tok' + k] = r.dados.token;
      ctx['user' + k] = r.dados.user.id;
    }
    // a senha de B não abre a conta de A, e o e-mail de A não entra como TMX
    assert.strictEqual((await login(ctx.emailA, ctx.senhaB)).status, 401);
    assert.strictEqual((await login('ninguem@lugar-nenhum.com', 'qualquer-coisa')).status, 401);
  });

  await t.test('sincronização: cada um só vê o seu', async () => {
    const ontem = new Date(Date.now() - 3 * 3600000 - 86400000).toISOString().slice(0, 10);
    const tarefa = (id, nome, resp) => [{ id, nome, status: 'A_FAZER', data: ontem, respId: resp, _updatedAt: Date.now() }];
    assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: ctx.tmx, corpo: tarefa('t-tmx', 'Tarefa da TMX', ctx.tmxUser) })).status, 200);
    assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: ctx.tokA, corpo: tarefa('t-a', 'Tarefa da A', ctx.userA) })).status, 200);
    assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: ctx.tokB, corpo: tarefa('t-b', 'Tarefa da B', ctx.userB) })).status, 200);
    const ver = async (tok) => (await chamar('GET', '/api/store', { token: tok })).dados;
    const a = await ver(ctx.tokA), b = await ver(ctx.tokB), x = await ver(ctx.tmx);
    assert.deepStrictEqual(a.tasks.map(t => t.id), ['t-a']);
    assert.deepStrictEqual(b.tasks.map(t => t.id), ['t-b']);
    assert.deepStrictEqual(x.tasks.map(t => t.id), ['t-tmx']);
    assert.deepStrictEqual(a.sl_usuarios.map(u => u.email), [ctx.emailA], 'empresa nova nasce só com a Diretoria dela');
    assert.ok(!x.sl_usuarios.some(u => u.email === ctx.emailA || u.email === ctx.emailB));
    assert.ok(!('sl_protocolo' in a), 'Meu Protocolo fica fora do produto');
    // atualização incremental também
    const upd = await chamar('GET', '/api/updates/0', { token: ctx.tokA });
    assert.deepStrictEqual(upd.dados.data.tasks.map(t => t.id), ['t-a']);
  });

  await t.test('sessão de uma empresa não abre outra', async () => {
    assert.strictEqual((await chamar('GET', '/e/' + ctx.idB + '/api/store', { token: ctx.tokA })).status, 401);
    assert.strictEqual((await chamar('GET', '/e/' + ctx.idA + '/api/store', { token: ctx.tmx })).status, 401);
    assert.strictEqual((await chamar('GET', '/api/store', { token: 'ses_zzzzzz9.' + 'a'.repeat(64) })).status, 401);
    assert.strictEqual((await chamar('GET', '/e/zzzzzz9/api/store', { token: ctx.tokA })).status, 401);
    assert.strictEqual((await chamar('GET', '/e/zzzzzz9/px.js')).status, 404, 'empresa que não existe nunca cai na TMX');
    // o que é da plataforma não existe dentro do motor
    assert.strictEqual((await chamar('GET', '/api/plataforma/empresas', { token: ctx.tokA })).status, 404);
    assert.strictEqual((await chamar('PUT', '/api/store/sl_protocolo', { token: ctx.tokA, corpo: { x: 1 } })).status, 404);
    assert.strictEqual((await chamar('POST', '/api/tokens/generate', { token: ctx.tokA, corpo: { nome: 'x' } })).status, 403);
    // Páginas (senhas de hospedagem) é só da Diretoria da TMX
    assert.strictEqual((await chamar('GET', '/api/pg/estado', { token: ctx.tokA })).status, 403);
    assert.strictEqual((await chamar('GET', '/api/pg/estado', { token: ctx.tmx })).status, 200);
  });

  await t.test('tempo real (SSE) da empresa abre no motor dela', async () => {
    const ac = new AbortController();
    const r = await fetch(base + '/api/sync/stream?token=' + encodeURIComponent(ctx.tokA), { signal: ac.signal });
    assert.strictEqual(r.status, 200);
    const leitor = r.body.getReader();
    const { value } = await leitor.read();
    assert.match(Buffer.from(value).toString(), /hello/);
    ac.abort();
  });

  await t.test('webhook de vendas cai só na empresa certa', async () => {
    const gerar = async tok => (await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: tok })).dados.urlWebhook;
    const urlA = await gerar(ctx.tokA), urlTmx = await gerar(ctx.tmx);
    assert.ok(urlA.startsWith('/e/' + ctx.idA + '/api/webhook/vendas/'), urlA);
    assert.ok(urlTmx.startsWith('/api/webhook/vendas/'), urlTmx);
    const venda = (pedido, valor) => ({ order_id: pedido, status: 'paid', amount: valor, product: { name: 'Produto' }, customer: { name: 'Cliente', email: pedido + '@cliente.com' } });
    assert.strictEqual((await chamar('POST', urlA + '/payt', { corpo: venda('P-A-1', 197) })).status, 200);
    assert.strictEqual((await chamar('POST', urlTmx + '/payt', { corpo: venda('P-TMX-1', 297) })).status, 200);
    // o token de A no endereço de B (ou sem endereço, que é a TMX) não entra
    const tokenA = urlA.split('/').pop();
    const errada = await chamar('POST', '/e/' + ctx.idB + '/api/webhook/vendas/' + tokenA + '/payt', { corpo: venda('P-X', 1) });
    assert.ok([401, 404].includes(errada.status), 'status ' + errada.status);
    const naTmx = await chamar('POST', '/api/webhook/vendas/' + tokenA + '/payt', { corpo: venda('P-Y', 1) });
    assert.strictEqual(naTmx.status, 401);
    const resumo = async tok => (await chamar('GET', '/api/integracoes/vendas/me', { token: tok })).dados;
    assert.strictEqual((await resumo(ctx.tokA)).eventos, 1);
    assert.strictEqual((await resumo(ctx.tokB)).eventos, 0);
    assert.strictEqual((await resumo(ctx.tmx)).eventos, 1);
    assert.strictEqual((await resumo(ctx.tokA)).totalVendas, 1);
  });

  await t.test('pixel: a visita entra só na base de pessoas da empresa', async () => {
    const px = await chamar('GET', '/e/' + ctx.idA + '/px.js');
    assert.strictEqual(px.status, 200);
    assert.match(String(px.headers.get('content-type')), /javascript/);
    const evento = { funil: 'fA', etapa: 'e1', tipo: 'entrou', id: 'visitante-da-A', pg: 'https://site-da-a.com/oferta' };
    assert.strictEqual((await chamar('POST', '/e/' + ctx.idA + '/api/funil/evento', { texto: JSON.stringify(evento) })).status, 204);
    const tmxEv = Object.assign({}, evento, { id: 'visitante-da-tmx', funil: 'fT' });
    assert.strictEqual((await chamar('POST', '/api/funil/evento', { texto: JSON.stringify(tmxEv) })).status, 204);
    const tem = (arq, vis) => fs.existsSync(arq) && lerSqlite(arq, 'SELECT id FROM visitantes WHERE id=?', vis).length > 0;
    const pA = path.join(dir, 'empresas', ctx.idA, 'pessoas.sqlite');
    const pB = path.join(dir, 'empresas', ctx.idB, 'pessoas.sqlite');
    const pT = path.join(dir, 'pessoas.sqlite');
    await ate(() => tem(pA, 'visitante-da-A'), 5000, 'visita na base da A');
    await ate(() => tem(pT, 'visitante-da-tmx'), 5000, 'visita na base da TMX');
    assert.ok(!tem(pT, 'visitante-da-A'), 'visita da A não pode estar na TMX');
    assert.ok(!tem(pB, 'visitante-da-A'), 'visita da A não pode estar na B');
    assert.ok(!tem(pA, 'visitante-da-tmx'), 'visita da TMX não pode estar na A');
  });

  await t.test('rotinas: lembretes e backup de cada empresa só com os dados dela', async () => {
    for (const tok of [ctx.tokA, ctx.tokB, ctx.tmx]) {
      const r = await chamar('POST', '/api/lembretes/rodar', { token: tok });
      assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    }
    const notifs = async tok => JSON.stringify((await chamar('GET', '/api/store', { token: tok })).dados.sl_notifs || []);
    const nA = await notifs(ctx.tokA), nB = await notifs(ctx.tokB), nT = await notifs(ctx.tmx);
    assert.match(nA, /Tarefa da A/);
    assert.doesNotMatch(nA, /Tarefa da (B|TMX)/);
    assert.match(nB, /Tarefa da B/);
    assert.doesNotMatch(nB, /Tarefa da (A|TMX)/);
    assert.doesNotMatch(nT, /Tarefa da (A|B)/);
    const snap = await chamar('POST', '/api/backup/snapshot', { token: ctx.tokA });
    assert.strictEqual(snap.status, 200, JSON.stringify(snap.dados));
    const arqs = fs.readdirSync(path.join(dir, 'empresas', ctx.idA, 'backups'));
    assert.ok(arqs.some(f => /manual/.test(f)), 'snapshot manual na pasta da A: ' + arqs.join(', '));
    const daTmx = fs.existsSync(path.join(dir, 'backups')) ? fs.readdirSync(path.join(dir, 'backups')) : [];
    assert.ok(!daTmx.some(f => /manual/.test(f)), 'o backup da A não vai pra pasta da TMX');
  });

  await t.test('o que é só da TMX não roda na empresa nova', async () => {
    const dbA = JSON.parse(fs.readFileSync(path.join(dir, 'empresas', ctx.idA, 'db.json'), 'utf8'));
    assert.deepStrictEqual(dbA.store.sl_usuarios.map(u => u.email), [ctx.emailA], 'sem os 6 usuários de exemplo');
    assert.ok(!dbA._migrated_v1_tenant, 'sem a migração antiga de multiempresa');
    assert.ok(!dbA._mig_assinatura_funil && !dbA._mig_upsell_paginas, 'sem as migrações do funil KALEBE');
    assert.ok(dbA.sessions.length >= 1, 'a sessão do 1º login continua de pé');
  });

  await t.test('motor que cai volta sozinho, sem perder o banco', async () => {
    const lista = async () => (await chamar('GET', '/api/plataforma/empresas', { token: ctx.tmx })).dados.empresas;
    const antes = (await lista()).find(e => e.id === ctx.idB);
    assert.ok(antes.pid, 'motor da B ligado');
    process.kill(antes.pid, 'SIGKILL');
    // enquanto religa, o pedido espera; quando volta, a B segue com os dados dela
    await ate(async () => {
      const r = await chamar('GET', '/api/store', { token: ctx.tokB });
      return r.status === 200 && r.dados.tasks.some(x => x.id === 't-b');
    }, 15000, 'motor da B religar');
    const depois = (await lista()).find(e => e.id === ctx.idB);
    assert.notStrictEqual(depois.pid, antes.pid);
    assert.strictEqual(depois.motor, 'ligado');
  });

  await t.test('TMX sem marca continua caindo na TMX', async () => {
    // com empresas existindo, o login passa pela portaria (que lê o e-mail) e tem de chegar na TMX igual
    const de_novo = await login('thiago@axcend.com', 'axcend2026');
    assert.strictEqual(de_novo.status, 200, JSON.stringify(de_novo.dados));
    assert.match(de_novo.dados.token, /^ses_[0-9a-f]{64}$/);
    assert.strictEqual((await login('thiago@axcend.com', 'senha-errada')).status, 401);
    const me = await chamar('GET', '/api/auth/me', { token: ctx.tmx });
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.dados.empresa.id, 'tmx');
    assert.strictEqual((await chamar('GET', '/px.js')).status, 200);
    const meA = await chamar('GET', '/api/auth/me', { token: ctx.tokA });
    assert.strictEqual(meA.dados.empresa.id, ctx.idA);
  });
});
