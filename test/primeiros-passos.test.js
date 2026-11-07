// Primeiros passos do cliente (07/11/2026).
// Sobe o servidor numa pasta temporária (a TMX + a empresa A) e confere que a rota diz o que
// já está ligado lendo o que existe (checkout, produtos, vendas), guarda só quando a tela foi
// vista e o que a pessoa pulou, não existe na TMX e é só da Diretoria.
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
  return { status: r.status, dados };
}
const login = (email, senha) => chamar('POST', '/api/auth/login', { corpo: { email, senha } });

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-primeiros-'));
  const porta = 45000 + Math.floor(Math.random() * 2000);
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

test('primeiros passos da empresa cliente', async (t) => {
  const ctx = {};

  await t.test('prepara a TMX e a empresa A', async () => {
    const r = await login('thiago@axcend.com', 'axcend2026');
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    ctx.tmx = r.dados.token;
    const c = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx,
      corpo: { nome: 'Empresa A', usuario: { nome: 'Dona A', email: 'dona@empresa-a.com', senha: 'senha-da-A-123' } } });
    assert.strictEqual(c.status, 200, JSON.stringify(c.dados) + log.slice(-2000));
    ctx.idA = c.dados.empresa.id;
    const l = await login('dona@empresa-a.com', 'senha-da-A-123');
    assert.strictEqual(l.status, 200, JSON.stringify(l.dados));
    ctx.tokA = l.dados.token;
  });

  await t.test('na TMX não existe', async () => {
    const r = await chamar('GET', '/api/primeiros-passos', { token: ctx.tmx });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.dados.mostrar, false);
    assert.strictEqual((await chamar('POST', '/api/primeiros-passos', { token: ctx.tmx, corpo: { visto: true } })).status, 404);
  });

  await t.test('cliente novo: nada ligado e ainda não viu a tela', async () => {
    const r = await chamar('GET', '/api/primeiros-passos', { token: ctx.tokA });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.strictEqual(r.dados.mostrar, true);
    assert.strictEqual(r.dados.vistoEm, null);
    assert.strictEqual(r.dados.total, 6);
    assert.strictEqual(r.dados.feitos, 0);
    assert.deepStrictEqual(Object.keys(r.dados.passos), ['meta', 'utmify', 'checkout', 'produtos', 'projeto', 'venda']);
    assert.strictEqual(r.dados.passos.checkout.url, null);
    assert.strictEqual((await chamar('GET', '/api/primeiros-passos')).status, 401, 'sem login não lê');
  });

  await t.test('o suporte da TMX olha sem gastar o primeiro login do cliente', async () => {
    const r = await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/suporte', { token: ctx.tmx,
      corpo: { motivo: 'ajudar a ligar a Meta', modo: 'mexer', minutos: 15, avisar: false } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const v = await chamar('POST', '/api/primeiros-passos', { token: r.dados.token, corpo: { visto: true } });
    assert.strictEqual(v.status, 200, JSON.stringify(v.dados));
    assert.strictEqual(v.dados.vistoEm, null);
  });

  await t.test('a primeira vez que a tela abre fica guardada, uma vez só', async () => {
    const v = await chamar('POST', '/api/primeiros-passos', { token: ctx.tokA, corpo: { visto: true } });
    assert.strictEqual(v.status, 200);
    assert.ok(v.dados.vistoEm, 'guardou quando viu');
    const de2 = await chamar('POST', '/api/primeiros-passos', { token: ctx.tokA, corpo: { visto: true } });
    assert.strictEqual(de2.dados.vistoEm, v.dados.vistoEm, 'não muda depois');
  });

  await t.test('pular a Utmify conta como feito e dá pra desfazer; os outros passos não pulam', async () => {
    const p = await chamar('POST', '/api/primeiros-passos', { token: ctx.tokA, corpo: { pular: 'utmify' } });
    assert.strictEqual(p.dados.passos.utmify.pulado, true);
    assert.strictEqual(p.dados.feitos, 1);
    const d = await chamar('POST', '/api/primeiros-passos', { token: ctx.tokA, corpo: { pular: 'utmify', desfazer: true } });
    assert.strictEqual(d.dados.passos.utmify.pulado, false);
    assert.strictEqual(d.dados.feitos, 0);
    assert.strictEqual((await chamar('POST', '/api/primeiros-passos', { token: ctx.tokA, corpo: { pular: 'checkout' } })).status, 400);
  });

  await t.test('checkout, produto e venda: o passo fica verde lendo o que já existe', async () => {
    const g = await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: ctx.tokA });
    assert.strictEqual(g.status, 200);
    let r = (await chamar('GET', '/api/primeiros-passos', { token: ctx.tokA })).dados;
    assert.ok(r.passos.checkout.url.startsWith('/e/' + ctx.idA + '/api/webhook/vendas/'), r.passos.checkout.url);
    assert.strictEqual(r.passos.checkout.ok, false, 'endereço gerado ainda não é venda recebida');
    const pr = await chamar('POST', '/api/produtos', { token: ctx.tokA, corpo: { lista: [{ nome: 'Guia A', papel: 'principal', projeto: 'Projeto A', ofertas: [{ nome: 'Oferta', preco: 97, periodo: 'unico' }] }] } });
    assert.strictEqual(pr.status, 200, JSON.stringify(pr.dados));
    const venda = { order_id: 'P-A-1', status: 'paid', amount: 97, product: { name: 'Guia A' }, customer: { name: 'Cliente', email: 'c@cliente.com' } };
    assert.strictEqual((await chamar('POST', r.passos.checkout.url + '/payt', { corpo: venda })).status, 200);
    r = (await chamar('GET', '/api/primeiros-passos', { token: ctx.tokA })).dados;
    assert.strictEqual(r.passos.checkout.ok, true);
    assert.strictEqual(r.passos.produtos.ok, true);
    assert.deepStrictEqual(r.passos.produtos.nomes, ['Guia A']);
    assert.strictEqual(r.passos.venda.ok, true);
    assert.strictEqual(r.feitos, 3);
    // a TMX continua sem nada disso
    assert.strictEqual((await chamar('GET', '/api/primeiros-passos', { token: ctx.tmx })).dados.mostrar, false);
  });

  await t.test('a Central TMX Admin recomeça: a tela volta a abrir no próximo login, sem desligar nada', async () => {
    await chamar('POST', '/api/primeiros-passos', { token: ctx.tokA, corpo: { pular: 'utmify' } });
    const antes = (await chamar('GET', '/api/primeiros-passos', { token: ctx.tokA })).dados;
    assert.ok(antes.vistoEm);
    assert.strictEqual(antes.passos.utmify.pulado, true);
    // o cliente não chama a rota da Central
    assert.notStrictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/primeiros-passos', { token: ctx.tokA })).status, 200);
    const r = await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/primeiros-passos', { token: ctx.tmx });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const depois = (await chamar('GET', '/api/primeiros-passos', { token: ctx.tokA })).dados;
    assert.strictEqual(depois.vistoEm, null);
    assert.strictEqual(depois.passos.utmify.pulado, false);
    assert.strictEqual(depois.passos.checkout.ok, true, 'o que já estava ligado continua');
    assert.strictEqual(depois.passos.produtos.ok, true);
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/nao-existe/primeiros-passos', { token: ctx.tmx })).status, 404);
  });

  await t.test('só a Diretoria da empresa', async () => {
    const us = (await chamar('GET', '/api/store', { token: ctx.tokA })).dados.sl_usuarios;
    us.push({ id: 'u-copy-a', nome: 'Copy A', email: 'copy@empresa-a.com', senha: 'senha-copy-a-123', cargo: 'Copy', ativo: true, _updatedAt: Date.now() });
    assert.strictEqual((await chamar('PUT', '/api/store/sl_usuarios', { token: ctx.tokA, corpo: us })).status, 200);
    const l = await login('copy@empresa-a.com', 'senha-copy-a-123');
    assert.strictEqual(l.status, 200, JSON.stringify(l.dados));
    assert.strictEqual((await chamar('GET', '/api/primeiros-passos', { token: l.dados.token })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/primeiros-passos', { token: l.dados.token, corpo: { pular: 'utmify' } })).status, 403);
  });
});
