// Venda do TMX pela Payt (07/11/2026).
// Sobe o servidor numa pasta temporária, cola os links da Payt como a Central faz e manda os avisos
// de venda da Payt pro endereço próprio da venda do TMX. Confere que a venda paga vira o convite do
// plano certo (com o e-mail e o WhatsApp da compra), que a renovação não gera outro, que reembolso
// muda o estado, que o endereço errado é recusado e que nada disso entra nas vendas dos funis.
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
  if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined, redirect: 'manual' });
  let dados = null;
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados, location: r.headers.get('location') };
}
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-payt-'));
  const porta = 49000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, URL_TMX: base }, stdio: ['ignore', 'pipe', 'pipe']
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const LINK_STARTER = 'https://checkout.payt.com.br/abc123starter';
const LINK_ESCALA_ANUAL = 'https://checkout.payt.com.br/xyz789escalaanual';
const venda = (status, extra = {}) => Object.assign({
  id: 'ord-1', status,
  product: { name: 'TMX Digital', code: 'P1' },
  customer: { name: 'Caio Lima', email: 'Caio@Loja.com', phone: '(11) 98888-7777' },
  transaction: { total_price: 19700, payment_method: 'credit_card', payment_status: status },
  link: { title: 'TMX Starter', url: LINK_STARTER },
  subscription: { code: 'sub-starter-1', charges: 1, status: 'active' }
}, extra);

test('venda do TMX pela Payt', async (t) => {
  const ctx = {};
  ctx.tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;

  await t.test('a Central cola os links e pega o endereço do aviso', async () => {
    assert.strictEqual((await chamar('GET', '/api/plataforma/venda-tmx')).status, 401);
    const c = await chamar('GET', '/api/plataforma/venda-tmx', { token: ctx.tmx });
    assert.strictEqual(c.status, 200);
    assert.strictEqual(c.dados.gateway, 'pagarme', 'sem links, continua a Pagar.me');
    assert.match(c.dados.webhook, /\/api\/billing\/payt\/[0-9a-f]{48}$/);
    ctx.aviso = new URL(c.dados.webhook).pathname;
    assert.strictEqual((await chamar('POST', '/api/plataforma/venda-tmx', { token: ctx.tmx, corpo: { links: { 'starter:mensal': 'http://inseguro' } } })).status, 400);
    const s = await chamar('POST', '/api/plataforma/venda-tmx', { token: ctx.tmx, corpo: { gateway: 'payt', links: { 'starter:mensal': LINK_STARTER, 'escala:anual': LINK_ESCALA_ANUAL } } });
    assert.strictEqual(s.status, 200);
    assert.strictEqual(Object.keys(s.dados.links).length, 2);
  });

  await t.test('a página de planos e o link direto levam pro checkout da Payt', async () => {
    const l = (await chamar('GET', '/api/planos-tmx')).dados;
    assert.strictEqual(l.gateway, 'payt');
    assert.strictEqual(l.cobranca, true);
    assert.strictEqual(l.planos.find(p => p.id === 'starter').checkout.mensal, LINK_STARTER);
    assert.strictEqual(l.planos.find(p => p.id === 'iniciante').checkout, null);
    const a = await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', ciclo: 'mensal' } });
    assert.strictEqual(a.status, 200);
    assert.strictEqual(a.dados.url, LINK_STARTER);
    const d = await chamar('GET', '/assinar/escala?ciclo=anual');
    assert.strictEqual(d.status, 302);
    assert.strictEqual(d.location, LINK_ESCALA_ANUAL);
    assert.strictEqual((await chamar('GET', '/assinar/agencia')).location, '/planos#planos', 'plano sem link volta pros planos');
  });

  await t.test('endereço de aviso errado é recusado', async () => {
    assert.strictEqual((await chamar('POST', '/api/billing/payt/' + 'f'.repeat(48), { corpo: venda('paid') })).status, 404);
  });

  await t.test('venda paga vira o convite do plano, com o contato da compra', async () => {
    assert.strictEqual((await chamar('POST', ctx.aviso, { corpo: venda('waiting_payment') })).status, 200);
    assert.strictEqual((await chamar('POST', ctx.aviso, { corpo: venda('paid') })).status, 200);
    let pedido;
    await ate(async () => {
      pedido = (await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas.find(x => x.email === 'caio@loja.com');
      return pedido && pedido.status === 'paga';
    }, 5000, 'liberar a venda da Payt');
    assert.strictEqual(pedido.plano, 'starter');
    assert.strictEqual(pedido.ciclo, 'mensal');
    assert.strictEqual(pedido.whatsapp, '5511988887777');
    assert.match(pedido.convite, /\/cadastro\?c=cv_/);
    const c = await chamar('GET', '/api/cadastro/convite?c=' + new URL(pedido.convite).searchParams.get('c'));
    assert.strictEqual(c.dados.email, 'caio@loja.com');
    assert.strictEqual(c.dados.plano, 'starter');
    ctx.convite = pedido.convite;
    const cfg = (await chamar('GET', '/api/plataforma/venda-tmx', { token: ctx.tmx })).dados;
    assert.strictEqual(cfg.ultimoAviso.evento, 'paid', 'a Central vê quando chegou o último aviso');
    assert.ok(cfg.ultimoAviso.em > Date.now() - 60000);
  });

  await t.test('renovação não gera outro convite; reembolso muda o estado', async () => {
    await chamar('POST', ctx.aviso, { corpo: venda('paid', { id: 'ord-2', subscription: { code: 'sub-starter-1', charges: 2, status: 'active' } }) });
    await espera(300);
    const lista = (await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas.filter(x => x.email === 'caio@loja.com');
    assert.strictEqual(lista.length, 1, 'um pedido só por assinatura');
    assert.strictEqual(lista[0].convite, ctx.convite);
    await chamar('POST', ctx.aviso, { corpo: venda('canceled', { transaction: { total_price: 0, payment_status: 'refunded' } }) });
    await ate(async () => (await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas.find(x => x.email === 'caio@loja.com').status === 'cancelada', 4000, 'reembolso');
  });

  await t.test('pelo nome também acha o plano; produto desconhecido não vira pedido', async () => {
    await chamar('POST', ctx.aviso, { corpo: venda('paid', { id: 'ord-3', link: { title: 'Plano Escala anual' }, subscription: { code: 'sub-esc-1', charges: 1 },
      customer: { name: 'Duda', email: 'duda@x.com', phone: '31977776666' } }) });
    await chamar('POST', ctx.aviso, { corpo: venda('paid', { id: 'ord-4', link: { title: 'Curso de culinária' }, product: { name: 'Curso de culinária' }, subscription: { code: 'sub-x' },
      customer: { name: 'Edu', email: 'edu@x.com' } }) });
    await ate(async () => !!(await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas.find(x => x.email === 'duda@x.com'), 4000, 'pelo nome');
    const lista = (await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas;
    const duda = lista.find(x => x.email === 'duda@x.com');
    assert.strictEqual(duda.plano, 'escala');
    assert.strictEqual(duda.ciclo, 'anual');
    assert.ok(!lista.find(x => x.email === 'edu@x.com'), 'produto que não é plano do TMX não vira pedido');
  });

  await t.test('renovação sem o código da assinatura reconhece o cliente pelo e-mail', async () => {
    await chamar('POST', ctx.aviso, { corpo: venda('paid', { id: 'ord-5', subscription: undefined, link: { title: 'Plano Escala anual' },
      customer: { name: 'Duda', email: 'duda@x.com', phone: '31977776666' } }) });
    await espera(300);
    const dela = (await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas.filter(x => x.email === 'duda@x.com');
    assert.strictEqual(dela.length, 1, 'não abriu um segundo pedido nem outro convite');
  });

  await t.test('a venda do TMX não entra nas vendas dos funis', async () => {
    const me = (await chamar('GET', '/api/integracoes/vendas/me', { token: ctx.tmx })).dados;
    assert.strictEqual(me.eventos, 0);
  });
});
