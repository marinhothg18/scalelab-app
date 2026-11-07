// Cobrança pela Pagar.me (07/11/2026).
// Sobe o servidor numa pasta temporária com uma Pagar.me de mentira e faz o caminho do cliente:
// página de planos → assinar → link de pagamento → pago → convite → cadastro. Confere que o aviso
// da Pagar.me não libera nada sem a conferência pela API, que o teste grátis vira pedido e que
// os avisos de cobrança recusada e cancelamento mudam o estado do pedido.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
let dir, srv, base, log = '', falsa, baseFalsa;
const pg = { planos: [], links: [], pagos: new Set(), cobrancas: {} };
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
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null;
  const tipo = r.headers.get('content-type') || '';
  if (tipo.includes('json')) { try { dados = await r.json(); } catch (e) {} } else { try { dados = await r.text(); } catch (e) {} }
  return { status: r.status, dados };
}

before(async () => {
  // a Pagar.me de mentira: planos, links de assinatura e cobranças
  falsa = http.createServer((req, res) => {
    let txt = '';
    req.on('data', b => { txt += b; });
    req.on('end', () => {
      const corpo = txt ? JSON.parse(txt) : null;
      const manda = (st, j) => { res.writeHead(st, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(j)); };
      if (!/^Basic /.test(req.headers.authorization || '')) return manda(401, { message: 'sem chave' });
      if (req.method === 'POST' && req.url === '/plans') { const id = 'plan_' + (pg.planos.length + 1); pg.planos.push(Object.assign({ id }, corpo)); return manda(200, { id, status: 'active' }); }
      if (req.method === 'POST' && req.url === '/paymentlinks') {
        const id = 'pl_' + (pg.links.length + 1);
        pg.links.push(Object.assign({ id }, corpo));
        return manda(200, { id, url: 'https://payment-link.pagar.me/' + id, status: 'active', total_paid_sessions: 0 });
      }
      let m = req.url.match(/^\/paymentlinks\/(pl_\d+)$/);
      if (req.method === 'GET' && m) return manda(200, { id: m[1], total_paid_sessions: pg.pagos.has(m[1]) ? 1 : 0 });
      m = req.url.match(/^\/charges\/(ch_\w+)$/);
      if (req.method === 'GET' && m) return pg.cobrancas[m[1]] ? manda(200, pg.cobrancas[m[1]]) : manda(404, { message: 'não existe' });
      manda(404, { message: 'rota de mentira não existe' });
    });
  });
  await new Promise(r => falsa.listen(0, '127.0.0.1', r));
  baseFalsa = 'http://127.0.0.1:' + falsa.address().port;

  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-cobranca-'));
  const porta = 43000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
           PAGARME_API_KEY: 'sk_test_de_mentira', PAGARME_API_BASE: baseFalsa, URL_TMX: base },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (falsa) falsa.close();
  if (process.env.TMX_TESTE_LOG) fs.writeFileSync(process.env.TMX_TESTE_LOG, log);
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('cobrança pela Pagar.me', async (t) => {
  const ctx = {};
  const aviso = (type, data) => chamar('POST', '/api/billing/webhook', { corpo: { id: 'hook_' + Date.now(), type, data } });

  await t.test('a página e os planos abrem para qualquer um', async () => {
    const p = await chamar('GET', '/planos');
    assert.strictEqual(p.status, 200);
    assert.match(p.dados, /Você paga pela faixa de investimento/);
    assert.strictEqual((await chamar('GET', '/planos/obrigado?r=as_x')).status, 200);
    const l = await chamar('GET', '/api/planos');
    assert.strictEqual(l.status, 200);
    assert.strictEqual(l.dados.cobranca, true);
    assert.deepStrictEqual(l.dados.planos.map(x => x.id), ['iniciante', 'starter', 'escala', 'agencia']);
    const st = l.dados.planos.find(x => x.id === 'starter');
    assert.strictEqual(st.mensal, 197);
    assert.strictEqual(st.anual, 1970, 'anual = 10 meses (2 grátis)');
  });

  await t.test('confere os dados antes de abrir o pagamento', async () => {
    assert.strictEqual((await chamar('POST', '/api/assinar', { corpo: { plano: 'nada' } })).status, 400);
    assert.strictEqual((await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', email: 'a@b.com', whatsapp: '11999990000' } })).dados.campo, 'nome');
    assert.strictEqual((await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', nome: 'Ana', email: 'ana', whatsapp: '11999990000' } })).dados.campo, 'email');
    assert.strictEqual((await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', nome: 'Ana', email: 'ana@clinica.com', whatsapp: '123' } })).dados.campo, 'whatsapp');
    assert.strictEqual((await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', nome: 'T', email: 'thiago@axcend.com', whatsapp: '11999990000' } })).status, 409, 'quem já tem conta entra pelo login');
    assert.strictEqual(pg.links.length, 0, 'nada chegou na Pagar.me');
  });

  await t.test('o teste grátis vira pedido pra TMX liberar, sem Pagar.me', async () => {
    const r = await chamar('POST', '/api/assinar', { corpo: { plano: 'iniciante', nome: 'Bia', email: 'bia@loja.com', whatsapp: '(21) 98888-7777' } });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.dados.gratis, true);
    assert.strictEqual(pg.links.length, 0);
    const tmx = await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } });
    ctx.tmx = tmx.dados.token;
    const l = await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx });
    assert.strictEqual(l.status, 200);
    const pedido = l.dados.assinaturas.find(a => a.email === 'bia@loja.com');
    assert.ok(pedido && pedido.status === 'pedido' && pedido.whatsapp === '5521988887777');
    assert.strictEqual((await chamar('GET', '/api/plataforma/assinaturas')).status, 401, 'lista só pra Diretoria da TMX');
  });

  await t.test('assinar o Starter anual abre o link de assinatura da Pagar.me', async () => {
    const r = await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', ciclo: 'anual', nome: 'Ana Souza', email: 'Ana@Clinica.com', whatsapp: '11 99999-0000' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-1500));
    assert.match(r.dados.url, /^https:\/\/payment-link\.pagar\.me\/pl_1$/);
    ctx.ref = r.dados.ref;
    assert.strictEqual(pg.planos.length, 1);
    assert.strictEqual(pg.planos[0].interval, 'year');
    assert.strictEqual(pg.planos[0].items[0].pricing_scheme.price, 197000, 'R$ 1.970 em centavos');
    assert.deepStrictEqual(pg.planos[0].payment_methods, ['credit_card']);
    const link = pg.links[0];
    assert.strictEqual(link.type, 'subscription');
    assert.strictEqual(link.cart_settings.recurrences[0].plan_id, 'plan_1');
    assert.strictEqual(link.max_paid_sessions, 1);
    assert.strictEqual(link.customer_settings.customer.code, ctx.ref);
    assert.strictEqual(link.customer_settings.customer.email, 'ana@clinica.com');
    assert.ok(link.flow_settings.success_url.endsWith('/planos/obrigado?r=' + ctx.ref));
    // o segundo pedido do mesmo plano e ciclo reaproveita o plano já criado lá
    const r2 = await chamar('POST', '/api/assinar', { corpo: { plano: 'starter', ciclo: 'anual', nome: 'Caio', email: 'caio@x.com', whatsapp: '11988887777' } });
    assert.strictEqual(r2.status, 200);
    assert.strictEqual(pg.planos.length, 1);
  });

  await t.test('aviso inventado não libera: o TMX confere com a Pagar.me', async () => {
    const s = await chamar('GET', '/api/assinar/situacao?r=' + ctx.ref);
    assert.strictEqual(s.status, 200);
    assert.strictEqual(s.dados.status, 'aguardando');
    assert.ok(!s.dados.convite);
    await aviso('charge.paid', { id: 'ch_falsa', status: 'paid', customer: { code: ctx.ref, email: 'ana@clinica.com' } });
    await espera(400);
    const s2 = await chamar('GET', '/api/assinar/situacao?r=' + ctx.ref);
    assert.strictEqual(s2.dados.status, 'aguardando', 'o link não foi pago de verdade');
    assert.strictEqual((await chamar('GET', '/api/assinar/situacao?r=as_' + 'x'.repeat(24))).status, 404);
  });

  await t.test('pago de verdade: a tela de volta mostra o convite do plano comprado', async () => {
    pg.pagos.add('pl_1');
    await aviso('subscription.created', { id: 'sub_123', status: 'active', customer: { id: 'cus_9', code: ctx.ref, email: 'ana@clinica.com' } });
    await ate(async () => (await chamar('GET', '/api/assinar/situacao?r=' + ctx.ref)).dados.status === 'paga', 5000, 'liberar');
    const s = await chamar('GET', '/api/assinar/situacao?r=' + ctx.ref);
    assert.match(s.dados.convite, /\/cadastro\?c=cv_/);
    assert.strictEqual(s.dados.plano, 'Starter');
    assert.strictEqual(s.dados.valor, 1970);
    ctx.codigo = new URL(s.dados.convite).searchParams.get('c');
    const c = await chamar('GET', '/api/cadastro/convite?c=' + ctx.codigo);
    assert.strictEqual(c.status, 200);
    assert.strictEqual(c.dados.email, 'ana@clinica.com');
    assert.strictEqual(c.dados.plano, 'starter');
    // o aviso repetido não gera outro convite
    await aviso('charge.paid', { id: 'ch_1', customer: { code: ctx.ref } });
    await espera(300);
    assert.strictEqual((await chamar('GET', '/api/assinar/situacao?r=' + ctx.ref)).dados.convite, s.dados.convite);
  });

  await t.test('a tela de volta também libera sozinha, sem esperar o aviso', async () => {
    const l = await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx });
    const caio = l.dados.assinaturas.find(a => a.email === 'caio@x.com');
    assert.strictEqual(caio.status, 'aguardando');
    pg.pagos.add('pl_2');
    const ref2 = pg.links[1].customer_settings.customer.code;
    await ate(async () => (await chamar('GET', '/api/assinar/situacao?r=' + ref2)).dados.status === 'paga', 15000, 'conferência pela tela');
  });

  await t.test('o cadastro com o convite da compra cria a empresa no plano comprado', async () => {
    const r = await chamar('POST', '/api/cadastro', { corpo: { c: ctx.codigo, nome: 'Ana Souza', email: 'ana@clinica.com', senha: 'senha-forte-1',
      whatsapp: '11999990000', empresa: 'Clínica Ana', projetos: [{ nicho: 'Concursos', nome: 'Projeto Ana' }] } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-2000));
    const emp = await chamar('GET', '/api/plataforma/empresas', { token: ctx.tmx });
    const e = emp.dados.empresas.find(x => x.nome === 'Clínica Ana');
    assert.strictEqual(e.plano, 'starter');
    assert.strictEqual(e.origem, 'compra');
    const s = await chamar('GET', '/api/assinar/situacao?r=' + ctx.ref);
    assert.strictEqual(s.dados.cadastrado, true);
    assert.ok(!s.dados.convite, 'depois do cadastro o link some');
    // o Meu plano do cliente mostra a assinatura dele
    const mp = await chamar('GET', '/api/meu-plano', { token: r.dados.token });
    assert.strictEqual(mp.status, 200, JSON.stringify(mp.dados));
    assert.strictEqual(mp.dados.plano.id, 'starter');
    assert.strictEqual(mp.dados.cobranca.ligada, true);
    assert.strictEqual(mp.dados.cobranca.status, 'paga');
    assert.strictEqual(mp.dados.cobranca.ciclo, 'anual');
    assert.strictEqual(mp.dados.cobranca.valor, 1970);
    assert.ok(Array.isArray(mp.dados.cobranca.faturas));
  });

  await t.test('cobrança recusada, paga de novo e cancelada mudam o estado', async () => {
    const estado = async () => (await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx })).dados.assinaturas.find(a => a.email === 'ana@clinica.com').status;
    await aviso('charge.payment_failed', { id: 'ch_2', invoice: { subscription_id: 'sub_123' } });
    await ate(async () => (await estado()) === 'atrasada', 4000, 'atrasada');
    await aviso('charge.paid', { id: 'ch_3', invoice: { subscription_id: 'sub_123' } });
    await ate(async () => (await estado()) === 'paga', 4000, 'em dia');
    await aviso('subscription.canceled', { id: 'sub_123', status: 'canceled' });
    await ate(async () => (await estado()) === 'cancelada', 4000, 'cancelada');
  });
});
