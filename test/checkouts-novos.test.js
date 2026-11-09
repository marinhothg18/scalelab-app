// Vendas da Kirvano, Cakto, Perfect Pay e Cartpanda pelo webhook (09/11/2026).
// Os avisos são os exemplos da documentação de cada uma (a Cartpanda só publica o pedido, não o aviso).
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
let dir, srv, base, log = '', tmx, caminho;
const espera = ms => new Promise(r => setTimeout(r, ms));
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
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-checkouts-'));
  const porta = 49000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
  tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  caminho = new URL((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: tmx })).dados.urlWebhook, base).pathname;
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});
const enviar = async (plataforma, corpo) => {
  const r = await chamar('POST', caminho + (plataforma ? '/' + plataforma : ''), { corpo });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
};
const vendas = () => JSON.parse(fs.readFileSync(path.join(dir, 'db.json'), 'utf8')).store.sl_vendas || [];
// cada aviso é uma linha nova: o reembolso entra ao lado da venda, com o mesmo pedido
const achar = (id, status) => vendas().find(v => v.pedidoId === id && (!status || v.status === status));
const resumo = async () => (await chamar('GET', '/api/integracoes/vendas/me', { token: tmx })).dados;

const kirvano = (event, status, extra = {}) => Object.assign({
  event, event_description: 'x', checkout_id: 'Q8J1N6K3', sale_id: 'D2RP8RQ7', payment_method: 'CREDIT_CARD', total_price: 'R$ 1.169,80', type: 'ONE_TIME', status,
  created_at: '2026-11-09 10:00:00', customer: { name: 'João da Silva', document: '23875090127', email: 'joao@exemplo.com', phone_number: '5511987654321' },
  payment: { method: 'CREDIT_CARD', brand: 'visa', installments: 1, finished_at: '2026-11-09 10:00:15' },
  products: [{ id: 'b1', name: 'Excel', is_order_bump: true, price: 'R$ 49,90' }, { id: 'p1', name: 'Mercado de Ações', is_order_bump: false, price: 'R$ 1.119,90' }],
  utm: { src: 'tmx_vkirvano123', utm_source: 'facebook', utm_medium: 'cpc', utm_campaign: 'camp', utm_term: 't', utm_content: 'AD1' }
}, extra);
const cakto = (event, d = {}) => ({ secret: 'seg', event, data: Object.assign({
  id: 'b3df956e-1998', refId: '4852F91', status: 'paid', offer_type: 'main', checkoutUrl: 'https://pay.cakto.com.br/a8BcHrY', baseAmount: 500, amount: 500, currency: 'BRL', fees: 40, installments: 1, paymentMethod: 'credit_card',
  customer: { name: 'Maria', email: 'maria@exemplo.com', phone: '5534999999999', docType: 'cpf', docNumber: '12345678909' },
  product: { id: 'p', name: 'Produto Cakto' }, offer: { id: 'a8', name: 'Oferta', price: 500 }, subscription: null,
  utm_source: 'facebook', utm_medium: 'cpc', utm_campaign: 'c', utm_term: null, utm_content: 'AD2', sck: 'tmx_vcakto1234', createdAt: '2026-11-09T10:00:00-03:00', paidAt: '2026-11-09T10:00:05-03:00'
}, d) });
const perfect = (status, extra = {}) => Object.assign({
  token: 'pub', code: 'PPCPMT000000000', sale_amount: 197.9, currency_enum: 1, currency_enum_key: 'BRL', installments: 3, payment_type_enum: 1, payment_type_enum_key: 'credit_card', sale_status_enum: status, date_created: '2026-11-09 10:00:00', date_approved: '2026-11-09 10:00:05',
  product: { code: 'PP', name: 'Curso Perfect' }, plan: { code: 'PL', name: 'Plano Mensal' },
  customer: { full_name: 'Bia Souza', email: 'bia@exemplo.com', identification_number: '00000000000', phone_formated_ddi: '+5511988887777' },
  metadata: { src: 'organic', sck: 'tmx_vperfect12', utm_source: 'facebook', utm_medium: 'cpc', utm_campaign: 'c', utm_content: 'AD3', utm_term: null },
  commission: [{ name: 'PerfectPay', commission_amount: 9.9, affiliation_type_enum: 0 }]
}, extra);
const pedido = (extra = {}) => Object.assign({
  id: 21021, name: '#493', total_price: '500,00', unformatted_total_price: 50000, email: 'cli@exemplo.com', phone: '+5511', currency: 'R$', presentment_currency: 'R$', payment_status: 3, status_id: '2', payment_type: 'cc', test: 0, is_cartx_test: 0,
  chargeback_received: 0, created_at: '2026-11-09 10:00:00', processed_at: '2026-11-09 10:00:05', checkout_link: 'https://loja.mycartpanda.com/checkout?sck=tmx_vpanda1234&utm_source=facebook',
  line_items: [{ id: 1, title: 'Camiseta', name: 'Camiseta M', quantity: 1 }], customer: { first_name: 'Carla', last_name: 'Lima', email: 'carla@exemplo.com', phone: '5511977776666', cpf: '156218321', full_name: 'Carla Lima' }
}, extra);

test('Kirvano', async () => {
  await enviar('kirvano', kirvano('PIX_GENERATED', 'PENDING', { sale_id: 'PIX1' }));
  assert.strictEqual(achar('kirvano:PIX1').status, 'waiting_payment', log.slice(-800));
  await enviar('kirvano', kirvano('SALE_APPROVED', 'APPROVED'));
  const v = achar('kirvano:D2RP8RQ7');
  assert.strictEqual(v.status, 'paid');
  assert.strictEqual(v.valor, 1169.8, 'R$ 1.169,80 vira número');
  assert.strictEqual(v.produto, 'Mercado de Ações', 'o principal, não o order bump');
  assert.strictEqual(v.vid, 'vkirvano123', 'o id da pessoa volta no src');
  await enviar('kirvano', kirvano('SALE_REFUNDED', 'REFUNDED'));
  assert.ok(achar('kirvano:D2RP8RQ7', 'refunded'), 'o reembolso cai no mesmo pedido');
  await enviar('kirvano', kirvano('SUBSCRIPTION_RENEWED', 'APPROVED', { sale_id: 'SUB1', type: 'RECURRING', created_at: '2026-12-09 10:00:00' }));
  const renov = vendas().find(x => String(x.pedidoId).startsWith('kirvano:SUB1:renov:'));
  assert.ok(renov && renov.renovacao === true, 'renovação é venda à parte e conta como renovação');
  await enviar('kirvano', kirvano('SUBSCRIPTION_CANCELED', 'CANCELED', { sale_id: 'SUB2', type: 'RECURRING' }));
  assert.ok(!achar('kirvano:SUB2'), 'cancelamento de assinatura não é venda');
  await enviar('kirvano', { event: 'ABANDONED_CART', status: 'ABANDONED_CART', checkout_id: 'Q8', total_price: 'R$ 10,00', customer: { name: 'A', email: 'aband@exemplo.com' }, products: [{ name: 'P' }], utm: {} });
  assert.strictEqual(achar('kirvano-carrinho:aband@exemplo.com').status, 'lost_cart');
});

test('Cakto', async () => {
  await enviar('cakto', cakto('purchase_approved'));
  const v = achar('cakto:b3df956e-1998');
  assert.strictEqual(v.status, 'paid', log.slice(-800));
  assert.strictEqual(v.valor, 500);
  assert.strictEqual(v.vid, 'vcakto1234');
  assert.strictEqual(v.produto, 'Produto Cakto');
  await enviar('cakto', cakto('chargeback', { status: 'MED' }));
  assert.ok(achar('cakto:b3df956e-1998', 'chargeback'));
  await enviar('cakto', { secret: 's', event: 'purchase_approved', data: [cakto('x', { id: 'v2-main', amount: 100, fees: 10 }).data, cakto('x', { id: 'v2-bump', amount: 30, fees: 3, offer_type: 'orderbump' }).data] });
  assert.strictEqual(achar('cakto:v2-main').valor, 130, 'webhook V2: principal mais order bump');
  await enviar('cakto', cakto('refund_requested', { id: 'pedido-reembolso', status: 'refund_requested' }));
  assert.ok(!achar('cakto:pedido-reembolso'), 'pedido de reembolso ainda não é reembolso');
  await enviar('cakto', { secret: 's', event: 'checkout_abandonment', data: { offer: { name: 'O' }, product: { name: 'P' }, customerName: 'A', customerEmail: 'ab@exemplo.com', customerCellphone: '55', checkoutUrl: 'https://pay.cakto.com.br/x', createdAt: '2026-11-09T10:00:00-03:00' } });
  assert.strictEqual(achar('cakto-carrinho:ab@exemplo.com').status, 'lost_cart');
});

test('Perfect Pay', async () => {
  await enviar('perfectpay', perfect(1, { code: 'PPPIX' }));
  assert.strictEqual(achar('perfectpay:PPPIX').status, 'waiting_payment', log.slice(-800));
  await enviar('perfectpay', perfect(2));
  const v = achar('perfectpay:PPCPMT000000000');
  assert.strictEqual(v.status, 'paid');
  assert.strictEqual(v.valor, 197.9);
  assert.strictEqual(v.vid, 'vperfect12');
  assert.strictEqual(v.produto, 'Curso Perfect');
  await enviar('perfectpay', perfect(4, { code: 'PPDISPUTA' }));
  assert.ok(!achar('perfectpay:PPDISPUTA'), 'em disputa não muda nada');
  await enviar('perfectpay', perfect(9));
  assert.ok(achar('perfectpay:PPCPMT000000000', 'chargeback'));
});

test('Cartpanda', async () => {
  await enviar('cartpanda', { event: 'order.created', order: pedido({ id: 1, payment_status: 1 }) });
  assert.strictEqual(achar('cartpanda:1').status, 'waiting_payment', log.slice(-800));
  await enviar('cartpanda', { event: 'order.paid', order: pedido() });
  const v = achar('cartpanda:21021');
  assert.strictEqual(v.status, 'paid');
  assert.strictEqual(v.valor, 500, 'centavos viram reais');
  assert.strictEqual(v.vid, 'vpanda1234', 'o id vem do link do checkout');
  assert.strictEqual(v.produto, 'Camiseta');
  await enviar('cartpanda', { event: 'order.refunded', order: pedido() });
  assert.ok(achar('cartpanda:21021', 'refunded'));
  await enviar('cartpanda', { event: 'order.paid', order: pedido({ id: 2, is_cartx_test: 1 }) });
  assert.ok(!achar('cartpanda:2'), 'pedido de teste não vira venda');
  await enviar('cartpanda', { event: 'product.updated', id: 77, title: 'x' });
  assert.ok(!achar('cartpanda:77'), 'aviso de produto não vira venda');
});

test('a URL sem plataforma descobre sozinha, e o resumo mostra as quatro', async () => {
  await enviar('', kirvano('SALE_APPROVED', 'APPROVED', { sale_id: 'AUTO1' }));
  await enviar('', cakto('purchase_approved', { id: 'AUTO2' }));
  await enviar('', perfect(2, { code: 'AUTO3' }));
  await enviar('', { event: 'order.paid', order: pedido({ id: 3 }) });
  assert.ok(achar('kirvano:AUTO1') && achar('cakto:AUTO2') && achar('perfectpay:AUTO3') && achar('cartpanda:3'), log.slice(-800));
  const me = await resumo();
  for (const p of ['kirvano', 'cakto', 'perfectpay', 'cartpanda']) assert.ok(me.porPlataforma[p] && me.porPlataforma[p].pagas >= 1, p + ' ' + JSON.stringify(me.porPlataforma[p]));
});

test('o pixel põe o id da pessoa no src dos links da Kirvano', async () => {
  const js = await (await fetch(base + '/px.js')).text();
  assert.match(js, /kirvano/);
  assert.match(js, /srcK/);
  assert.match(js, /cartpanda/);
});
