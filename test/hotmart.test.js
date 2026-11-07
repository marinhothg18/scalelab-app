// Vendas da Hotmart pelo webhook (07/11/2026).
// Sobe o servidor numa pasta temporária, gera a URL de vendas e manda os avisos da Hotmart
// (versão 2.0.0): compra aprovada com o sck do pixel, boleto impresso, reembolso, abandono de
// carrinho e um evento que não é venda. Confere que viram vendas da Hotmart com valor, líquido
// do produtor e o id da pessoa.
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
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null;
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-hotmart-'));
  const porta = 47000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe']
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const compra = (event, status, extra = {}) => ({
  id: 'evt-' + Math.random().toString(36).slice(2), creation_date: 1794070000000, event, version: '2.0.0',
  data: Object.assign({
    product: { id: 123, name: 'Apostilai Foco' },
    buyer: { email: 'ana@exemplo.com', name: 'Ana Souza', checkout_phone: '5511999990000', document: '12345678900' },
    commissions: [{ value: 69.7, source: 'MARKETPLACE' }, { value: 597.3, source: 'PRODUCER' }],
    purchase: { transaction: 'HP1234567890', status, order_date: 1794069000000, approved_date: 1794069100000,
      price: { value: 697, currency_value: 'BRL' }, full_price: { value: 865.03, currency_value: 'BRL' },
      payment: { type: 'CREDIT_CARD', installments_number: 12 }, origin: { sck: 'tmx_v123abc', src: 'meta' } }
  }, extra)
});

test('vendas da Hotmart pelo webhook', async () => {
  const tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  const url = (await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: tmx })).dados.urlWebhook;
  assert.match(url, /\/api\/webhook\/vendas\/[0-9a-f]+$/);
  const caminho = new URL(url, base).pathname;

  // URL própria da Hotmart e a URL sem plataforma (descobre pelo formato)
  assert.strictEqual((await chamar('POST', caminho + '/hotmart', { corpo: compra('PURCHASE_BILLET_PRINTED', 'BILLET_PRINTED') })).status, 200);
  assert.strictEqual((await chamar('POST', caminho, { corpo: compra('PURCHASE_APPROVED', 'APPROVED') })).status, 200);
  assert.strictEqual((await chamar('POST', caminho + '/hotmart', { corpo: { event: 'PURCHASE_OUT_OF_SHOPPING_CART', creation_date: 1794070000000,
    data: { buyer: { email: 'beto@exemplo.com', name: 'Beto' }, product: { name: 'Apostilai Foco' } } } })).status, 200);
  assert.strictEqual((await chamar('POST', caminho + '/hotmart', { corpo: { event: 'SWITCH_PLAN', data: { subscription: { status: 'ACTIVE' } } } })).status, 200, 'evento que não é venda responde 200');

  const me = (await chamar('GET', '/api/integracoes/vendas/me', { token: tmx })).dados;
  const h = me.porPlataforma.hotmart;
  assert.ok(h, 'a Hotmart aparece no resumo por plataforma');
  assert.strictEqual(h.pagas, 1, JSON.stringify(me.porStatus) + log.slice(-1500));
  assert.strictEqual(h.comVid, 1, 'a venda chegou com o id da pessoa (sck do pixel)');
  assert.ok(me.porStatus.lost_cart >= 1, 'abandono de carrinho entrou');
  assert.strictEqual(me.receitaHoje, 697, 'valor = preço do produto, sem os juros do parcelamento');
  const bruto = me.ultimosBrutos.find(x => x.payload && x.payload.event === 'SWITCH_PLAN');
  assert.ok(bruto && bruto.plataforma === 'hotmart', 'o aviso que não é venda fica guardado como da Hotmart');
});
