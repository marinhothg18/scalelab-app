// Bloco de checkout do funil por integração, produto e checkout (09/11/2026). A lista traz só o que vendeu na
// plataforma, cada venda guarda o checkout dela, e o bloco conta só o que foi escolhido: dois links do mesmo
// produto ficam separados, o nome do produto vale inteiro e bloco novo sem produto não puxa o total.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

let srv, dir, base, log = '', tmx, aviso;
async function chamar(metodo, c, { token, corpo, texto } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: texto !== undefined ? texto : (corpo !== undefined ? JSON.stringify(corpo) : undefined) });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-ckprod-'));
  const porta = 59000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  aviso = new URL((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: tmx })).dados.urlWebhook, base).pathname;
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const payt = (id, produto, titulo, link, extra = {}) => Object.assign({
  id, status: 'paid', product: { name: produto, code: 'P' + id },
  customer: { name: 'Pessoa ' + id, email: id + '@exemplo.com', phone: '11988887777' },
  transaction: { total_price: 69700, payment_method: 'pix', payment_status: 'paid' },
  link: { title: titulo, url: 'https://payt.com.br/' + link + '?sck=x' }
}, extra);
const enviar = async (corpo, plataforma) => assert.strictEqual((await chamar('POST', aviso + (plataforma ? '/' + plataforma : ''), { corpo })).status, 200);
const hoje = () => new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);
const blocos = async () => (await chamar('GET', '/api/funil/blocos?funil=f1&de=' + hoje() + '&ate=' + hoje(), { token: tmx })).dados;

const L697 = 'payt.com.br/link697', L297 = 'payt.com.br/link297';
const ck = (id, nome, extra = {}) => Object.assign({ id, nome, tipo: 'checkout', url: '', x: 10, y: 10 }, extra);
const funil = etapas => [{ id: 'f1', nome: 'Funil', projeto: 'P1', fontes: [], ligacoes: [], etapas: [{ id: 'pag', nome: 'Página', tipo: 'vsl', url: 'https://site.test/vsl', x: 0, y: 0 }, ...etapas], _updatedAt: Date.now() }];
const salvarFunil = async etapas => assert.strictEqual((await chamar('PUT', '/api/store/sl_funis', { token: tmx, corpo: funil(etapas) })).status, 200);

test('a lista de produtos, os checkouts e a separação nos blocos', async (t) => {
  await t.test('as vendas chegam com o checkout de cada uma', async () => {
    for (let i = 0; i < 3; i++) await enviar(payt('a' + i, 'Curso Foco', 'FOCO - ANUAL - R$ 697', 'link697'));
    // assinatura paga vem com o título genérico: o nome certo vem de outro aviso do mesmo link
    await enviar(payt('a9', 'Curso Foco', 'Assinatura', 'link697'));
    for (let i = 0; i < 2; i++) await enviar(payt('b' + i, 'Curso Foco', 'FOCO - R$ 297', 'link297', { transaction: { total_price: 29700, payment_method: 'pix', payment_status: 'paid' } }));
    await enviar(payt('c0', 'Curso Elite', 'Elite mensal', 'linkelite'));
    await enviar(payt('c1', 'Curso Elite 10', 'Elite 10', 'linkelite10'));
    await enviar(payt('c2', 'Curso Foco Reembolso', 'x', 'linkrb', { status: 'refunded', transaction: { total_price: 0, payment_method: 'pix', payment_status: 'refunded' } }));
    await enviar({ event: 'SALE_APPROVED', checkout_id: 'K1', sale_id: 'KV1', payment_method: 'PIX', total_price: 'R$ 100,00', type: 'ONE_TIME', status: 'APPROVED', created_at: '2026-11-09 10:00:00',
      customer: { name: 'K', document: '1', email: 'k@exemplo.com', phone_number: '5511987654321' }, payment: { method: 'PIX' }, products: [{ id: 'p', name: 'Só na Kirvano', is_order_bump: false }], plan: { name: 'Oferta Kirvano' }, utm: {} }, 'kirvano');
  });

  await t.test('a lista traz só o que vendeu em cada plataforma', async () => {
    const d = (await chamar('GET', '/api/produtos', { token: tmx })).dados.vendidos;
    assert.deepStrictEqual(d.payt.map(p => p.nome).sort(), ['Curso Elite', 'Curso Elite 10', 'Curso Foco']);
    assert.deepStrictEqual(d.kirvano.map(p => p.nome), ['Só na Kirvano']);
    assert.deepStrictEqual(d.kirvano[0].checkouts.map(c => c.nome), ['Oferta Kirvano']);
    const foco = d.payt.find(p => p.nome === 'Curso Foco');
    assert.strictEqual(foco.vendas, 6);
    assert.deepStrictEqual(foco.checkouts.map(c => [c.nome, c.link, c.vendas]), [['FOCO - ANUAL - R$ 697', L697, 4], ['FOCO - R$ 297', L297, 2]]);
  });

  await t.test('cada checkout marcado conta só o dele', async () => {
    const base = { integracao: 'Payt', produto: 'Curso Foco', prodExato: true };
    await salvarFunil([
      ck('c697', 'Checkout 697', Object.assign({}, base, { checkouts: [{ nome: 'FOCO - ANUAL - R$ 697', link: L697 }] })),
      ck('c297', 'Checkout 297', Object.assign({}, base, { checkouts: [{ nome: 'FOCO - R$ 297', link: L297 }] })),
      ck('ctodos', 'Todos do Foco', Object.assign({}, base)),
      ck('celite', 'Elite', { integracao: 'Payt', produto: 'Curso Elite', prodExato: true }),
      ck('celite10', 'Elite 10', { integracao: 'Payt', produto: 'Curso Elite 10', prodExato: true }),
      ck('cnovo', 'Novo', { exigeProduto: true, integracao: 'Hubla' }),
      ck('cvelho', 'Antigo', {})
    ]);
    const { nos } = await blocos();
    assert.strictEqual(nos.c697.vendas, 4);
    assert.strictEqual(nos.c297.vendas, 2);
    assert.strictEqual(nos.c297.faturamento < nos.c697.faturamento, true);
    assert.strictEqual(nos.ctodos.vendas, 6, 'sem checkout marcado, o produto inteiro');
    assert.strictEqual(nos.celite.vendas, 1, 'o nome vale inteiro: Elite não leva Elite 10');
    assert.strictEqual(nos.celite10.vendas, 1);
    assert.strictEqual(nos.cnovo.pedeProduto, true);
    assert.strictEqual(nos.cnovo.vendas, 0, 'bloco novo sem produto não puxa o total');
    assert.strictEqual(nos.cvelho.pedeProduto, undefined, 'bloco antigo continua contando');
  });

  await t.test('produto escrito à mão continua achando por parte do nome', async () => {
    await salvarFunil([ck('cmao', 'À mão', { integracao: 'Payt', produto: 'Elite' })]);
    assert.strictEqual((await blocos()).nos.cmao.vendas, 2);
  });

  await t.test('Abriram conta quem clicou no link daquele checkout', async () => {
    const base = { integracao: 'Payt', produto: 'Curso Foco', prodExato: true };
    await salvarFunil([
      ck('c697', 'Checkout 697', Object.assign({}, base, { checkouts: [{ nome: 'FOCO - ANUAL - R$ 697', link: L697 }] })),
      ck('c297', 'Checkout 297', Object.assign({}, base, { checkouts: [{ nome: 'FOCO - R$ 297', link: L297 }] })),
      ck('ctodos', 'Todos do Foco', Object.assign({}, base)),
      ck('cnovo', 'Novo', { exigeProduto: true })
    ]);
    const ev = (id, tipo, extra = {}) => chamar('POST', '/api/funil/evento', { texto: JSON.stringify(Object.assign({ funil: 'f1', etapa: 'pag', tipo, id, pg: 'https://site.test/vsl' }, extra)) });
    await ev('v1', 'entrou'); await ev('v2', 'entrou'); await ev('v3', 'entrou');
    await ev('v1', 'checkout', { destino: 'payt.com.br', dest: L697 });
    await ev('v2', 'checkout', { destino: 'payt.com.br', dest: L697 });
    await ev('v3', 'checkout', { destino: 'payt.com.br', dest: L297 });
    await ate(async () => (await blocos()).nos.c697.pessoas >= 2, 5000, 'os cliques contarem', () => log);
    const { nos, fios } = await blocos();
    assert.strictEqual(nos.c697.cliques, 2);
    assert.strictEqual(nos.c297.cliques, 1);
    assert.strictEqual(nos.ctodos.cliques, 3, 'o produto inteiro soma os dois links');
    assert.strictEqual(nos.cnovo.cliques, 0);
    assert.ok(!fios['pag|cnovo'] || fios['pag|cnovo'].n === 0);
  });
});
