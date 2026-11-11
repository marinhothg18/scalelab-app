// O que o TMX fez com cada aviso do checkout (11/11/2026). Seis vendas aprovadas na Payt não apareceram e
// não dava pra saber se a Payt não mandou ou se o TMX descartou calado. Confere: venda paga vira
// "registrou", o mesmo aviso de novo vira "repetido", o registro não leva dado de cliente, e os avisos que
// chegaram antes do registro saem do cru conferidos contra as vendas ("chegou, mas não está nas vendas").
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
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-avisos-'));
  const porta = 47000 + Math.floor(Math.random() * 2000);
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

const payt = (id, status, centavos) => ({
  id, status,
  product: { name: 'Apostilai Foco', code: 'P1' },
  customer: { name: 'Pessoa Exemplo', email: 'pessoa@exemplo.com', phone: '(11) 98888-7777' },
  transaction: { total_price: centavos, payment_method: 'credit_card', payment_status: status }
});
const enviar = async corpo => {
  const r = await chamar('POST', caminho, { corpo });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  return r.dados;
};
const avisos = async () => (await chamar('GET', '/api/integracoes/vendas/me', { token: tmx })).dados.avisos;
const DB = () => path.join(dir, 'db.json');

test('cada aviso fica registrado com o que o TMX fez, sem dado de cliente', async () => {
  await enviar(payt('PEDIDO1', 'paid', 83976));
  await enviar(payt('PEDIDO1', 'paid', 83976));          // o mesmo aviso de novo
  await enviar(payt('PEDIDO2', 'lost_cart', 69700));
  const l = await avisos();
  assert.deepStrictEqual(l.slice(0, 3).map(a => [a.pedido, a.status, a.resultado]), [
    ['PEDIDO2', 'lost_cart', 'registrado'],
    ['PEDIDO1', 'paid', 'duplicado'],
    ['PEDIDO1', 'paid', 'registrado']
  ]);
  assert.strictEqual(l[2].valor, 839.76);
  assert.strictEqual(l[2].produto, 'Apostilai Foco');
  assert.ok(l[2].em > 0 && l[2].plataforma === 'payt', JSON.stringify(l[2]));
  const txt = JSON.stringify(l);
  assert.ok(!/pessoa@exemplo|Pessoa Exemplo|98888/.test(txt), 'o registro não leva e-mail, nome nem telefone');
  // a lista é só do servidor: não vai pro aparelho pelo /api/store
  const store = (await chamar('GET', '/api/store', { token: tmx })).dados;
  assert.ok(!JSON.stringify(store).includes('sl_vendas_avisos'), 'sl_vendas_avisos fica fora do /api/store');
});

test('avisos de antes do registro saem do cru, conferidos contra as vendas', async () => {
  // como estava em produção: o cru guardado, sem o registro novo, e uma venda paga que chegou mas não virou venda
  const db = JSON.parse(fs.readFileSync(DB(), 'utf8'));
  delete db.store.sl_vendas_avisos;
  db.store.sl_vendas_raw.push({ em: new Date().toISOString(), plataforma: 'payt', payload: payt('PEDIDO3', 'paid', 83976) });
  fs.writeFileSync(DB(), JSON.stringify(db));
  const l = await avisos();
  const por = Object.fromEntries(l.map(a => [a.pedido + '|' + a.status + '|' + a.resultado, a]));
  assert.ok(por['PEDIDO3|paid|nao_esta'], 'a paga que não virou venda aparece como "chegou, mas não está": ' + JSON.stringify(l));
  assert.ok(por['PEDIDO1|paid|registrado'], JSON.stringify(l));
  assert.ok(por['PEDIDO2|lost_cart|registrado'], JSON.stringify(l));
  assert.ok(l.every(a => a.antigo), 'todos vieram do cru');
  // o próximo aviso volta a usar o registro novo
  await enviar(payt('PEDIDO4', 'paid', 69700));
  const l2 = await avisos();
  assert.deepStrictEqual([l2[0].pedido, l2[0].resultado, !!l2[0].antigo], ['PEDIDO4', 'registrado', false]);
});
