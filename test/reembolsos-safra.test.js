// Reembolsos por data da compra, a safra (17/11/2026). Projeto › Reembolsos contava o reembolso que CHEGOU no
// período contra as vendas do período, e a taxa podia passar de 100%. Com por=compra a conta é das vendas FEITAS
// no período: quantas delas pediram o dinheiro de volta até hoje, chegue quando chegar. Confere os dois jeitos
// com a mesma base: o reembolso de compra antiga fica fora da safra, o de depois do período entra, o pedido com
// duas linhas pagas conta uma vez só e a venda ainda dentro dos 7 dias de garantia vem contada à parte.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
const DIA = 86400000, agora = Date.now();
const diaBR = ms => new Date(ms - 3 * 3600000).toISOString().slice(0, 10);
let dir, srv, base, log = '', dono;
const ate = async (cond, ms, oQue) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-2000)); await espera(150); } };
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
// período da tela: de 20 dias atrás até ontem
const DE = diaBR(agora - 20 * DIA), ATE = diaBR(agora - 1 * DIA);

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-reemb-safra-'));
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: { sl_funis: [{ id: 'f1', nome: 'Funil', projeto: 'CONCURSO' }] }, timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 45000 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  const { DatabaseSync } = require('node:sqlite');
  const b = new DatabaseSync(path.join(dir, 'pessoas.sqlite'));
  const ins = b.prepare('INSERT INTO pedidos(id, pedido, status, pago, estorno, valor, produto, renovacao, em, dia, funil, plataforma) VALUES(?,?,?,?,?,?,?,0,?,?,?,?)');
  const linha = (pedido, status, pago, estorno, diasAtras, produto) => { const em = agora - diasAtras * DIA; ins.run(pedido + '|' + status, pedido, status, pago, estorno, 100, produto || 'Apostilai Foco', em, diaBR(em), 'f1', 'payt'); };
  linha('A', 'paid', 1, 0, 15);  linha('A', 'approved', 1, 0, 15);   // comprou no período (duas linhas pagas)...
  linha('A', 'refunded', 0, 1, 0);                                    // ...e devolveu hoje, depois do período
  linha('B', 'paid', 1, 0, 30);  linha('B', 'refunded', 0, 1, 10);    // comprou antes e devolveu dentro do período
  linha('C', 'paid', 1, 0, 3);                                        // comprou há 3 dias: ainda na garantia
  linha('D', 'paid', 1, 0, 12);                                       // comprou e ficou
  linha('E', 'paid', 1, 0, 5, 'Outro Produto'); linha('E', 'chargeback', 0, 1, 1, 'Outro Produto');   // chargeback ontem
  b.close();
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});
const pedir = por => chamar('GET', '/api/projeto/reembolsos?projeto=CONCURSO&de=' + DE + '&ate=' + ATE + (por ? '&por=' + por : ''), { token: dono });

test('pela data do reembolso continua como era', async () => {
  const r = await pedir('');
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.strictEqual(r.dados.modo, 'reembolso');
  // no período chegaram os reembolsos de B (compra antiga) e de E; o de A chegou hoje, fora
  assert.deepStrictEqual(r.dados.reembolsos.map(x => x.pedido).sort(), ['B', 'E']);
  assert.strictEqual(r.dados.total.naGarantia, null);
});

test('pela data da compra: a safra das vendas feitas no período', async () => {
  const r = await pedir('compra');
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  const d = r.dados;
  assert.strictEqual(d.modo, 'compra');
  // vendas do período: A (uma vez só, mesmo com duas linhas pagas), C, D e E
  assert.strictEqual(d.total.vendas, 4);
  // reembolsadas até hoje: A (reembolso depois do período) e E (chargeback); B comprou antes, fica fora
  assert.deepStrictEqual(d.reembolsos.map(x => x.pedido).sort(), ['A', 'E']);
  assert.strictEqual(d.total.n, 2);
  assert.strictEqual(d.total.chargebacks, 1);
  // C comprou há 3 dias e não devolveu: ainda na garantia; D tem 12 dias, já passou
  assert.strictEqual(d.total.naGarantia, 1);
  assert.strictEqual(d.garantiaDias, 7);
  const foco = d.produtos.find(p => p.produto === 'Apostilai Foco');
  assert.deepStrictEqual([foco.vendas, foco.reembolsos], [3, 1], 'por produto a taxa não passa de 100%');
  const a = d.reembolsos.find(x => x.pedido === 'A');
  assert.ok(a.compraEm && a.reembolsoEm > a.compraEm, 'traz a compra e o reembolso');
});

test('sem login não entra', async () => {
  assert.strictEqual((await chamar('GET', '/api/projeto/reembolsos?projeto=CONCURSO&de=' + DE + '&ate=' + ATE + '&por=compra')).status, 401);
});
