// Bloco do teste A/B no Mapa (19 e 20/11/2026). A página da variante (raiox4) também recebe gente da VSL:
// em 19/11 o bloco "Teste bio" mostrava 3 vendas e a tela do teste mostrava 0. As três eram de
// anúncio, entraram pela VSL e compraram na raiox4 sem passar pelo /r/bio. O bloco separa
// "vendas pelo link" (a mesma conta da tela do teste) das "vendas na página", e diz de onde vieram
// as que não passaram pelo link. Desde 20/11 a venda de quem entrou pela VSL e clicou na oferta da
// variante é da VSL: o mapa mostrava a VSL que vendeu com zero.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };
const hoje = () => new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10);

let srv, dir, base, log = '', tmx, aviso;
async function chamar(metodo, c, { token, corpo, texto } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: texto !== undefined ? texto : (corpo !== undefined ? JSON.stringify(corpo) : undefined) });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-mapa-bio-'));
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ store: {
    sl_redirecionadores: [{ id: 'r1', slug: 'bio', nome: 'Teste bio', ativo: true, criadoEm: new Date(Date.now() - 86400000).toISOString(), destinos: [
      { id: 'va', nome: 'Variante 1', url: 'https://site.test/raiox4/', peso: 90 },
      { id: 'vb', nome: 'Variante 2', url: 'https://site.test/raiox6/', peso: 10 }] }],
    sl_funis: [{ id: 'f1', nome: 'KALEBE', fontes: [{ id: 'ads', nome: 'Tráfego pago', canal: 'meta' }], ligacoes: [['ads', 'vsl']], etapas: [
      { id: 'vsl', nome: 'VSL 697', tipo: 'vsl', url: 'https://site.test/vsl', x: 0, y: 0 },
      { id: 'sp', nome: 'Teste bio', tipo: 'split', slug: 'bio', x: 0, y: 200 }] }]
  }, timestamps: {}, api_tokens: [], api_logs: [], sessions: [] }));
  const porta = 61000 + Math.floor(Math.random() * 2000);
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

const ev = (vid, sid, tipo, pg, extra = {}) => chamar('POST', '/api/funil/evento', { texto: JSON.stringify(Object.assign({ funil: 'f1', etapa: '', tipo, id: vid, sid, pg }, extra)) });
const venda = (id, vid) => chamar('POST', aviso, { corpo: {
  id, status: 'paid', product: { name: 'Apostilai Foco', code: 'P1' },
  customer: { name: 'Pessoa ' + id, email: id + '@exemplo.com', phone: '11988887777' },
  transaction: { total_price: 69700, payment_method: 'pix', payment_status: 'paid' },
  link: { title: 'FOCO', url: 'https://payt.com.br/link697?sck=tmx_' + vid } } });

test('o bloco do teste separa as vendas pelo link das feitas na página da variante', async () => {
  const anuncio = { utm_source: 'FB', utm_medium: 'paid', utm_campaign: 'CBO | CONCURSO | 52715888868034', utm_content: 'AD300hk.3' };
  const bio = { utm_source: 'ig', utm_content: 'link_in_bio' };
  // A: veio do anúncio, entrou na VSL, foi pra raiox4 e comprou lá (sem passar pelo /r/bio)
  await ev('vidanuncio1', 'sa1', 'entrou', 'https://site.test/vsl', { etapa: 'vsl', aqui: anuncio });
  await ev('vidanuncio1', 'sa1', 'entrou', 'https://site.test/raiox4/', { aqui: anuncio });
  await ev('vidanuncio1', 'sa1', 'checkout', 'https://site.test/raiox4/', { destino: 'payt.com.br', dest: 'payt.com.br/link697', aqui: anuncio });
  // B: chegou pelo /r/bio (Variante 1) e comprou
  await ev('vidbiocompra', 'sb1', 'entrou', 'https://site.test/raiox4/', { teste: 'bio', variante: 'va', aqui: bio });
  await ev('vidbiocompra', 'sb1', 'checkout', 'https://site.test/raiox4/', { teste: 'bio', variante: 'va', destino: 'payt.com.br', dest: 'payt.com.br/link697', aqui: bio });
  // C: chegou pelo /r/bio (Variante 2) e não comprou
  await ev('vidbiosemcompra', 'sc1', 'entrou', 'https://site.test/raiox6/', { teste: 'bio', variante: 'vb', aqui: bio });
  // D: o anúncio levou direto pra raiox4 (sem VSL e sem o link) e comprou lá
  await ev('vidanuncio2', 'sd1', 'entrou', 'https://site.test/raiox4/', { aqui: anuncio });
  await ev('vidanuncio2', 'sd1', 'checkout', 'https://site.test/raiox4/', { destino: 'payt.com.br', dest: 'payt.com.br/link697', aqui: anuncio });
  await espera(300);
  assert.strictEqual((await venda('VA1', 'vidanuncio1')).status, 200);
  assert.strictEqual((await venda('VB1', 'vidbiocompra')).status, 200);
  assert.strictEqual((await venda('VD1', 'vidanuncio2')).status, 200);

  const q = '&de=' + hoje() + '&ate=' + hoje();
  let nos;
  await ate(async () => { nos = (await chamar('GET', '/api/funil/blocos?funil=f1' + q, { token: tmx })).dados.nos; return nos && nos.sp && (nos.sp.vendas + nos.vsl.vendas) === 3; }, 8000,
    'as vendas chegarem no mapa', () => log + '\n' + JSON.stringify(nos));
  const sp = nos.sp;

  // A entrou pela VSL e clicou na oferta da raiox4: a venda é da VSL, não do teste
  assert.strictEqual(nos.vsl.vendas, 1, 'a VSL de entrada fica com a venda');
  assert.ok(!nos.vsl.levou, 'e não aparece como "levou pro teste"');
  assert.strictEqual(sp.vendas, 2, 'na página: a de quem veio pelo link e a de quem o anúncio levou direto pra raiox4');
  assert.strictEqual(sp.vendasOrigem, 1, 'pelo link: só a de quem veio pelo /r/bio');
  assert.strictEqual(sp.vendasForaDoLink, 1);
  assert.deepStrictEqual(sp.foraOrigens, { 'Tráfego pago': 1 });
  assert.deepStrictEqual(sp.foraEntradas, {}, 'entrou direto na raiox4: não tem outra página de entrada');
  assert.ok(sp.faturamentoLink > 0 && sp.faturamentoLink < sp.faturamento);
  assert.deepStrictEqual(sp.divisao.map(d => [d.nome, d.vendas, d.vendasLink]), [['Variante 1', 2, 1], ['Variante 2', 0, 0]]);

  // a tela do teste conta igual ao "pelo link" do bloco
  const ab = (await chamar('GET', '/api/ab/v2?teste=bio' + q, { token: tmx })).dados;
  assert.deepStrictEqual(ab.variantes.map(v => [v.id, v.pessoas, v.vendas]), [['va', 1, 1], ['vb', 1, 0]]);
  assert.strictEqual(ab.variantes.reduce((a, v) => a + v.vendas, 0), sp.vendasOrigem);
});
