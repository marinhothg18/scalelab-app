// "Checar" domínio da hospedagem de páginas (18/11/2026). O www.apostilai.online é servido pela hospedagem da
// SCALROI (Cloudflare), que só repassa pra cá o que os links e o pixel usam (/r/, /l/, /q/, /px.js). O "checar"
// perguntava /api/versao, recebia 404 e dizia "o DNS aponta pra outro servidor" num domínio que funciona.
// Agora, com 404, ele pergunta o /px.js: se vem deste servidor (cabeçalho X-TMX-Versao desta execução), passa.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
let dir, srv, base, log = '', dono, falso, versaoDoPixel = '', pediuPx = '';
const ate = async (cond, ms, oQue) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-2000)); await espera(150); } };
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
// o "domínio": como a hospedagem, não conhece /api/versao e devolve o px.js com a versão que o teste mandar
function hospedagem(req, res) {
  if (req.url.startsWith('/px.js')) { pediuPx = req.url; res.setHeader('X-TMX-Versao', versaoDoPixel); res.setHeader('Content-Type', 'application/javascript'); return res.end('// px'); }
  res.statusCode = 404; res.end('não achei');
}
before(async () => {
  falso = await new Promise(r => { const s = http.createServer(hospedagem).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-dom-hosp-'));
  const porta = 43000 + Math.floor(Math.random() * 1500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
    TMX_DOMINIO_TESTE_URL: 'http://127.0.0.1:' + falso.address().port }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar');
  dono = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (falso) falso.close();
});

test('domínio da hospedagem da SCALROI passa no checar', async () => {
  versaoDoPixel = (await fetch(base + '/px.js')).headers.get('x-tmx-versao');
  assert.ok(versaoDoPixel, 'o px.js deste servidor traz a versão');
  const r = await chamar('POST', '/api/dominios/checar', { token: dono, corpo: { dominio: 'www.exemplo-hospedado.com' } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.deepStrictEqual([r.dados.apontado, r.dados.erro], [true, '']);
  assert.match(pediuPx, /^\/px\.js\?checar=\d+$/, 'pergunta sem cópia guardada');
});

test('domínio que serve o px.js de outro servidor continua recusado', async () => {
  versaoDoPixel = 'outra-versao';
  const r = await chamar('POST', '/api/dominios/checar', { token: dono, corpo: { dominio: 'www.exemplo-hospedado.com' } });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.dados.apontado, false);
  assert.match(r.dados.erro, /respondeu 404/);
});
