// Endereço só de vendas e endereço só de links (11/11/2026). scalroi.com mostra a página de vendas na raiz e manda
// as telas do sistema pro app.scalroi.com; o domínio de links (ir.kalebeaprovado.online) não mostra o sistema;
// app.scalroi.com e os outros endereços continuam abrindo o sistema; API e arquivos seguem iguais em todos.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
let dir, srv, porta, log = '';
function pedir(host, caminho, metodo) {
  return new Promise((ok, nao) => {
    const r = http.request({ host: '127.0.0.1', port: porta, path: caminho, method: metodo || 'GET', headers: { Host: host } }, res => {
      let b = ''; res.on('data', c => { b += c; }); res.on('end', () => ok({ status: res.statusCode, local: res.headers.location || '', corpo: b }));
    });
    r.on('error', nao); r.end();
  });
}
before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-enderecos-'));
  porta = 52000 + Math.floor(Math.random() * 2000);
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  const fim = Date.now() + 20000;
  for (;;) {
    try { if ((await pedir('127.0.0.1', '/api/ping')).status === 200) break; } catch (e) {}
    if (Date.now() > fim) throw new Error('servidor não subiu\n' + log.slice(-2000));
    await espera(150);
  }
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});
const ehSistema = c => /id="login-pwd"/.test(c);
const ehVendas = c => /class="lnk" href="\/ScaleLab\.html">Entrar</.test(c);

test('scalroi.com: a raiz é a página de vendas e as telas do sistema vão pro app.scalroi.com', async () => {
  for (const h of ['scalroi.com', 'www.scalroi.com']) {
    const raiz = await pedir(h, '/');
    assert.strictEqual(raiz.status, 200);
    assert.ok(ehVendas(raiz.corpo) && !ehSistema(raiz.corpo), 'raiz de ' + h + ' devia ser a página de vendas');
  }
  assert.ok(ehVendas((await pedir('scalroi.com', '/planos')).corpo));
  for (const [c, para] of [['/ScaleLab.html', '/ScaleLab.html'], ['/cadastro?c=cv_abc', '/cadastro?c=cv_abc'], ['/admin', '/admin'], ['/admin.html', '/admin.html']]) {
    const r = await pedir('scalroi.com', c);
    assert.deepStrictEqual([r.status, r.local], [301, 'https://app.scalroi.com' + para], c);
  }
  // o que a página de vendas usa continua respondendo ali mesmo
  assert.strictEqual((await pedir('scalroi.com', '/api/planos-tmx')).status, 200);
  assert.strictEqual((await pedir('scalroi.com', '/favicon.svg')).status, 200);
  assert.strictEqual((await pedir('scalroi.com', '/px.js')).status, 200);
});

test('domínio de links não mostra o sistema nem a página de vendas', async () => {
  for (const c of ['/', '/ScaleLab.html', '/admin', '/planos', '/cadastro']) {
    const r = await pedir('ir.kalebeaprovado.online', c);
    assert.strictEqual(r.status, 404, c);
    assert.ok(!ehSistema(r.corpo) && !ehVendas(r.corpo), c);
  }
  assert.strictEqual((await pedir('ir.kalebeaprovado.online', '/px.js')).status, 200, 'o pixel continua servindo');
});

test('app.scalroi.com e os outros endereços continuam abrindo o sistema', async () => {
  for (const h of ['app.scalroi.com', 'app.centraltmx.com', '127.0.0.1']) {
    const r = await pedir(h, '/');
    assert.strictEqual(r.status, 200, h);
    assert.ok(ehSistema(r.corpo), h + ' devia abrir o sistema');
  }
  assert.ok(ehVendas((await pedir('app.scalroi.com', '/planos')).corpo));
});
