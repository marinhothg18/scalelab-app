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
function pedir(host, caminho, metodo, extra) {
  extra = extra || {};
  return new Promise((ok, nao) => {
    const headers = Object.assign({ Host: host }, extra.headers || {});
    if (extra.corpo !== undefined) headers['Content-Type'] = 'application/json';
    const r = http.request({ host: '127.0.0.1', port: porta, path: caminho, method: metodo || 'GET', headers }, res => {
      let b = ''; res.on('data', c => { b += c; }); res.on('end', () => ok({ status: res.statusCode, local: res.headers.location || '', corpo: b }));
    });
    r.on('error', nao); if (extra.corpo !== undefined) r.write(JSON.stringify(extra.corpo)); r.end();
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

test('o que chega pelo app.centraltmx.com fica contado, por tipo, sem dado de cliente', async () => {
  const fim = Date.now() + 40000;
  while (!/sessões derrubadas/.test(log)) { if (Date.now() > fim) throw new Error('rotina das sessões não rodou'); await espera(200); }
  const antigo = 'app.centraltmx.com';
  await pedir(antigo, '/api/webhook/vendas/tokenquenaoexiste/kiwify', 'POST', { corpo: { status: 'paid', customer: { email: 'pessoa@exemplo.com' } } });
  await pedir(antigo, '/px.js', 'GET', { headers: { Referer: 'https://apostilai.ai/acervo/' } });
  await pedir(antigo, '/q/quiz-velho');
  await pedir(antigo, '/');
  await pedir('app.scalroi.com', '/px.js', 'GET', { headers: { Referer: 'https://nao-conta.com/' } });   // endereço novo não entra
  const login = await pedir('127.0.0.1', '/api/auth/login', 'POST', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } });
  const token = JSON.parse(login.corpo).token;
  const r = await pedir('127.0.0.1', '/api/endereco-antigo', 'GET', { headers: { Authorization: 'Bearer ' + token } });
  assert.strictEqual(r.status, 200, r.corpo);
  const d = JSON.parse(r.corpo), por = Object.fromEntries(d.itens.map(x => [x.tipo + '|' + x.item, x.qtd]));
  assert.strictEqual(por['Webhook de checkout|kiwify'], 1, r.corpo);
  assert.strictEqual(por['Pixel das páginas|apostilai.ai'], 1, r.corpo);
  assert.strictEqual(por['Link, quiz ou teste A/B|/q/quiz-velho'], 1, r.corpo);
  assert.ok(por['Telas do sistema|/'] >= 1, r.corpo);   // o teste de cima também abre a raiz pelo endereço antigo
  assert.ok(!r.corpo.includes('nao-conta.com') && !r.corpo.includes('pessoa@exemplo') && !r.corpo.includes('tokenquenaoexiste'), r.corpo);
  assert.strictEqual(d.zeradoHa7Dias, false);
  assert.strictEqual((await pedir('127.0.0.1', '/api/endereco-antigo')).status, 401);
});

test('as páginas legais abrem no scalroi.com e no app (pra Meta conferir)', async () => {
  for (const h of ['scalroi.com', 'app.scalroi.com']) {
    for (const [c, txt] of [['/privacidade', 'Política de Privacidade'], ['/termos', 'Termos de Uso'], ['/exclusao-de-dados', 'Exclusão de dados'], ['/privacidade/', 'Política de Privacidade']]) {
      const r = await pedir(h, c);
      assert.strictEqual(r.status, 200, h + c);
      assert.ok(r.corpo.includes(txt) && r.corpo.includes('58.197.325/0001-96'), h + c);
    }
  }
});
