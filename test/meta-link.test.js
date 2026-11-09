// Link para navegador multilogin (09/11/2026): Dono e Gestor geram um link que vale 30 minutos e uma conexão,
// aberto sem login no TMX. Só o hash fica guardado, e a conexão sai em nome de quem gerou.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const TOKEN = 'EAAtokenDoLinkDeTeste1234567890abcdefghijklmnopqrstuvwxyz';
const APP_ID = '1234567890';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

let meta, srv, dir, base, log = '', dono, gestor, copy;
function falsa(req, res) {
  const p = new URL(req.url, 'http://x').pathname.replace(/^\/v[\d.]+\//, '');
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (p === 'oauth/access_token') return ok({ access_token: TOKEN, token_type: 'bearer', expires_in: 5184000 });
  if (p === 'debug_token') return ok({ data: { app_id: APP_ID, type: 'USER', expires_at: Math.floor(Date.now() / 1000) + 5184000 } });
  if (p === 'me/permissions') return ok({ data: ['ads_read', 'ads_management'].map(permission => ({ permission, status: 'granted' })) });
  if (p === 'me/adaccounts') return ok({ data: [{ id: 'act_111', account_id: '111', name: 'Conta real', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo' }] });
  if (p === 'me') return ok({ id: '77', name: 'Perfil Multilogin' });
  ok({ data: [] });
}
async function chamar(metodo, c, { token, corpo } = {}) {
  const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + c, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null; try { dados = await r.clone().json(); } catch (e) {}
  return { status: r.status, dados, texto: await r.text(), cab: r.headers };
}
const entrar = async (email, senha) => (await chamar('POST', '/api/auth/login', { corpo: { email, senha } })).dados.token;
const conta = (id, nome, email, senha, cargo) => ({ id, nome, email, senha, cargo, ativo: true, _updatedAt: Date.now() });
const banco = () => JSON.parse(fs.readFileSync(path.join(dir, 'db.json'), 'utf8'));
const gerar = async (t = gestor) => (await chamar('POST', '/api/meta/login/link', { token: t, corpo: {} }));
const doLink = c => '/api/meta/login/link/' + c.split('/').pop();

before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-metalink-'));
  const porta = 61000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0', META_APP_ID: APP_ID, META_APP_SECRET: 'segredo-de-teste', META_LOGIN_CONFIG_ID: '999' }, stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', () => log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', () => log);
  dono = await entrar('thiago@axcend.com', 'axcend2026');
  await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [conta('u-gestor', 'Gestor Teste', 'gestor@tmx.test', 'senha-gestor-1', 'Gestor de Tráfego'), conta('u-copy', 'Copy Teste', 'copy@tmx.test', 'senha-copy-1', 'Copy')] });
  gestor = await entrar('gestor@tmx.test', 'senha-gestor-1');
  copy = await entrar('copy@tmx.test', 'senha-copy-1');
  assert.ok(dono && gestor && copy, log.slice(-1500));
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
  if (meta) meta.close();
});

test('quem pode gerar o link', async () => {
  assert.strictEqual((await chamar('POST', '/api/meta/login/link', { corpo: {} })).status, 401);
  assert.strictEqual((await gerar(copy)).status, 403);
  assert.strictEqual((await gerar(dono)).status, 200);
});

test('o link abre sem login, conecta uma vez e fica em nome de quem gerou', async (t) => {
  const r = await gerar();
  assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
  assert.match(r.dados.caminho, /^\/conectar-meta\/ml_[\w-]{20,}$/);
  const api = doLink(r.dados.caminho), tk = r.dados.caminho.split('/').pop();

  await t.test('no banco fica só o hash', () => {
    assert.ok(!fs.readFileSync(path.join(dir, 'db.json'), 'utf8').includes(tk));
  });
  await t.test('a página abre sem sessão e não entra em buscador', async () => {
    const p = await chamar('GET', r.dados.caminho);
    assert.strictEqual(p.status, 200);
    assert.match(p.texto, /Continuar com Meta Ads/);
    assert.match(p.cab.get('x-robots-tag'), /noindex/);
  });
  await t.test('a página recebe só o que é público', async () => {
    const v = await chamar('GET', api);
    assert.strictEqual(v.status, 200, JSON.stringify(v.dados));
    assert.strictEqual(v.dados.appId, APP_ID);
    assert.strictEqual(v.dados.por, 'Gestor');
    assert.ok(!v.texto.includes('segredo-de-teste'));
  });
  await t.test('link errado é recusado', async () => {
    assert.strictEqual((await chamar('GET', '/api/meta/login/link/ml_inventado')).status, 410);
    assert.strictEqual((await chamar('POST', '/api/meta/login/link/ml_inventado', { corpo: { accessToken: 'x' } })).status, 410);
  });
  await t.test('sem a autorização do Facebook o link continua valendo', async () => {
    assert.strictEqual((await chamar('POST', api, { corpo: { statusFb: 'unknown' } })).status, 400);
    assert.strictEqual((await chamar('GET', api)).status, 200);
  });
  await t.test('conecta sem sessão e não devolve o token', async () => {
    const c = await chamar('POST', api, { corpo: { accessToken: 'curto-do-facebook' } });
    assert.strictEqual(c.status, 200, JSON.stringify(c.dados) + log.slice(-600));
    assert.deepStrictEqual(c.dados, { ok: true, contas: 1, perfil: 'Perfil Multilogin' });
    assert.ok(!c.texto.includes(TOKEN));
    const v = await chamar('GET', '/api/meta/conexao', { token: dono });
    assert.strictEqual(v.dados.conectado, true);
    assert.strictEqual(v.dados.via, 'facebook');
  });
  await t.test('não vale duas vezes', async () => {
    assert.strictEqual((await chamar('POST', api, { corpo: { accessToken: 'curto' } })).status, 410);
    assert.match((await chamar('GET', api)).dados.error, /já foi usado/);
  });
  await t.test('o histórico mostra quem gerou e conectou', async () => {
    const h = (await chamar('GET', '/api/meta/historico', { token: dono })).dados.itens;
    assert.ok(h.some(i => i.quem === 'Gestor Teste' && i.texto === 'gerou um link para conectar a Meta'));
    assert.ok(h.some(i => i.quem === 'Gestor Teste' && i.texto === 'conectou a Meta pelo link do multilogin'));
  });
});

test('link vencido é recusado e avisa que já tem perfil conectado', async () => {
  const r = await gerar();
  const api = doLink(r.dados.caminho);
  assert.strictEqual((await chamar('GET', api)).dados.substitui, true);
  const d = banco();
  d.store.sl_integracoes_meta.linksLogin.forEach(x => { x.expira = Date.now() - 1000; });
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify(d));
  const v = await chamar('GET', api);
  assert.strictEqual(v.status, 410);
  assert.match(v.dados.error, /venceu/);
  assert.strictEqual((await chamar('POST', api, { corpo: { accessToken: 'curto' } })).status, 410);
});
