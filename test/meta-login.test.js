// Conectar a Meta pelo botão do Facebook (08/11/2026).
// Sobe o servidor com uma Meta falsa e confere: o botão só aparece com o app configurado, o code vira
// token no servidor, o token e o segredo nunca voltam pra tela, e autorização de outro app é recusada.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const SEGREDO = 'segredo-do-app-de-teste', TOKEN = 'EAAtokenLongoDeTeste1234567890abcdefghijklmnopqrstuvwxyz';
const chamadas = [];
let meta, servidores = [], appDoToken = 'app-1';
const espera = ms => new Promise(r => setTimeout(r, ms));
const ate = async (cond, ms, oQue, log) => { const fim = Date.now() + ms; for (;;) { try { if (await cond()) return; } catch (e) {} if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + (log ? log().slice(-1500) : '')); await espera(150); } };

function falsa(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname, q = Object.fromEntries(u.searchParams);
  chamadas.push({ p, q });
  const ok = o => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); };
  if (p.endsWith('/oauth/access_token')) {
    if (q.code === 'ruim') { res.statusCode = 400; return ok({ error: { code: 100, message: 'Invalid verification code' } }); }
    return ok({ access_token: TOKEN, token_type: 'bearer', expires_in: 5184000 });
  }
  if (p.endsWith('/debug_token')) return ok({ data: { app_id: appDoToken, type: 'USER', is_valid: true, expires_at: 1900000000 } });
  if (p.endsWith('/me/permissions')) return ok({ data: [{ permission: 'ads_read', status: 'granted' }] });
  if (p.endsWith('/me/adaccounts')) return ok({ data: q.semContas ? [] : [{ id: 'act_111', account_id: '111', name: 'Conta Exemplo', account_status: 1, currency: 'BRL', timezone_name: 'America/Sao_Paulo', business: { id: '9', name: 'BM Exemplo' } }] });
  if (p.endsWith('/me')) return ok({ id: '77', name: 'Pessoa Exemplo' });
  ok({ data: [] });
}
async function subir(env) {
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-metalogin-'));
  const porta = 53000 + Math.floor(Math.random() * 2000);
  let log = '';
  const srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, env: Object.assign({ PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir, META_API_BASE_TESTE: 'http://127.0.0.1:' + meta.address().port + '/v25.0' }, env), stdio: ['ignore', 'pipe', 'pipe'] });
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  const base = 'http://127.0.0.1:' + porta, s = { srv, dir, base, log: () => log };
  servidores.push(s);
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir', s.log);
  await ate(() => /sessões derrubadas/.test(log), 40000, 'a rotina das sessões rodar', s.log);
  s.chamar = async (metodo, caminho, { token, corpo } = {}) => {
    const headers = {}; if (token) headers.Authorization = 'Bearer ' + token; if (corpo !== undefined) headers['Content-Type'] = 'application/json';
    const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
    let dados = null; try { dados = await r.json(); } catch (e) {}
    return { status: r.status, dados };
  };
  s.dono = (await s.chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
  assert.ok(s.dono, log.slice(-1500));
  return s;
}
const ENV = { META_APP_ID: 'app-1', META_APP_SECRET: SEGREDO, META_LOGIN_CONFIG_ID: 'config-1' };
let comApp, semApp;
before(async () => {
  meta = await new Promise(r => { const s = http.createServer(falsa).listen(0, '127.0.0.1', () => r(s)); });
  [comApp, semApp] = await Promise.all([subir(ENV), subir({})]);
});
after(async () => {
  for (const s of servidores) { if (s.srv.exitCode === null) { s.srv.kill('SIGTERM'); await Promise.race([new Promise(r => s.srv.once('exit', r)), espera(10000)]); } fs.rmSync(s.dir, { recursive: true, force: true }); }
  if (meta) meta.close();
});

test('sem o app configurado o botão não aparece e a rota recusa', async () => {
  const c = (await semApp.chamar('GET', '/api/meta/conexao', { token: semApp.dono })).dados;
  assert.strictEqual(c.login.pronto, false);
  assert.strictEqual((await semApp.chamar('POST', '/api/meta/login', { token: semApp.dono, corpo: { code: 'x' } })).status, 400);
});

test('o botão do Facebook conecta sem ninguém criar token', async (t) => {
  const { chamar, dono, dir } = comApp;
  await t.test('a tela recebe o que precisa, sem o segredo', async () => {
    const c = (await chamar('GET', '/api/meta/conexao', { token: dono })).dados;
    assert.deepStrictEqual({ pronto: c.login.pronto, appId: c.login.appId, configId: c.login.configId }, { pronto: true, appId: 'app-1', configId: 'config-1' });
    assert.ok(!JSON.stringify(c).includes(SEGREDO));
    assert.strictEqual(c.conectado, false);
  });
  await t.test('só a Diretoria conecta', async () => {
    assert.strictEqual((await chamar('POST', '/api/meta/login', { corpo: { code: 'x' } })).status, 401);
    const agora = Date.now();
    await chamar('PUT', '/api/store/sl_usuarios', { token: dono, corpo: [{ id: 'u-copy', nome: 'Copy', email: 'copy@tmx.test', senha: 'senha-copy-1', cargo: 'Copy', ativo: true, _updatedAt: agora }] });
    const copy = (await chamar('POST', '/api/auth/login', { corpo: { email: 'copy@tmx.test', senha: 'senha-copy-1' } })).dados.token;
    assert.strictEqual((await chamar('POST', '/api/meta/login', { token: copy, corpo: { code: 'x' } })).status, 403);
  });
  await t.test('sem autorização e com code recusado não conecta', async () => {
    assert.strictEqual((await chamar('POST', '/api/meta/login', { token: dono, corpo: {} })).status, 400);
    const r = await chamar('POST', '/api/meta/login', { token: dono, corpo: { code: 'ruim' } });
    assert.strictEqual(r.status, 400);
    assert.match(r.dados.error, /Invalid verification code/);
    assert.strictEqual((await chamar('GET', '/api/meta/conexao', { token: dono })).dados.conectado, false);
  });
  await t.test('autorização de outro app é recusada', async () => {
    appDoToken = 'app-de-outra-empresa';
    const r = await chamar('POST', '/api/meta/login', { token: dono, corpo: { code: 'bom' } });
    appDoToken = 'app-1';
    assert.strictEqual(r.status, 400);
    assert.match(r.dados.error, /não veio do app da TMX/);
  });
  await t.test('o code vira token no servidor e a conexão fica de pé', async () => {
    const r = await chamar('POST', '/api/meta/login', { token: dono, corpo: { code: 'bom' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.strictEqual(r.dados.via, 'facebook');
    assert.strictEqual(r.dados.expiraEm, 1900000000000);
    assert.strictEqual(r.dados.contas[0].nome, 'Conta Exemplo');
    assert.ok(!JSON.stringify(r.dados).includes(TOKEN) && !JSON.stringify(r.dados).includes(SEGREDO), 'token e segredo não voltam pra tela');
    const troca = chamadas.filter(c => c.p.endsWith('/oauth/access_token') && c.q.code === 'bom').pop();
    assert.deepStrictEqual({ id: troca.q.client_id, seg: troca.q.client_secret }, { id: 'app-1', seg: SEGREDO });
    const c = (await chamar('GET', '/api/meta/conexao', { token: dono })).dados;
    assert.strictEqual(c.conectado, true);
    assert.strictEqual(c.quem.nome, 'Pessoa Exemplo');
    const banco = JSON.parse(fs.readFileSync(path.join(dir, 'db.json'), 'utf8'));
    assert.strictEqual(banco.store.sl_integracoes_meta ? banco.store.sl_integracoes_meta.accessToken : Object.values(banco.store).find(v => v && v.via === 'facebook').accessToken, TOKEN);
  });
  await t.test('quando vem token curto, ele é trocado por um longo', async () => {
    const r = await chamar('POST', '/api/meta/login', { token: dono, corpo: { accessToken: 'tokenCurtoDoNavegador' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const troca = chamadas.filter(c => c.q.grant_type === 'fb_exchange_token').pop();
    assert.strictEqual(troca.q.fb_exchange_token, 'tokenCurtoDoNavegador');
  });
  await t.test('colar token continua funcionando e marca a origem', async () => {
    const r = await chamar('POST', '/api/meta/conexao', { token: dono, corpo: { token: TOKEN } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.strictEqual(r.dados.via, 'token');
    assert.strictEqual(r.dados.expiraEm, null);
  });
});
