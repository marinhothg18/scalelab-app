// Central TMX Admin: bloquear, entrar como suporte e chamados (07/11/2026).
// Sobe o servidor numa pasta temporária com a TMX e duas empresas (A e B) e confere:
// bloqueio fecha o app mas o pixel continua; suporte "só olhar" não grava e "pode mexer"
// grava; a Diretoria do cliente é avisada; chamado vai e volta e outra empresa não enxerga.
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
async function chamar(metodo, caminho, { token, corpo, texto } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  let body;
  if (texto !== undefined) { headers['Content-Type'] = 'text/plain'; body = texto; }
  else if (corpo !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(corpo); }
  const r = await fetch(base + caminho, { method: metodo, headers, body });
  let dados = null;
  const tipo = r.headers.get('content-type') || '';
  if (tipo.includes('json')) { try { dados = await r.json(); } catch (e) {} } else { try { dados = await r.text(); } catch (e) {} }
  return { status: r.status, dados, headers: r.headers };
}
const login = (email, senha) => chamar('POST', '/api/auth/login', { corpo: { email, senha } });

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-admin-'));
  const porta = 43000 + Math.floor(Math.random() * 2000);
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
  if (process.env.TMX_TESTE_LOG) fs.writeFileSync(process.env.TMX_TESTE_LOG, log);
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('Central TMX Admin: bloquear, suporte e chamados', async (t) => {
  const ctx = {};
  const store = async tok => (await chamar('GET', '/api/store', { token: tok })).dados;

  await t.test('prepara a TMX e as empresas A e B', async () => {
    ctx.tmx = (await login('thiago@axcend.com', 'axcend2026')).dados.token;
    for (const k of ['A', 'B']) {
      const r = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx, corpo: { nome: 'Empresa ' + k, usuario: { nome: 'Dona ' + k, email: 'dona@empresa-' + k.toLowerCase() + '.com', senha: 'senha-da-' + k + '-123' } } });
      assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
      ctx['id' + k] = r.dados.empresa.id;
      const l = await login('dona@empresa-' + k.toLowerCase() + '.com', 'senha-da-' + k + '-123');
      ctx['tok' + k] = l.dados.token; ctx['user' + k] = l.dados.user.id;
    }
    assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: ctx.tokA, corpo: [{ id: 't-a', nome: 'Tarefa da A', status: 'A_FAZER', _updatedAt: Date.now() }] })).status, 200);
  });

  await t.test('só a Diretoria da TMX bloqueia e entra como suporte', async () => {
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/bloquear', { corpo: {} })).status, 401);
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/bloquear', { token: ctx.tokB, corpo: {} })).status, 404, 'dentro do motor não existe');
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/suporte', { token: ctx.tokB, corpo: { motivo: 'x' } })).status, 404);
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/suporte', { token: ctx.tmx, corpo: {} })).status, 400, 'motivo é obrigatório');
  });

  await t.test('bloqueio fecha o app da equipe, mas o pixel continua gravando', async () => {
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/bloquear', { token: ctx.tmx, corpo: { motivo: 'Pagamento atrasado' } })).status, 200);
    const r = await chamar('GET', '/api/store', { token: ctx.tokA });
    assert.strictEqual(r.status, 403);
    assert.strictEqual(r.headers.get('x-tmx-bloqueada'), '1');
    const l = await login('dona@empresa-a.com', 'senha-da-A-123');
    assert.strictEqual(l.status, 403, 'login também para');
    assert.match(l.dados.error, /suspensa/);
    // o pixel e o px.js passam pelo endereço público, sem sessão
    assert.strictEqual((await chamar('GET', '/e/' + ctx.idA + '/px.js')).status, 200);
    const ev = { funil: 'fA', etapa: 'e1', tipo: 'entrou', id: 'visitante-bloqueada', pg: 'https://site-a.com/oferta' };
    assert.strictEqual((await chamar('POST', '/e/' + ctx.idA + '/api/funil/evento', { texto: JSON.stringify(ev) })).status, 204);
    const { DatabaseSync } = require('node:sqlite');
    const arq = path.join(dir, 'empresas', ctx.idA, 'pessoas.sqlite');
    await ate(() => { const db = new DatabaseSync(arq, { readOnly: true }); try { return db.prepare('SELECT 1 FROM visitantes WHERE id=?').get('visitante-bloqueada'); } finally { db.close(); } }, 5000, 'visita gravada na empresa bloqueada');
    // B não é afetada
    assert.strictEqual((await chamar('GET', '/api/store', { token: ctx.tokB })).status, 200);
    const lista = (await chamar('GET', '/api/plataforma/empresas', { token: ctx.tmx })).dados.empresas;
    const a = lista.find(e => e.id === ctx.idA);
    assert.strictEqual(a.status, 'bloqueada');
    assert.strictEqual(a.bloqueio_motivo, 'Pagamento atrasado');
  });

  await t.test('suporte só olhar entra até na bloqueada, vê tudo e não grava nada', async () => {
    const r = await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/suporte', { token: ctx.tmx, corpo: { motivo: 'chamado do pixel', modo: 'olhar', minutos: 15 } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.ok(r.dados.token.startsWith('ses_' + ctx.idA + '.sup'));
    assert.ok(r.dados.expira > Date.now() + 14 * 60000 && r.dados.expira < Date.now() + 16 * 60000);
    ctx.supA = r.dados.token;
    const me = await chamar('GET', '/api/auth/me', { token: ctx.supA });
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.dados.user.suporte.modo, 'olhar');
    assert.match(me.dados.user.nome, /^Suporte TMX/);
    const st = await store(ctx.supA);
    assert.deepStrictEqual(st.tasks.map(x => x.id), ['t-a']);
    assert.ok(!st.sl_usuarios.some(u => /suporte/i.test(u.nome)), 'o suporte não vira gente da equipe do cliente');
    const grava = await chamar('PUT', '/api/store/tasks', { token: ctx.supA, corpo: [{ id: 't-sup', nome: 'Do suporte', _updatedAt: Date.now() }] });
    assert.strictEqual(grava.status, 403);
    assert.strictEqual(grava.headers.get('x-tmx-so-olhar'), '1');
    // a Diretoria da A foi avisada e a auditoria da TMX registrou
    await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/desbloquear', { token: ctx.tmx });
    const notifs = JSON.stringify((await store(ctx.tokA)).sl_notifs || []);
    assert.match(notifs, /suporte da TMX entrou/);
    assert.match(notifs, /chamado do pixel/);
    const tmxStore = await store(ctx.tmx);
    assert.ok((tmxStore.sl_auditlog || []).some(x => x.action === 'suporte_entrou'));
    assert.ok((tmxStore.sl_auditlog || []).some(x => x.action === 'empresa_bloqueada'));
  });

  await t.test('desbloqueada volta a abrir; suporte "pode mexer" grava, mas não mexe na conta de ninguém', async () => {
    assert.strictEqual((await chamar('GET', '/api/store', { token: ctx.tokA })).status, 200);
    assert.strictEqual((await login('dona@empresa-a.com', 'senha-da-A-123')).status, 200);
    const r = await chamar('POST', '/api/plataforma/empresas/' + ctx.idA + '/suporte', { token: ctx.tmx, corpo: { motivo: 'ajustar o mapa', modo: 'mexer', minutos: 30, avisar: false } });
    const sup = r.dados.token;
    assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: sup, corpo: [{ id: 't-sup', nome: 'Feita pelo suporte', _updatedAt: Date.now() }] })).status, 200);
    assert.ok((await store(ctx.tokA)).tasks.some(x => x.id === 't-sup'));
    assert.strictEqual((await chamar('PUT', '/api/me', { token: sup, corpo: { nome: 'x' } })).status, 403);
    // a sessão de suporte da A não abre a B
    assert.strictEqual((await chamar('GET', '/e/' + ctx.idB + '/api/store', { token: sup })).status, 401);
    // sair do suporte encerra a sessão
    await chamar('POST', '/api/auth/logout', { token: sup });
    assert.strictEqual((await chamar('GET', '/api/store', { token: sup })).status, 401);
  });

  await t.test('chamado: o cliente abre, a TMX responde, e outra empresa não enxerga', async () => {
    assert.strictEqual((await chamar('POST', '/api/suporte/chamados', { token: ctx.tokA, corpo: { assunto: '', texto: '' } })).status, 400);
    const ab = await chamar('POST', '/api/suporte/chamados', { token: ctx.tokA, corpo: { assunto: 'Pixel não conta a VSL', tipo: 'Problema', projeto: 'SECA 30', texto: 'O bloco ficou zerado.' } });
    assert.strictEqual(ab.status, 200, JSON.stringify(ab.dados));
    ctx.ch = ab.dados.id;
    const doTmx = (await chamar('GET', '/api/plataforma/chamados', { token: ctx.tmx })).dados.chamados.find(c => c.id === ctx.ch);
    assert.strictEqual(doTmx.empresa, ctx.idA);
    assert.strictEqual(doTmx.empresa_nome, 'Empresa A');
    assert.strictEqual(doTmx.status, 'aberto');
    assert.match(JSON.stringify((await store(ctx.tmx)).sl_notifs || []), /Chamado #\d+ · Empresa A/);
    // nota interna e resposta
    assert.strictEqual((await chamar('POST', '/api/plataforma/chamados/' + ctx.ch + '/responder', { token: ctx.tmx, corpo: { texto: 'Nota: data-e errado', nota: true } })).status, 200);
    assert.strictEqual((await chamar('POST', '/api/plataforma/chamados/' + ctx.ch + '/responder', { token: ctx.tmx, corpo: { texto: 'Troca o data-e pelo da Seca 30.' } })).status, 200);
    const visto = (await chamar('GET', '/api/suporte/chamados/' + ctx.ch, { token: ctx.tokA })).dados.chamado;
    assert.strictEqual(visto.status, 'cliente');
    assert.deepStrictEqual(visto.msgs.map(m => m.de), ['cliente', 'tmx'], 'nota interna não aparece pro cliente');
    await ate(async () => /A TMX respondeu/.test(JSON.stringify((await store(ctx.tokA)).sl_notifs || [])), 5000, 'aviso da resposta no cliente');
    // cliente responde e volta pra fila da TMX
    assert.strictEqual((await chamar('POST', '/api/suporte/chamados/' + ctx.ch + '/responder', { token: ctx.tokA, corpo: { texto: 'Troquei, deu certo.' } })).status, 200);
    assert.strictEqual((await chamar('GET', '/api/plataforma/chamados/' + ctx.ch, { token: ctx.tmx })).dados.chamado.status, 'aberto');
    // B não vê nem responde o chamado da A, e a TMX não abre chamado pra ela mesma
    assert.strictEqual((await chamar('GET', '/api/suporte/chamados/' + ctx.ch, { token: ctx.tokB })).status, 404);
    assert.strictEqual((await chamar('POST', '/api/suporte/chamados/' + ctx.ch + '/responder', { token: ctx.tokB, corpo: { texto: 'oi' } })).status, 400);
    assert.deepStrictEqual((await chamar('GET', '/api/suporte/chamados', { token: ctx.tokB })).dados.chamados, []);
    assert.strictEqual((await chamar('GET', '/api/suporte/chamados', { token: ctx.tmx })).status, 404);
    // resolvido avisa o cliente
    assert.strictEqual((await chamar('POST', '/api/plataforma/chamados/' + ctx.ch + '/responder', { token: ctx.tmx, corpo: { status: 'resolvido' } })).status, 200);
    assert.strictEqual((await chamar('GET', '/api/suporte/chamados/' + ctx.ch, { token: ctx.tokA })).dados.chamado.status, 'resolvido');
  });
});
