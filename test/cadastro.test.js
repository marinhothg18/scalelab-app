// Cadastro do cliente por convite (07/11/2026).
// Sobe o servidor numa pasta temporária, gera um convite como a Diretoria da TMX e faz
// o cadastro como o cliente faria: acesso, empresa e projetos. Confere que a empresa nasce
// com a conta, o WhatsApp, os projetos e o nome dela, que o convite vale uma vez só e que
// a pessoa entra pelo login normal depois.
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
async function chamar(metodo, caminho, { token, corpo } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + caminho, { method: metodo, headers, body: corpo !== undefined ? JSON.stringify(corpo) : undefined });
  let dados = null;
  const tipo = r.headers.get('content-type') || '';
  if (tipo.includes('json')) { try { dados = await r.json(); } catch (e) {} } else { try { dados = await r.text(); } catch (e) {} }
  return { status: r.status, dados };
}

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-cadastro-'));
  const porta = 41000 + Math.floor(Math.random() * 2000);
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

test('cadastro do cliente por convite', async (t) => {
  const ctx = {};
  const codigoDo = link => new URL(link).searchParams.get('c');

  await t.test('só a Diretoria da TMX gera convite', async () => {
    assert.strictEqual((await chamar('POST', '/api/plataforma/convites', { corpo: {} })).status, 401);
    const tmx = await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } });
    assert.strictEqual(tmx.status, 200);
    ctx.tmx = tmx.dados.token;
    assert.strictEqual((await chamar('POST', '/api/plataforma/convites', { token: ctx.tmx, corpo: { email: 'thiago@axcend.com' } })).status, 409, 'e-mail da TMX não vira convite');
    const c = await chamar('POST', '/api/plataforma/convites', { token: ctx.tmx, corpo: { email: 'ana@clinica.com', obs: 'teste automático' } });
    assert.strictEqual(c.status, 200, JSON.stringify(c.dados));
    assert.match(c.dados.link, /\/cadastro\?c=cv_/);
    ctx.codigo = codigoDo(c.dados.link);
  });

  await t.test('a página e o convite abrem; convite inventado não', async () => {
    const pg = await chamar('GET', '/cadastro');
    assert.strictEqual(pg.status, 200);
    assert.match(pg.dados, /Crie seu acesso|Conferindo o seu convite/);
    const ok = await chamar('GET', '/api/cadastro/convite?c=' + ctx.codigo);
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(ok.dados.email, 'ana@clinica.com');
    assert.ok(ok.dados.nichos.includes('Concursos'));
    assert.strictEqual((await chamar('GET', '/api/cadastro/convite?c=cv_' + 'x'.repeat(30))).status, 404);
    assert.strictEqual((await chamar('GET', '/api/cadastro/convite')).status, 404);
  });

  await t.test('confere os campos antes de gastar o convite', async () => {
    const semProjeto = await chamar('POST', '/api/cadastro', { corpo: { c: ctx.codigo, nome: 'Ana', email: 'ana@clinica.com', senha: 'senha-da-ana-1', empresa: 'Clínica', projetos: [] } });
    assert.strictEqual(semProjeto.status, 400);
    assert.strictEqual(semProjeto.dados.campo, 'projetos');
    const senhaCurta = await chamar('POST', '/api/cadastro', { corpo: { c: ctx.codigo, nome: 'Ana', email: 'ana@clinica.com', senha: '123', empresa: 'Clínica', projetos: [{ nicho: 'Emagrecimento', nome: 'SECA 30' }] } });
    assert.strictEqual(senhaCurta.dados.campo, 'senha');
    const emailTmx = await chamar('POST', '/api/cadastro', { corpo: { c: ctx.codigo, nome: 'Ana', email: 'thiago@axcend.com', senha: 'senha-da-ana-1', empresa: 'Clínica', projetos: [{ nicho: 'Emagrecimento', nome: 'SECA 30' }] } });
    assert.strictEqual(emailTmx.status, 409);
    // nenhum desses gastou o convite
    assert.strictEqual((await chamar('GET', '/api/cadastro/convite?c=' + ctx.codigo)).status, 200);
  });

  await t.test('cadastro cria a empresa com a conta, o WhatsApp, os projetos e o nome', async () => {
    const r = await chamar('POST', '/api/cadastro', { corpo: { c: ctx.codigo, nome: 'Ana Souza', email: 'Ana@Clinica.com', whatsapp: '(11) 98888-7777',
      senha: 'senha-da-ana-1', empresa: 'Clínica Bem Estar', projetos: [{ nicho: 'Emagrecimento', nome: 'SECA 30' }, { nicho: 'Emagrecimento', nome: 'DETOX 7' }, { nicho: 'Pets', nome: 'RAÇÃO NATURAL' }] } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados) + log.slice(-1500));
    ctx.id = r.dados.empresa.id;
    assert.ok(r.dados.token.startsWith('ses_' + ctx.id + '.'), 'sessão já com a marca da empresa nova');
    assert.ok(!('senhaHash' in r.dados.user) && !('senha' in r.dados.user), 'senha nunca volta pro navegador');
    const store = (await chamar('GET', '/api/store', { token: r.dados.token })).dados;
    const eu = store.sl_usuarios.find(u => u.email === 'ana@clinica.com');
    assert.ok(eu, 'a conta existe na empresa nova');
    assert.strictEqual(eu.cargo, 'Diretoria');
    assert.strictEqual(eu.whatsapp, '5511988887777');
    assert.deepStrictEqual(store.sl_nichos.map(n => n.nome).sort(), ['Emagrecimento', 'Pets']);
    assert.deepStrictEqual(store.sl_ofertas_v2.map(o => o.nome).sort(), ['DETOX 7', 'RAÇÃO NATURAL', 'SECA 30']);
    const emag = store.sl_nichos.find(n => n.nome === 'Emagrecimento').id;
    assert.strictEqual(store.sl_ofertas_v2.filter(o => o.nichoId === emag).length, 2, 'dois projetos no mesmo nicho');
    assert.strictEqual(store.cfg.projeto, 'Clínica Bem Estar');
    // e a TMX não ganhou nada disso
    const tmx = (await chamar('GET', '/api/store', { token: ctx.tmx })).dados;
    assert.ok(!(tmx.sl_ofertas_v2 || []).some(o => o.nome === 'SECA 30'));
    assert.ok(!tmx.sl_usuarios.some(u => u.email === 'ana@clinica.com'));
  });

  await t.test('o convite vale uma vez só e aparece como usado', async () => {
    const de_novo = await chamar('POST', '/api/cadastro', { corpo: { c: ctx.codigo, nome: 'Outra', email: 'outra@x.com', senha: 'senha-outra-123', empresa: 'Outra', projetos: [{ nicho: 'Fitness', nome: 'X' }] } });
    assert.strictEqual(de_novo.status, 404);
    const lista = (await chamar('GET', '/api/plataforma/convites', { token: ctx.tmx })).dados.convites;
    const usado = lista.find(c => c.email === 'ana@clinica.com');
    assert.strictEqual(usado.situacao, 'usado');
    assert.strictEqual(usado.empresa, ctx.id);
    const emp = (await chamar('GET', '/api/plataforma/empresas', { token: ctx.tmx })).dados.empresas.find(e => e.id === ctx.id);
    assert.strictEqual(emp.nome, 'Clínica Bem Estar');
    assert.strictEqual(emp.contas, 1);
  });

  await t.test('depois ela entra pelo login normal, e o e-mail não serve pra outro cadastro', async () => {
    const l = await chamar('POST', '/api/auth/login', { corpo: { email: 'ana@clinica.com', senha: 'senha-da-ana-1' } });
    assert.strictEqual(l.status, 200, JSON.stringify(l.dados));
    assert.strictEqual(l.dados.empresa.id, ctx.id);
    const c2 = await chamar('POST', '/api/plataforma/convites', { token: ctx.tmx, corpo: {} });
    const repetido = await chamar('POST', '/api/cadastro', { corpo: { c: codigoDo(c2.dados.link), nome: 'Ana', email: 'ana@clinica.com', senha: 'senha-da-ana-2', empresa: 'Segunda', projetos: [{ nicho: 'Fitness', nome: 'Y' }] } });
    assert.strictEqual(repetido.status, 409);
    assert.strictEqual(repetido.dados.campo, 'email');
    // dentro do motor da empresa, cadastro e convites não existem
    assert.strictEqual((await chamar('GET', '/e/' + ctx.id + '/cadastro')).status, 404);
    assert.strictEqual((await chamar('POST', '/api/plataforma/convites', { token: l.dados.token, corpo: {} })).status, 404);
  });
});
