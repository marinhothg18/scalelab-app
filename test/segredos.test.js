// Segredos da TMX (07/11/2026).
// Sobe a TMX numa pasta temporária e confere três coisas:
// 1. A lixeira não é atalho pra escrever onde só a Diretoria escreve: ninguém da equipe
//    inventa um item na lixeira e "restaura" uma conta de Diretoria pra si.
// 2. Senha não chega ao navegador de quem não é Diretoria: nem as senhas guardadas na
//    Central (cd_pastas), nem a senha de uma conta que foi pra lixeira.
// 3. O token da API v1 lê os dados, mas não lê senha nem token de integração.
// Nada toca o banco de verdade: tudo vive numa pasta que é apagada no fim.
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
  let body;
  if (corpo !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(corpo); }
  const r = await fetch(base + caminho, { method: metodo, headers, body });
  let dados = null;
  const tipo = r.headers.get('content-type') || '';
  if (tipo.includes('json')) { try { dados = await r.json(); } catch (e) {} } else { try { dados = await r.text(); } catch (e) {} }
  return { status: r.status, dados };
}
const login = (email, senha) => chamar('POST', '/api/auth/login', { corpo: { email, senha } });
// hash bcrypt de "senha-inventada-123" (o mesmo que alguém da equipe poderia gerar no próprio Mac)
const HASH_INVENTADO = '$2b$10$C5bX0m3oQe1n0b5sH0yQ8u3o3mFQf6J3q2z7oXkq0p8m3Q5v2o1yG';

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-segredos-'));
  const porta = 43000 + Math.floor(Math.random() * 2000);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ,
    // ambiente limpo: nenhuma chave de verdade entra no teste
    env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});

after(async () => {
  if (srv && srv.exitCode === null) {
    srv.kill('SIGTERM');
    await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]);
  }
  if (process.env.TMX_TESTE_LOG) fs.writeFileSync(process.env.TMX_TESTE_LOG, log);
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('segredos da TMX ficam no servidor', async (t) => {
  const ctx = {};

  await t.test('prepara: Diretoria, alguém da equipe, uma conta extra e uma senha guardada na Central', async () => {
    const d = await login('thiago@axcend.com', 'axcend2026');
    assert.strictEqual(d.status, 200, JSON.stringify(d.dados));
    ctx.dir = d.dados.token;
    const e = await login('rafael@axcend.com', 'axcend2026');
    assert.strictEqual(e.status, 200, JSON.stringify(e.dados));
    assert.strictEqual(e.dados.user.cargo, 'Gestor de Tráfego');
    ctx.equipe = e.dados.token;
    // a Diretoria cria uma conta que depois vai pra lixeira
    const us = (await chamar('GET', '/api/store', { token: ctx.dir })).dados.sl_usuarios;
    us.push({ id: 'u-extra', nome: 'Extra', email: 'extra@axcend.com', senha: 'senha-do-extra-123', cargo: 'Copy', ativo: true, _updatedAt: Date.now() });
    us.push({ id: 'u-socio', nome: 'Sócio', email: 'socio@axcend.com', senha: 'senha-do-socio-123', cargo: 'Sócio', ativo: true, _updatedAt: Date.now() });
    assert.strictEqual((await chamar('PUT', '/api/store/sl_usuarios', { token: ctx.dir, corpo: us })).status, 200);
    const s = await login('socio@axcend.com', 'senha-do-socio-123');
    assert.strictEqual(s.status, 200, JSON.stringify(s.dados));
    ctx.socio = s.dados.token;
    // um candidato do RH (o Sócio vê o RH; a equipe não)
    assert.strictEqual((await chamar('PUT', '/api/store/sl_candidatos', { token: ctx.dir, corpo: [
      { id: 'c-1', nome: 'Candidato', _updatedAt: Date.now() }] })).status, 200);
    // e guarda uma senha na Central (pastas › credencial)
    const cd = await chamar('PUT', '/api/cd/data', { token: ctx.dir, corpo: { cd_pastas: [
      { id: 'p-cred', nome: 'Login do banco', tipo: 'cred', login: 'tmx', senha: 'senha-guardada-999', _updatedAt: Date.now() }] } });
    assert.strictEqual(cd.status, 200);
    // uma demanda comum, pra provar que a lixeira da equipe continua funcionando
    assert.strictEqual((await chamar('PUT', '/api/store/tasks', { token: ctx.equipe, corpo: [
      { id: 't-1', nome: 'Demanda comum', status: 'A_FAZER', _updatedAt: Date.now() }] })).status, 200);
  });

  await t.test('ninguém da equipe vira Diretoria pela lixeira', async () => {
    const falsa = { id: 'lx-falsa', sourceKey: 'sl_usuarios', tipo: 'Usuário', deletedAt: new Date().toISOString(), originalId: 'u-falsa',
      data: { id: 'u-falsa', nome: 'Falsa', email: 'falsa@axcend.com', senhaHash: HASH_INVENTADO, cargo: 'Diretoria', ativo: true } };
    const put = await chamar('PUT', '/api/store/sl_lixeira', { token: ctx.equipe, corpo: [falsa] });
    assert.strictEqual(put.status, 403, 'a lixeira só muda pelas rotas dela');
    assert.notStrictEqual((await chamar('POST', '/api/lixeira/restore/lx-falsa', { token: ctx.equipe })).status, 200);
    const us = (await chamar('GET', '/api/store', { token: ctx.dir })).dados.sl_usuarios;
    assert.ok(!us.some(u => u.id === 'u-falsa'), 'a conta inventada não pode existir');
    // nem a Diretoria escreve na lixeira pelo /api/store
    assert.strictEqual((await chamar('PUT', '/api/store/sl_lixeira', { token: ctx.dir, corpo: [falsa] })).status, 403);
  });

  await t.test('a equipe não manda conta nem dado da Diretoria pra lixeira', async () => {
    const r = await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.equipe, corpo: { key: 'sl_usuarios', itemId: 'u1', tipo: 'Usuário' } });
    assert.strictEqual(r.status, 403, 'apagar a conta da Diretoria trancaria todo mundo pra fora');
    assert.ok((await chamar('GET', '/api/store', { token: ctx.dir })).dados.sl_usuarios.some(u => u.id === 'u1'));
    // demanda comum: segue igual (vai pra lixeira e volta)
    const sd = await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.equipe, corpo: { key: 'tasks', itemId: 't-1', tipo: 'Demanda' } });
    assert.strictEqual(sd.status, 200, JSON.stringify(sd.dados));
    const lix = (await chamar('GET', '/api/store', { token: ctx.equipe })).dados.sl_lixeira;
    const ent = lix.find(x => x.sourceKey === 'tasks' && x.originalId === 't-1');
    assert.ok(ent, 'a demanda apagada aparece na lixeira da equipe');
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + ent.id, { token: ctx.equipe })).status, 200);
    assert.ok((await chamar('GET', '/api/store', { token: ctx.equipe })).dados.tasks.some(x => x.id === 't-1'));
  });

  await t.test('conta na lixeira: a equipe não vê, a Diretoria vê sem a senha e restaura com a senha', async () => {
    const sd = await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.dir, corpo: { key: 'sl_usuarios', itemId: 'u-extra', tipo: 'Usuário' } });
    assert.strictEqual(sd.status, 200, JSON.stringify(sd.dados));
    for (const rota of ['/api/store', '/api/updates/0']) {
      const daEquipe = (await chamar('GET', rota, { token: ctx.equipe })).dados;
      const lixE = (rota === '/api/store' ? daEquipe : daEquipe.data).sl_lixeira || [];
      assert.ok(!lixE.some(x => x.sourceKey === 'sl_usuarios'), rota + ': conta apagada não vai pra equipe');
      const daDir = (await chamar('GET', rota, { token: ctx.dir })).dados;
      const lixD = (rota === '/api/store' ? daDir : daDir.data).sl_lixeira || [];
      const ent = lixD.find(x => x.sourceKey === 'sl_usuarios' && x.originalId === 'u-extra');
      assert.ok(ent, rota + ': a Diretoria vê a conta na lixeira');
      assert.ok(!('senhaHash' in ent.data) && !('senha' in ent.data), rota + ': sem a senha');
      ctx.lxExtra = ent.id;
    }
    // a equipe não restaura conta
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + ctx.lxExtra, { token: ctx.equipe })).status, 403);
    // a Diretoria restaura e a senha volta junto (o servidor nunca perdeu)
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + ctx.lxExtra, { token: ctx.dir })).status, 200);
    assert.strictEqual((await login('extra@axcend.com', 'senha-do-extra-123')).status, 200);
  });

  await t.test('o Sócio mexe na lixeira do RH, como no app, mas não na das contas', async () => {
    assert.strictEqual((await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.dir, corpo: { key: 'sl_usuarios', itemId: 'u-extra', tipo: 'Usuário' } })).status, 200);
    const sd = await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.socio, corpo: { key: 'sl_candidatos', itemId: 'c-1', tipo: 'Candidato' } });
    assert.strictEqual(sd.status, 200, JSON.stringify(sd.dados));
    const lixS = (await chamar('GET', '/api/store', { token: ctx.socio })).dados.sl_lixeira;
    const cand = lixS.find(x => x.sourceKey === 'sl_candidatos');
    assert.ok(cand, 'o Sócio vê o candidato na lixeira');
    assert.ok(!lixS.some(x => x.sourceKey === 'sl_usuarios'), 'conta apagada é só da Diretoria');
    const lixE = (await chamar('GET', '/api/store', { token: ctx.equipe })).dados.sl_lixeira;
    assert.ok(!lixE.some(x => x.sourceKey === 'sl_candidatos'), 'a equipe não vê o RH nem na lixeira');
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + cand.id, { token: ctx.equipe })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + cand.id, { token: ctx.socio })).status, 200);
    assert.strictEqual((await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.socio, corpo: { key: 'sl_usuarios', itemId: 'u2', tipo: 'Usuário' } })).status, 403);
    const conta = (await chamar('GET', '/api/store', { token: ctx.dir })).dados.sl_lixeira.find(x => x.sourceKey === 'sl_usuarios');
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + conta.id, { token: ctx.socio })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/lixeira/restore/' + conta.id, { token: ctx.dir })).status, 200);
  });

  await t.test('a Central (com as senhas guardadas) não vai pro navegador da equipe', async () => {
    const daEquipe = await chamar('GET', '/api/store', { token: ctx.equipe });
    assert.strictEqual(daEquipe.status, 200);
    assert.ok(!JSON.stringify(daEquipe.dados).includes('senha-guardada-999'));
    assert.ok(!('cd_pastas' in daEquipe.dados));
    assert.strictEqual((await chamar('PUT', '/api/store/cd_pastas', { token: ctx.equipe, corpo: [] })).status, 403);
    // a Diretoria continua vendo e usando a Central como antes
    const cd = await chamar('GET', '/api/cd/data', { token: ctx.dir });
    assert.strictEqual(cd.dados.cd_pastas[0].senha, 'senha-guardada-999');
  });

  await t.test('o token da API v1 da TMX não lê senha nem token de integração', async () => {
    const g = await chamar('POST', '/api/tokens/generate', { token: ctx.dir, corpo: { nome: 'agente' } });
    assert.strictEqual(g.status, 200, JSON.stringify(g.dados));
    const api = g.dados.token;
    // segredos de integração existem no banco, mas não saem pela API
    assert.strictEqual((await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: ctx.dir })).status, 200);
    assert.strictEqual((await chamar('PUT', '/api/store/sl_whatsapp_config', { token: ctx.dir, corpo: { zapi_token: 'zapi-segredo-777', ativo: false } })).status, 200);
    for (const chave of ['sl_integracoes_vendas', 'sl_whatsapp_config']) {
      const r = await chamar('GET', '/api/v1/dados/' + chave, { token: api });
      assert.strictEqual(r.status, 404, chave);
    }
    // os dados comuns continuam saindo
    const tasks = await chamar('GET', '/api/v1/dados/tasks', { token: api });
    assert.strictEqual(tasks.status, 200);
    assert.ok(tasks.dados.some(x => x.id === 't-1'));
    // sem senha em lugar nenhum: contas, Central e lixeira
    const us = await chamar('GET', '/api/v1/dados/sl_usuarios', { token: api });
    assert.strictEqual(us.status, 200);
    assert.ok(us.dados.every(u => !('senha' in u) && !('senhaHash' in u) && !('resetSenha' in u)));
    const cd = await chamar('GET', '/api/v1/dados/cd_pastas', { token: api });
    assert.strictEqual(cd.status, 200);
    assert.strictEqual(cd.dados[0].nome, 'Login do banco');
    assert.ok(!JSON.stringify(cd.dados).includes('senha-guardada-999'));
    assert.strictEqual((await chamar('POST', '/api/lixeira/soft-delete', { token: ctx.dir, corpo: { key: 'sl_usuarios', itemId: 'u-extra', tipo: 'Usuário' } })).status, 200);
    const lix = await chamar('GET', '/api/v1/dados/sl_lixeira', { token: api });
    assert.strictEqual(lix.status, 200);
    assert.ok(lix.dados.some(x => x.sourceKey === 'sl_usuarios'));
    assert.ok(!/senhaHash|\$2[aby]\$/.test(JSON.stringify(lix.dados)), 'nem o hash da senha');
  });
});
