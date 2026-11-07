// Meu plano (07/11/2026): plano da empresa, uso de cada limite e troca de plano pela Central.
// Sobe o servidor numa pasta temporária com a TMX e uma empresa A.
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
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados };
}
const usoDe = (d, id) => d.uso.find(u => u.id === id);

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-plano-'));
  const porta = 45000 + Math.floor(Math.random() * 2000);
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
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('Meu plano', async (t) => {
  const ctx = {};
  await t.test('a TMX vê o plano Interno, sem limite', async () => {
    ctx.tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
    const r = await chamar('GET', '/api/meu-plano', { token: ctx.tmx });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.strictEqual(r.dados.interno, true);
    assert.strictEqual(r.dados.plano.nome, 'Interno');
    assert.strictEqual(r.dados.uso.length, 8);
    assert.ok(r.dados.uso.every(u => u.limite === null));
  });

  await t.test('empresa nova começa no Teste e vê os planos à venda', async () => {
    const c = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx, corpo: { nome: 'Empresa A', usuario: { nome: 'Dona A', email: 'dona@a.com', senha: 'senha-da-A-123' } } });
    ctx.id = c.dados.empresa.id;
    ctx.a = (await chamar('POST', '/api/auth/login', { corpo: { email: 'dona@a.com', senha: 'senha-da-A-123' } })).dados.token;
    const r = await chamar('GET', '/api/meu-plano', { token: ctx.a });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.strictEqual(r.dados.interno, false);
    assert.strictEqual(r.dados.plano.id, 'teste');
    assert.deepStrictEqual(r.dados.planos.map(p => p.id), ['iniciante', 'starter', 'escala', 'agencia']);
    assert.strictEqual(usoDe(r.dados, 'pessoas').usado, 1);
    assert.strictEqual(usoDe(r.dados, 'projetos').usado, 0);
    assert.strictEqual(r.dados.cobranca.ligada, false);
  });

  await t.test('a Central troca o plano e o uso conta projetos e vendas da própria empresa', async () => {
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.id + '/plano', { token: ctx.tmx, corpo: { plano: 'nao-existe' } })).status, 400);
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.id + '/plano', { token: ctx.tmx, corpo: { plano: 'interno' } })).status, 400, 'Interno é só da TMX');
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.id + '/plano', { token: ctx.a, corpo: { plano: 'agencia' } })).status, 404, 'o cliente não troca o próprio plano');
    assert.strictEqual((await chamar('POST', '/api/plataforma/empresas/' + ctx.id + '/plano', { token: ctx.tmx, corpo: { plano: 'escala' } })).status, 200);
    await chamar('PUT', '/api/store/sl_ofertas_v2', { token: ctx.a, corpo: [{ id: 'o1', nome: 'SECA 30', nichoId: 'n1', _updatedAt: Date.now() }, { id: 'o2', nome: 'DETOX', nichoId: 'n1', _updatedAt: Date.now() }] });
    const url = (await chamar('POST', '/api/integracoes/vendas/gerar-token', { token: ctx.a })).dados.urlWebhook;
    await chamar('POST', url + '/payt', { corpo: { order_id: 'P-1', status: 'paid', amount: 197, product: { name: 'X' }, customer: { name: 'C', email: 'c@c.com' } } });
    const r = (await chamar('GET', '/api/meu-plano', { token: ctx.a })).dados;
    assert.strictEqual(r.plano.id, 'escala');
    assert.strictEqual(usoDe(r, 'projetos').usado, 2);
    assert.strictEqual(usoDe(r, 'projetos').limite, 3);
    assert.strictEqual(usoDe(r, 'contas').limite, 10);
    assert.strictEqual(usoDe(r, 'invest').limite, 300000);
    assert.strictEqual(usoDe(r, 'vendas').usado, 1);
    // a TMX não ganhou o uso da A
    const tmx = (await chamar('GET', '/api/meu-plano', { token: ctx.tmx })).dados;
    assert.strictEqual(usoDe(tmx, 'vendas').usado, 0);
    const lista = (await chamar('GET', '/api/plataforma/empresas', { token: ctx.tmx })).dados.empresas;
    assert.strictEqual(lista.find(e => e.id === ctx.id).plano, 'escala');
  });

  await t.test('convite com plano: o cadastro mostra o nome e a empresa nasce no plano', async () => {
    const c = await chamar('POST', '/api/plataforma/convites', { token: ctx.tmx, corpo: { email: 'gratis@b.com', plano: 'iniciante', obs: 'Teste grátis' } });
    assert.strictEqual(c.status, 200);
    const codigo = new URL(c.dados.link).searchParams.get('c');
    const info = (await chamar('GET', '/api/cadastro/convite?c=' + codigo)).dados;
    assert.strictEqual(info.plano_nome, 'Iniciante');
    assert.strictEqual(info.gratis, true);
    const cad = await chamar('POST', '/api/cadastro', { corpo: { c: codigo, nome: 'Bia', email: 'gratis@b.com', senha: 'senha-da-bia-1', empresa: 'Empresa B', projetos: [{ nicho: 'Fitness', nome: 'TREINO' }] } });
    assert.strictEqual(cad.status, 200, JSON.stringify(cad.dados));
    const mp = (await chamar('GET', '/api/meu-plano', { token: cad.dados.token })).dados;
    assert.strictEqual(mp.plano.id, 'iniciante');
    assert.strictEqual(usoDe(mp, 'projetos').limite, 1);
    // a Central lê os pedidos da página de planos
    const ped = await chamar('GET', '/api/plataforma/assinaturas', { token: ctx.tmx });
    assert.strictEqual(ped.status, 200);
    assert.ok(Array.isArray(ped.dados.assinaturas));
  });

  await t.test('o pedido de troca de plano chega como chamado na Central', async () => {
    const p = await chamar('POST', '/api/suporte/chamados', { token: ctx.a, corpo: { tipo: 'Pedido', assunto: 'Trocar para o plano Agência', texto: 'Quero trocar.' } });
    assert.strictEqual(p.status, 200);
    const ch = (await chamar('GET', '/api/plataforma/chamados', { token: ctx.tmx })).dados.chamados.find(c => c.id === p.dados.id);
    assert.strictEqual(ch.tipo, 'Pedido');
    assert.strictEqual(ch.empresa, ctx.id);
  });
});
