// Painel da Central TMX Admin (07/11/2026): um pedido junta o resumo de cada empresa (pelo motor
// dela), a receita, os chamados e a saúde do servidor. Só a Diretoria da TMX lê.
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

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-painel-'));
  const porta = 47000 + Math.floor(Math.random() * 2000);
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

test('Painel da Central', async (t) => {
  const ctx = {};
  await t.test('junta o resumo de cada empresa, contado no motor dela', async () => {
    ctx.tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
    const c = await chamar('POST', '/api/plataforma/empresas', { token: ctx.tmx, corpo: { nome: 'Empresa A', usuario: { nome: 'Dona A', email: 'dona@a.com', senha: 'senha-da-A-123' } } });
    ctx.id = c.dados.empresa.id;
    ctx.a = (await chamar('POST', '/api/auth/login', { corpo: { email: 'dona@a.com', senha: 'senha-da-A-123' } })).dados.token;
    await chamar('PUT', '/api/store/sl_ofertas_v2', { token: ctx.a, corpo: [{ id: 'o1', nome: 'SECA 30', _updatedAt: Date.now() }, { id: 'o2', nome: 'DETOX', _updatedAt: Date.now() }] });
    await chamar('PUT', '/api/store/tasks', { token: ctx.a, corpo: [{ id: 't1', titulo: 'Subir VSL', _updatedAt: Date.now() }] });
    const r = await chamar('GET', '/api/plataforma/painel?novo=1', { token: ctx.tmx });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const a = r.dados.empresas.find(e => e.id === ctx.id);
    assert.ok(a.resumo, 'o motor respondeu: ' + a.erroResumo);
    assert.strictEqual(a.resumo.uso.pessoas, 1);
    assert.strictEqual(a.resumo.modulos.Projetos, 2);
    assert.strictEqual(a.resumo.modulos.Demandas, 1);
    assert.deepStrictEqual(a.resumo.projetos.sort(), ['DETOX', 'SECA 30']);
    assert.strictEqual(a.resumo.vendasSemanas.length, 12);
    assert.ok(a.resumo.ultimoAcesso > 0, 'a dona entrou');
    assert.ok(a.resumo.memMB > 0);
    assert.strictEqual(a.motor.estado, 'ligado');
    assert.strictEqual(a.limites.find(l => l.id === 'projetos').usado, 2);
    // o resumo não traz conteúdo: nada de título de demanda
    assert.ok(!JSON.stringify(r.dados).includes('Subir VSL'));
    // a TMX vem à parte e não soma o uso da A
    assert.ok(r.dados.tmx && r.dados.tmx.modulos.Demandas === 0);
  });

  await t.test('traz receita, cobrança, chamados e saúde', async () => {
    const ch = await chamar('POST', '/api/suporte/chamados', { token: ctx.a, corpo: { tipo: 'Problema', assunto: 'Pixel não conta', texto: 'Ajuda' } });
    assert.strictEqual(ch.status, 200);
    const d = (await chamar('GET', '/api/plataforma/painel?novo=1', { token: ctx.tmx })).dados;
    assert.strictEqual(d.receita.mensal, 0);
    assert.strictEqual(d.receita.meses.length, 6);
    assert.strictEqual(d.cobranca.ligada, false);
    assert.ok(d.cobranca.webhook.endsWith('/api/billing/webhook'));
    assert.ok(d.cobranca.linkCompra.endsWith('/assinar/{plano}'));
    assert.deepStrictEqual(d.cobranca.planos.map(p => p.id), ['teste', 'iniciante', 'starter', 'escala', 'agencia', 'pro', 'elite', 'premium']);
    assert.strictEqual(d.chamados.esperandoTmx, 1);
    assert.strictEqual(d.chamados.semResposta, 1);
    assert.strictEqual(d.chamados.esperando[0].empresaNome, 'Empresa A');
    assert.ok(d.saude.memoria.usadoMB > 0 && d.saude.memoria.limiteMB > 0);
    assert.ok(d.saude.disco && d.saude.disco.totalGB > 0);
    assert.ok(Array.isArray(d.saude.erros));
  });

  await t.test('só a Diretoria da TMX lê o painel', async () => {
    const r = await chamar('GET', '/api/plataforma/painel', { token: ctx.a });
    assert.ok([403, 404].includes(r.status), 'cliente não lê: ' + r.status);
    assert.strictEqual((await chamar('GET', '/api/plataforma/painel')).status, 401);
  });
});
