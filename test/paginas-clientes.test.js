// Criar páginas nas empresas clientes, cada uma com a própria chave do Claude (09/11/2026).
// Sobe a TMX e duas empresas numa pasta temporária, com uma Anthropic falsa.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
let dir, srv, base, log = '', anthropic;
const pedidos = [], modelosVistos = [];
const espera = ms => new Promise(r => setTimeout(r, ms));
async function ate(cond, ms, oQue) {
  const fim = Date.now() + ms;
  for (;;) {
    try { if (await cond()) return; } catch (e) {}
    if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-3000));
    await espera(120);
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
const CHAVE_A = 'sk-ant-chave-da-empresa-a-123456', CHAVE_B = 'sk-ant-chave-da-empresa-b-123456', CHAVE_RUIM = 'sk-ant-chave-recusada-00000000';

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-pg-cli-'));
  anthropic = await new Promise(ok => {
    const s = http.createServer((req, res) => {
      let b = ''; req.on('data', d => { b += d; }); req.on('end', () => {
        // o SDK 1.x manda a chave em Authorization; as versões antigas, em x-api-key
        const chave = (req.headers.authorization || '').replace(/^Bearer /, '') || req.headers['x-api-key'];
        res.setHeader('Content-Type', 'application/json');
        if (chave === CHAVE_RUIM) { res.statusCode = 401; return res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } })); }
        if (req.url.startsWith('/v1/models')) { modelosVistos.push(chave); return res.end(JSON.stringify({ data: [], has_more: false, first_id: null, last_id: null })); }
        pedidos.push({ chave, corpo: JSON.parse(b || '{}') });
        res.end(JSON.stringify({ id: 'msg_1', type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_sequence: null, stop_reason: 'end_turn',
          usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'text', text: 'pronto' }] }));
      });
    }).listen(0, '127.0.0.1', () => ok(s));
  });
  const porta = 49500 + Math.floor(Math.random() * 400);
  base = 'http://127.0.0.1:' + porta;
  // a chave da TMX existe no ambiente: o teste prova que ela não chega às empresas
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
      ANTHROPIC_API_KEY: 'sk-ant-chave-da-tmx-000000000', ANTHROPIC_BASE_URL: 'http://127.0.0.1:' + anthropic.address().port }
  });
  srv.stdout.on('data', b => { log += b; });
  srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (anthropic) anthropic.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('Criar páginas nas empresas', async (t) => {
  const c = {};
  const empresa = async (nome, email) => {
    const r = await chamar('POST', '/api/plataforma/empresas', { token: c.tmx, corpo: { nome, usuario: { nome: 'Dono', email, senha: 'senha-forte-12345' } } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    return { id: r.dados.empresa.id, token: (await chamar('POST', '/api/auth/login', { corpo: { email, senha: 'senha-forte-12345' } })).dados.token };
  };
  await t.test('a empresa abre o construtor, sem os modelos da TMX', async () => {
    c.tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
    c.a = await empresa('Empresa A', 'dono@a.com'); c.b = await empresa('Empresa B', 'dono@b.com');
    const e = await chamar('GET', '/api/pg/estado', { token: c.a.token });
    assert.strictEqual(e.status, 200, JSON.stringify(e.dados));
    assert.deepStrictEqual(e.dados.modelos, []);
    assert.ok(!JSON.stringify(e.dados).includes('apostilai'));
    assert.ok((await chamar('GET', '/api/pg/estado', { token: c.tmx })).dados.modelos.length > 0, 'na TMX os modelos continuam');
  });

  await t.test('cria em branco; por modelo a empresa não cria', async () => {
    const m = await chamar('POST', '/api/pg/paginas', { token: c.a.token, corpo: { modelo: 'vendas-vsl', slug: 'por-modelo' } });
    assert.strictEqual(m.status, 400);
    const r = await chamar('POST', '/api/pg/paginas', { token: c.a.token, corpo: { branco: true, slug: 'minha-pagina', titulo: 'Minha <página>' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    c.pag = r.dados.id;
    const p = await chamar('GET', '/api/pg/paginas/' + c.pag, { token: c.a.token });
    assert.strictEqual(p.dados.pagina.modelo, 'livre');
    assert.strictEqual(p.dados.versoes[0].resumo, 'Criada em branco');
  });

  await t.test('uma empresa não vê a página da outra', async () => {
    assert.strictEqual((await chamar('GET', '/api/pg/paginas/' + c.pag, { token: c.b.token })).status, 404);
    assert.strictEqual((await chamar('GET', '/api/pg/estado', { token: c.b.token })).dados.paginas.length, 0);
  });

  await t.test('sem chave própria o chat não anda, nem com a chave da TMX no ambiente', async () => {
    const st = await chamar('GET', '/api/ia/chave-status', { token: c.a.token });
    assert.strictEqual(st.dados.ligada, false);
    const r = await chamar('POST', '/api/pg/paginas/' + c.pag + '/chat', { token: c.a.token, corpo: { mensagem: 'oi' } });
    assert.strictEqual(r.status, 400);
    assert.match(r.dados.error, /sua chave do Claude/);
    assert.strictEqual(pedidos.length, 0);
  });

  await t.test('cadastra a chave nos Primeiros passos: confere na Anthropic e não devolve', async () => {
    let p = await chamar('GET', '/api/primeiros-passos', { token: c.a.token });
    assert.strictEqual(p.dados.passos.claude.ok, false);
    assert.strictEqual((await chamar('POST', '/api/primeiros-passos', { token: c.a.token, corpo: { pular: 'claude' } })).status, 400, 'esse passo não dá pra pular');
    assert.strictEqual((await chamar('POST', '/api/ia/chave', { token: c.a.token, corpo: { chave: 'nao-e-chave' } })).status, 400);
    const ruim = await chamar('POST', '/api/ia/chave', { token: c.a.token, corpo: { chave: CHAVE_RUIM } });
    assert.strictEqual(ruim.status, 400);
    assert.match(ruim.dados.error, /não aceitou/);
    const ok = await chamar('POST', '/api/ia/chave', { token: c.a.token, corpo: { chave: CHAVE_A } });
    assert.strictEqual(ok.status, 200, JSON.stringify(ok.dados));
    assert.ok(!JSON.stringify(ok.dados).includes('sk-ant'));
    assert.ok(modelosVistos.includes(CHAVE_A));
    p = await chamar('GET', '/api/primeiros-passos', { token: c.a.token });
    assert.strictEqual(p.dados.passos.claude.ok, true);
    assert.ok(!JSON.stringify(p.dados).includes('sk-ant'));
    assert.strictEqual((await chamar('GET', '/api/ia/chave-status', { token: c.b.token })).dados.ligada, false, 'a chave da A não vale pra B');
  });

  await t.test('o chat usa a chave da empresa e não fala da operação da TMX', async () => {
    const r = await chamar('POST', '/api/pg/paginas/' + c.pag + '/chat', { token: c.a.token, corpo: { mensagem: 'monte a página' } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const { chave, corpo } = pedidos[pedidos.length - 1];
    assert.strictEqual(chave, CHAVE_A);
    assert.ok(!/Apostilai|Thiago/.test(JSON.stringify(corpo.system)), 'a instrução não cita a TMX');
    assert.ok(!/página de modelo/i.test(JSON.stringify(corpo.system)), 'a instrução não fala de modelo');
    assert.ok(!corpo.tools.some(f => f.name === 'trocar_modelo'));
    assert.ok(corpo.tools.some(f => f.name === 'copiar_pagina'));
  });

  await t.test('dentro da empresa, só a Diretoria cria página e cadastra a chave', async () => {
    const us = (await chamar('GET', '/api/store', { token: c.a.token })).dados.sl_usuarios;
    us.push({ id: 'u-copy-a', nome: 'Copy A', email: 'copy@a.com', senha: 'senha-copy-a-123', cargo: 'Copy', ativo: true, _updatedAt: Date.now() });
    assert.strictEqual((await chamar('PUT', '/api/store/sl_usuarios', { token: c.a.token, corpo: us })).status, 200);
    const tok = (await chamar('POST', '/api/auth/login', { corpo: { email: 'copy@a.com', senha: 'senha-copy-a-123' } })).dados.token;
    assert.strictEqual((await chamar('GET', '/api/pg/estado', { token: tok })).status, 403);
    assert.strictEqual((await chamar('POST', '/api/ia/chave', { token: tok, corpo: { chave: CHAVE_B } })).status, 403);
  });

  await t.test('o suporte da TMX não cadastra a chave do cliente', async () => {
    const s = await chamar('POST', '/api/plataforma/empresas/' + c.b.id + '/suporte', { token: c.tmx, corpo: { motivo: 'teste', minutos: 15, modo: 'mexer', avisar: false } });
    assert.strictEqual(s.status, 200, JSON.stringify(s.dados));
    const r = await chamar('POST', '/api/ia/chave', { token: s.dados.token, corpo: { chave: CHAVE_B } });
    assert.strictEqual(r.status, 403);
  });

  await t.test('na TMX nada muda: a rota da chave não existe e a instrução é a dela', async () => {
    assert.strictEqual((await chamar('POST', '/api/ia/chave', { token: c.tmx, corpo: { chave: CHAVE_B } })).status, 404);
    const est = await chamar('GET', '/api/pg/estado', { token: c.tmx });
    const p = await chamar('POST', '/api/pg/paginas', { token: c.tmx, corpo: { modelo: est.dados.modelos[0].id, slug: 'na-tmx' } });
    assert.strictEqual(p.status, 200, JSON.stringify(p.dados));
    await chamar('POST', '/api/pg/paginas/' + p.dados.id + '/chat', { token: c.tmx, corpo: { mensagem: 'oi' } });
    const { chave, corpo } = pedidos[pedidos.length - 1];
    assert.strictEqual(chave, 'sk-ant-chave-da-tmx-000000000');
    assert.match(JSON.stringify(corpo.system), /Apostilai/);
    assert.ok(corpo.tools.some(f => f.name === 'trocar_modelo'));
  });
});
