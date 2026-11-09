// Anexar PDF e HTML no chat da página (09/11/2026).
// Sobe o servidor numa pasta temporária com uma Anthropic falsa. Confere que o PDF vai na mensagem, que o HTML fica
// guardado e o Claude lê por ferramenta, que a página vira o HTML limpo, e o que é recusado.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
let dir, srv, base, log = '', anthropic;
const pedidos = [];
let roteiro = [];   // cada item: função que recebe o pedido e devolve { content, stop_reason } ou { status, erro }
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
const texto = t => () => ({ content: [{ type: 'text', text: t }], stop_reason: 'end_turn' });
const usar = (name, input) => pedido => ({ content: [{ type: 'tool_use', id: 'tu_' + pedidos.length, name, input: typeof input === 'function' ? input(pedido) : input }], stop_reason: 'tool_use' });
const idDoHtml = pedido => [...JSON.stringify(pedido.messages).matchAll(/id (arq[0-9a-f]+)\./g)].pop()[1];   // o anexo mais novo
const ultimoResultado = pedido => pedido.messages[pedido.messages.length - 1].content.find(b => b.type === 'tool_result');

const PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n%%EOF').toString('base64');
const HTML = '<!doctype html><html><head><title>Oferta do arquivo</title>' +
  '<script>fbq("init", "123456789012345");fbq("track","PageView");</script></head>' +
  '<body><h1>Oferta secreta do arquivo</h1><img src="img/foto.png"><p>' + 'Texto da página. '.repeat(40) + '</p></body></html>';

before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-pg-arq-'));
  anthropic = await new Promise(ok => {
    const s = http.createServer((req, res) => {
      let b = ''; req.on('data', d => { b += d; }); req.on('end', () => {
        const pedido = JSON.parse(b || '{}'); pedidos.push(pedido);
        const r = (roteiro.shift() || texto('pronto'))(pedido);
        res.setHeader('Content-Type', 'application/json');
        if (r.status) { res.statusCode = r.status; return res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: r.erro } })); }
        res.end(JSON.stringify({ id: 'msg_' + pedidos.length, type: 'message', role: 'assistant', model: 'claude-opus-5-5', stop_sequence: null,
          usage: { input_tokens: 10, output_tokens: 5 }, content: r.content, stop_reason: r.stop_reason }));
      });
    }).listen(0, '127.0.0.1', () => ok(s));
  });
  const porta = 49000 + Math.floor(Math.random() * 500);
  base = 'http://127.0.0.1:' + porta;
  srv = spawn(process.execPath, [path.join(RAIZ, 'server.js')], {
    cwd: RAIZ, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta), TMX_DATA_DIR: dir,
      ANTHROPIC_API_KEY: 'chave-de-teste', ANTHROPIC_BASE_URL: 'http://127.0.0.1:' + anthropic.address().port }
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

test('Anexos no chat da página', async (t) => {
  const ctx = {};
  const enviar = corpo => chamar('POST', '/api/pg/paginas/' + ctx.id + '/chat', { token: ctx.tmx, corpo });
  await t.test('prepara uma página de modelo', async () => {
    ctx.tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
    const est = await chamar('GET', '/api/pg/estado', { token: ctx.tmx });
    assert.strictEqual(est.status, 200, JSON.stringify(est.dados));
    const c = await chamar('POST', '/api/pg/paginas', { token: ctx.tmx, corpo: { modelo: est.dados.modelos[0].id, slug: 'pagina-arquivo', titulo: 'Teste' } });
    assert.strictEqual(c.status, 200, JSON.stringify(c.dados));
    ctx.id = c.dados.id || (c.dados.pagina && c.dados.pagina.id);
    assert.ok(ctx.id, JSON.stringify(c.dados));
  });

  await t.test('o PDF vai na mensagem; o HTML fica guardado e vira a página pela ferramenta', async () => {
    pedidos.length = 0;
    roteiro = [usar('ver_arquivo', p => ({ id: idDoHtml(p), busca: 'Oferta secreta' })), usar('usar_arquivo_html', p => ({ id: idDoHtml(p), autorizacao: 'minha' })), texto('Pronto, usei o arquivo.')];
    const r = await enviar({ mensagem: 'Use esse HTML', arquivos: [{ tipo: 'pdf', nome: 'briefing.pdf', dados: PDF }, { tipo: 'html', nome: 'pagina.html', texto: HTML }] });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.strictEqual(pedidos.length, 3);
    const primeira = pedidos[0].messages[pedidos[0].messages.length - 1].content;
    const doc = primeira.find(b => b.type === 'document');
    assert.deepStrictEqual(doc.source, { type: 'base64', media_type: 'application/pdf', data: PDF });
    assert.strictEqual(doc.title, 'briefing.pdf');
    assert.strictEqual(primeira[primeira.length - 1].type, 'text', 'o texto vem depois do documento');
    assert.ok(!JSON.stringify(pedidos[0]).includes('Oferta secreta'), 'o HTML não vai inteiro na mensagem');
    assert.ok(ultimoResultado(pedidos[1]).content.includes('Oferta secreta'), 'ver_arquivo acha o trecho');
    const uso = JSON.parse(ultimoResultado(pedidos[2]).content);
    assert.ok(uso.versao_nova > 1);
    assert.ok(uso.tirei.some(x => /Pixel da Meta 123456789012345/.test(x)), JSON.stringify(uso.tirei));
    assert.ok(uso.avisos.some(x => /caminho relativo/.test(x)), JSON.stringify(uso.avisos));
    assert.strictEqual(r.dados.mudou, true);
    const eu = r.dados.mensagens.find(m => m.de === 'eu');
    assert.deepStrictEqual(eu.arquivos, ['briefing.pdf', 'pagina.html']);
    assert.strictEqual(eu.texto, 'Use esse HTML', 'a marca do arquivo não aparece na conversa');
    const pag = await chamar('GET', '/api/pg/paginas/' + ctx.id, { token: ctx.tmx });
    assert.strictEqual(pag.dados.pagina.modelo, 'livre');
    assert.match(pag.dados.versoes[0].resumo, /arquivo pagina\.html/);
  });

  await t.test('só com arquivo, sem texto, também vai', async () => {
    roteiro = [texto('Li o PDF.')];
    const r = await enviar({ mensagem: '', arquivos: [{ tipo: 'pdf', nome: 'so-arquivo.pdf', dados: PDF }] });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    const eu = r.dados.mensagens.filter(m => m.de === 'eu').pop();
    assert.strictEqual(eu.texto, '');
    assert.deepStrictEqual(eu.arquivos, ['so-arquivo.pdf']);
  });

  await t.test('recusa o que não é PDF nem HTML e o que passa do limite', async () => {
    const casos = [
      [{ tipo: 'pdf', nome: 'falso.pdf', dados: Buffer.from('não sou pdf').toString('base64') }, /não abriu/],
      [{ tipo: 'html', nome: 'vazio.html', texto: 'sem nenhuma tag' }, /não parece um HTML/],
      [{ tipo: 'html', nome: 'grande.html', texto: '<p>' + 'x'.repeat(3e6) }, /passa de 3 MB/],
      [{ tipo: 'exe', nome: 'virus.exe', dados: 'AAAA' }, /imagem, PDF ou HTML/]
    ];
    for (const [a, re] of casos) {
      const r = await enviar({ mensagem: 'oi', arquivos: [a] });
      assert.strictEqual(r.status, 400, a.nome);
      assert.match(r.dados.error, re);
    }
    const q = await enviar({ mensagem: 'oi', arquivos: [1, 2, 3, 4].map(n => ({ tipo: 'pdf', nome: n + '.pdf', dados: PDF })) });
    assert.match(q.dados.error, /até 3 arquivos/);
  });

  await t.test('pedido que falha não deixa o HTML guardado', async () => {
    roteiro = [() => ({ status: 400, erro: 'recusado' })];
    const r = await enviar({ mensagem: 'x', arquivos: [{ tipo: 'html', nome: 'falhou.html', texto: HTML }] });
    assert.strictEqual(r.status, 400);
    const id = idDoHtml(pedidos[pedidos.length - 1]);
    roteiro = [usar('ver_arquivo', { id }), texto('ok')];
    await enviar({ mensagem: 'leia' });
    const res = ultimoResultado(pedidos[pedidos.length - 1]);
    assert.strictEqual(res.is_error, true);
    assert.match(res.content, /Não achei esse arquivo/);
  });

  await t.test('nova conversa apaga os HTML anexados', async () => {
    roteiro = [texto('guardei')];
    await enviar({ mensagem: 'guarda', arquivos: [{ tipo: 'html', nome: 'b.html', texto: HTML }] });
    const id = idDoHtml(pedidos[pedidos.length - 1]);
    assert.strictEqual((await chamar('POST', '/api/pg/paginas/' + ctx.id + '/chat/nova', { token: ctx.tmx })).status, 200);
    roteiro = [usar('ver_arquivo', { id }), texto('ok')];
    await enviar({ mensagem: 'leia' });
    assert.strictEqual(ultimoResultado(pedidos[pedidos.length - 1]).is_error, true);
  });
});
