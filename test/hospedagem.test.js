// Hospedagem própria: TMX + 2 empresas numa pasta temporária, com uma Cloudflare de mentira que roda o
// programa de entrega de verdade (cloudflare/worker.mjs).
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const espera = ms => new Promise(r => setTimeout(r, ms));
let dir, srv, base, log = '', cf, W;
const CF = { hostnames: new Map(), rotas: [], buckets: [], worker: null, envios: 0, n: 0, r2: null };

function r2Falso() {
  const m = new Map();
  const obj = v => ({ httpMetadata: v.meta, body: new Blob([v.b]).stream(), text: async () => Buffer.from(v.b).toString('utf8') });
  return { m,
    get: async k => (m.has(k) ? obj(m.get(k)) : null),
    put: async (k, b, o) => { m.set(k, { b: Buffer.from(b), meta: (o && o.httpMetadata) || {} }); },
    delete: async k => { [].concat(k).forEach(x => m.delete(x)); },
    list: async ({ prefix }) => ({ objects: [...m.keys()].filter(k => k.startsWith(prefix)).map(key => ({ key })), truncated: false }) };
}
const envWorker = () => ({ PAGINAS: CF.r2, SEGREDO: CF.worker && CF.worker.segredo, ALVO: 'paginas.paginasnoar.com' });
const hostResp = h => ({ id: h.id, hostname: h.hostname, status: h.ativo ? 'active' : 'pending', ssl: { status: h.ativo ? 'active' : 'initializing' },
  ownership_verification: { type: 'txt', name: '_cf-custom-hostname.' + h.hostname, value: 'uuid-' + h.id } });

async function fakeCloudflare(req, res, corpo) {
  const u = new URL(req.url, 'http://x'), ok = (result, s) => { res.statusCode = s || 200; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ success: true, errors: [], result })); };
  const erro = (s, message) => { res.statusCode = s; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ success: false, errors: [{ code: 1, message }], result: null })); };
  if (u.pathname.startsWith('/_tmx-admin/')) {
    const r = await W.default.fetch(new Request('https://paginas.paginasnoar.com' + req.url, { method: req.method, headers: req.headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : corpo }), envWorker());
    res.statusCode = r.status; res.setHeader('Content-Type', 'application/json'); return res.end(await r.text());
  }
  if (req.headers.authorization !== 'Bearer tok-teste') return erro(403, 'token ruim');
  const p = u.pathname.replace('/client/v4', '');
  if (req.method === 'POST' && p === '/accounts/conta1/r2/buckets') { CF.buckets.push(JSON.parse(corpo).name); return ok({}); }
  if (req.method === 'PUT' && p === '/accounts/conta1/workers/scripts/tmx-paginas') {
    const f = await new Response(corpo, { headers: { 'content-type': req.headers['content-type'] } }).formData();
    const meta = JSON.parse(f.get('metadata'));
    CF.worker = { meta, segredo: meta.bindings.find(b => b.name === 'SEGREDO').text, fonte: await f.get('worker.mjs').text() };
    CF.envios++;
    return ok({});
  }
  if (p === '/zones/zona1/workers/routes') {
    if (req.method === 'GET') return ok(CF.rotas);
    CF.rotas.push(JSON.parse(corpo)); return ok({});
  }
  if (p === '/zones/zona1/custom_hostnames') {
    if (req.method === 'GET') return ok([...CF.hostnames.values()].filter(h => h.hostname === u.searchParams.get('hostname')).map(hostResp));
    const b = JSON.parse(corpo), id = 'cfh' + (++CF.n), h = { id, hostname: b.hostname, ativo: false };
    if ([...CF.hostnames.values()].some(x => x.hostname === b.hostname)) return erro(409, 'Duplicate custom hostname found.');
    CF.hostnames.set(id, h); return ok(hostResp(h));
  }
  const m = p.match(/^\/zones\/zona1\/custom_hostnames\/(.+)$/);
  if (m) {
    const h = CF.hostnames.get(m[1]); if (!h) return erro(404, 'não existe');
    if (req.method === 'DELETE') { CF.hostnames.delete(m[1]); return ok({ id: m[1] }); }
    return ok(hostResp(h));
  }
  erro(404, 'rota falsa ' + req.method + ' ' + p);
}
const hostDe = nome => [...CF.hostnames.values()].find(h => h.hostname === nome);
const visitar = (host, cam, cookie) => W.default.fetch(new Request('https://' + host + cam, { headers: cookie ? { Cookie: cookie } : {} }), envWorker());
function subir(env, porta) {
  return spawn(process.execPath, [path.join(RAIZ, 'server.js')], { cwd: RAIZ, stdio: ['ignore', 'pipe', 'pipe'],
    env: Object.assign({ PATH: process.env.PATH, HOME: process.env.HOME, PORT: String(porta) }, env) });
}
async function ate(cond, ms, oQue) {
  const fim = Date.now() + ms;
  for (;;) {
    try { const v = await cond(); if (v) return v; } catch (e) {}
    if (Date.now() > fim) throw new Error('demorou demais: ' + oQue + '\n' + log.slice(-2500));
    await espera(100);
  }
}
async function chamar(metodo, caminho, { token, corpo, cru, tipo } = {}) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (corpo !== undefined) headers['Content-Type'] = 'application/json';
  if (cru) headers['Content-Type'] = tipo;
  const r = await fetch(base + caminho, { method: metodo, headers, redirect: 'manual', body: cru || (corpo !== undefined ? JSON.stringify(corpo) : undefined) });
  let dados = null;
  try { dados = await r.json(); } catch (e) {}
  return { status: r.status, dados, r };
}

before(async () => {
  W = await import('../cloudflare/worker.mjs');
  CF.r2 = r2Falso();
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-hosp-'));
  cf = await new Promise(ok => {
    const s = http.createServer((req, res) => {
      const partes = []; req.on('data', d => partes.push(d));
      req.on('end', () => fakeCloudflare(req, res, Buffer.concat(partes)).catch(e => { res.statusCode = 500; res.end(String(e.stack)); }));
    }).listen(0, '127.0.0.1', () => ok(s));
  });
  const pf = cf.address().port, porta = 49900 + Math.floor(Math.random() * 90);
  base = 'http://127.0.0.1:' + porta;
  srv = subir({ TMX_DATA_DIR: dir, CLOUDFLARE_API_TOKEN: 'tok-teste', CLOUDFLARE_ACCOUNT_ID: 'conta1', CLOUDFLARE_ZONE_ID: 'zona1',
    CLOUDFLARE_API_BASE: 'http://127.0.0.1:' + pf + '/client/v4', HOSPEDAGEM_ADMIN_BASE: 'http://127.0.0.1:' + pf, HOSPEDAGEM_ORIGEM: base }, porta);
  srv.stdout.on('data', b => { log += b; }); srv.stderr.on('data', b => { log += b; });
  await ate(async () => (await fetch(base + '/api/ping')).ok, 20000, 'servidor subir');
});
after(async () => {
  if (srv && srv.exitCode === null) { srv.kill('SIGTERM'); await Promise.race([new Promise(r => srv.once('exit', r)), espera(10000)]); }
  if (cf) cf.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('hospedagem no TMX', async (t) => {
  const c = {};
  const empresa = async (nome, email) => {
    const r = await chamar('POST', '/api/plataforma/empresas', { token: c.tmx, corpo: { nome, usuario: { nome: 'Dono', email, senha: 'senha-forte-12345' } } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    return { id: r.dados.empresa.id, token: (await chamar('POST', '/api/auth/login', { corpo: { email, senha: 'senha-forte-12345' } })).dados.token };
  };
  const cadastrar = (tok, dominio) => chamar('POST', '/api/pg/dominios/hospedado', { token: tok, corpo: { dominio } });

  await t.test('ao ligar, instala o armazenamento, o programa e a rota uma vez', async () => {
    await ate(() => CF.rotas.length > 1, 8000, 'instalar');
    assert.deepStrictEqual(CF.buckets, ['tmx-paginas']);
    assert.deepStrictEqual(CF.rotas, [{ pattern: '*/*', script: 'tmx-paginas' }, { pattern: 'paginas.paginasnoar.com/*', script: 'tmx-paginas' }]);
    assert.strictEqual(CF.envios, 1);
    assert.deepStrictEqual(CF.worker.meta.bindings.map(b => b.type).sort(), ['plain_text', 'plain_text', 'r2_bucket', 'secret_text']);
    assert.strictEqual(CF.worker.meta.bindings.find(b => b.name === 'ORIGEM').text, base, 'o programa sabe pra onde repassar o link da Meta');
    assert.ok(!JSON.stringify(CF.worker.meta).includes('tok-teste'), 'a chave de API não vai pro programa');
    c.tmx = (await chamar('POST', '/api/auth/login', { corpo: { email: 'thiago@axcend.com', senha: 'axcend2026' } })).dados.token;
    c.a = await empresa('Loja A', 'dono@a.com'); c.b = await empresa('Loja B', 'dono@b.com');
    const e = await chamar('GET', '/api/pg/estado', { token: c.a.token });
    assert.strictEqual(e.dados.hospedagem.ligada, true);
    assert.strictEqual(e.dados.hospedagem.alvo, 'paginas.paginasnoar.com');
  });

  await t.test('cadastra o subdomínio e mostra o registro; domínio raiz pede a prova', async () => {
    const r = await cadastrar(c.a.token, 'https://LP.loja-a.com.br/');
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    c.dom = r.dados.dominio;
    assert.strictEqual(c.dom.dominio, 'lp.loja-a.com.br');
    assert.strictEqual(c.dom.modo, 'tmx');
    assert.strictEqual(c.dom.est, 'dns');
    assert.strictEqual(c.dom.raiz, false);
    assert.strictEqual(c.dom.nome_dns, 'lp');
    assert.ok(hostDe('lp.loja-a.com.br'));
    const raiz = await cadastrar(c.a.token, 'loja-a.com.br');
    assert.strictEqual(raiz.dados.dominio.raiz, true);
    assert.strictEqual(raiz.dados.dominio.nome_dns, '@');
    assert.strictEqual(raiz.dados.dominio.txt_nome, '_cf-custom-hostname.loja-a.com.br');
    c.raiz = raiz.dados.dominio;
  });

  await t.test('um domínio é de uma empresa só e os do sistema não entram', async () => {
    const r = await cadastrar(c.b.token, 'lp.loja-a.com.br');
    assert.strictEqual(r.status, 400);
    assert.match(r.dados.error, /outra conta/);
    for (const d of ['x.paginasnoar.com', 'app.centraltmx.com', 'ir.kalebeaprovado.online', 'nao-e-dominio']) assert.strictEqual((await cadastrar(c.b.token, d)).status, 400, d);
    assert.strictEqual((await cadastrar(c.a.token, 'lp.loja-a.com.br')).status, 409);
    const est = await chamar('GET', '/api/pg/estado', { token: c.b.token });
    assert.strictEqual(est.dados.dominios.length, 0);
  });

  await t.test('só publica depois do DNS', async () => {
    const criar = (slug, titulo) => chamar('POST', '/api/pg/paginas', { token: c.a.token, corpo: { branco: true, slug, titulo, dominio_id: c.dom.id } });
    const p1 = await criar('oferta-a', 'Oferta A'), p2 = await criar('oferta-b', 'Oferta B');
    assert.strictEqual(p1.status, 200, JSON.stringify(p1.dados));
    c.p1 = p1.dados.id; c.p2 = p2.dados.id;
    const pub = await chamar('POST', '/api/pg/paginas/' + c.p1 + '/publicar', { token: c.a.token, corpo: {} });
    assert.strictEqual(pub.status, 409, JSON.stringify(pub.dados));
    assert.strictEqual(pub.dados.codigo, 'dns');
  });

  await t.test('quando o DNS aparece, o domínio fica no ar e a página abre nele', async () => {
    hostDe('lp.loja-a.com.br').ativo = true;
    const v = await chamar('POST', '/api/pg/dominios/' + c.dom.id + '/verificar', { token: c.a.token });
    assert.strictEqual(v.dados.dominio.est, 'ok', JSON.stringify(v.dados));
    const cfg = JSON.parse(CF.r2.m.get('lp.loja-a.com.br/_tmx.json').b.toString());
    assert.strictEqual(cfg.base, '/e/' + c.a.id);
    assert.strictEqual(cfg.origem, base);
    for (const id of [c.p1, c.p2]) {
      const pub = await chamar('POST', '/api/pg/paginas/' + id + '/publicar', { token: c.a.token, corpo: {} });
      assert.strictEqual(pub.status, 200, JSON.stringify(pub.dados));
      assert.strictEqual(pub.dados.url.replace(/\/$/, '').split('/').slice(0, 3).join('/'), 'https://lp.loja-a.com.br');
    }
    W.limparCache();
    const r = await visitar('lp.loja-a.com.br', '/oferta-a');
    assert.strictEqual(r.status, 200);
    assert.match(await r.text(), /<title>Oferta A<\/title>/);
    assert.strictEqual((await visitar('lp.loja-a.com.br', '/_tmx.json')).status, 404);
    const est = await chamar('GET', '/api/pg/estado', { token: c.a.token });
    assert.strictEqual(est.dados.paginas.find(p => p.id === c.p1).publicada, 1);
  });

  await t.test('scripts globais e ícone', async () => {
    const s = await chamar('POST', '/api/pg/dominios/' + c.dom.id + '/scripts', { token: c.a.token, corpo: { head: '<!--GTM-A-->', corpo: '' } });
    assert.strictEqual(s.status, 200, JSON.stringify(s.dados));
    W.limparCache();
    assert.match(await (await visitar('lp.loja-a.com.br', '/oferta-a')).text(), /<!--GTM-A-->/);
    assert.strictEqual((await chamar('POST', '/api/pg/dominios/' + c.dom.id + '/icone', { token: c.a.token, cru: Buffer.from('x'), tipo: 'text/plain' })).status, 400);
    const i = await chamar('POST', '/api/pg/dominios/' + c.dom.id + '/icone', { token: c.a.token, cru: Buffer.from('png'), tipo: 'image/png' });
    assert.strictEqual(i.status, 200, JSON.stringify(i.dados));
    W.limparCache();
    assert.strictEqual((await visitar('lp.loja-a.com.br', '/favicon.ico')).status, 200);
  });

  await t.test('teste A/B no próprio domínio: o sorteio, a contagem e a vencedora', async () => {
    const teste = { id: 'r1', nome: 'Oferta A × B', slug: 'oferta-ab', projeto: '', ativo: true, meta: '', _updatedAt: Date.now(), hospedado: { dominio: c.dom.id, caminho: 'oferta' },
      destinos: [{ id: 'v1', nome: 'Versão A', url: 'https://lp.loja-a.com.br/oferta-a/', peso: 1 }, { id: 'v2', nome: 'Versão B', url: 'https://lp.loja-a.com.br/oferta-b/', peso: 1 }] };
    const put = await chamar('PUT', '/api/store/sl_redirecionadores', { token: c.a.token, corpo: [teste] });
    assert.strictEqual(put.status, 200, JSON.stringify(put.dados));
    await ate(() => JSON.parse(CF.r2.m.get('lp.loja-a.com.br/_tmx.json').b.toString()).testes.oferta, 6000, 'teste chegar na Cloudflare');
    W.limparCache();
    const r = await visitar('lp.loja-a.com.br', '/oferta');
    assert.strictEqual(r.status, 200);
    const h = await r.text(), ab = JSON.parse(h.match(/window\.TMX_AB=(\{.*?\})<\/script>/)[1]);
    assert.strictEqual(ab.t, 'oferta-ab');
    assert.match(r.headers.get('Set-Cookie'), /^tmx_ab_oferta-ab=v[12];/);
    assert.ok(/oferta-[ab]\/$/.test(ab.p));

    // o pixel avisa o servidor na primeira visita
    const evento = { id: 'visitante-teste-01', funil: 'f1', etapa: 'vsl', tipo: 'entrou', utm: {}, pg: ab.p, teste: ab.t, variante: ab.v, abn: 1, sid: 's1' };
    const ev = await fetch(base + '/e/' + c.a.id + '/api/funil/evento', { method: 'POST', body: JSON.stringify(evento) });
    assert.ok(ev.status < 300, 'evento: ' + ev.status);
    const est = await ate(async () => {
      const s = await chamar('GET', '/api/ab/stats?teste=oferta-ab', { token: c.a.token });
      const v = (s.dados.variantes || []).find(x => x.id === ab.v);
      return v && v.sorteios === 1 && v.pessoas === 1 ? v : null;
    }, 4000, 'contar o sorteio e a pessoa');
    assert.strictEqual(est.pessoas, 1);

    // a regra de declarar (95% e o mínimo de vendas) continua na rota; aqui o que importa é a vencedora chegar lá
    const venc = await chamar('PUT', '/api/store/sl_redirecionadores', { token: c.a.token, corpo: [Object.assign({}, teste, { vencedora: 'v2', _updatedAt: Date.now() + 1000 })] });
    assert.strictEqual(venc.status, 200, JSON.stringify(venc.dados));
    await ate(() => JSON.parse(CF.r2.m.get('lp.loja-a.com.br/_tmx.json').b.toString()).testes.oferta.vencedora === 'v2', 6000, 'vencedora chegar na Cloudflare');
    W.limparCache();
    assert.match(await (await visitar('lp.loja-a.com.br', '/oferta', 'tmx_ab_oferta-ab=v1')).text(), /<title>Oferta B<\/title>/);
    const lista = await chamar('GET', '/api/pg/estado', { token: c.a.token });
    assert.deepStrictEqual(lista.dados.testes.map(x => [x.slug, x.caminho, x.vencedora]), [['oferta-ab', 'oferta', 'v2']]);
  });

  await t.test('o link curto do teste passa pelo domínio do cliente até a empresa certa', async () => {
    W.limparCache();
    const r = await visitar('lp.loja-a.com.br', '/r/oferta-ab');
    assert.strictEqual(r.status, 302);
    assert.match(r.headers.get('location'), /^https:\/\/lp\.loja-a\.com\.br\/oferta-b\//);
  });

  await t.test('o pixel lê a versão entregue na página', async () => {
    const js = await (await fetch(base + '/px.js')).text();
    assert.match(js, /AB_ENTREGA = w\.TMX_AB/);
  });

  await t.test('entra na lista de domínios de links e quiz quando está no ar', async () => {
    const l = await chamar('GET', '/api/dominios', { token: c.a.token });
    const d = l.dados.dominios.find(x => x.dominio === 'lp.loja-a.com.br');
    assert.ok(d && d.ok && d.hospedado, JSON.stringify(l.dados));
    assert.ok(!l.dados.dominios.some(x => x.dominio === 'loja-a.com.br'), 'o que espera DNS ainda não aparece');
  });

  await t.test('só a Diretoria cadastra', async () => {
    const us = (await chamar('GET', '/api/store', { token: c.a.token })).dados.sl_usuarios;
    us.push({ id: 'u-copy-a', nome: 'Copy A', email: 'copy@a.com', senha: 'senha-copy-a-123', cargo: 'Copy', ativo: true, _updatedAt: Date.now() });
    assert.strictEqual((await chamar('PUT', '/api/store/sl_usuarios', { token: c.a.token, corpo: us })).status, 200);
    const tok = (await chamar('POST', '/api/auth/login', { corpo: { email: 'copy@a.com', senha: 'senha-copy-a-123' } })).dados.token;
    assert.strictEqual((await cadastrar(tok, 'x.loja-a.com.br')).status, 403);
  });

  await t.test('remover tira da Cloudflare, volta as páginas pra rascunho e encerra os testes', async () => {
    const r = await chamar('POST', '/api/pg/dominios/' + c.dom.id + '/excluir', { token: c.a.token });
    assert.strictEqual(r.status, 200, JSON.stringify(r.dados));
    assert.ok(!hostDe('lp.loja-a.com.br'));
    assert.deepStrictEqual([...CF.r2.m.keys()].filter(k => k.startsWith('lp.loja-a.com.br/')), []);
    const est = await chamar('GET', '/api/pg/estado', { token: c.a.token });
    const p = est.dados.paginas.find(x => x.id === c.p1);
    assert.strictEqual(p.dominio_id, null);
    assert.strictEqual(p.publicada, null);
    const t1 = (await chamar('GET', '/api/store', { token: c.a.token })).dados.sl_redirecionadores[0];
    assert.strictEqual(t1.hospedado, undefined);
    assert.strictEqual(t1.ativo, false);
    // liberado: outra empresa já pode cadastrar
    assert.strictEqual((await cadastrar(c.b.token, 'lp.loja-a.com.br')).status, 200);
  });
});

test('sem as chaves da Cloudflare, a opção não liga e o FTP segue', async () => {
  const d2 = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'tmx-hosp2-'));
  const porta = 49800 + Math.floor(Math.random() * 90), b2 = 'http://127.0.0.1:' + porta;
  const s2 = subir({ TMX_DATA_DIR: d2 }, porta);
  try {
    await ate(async () => (await fetch(b2 + '/api/ping')).ok, 20000, 'servidor sem chave');
    const tok = (await (await fetch(b2 + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'thiago@axcend.com', senha: 'axcend2026' }) })).json()).token;
    const cab = { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' };
    const e = await (await fetch(b2 + '/api/pg/estado', { headers: cab })).json();
    assert.strictEqual(e.hospedagem.ligada, false);
    const r = await fetch(b2 + '/api/pg/dominios/hospedado', { method: 'POST', headers: cab, body: JSON.stringify({ dominio: 'lp.loja.com' }) });
    assert.strictEqual(r.status, 400);
    assert.match((await r.json()).error, /ainda não está ligada/);
  } finally {
    s2.kill('SIGTERM'); await Promise.race([new Promise(r => s2.once('exit', r)), espera(8000)]);
    fs.rmSync(d2, { recursive: true, force: true });
  }
});
