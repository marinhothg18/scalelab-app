// O programa que entrega as páginas na Cloudflare (cloudflare/worker.mjs), rodando com um armazenamento de mentira.
const { test, before, beforeEach } = require('node:test');
const assert = require('node:assert');

let W;
function r2Falso() {
  const m = new Map();
  const obj = v => ({ httpMetadata: v.meta, body: new Blob([v.b]).stream(), text: async () => Buffer.from(v.b).toString('utf8') });
  return { m,
    get: async k => (m.has(k) ? obj(m.get(k)) : null),
    put: async (k, b, o) => { m.set(k, { b: Buffer.from(b), meta: (o && o.httpMetadata) || {} }); },
    delete: async k => { [].concat(k).forEach(x => m.delete(x)); },
    list: async ({ prefix }) => ({ objects: [...m.keys()].filter(k => k.startsWith(prefix)).map(key => ({ key })), truncated: false }) };
}
const HOST = 'lp.loja.com.br', SEGREDO = 'x'.repeat(64);
let env;
const pagina = (nome, extra) => '<!doctype html><html><head><title>' + nome + '</title></head><body><img src="arquivos/a.png">' + (extra || '') + '</body></html>';
async function pr(env, k, txt, tipo) { await env.PAGINAS.put(k, Buffer.from(txt), { httpMetadata: { contentType: tipo || 'text/html; charset=utf-8' } }); }
const abrir = (caminho, cookie) => W.default.fetch(new Request('https://' + HOST + caminho, { headers: cookie ? { Cookie: cookie } : {} }), env);
const tmxAb = html => JSON.parse(html.match(/window\.TMX_AB=(\{.*?\})<\/script>/)[1]);
function config(mais) { return JSON.stringify(Object.assign({ origem: 'https://origem.test', base: '/e/abc', testes: {}, head: '', corpo: '', icone: false }, mais)); }

before(async () => { W = await import('../cloudflare/worker.mjs'); });
beforeEach(async () => {
  W.limparCache();
  env = { PAGINAS: r2Falso(), SEGREDO, ALVO: 'paginas.paginasnoar.com' };
  await pr(env, HOST + '/_tmx.json', config(), 'application/json');
  await pr(env, HOST + '/a/index.html', pagina('A'));
  await pr(env, HOST + '/b/index.html', pagina('B'));
});

test('entrega a página com e sem a barra, sem redirecionar, e acerta os arquivos', async () => {
  for (const c of ['/a', '/a/']) {
    const r = await abrir(c), h = await r.text();
    assert.strictEqual(r.status, 200, c);
    assert.match(h, /<title>A<\/title>/);
    assert.match(h, /src="\/a\/arquivos\/a\.png"/);
  }
  await env.PAGINAS.put(HOST + '/a/arquivos/a.png', Buffer.from('png'), { httpMetadata: { contentType: 'image/png', cacheControl: 'public, max-age=31536000, immutable' } });
  const f = await abrir('/a/arquivos/a.png');
  assert.strictEqual(f.status, 200);
  assert.strictEqual(f.headers.get('Content-Type'), 'image/png');
  assert.match(f.headers.get('Cache-Control'), /immutable/);
});

test('domínio sem cadastro, página que não existe e a configuração não abrem', async () => {
  assert.strictEqual((await abrir('/nao-existe')).status, 404);
  assert.strictEqual((await abrir('/')).status, 404);
  assert.strictEqual((await abrir('/_tmx.json')).status, 404);
  assert.strictEqual((await abrir('/a/../_tmx.json')).status, 404);
  assert.strictEqual((await abrir('/%5Ftmx.json')).status, 404);
  const r = await W.default.fetch(new Request('https://outro.com/a'), env);
  assert.strictEqual(r.status, 404);
});

test('scripts globais e ícone entram em todas as páginas', async () => {
  await pr(env, HOST + '/_tmx.json', config({ head: '<!--GTM-->', corpo: '<!--FIM-->', icone: true }), 'application/json');
  W.limparCache();
  const h = await (await abrir('/a')).text();
  assert.match(h, /<head><link rel="icon" href="\/favicon\.ico"><!--GTM-->/);
  assert.match(h, /<!--FIM--><\/body>/);
  await env.PAGINAS.put(HOST + '/_icone', Buffer.from('ic'), { httpMetadata: { contentType: 'image/png' } });
  const i = await abrir('/favicon.ico');
  assert.strictEqual(i.status, 200);
  assert.strictEqual(i.headers.get('Content-Type'), 'image/png');
});

test('teste A/B no mesmo endereço: sorteia, guarda e não redireciona', async () => {
  const t = { id: 'oferta-ab', ativo: true, vencedora: null, variantes: [{ id: 'v1', pagina: 'a', peso: 1 }, { id: 'v2', pagina: 'b', peso: 1 }] };
  await pr(env, HOST + '/_tmx.json', config({ testes: { oferta: t } }), 'application/json');
  W.limparCache();
  const r = await abrir('/oferta');
  assert.strictEqual(r.status, 200);
  const c = r.headers.get('Set-Cookie');
  assert.match(c, /^tmx_ab_oferta-ab=v[12];Path=\/;Max-Age=7776000/);
  const h = await r.text(), ab = tmxAb(h);
  assert.strictEqual(ab.t, 'oferta-ab');
  assert.strictEqual(ab.n, 1);
  const pag = ab.v === 'v1' ? 'a' : 'b';
  assert.strictEqual(ab.p, HOST + '/' + pag + '/');
  assert.ok(h.includes('src="/' + pag + '/arquivos/a.png"'), 'os arquivos saem da pasta da versão');

  const b = 'tmx_ab_oferta-ab=' + ab.v;
  for (let i = 0; i < 12; i++) {
    const de = await abrir('/oferta', b);
    assert.strictEqual(de.headers.get('Set-Cookie'), null);
    const x = tmxAb(await de.text());
    assert.strictEqual(x.v, ab.v, 'quem volta vê a mesma');
    assert.strictEqual(x.n, 0, 'quem volta não conta sorteio de novo');
  }
  // versão que saiu do teste: sorteia de novo
  const sumiu = await abrir('/oferta', 'tmx_ab_oferta-ab=v9');
  assert.ok(sumiu.headers.get('Set-Cookie'));
});

test('a divisão respeita o peso', () => {
  const vars = [{ id: 'a', peso: 70 }, { id: 'b', peso: 30 }];
  let a = 0;
  for (let i = 0; i < 1000; i++) if (W.sortear(vars, i / 1000).id === 'a') a++;
  assert.strictEqual(a, 700);
  assert.strictEqual(W.sortear([{ id: 'x', peso: 0 }, { id: 'y', peso: 0 }], 0.5).id, 'x');
});

test('com vencedora, todo mundo vê ela; pausado, todo mundo vê a original sem entrar na conta', async () => {
  const t = { id: 'o', ativo: true, vencedora: 'v2', variantes: [{ id: 'v1', pagina: 'a', peso: 1 }, { id: 'v2', pagina: 'b', peso: 1 }] };
  await pr(env, HOST + '/_tmx.json', config({ testes: { oferta: t } }), 'application/json');
  W.limparCache();
  let h = await (await abrir('/oferta', 'tmx_ab_o=v1')).text();
  assert.match(h, /<title>B<\/title>/);
  assert.strictEqual(tmxAb(h).v, 'v2');
  t.vencedora = null; t.ativo = false;
  await pr(env, HOST + '/_tmx.json', config({ testes: { oferta: t } }), 'application/json');
  W.limparCache();
  h = await (await abrir('/oferta')).text();
  assert.match(h, /<title>A<\/title>/);
  assert.ok(!h.includes('TMX_AB'));
});

test('o link da Meta para multilogin passa pela Cloudflare, só no endereço do sistema', async () => {
  const antes = global.fetch, pedidos = [];
  global.fetch = async (u, o) => { pedidos.push({ u, o }); return new Response('ok', { status: 200 }); };
  const noAlvo = (c, m) => W.default.fetch(new Request('https://paginas.paginasnoar.com' + c, { method: m || 'GET', headers: { 'CF-Connecting-IP': '9.9.9.9' } }), Object.assign({}, env, { ORIGEM: 'https://app.centraltmx.com' }));
  try {
    await noAlvo('/conectar-meta/ml_abc-1');
    await noAlvo('/api/meta/login/link/ml_abc-1', 'POST');
    assert.deepStrictEqual(pedidos.map(p => [p.u, p.o.method]), [['https://app.centraltmx.com/conectar-meta/ml_abc-1', 'GET'], ['https://app.centraltmx.com/api/meta/login/link/ml_abc-1', 'POST']]);
    assert.strictEqual(pedidos[0].o.headers.get('X-Forwarded-For'), '9.9.9.9');
    pedidos.length = 0;
    assert.strictEqual((await noAlvo('/api/store')).status, 404);
    assert.strictEqual((await noAlvo('/api/meta/login/link', 'POST')).status, 404, 'gerar link continua só no painel');
    assert.strictEqual((await W.default.fetch(new Request('https://' + HOST + '/conectar-meta/ml_abc'), Object.assign({}, env, { ORIGEM: 'https://app.centraltmx.com' }))).status, 404, 'domínio de cliente não abre o link');
    assert.strictEqual(pedidos.length, 0);
  } finally { global.fetch = antes; }
});

test('links, quiz e pixel passam pro servidor, com o prefixo da empresa', async () => {
  const antes = global.fetch, pedidos = [];
  global.fetch = async (u, o) => { pedidos.push({ u, o }); return new Response('ok', { status: 200 }); };
  try {
    await abrir('/r/oferta?utm_source=x');
    await abrir('/q/quiz1');
    await abrir('/e/abc/api/quiz/evento');
    await abrir('/px.js');
    assert.deepStrictEqual(pedidos.map(p => p.u), ['https://origem.test/e/abc/r/oferta?utm_source=x', 'https://origem.test/e/abc/q/quiz1',
      'https://origem.test/e/abc/api/quiz/evento', 'https://origem.test/e/abc/px.js']);
    assert.strictEqual(pedidos[0].o.headers.get('X-TMX-Dominio'), HOST);
    assert.strictEqual(pedidos[0].o.redirect, 'manual');
    pedidos.length = 0;
    await abrir('/api/store');
    await abrir('/e/abc/api/store');
    assert.strictEqual(pedidos.length, 0, 'o resto do sistema não abre pelo domínio do cliente');
  } finally { global.fetch = antes; }
});

test('gravar exige o segredo e o endereço do sistema', async () => {
  const adm = (h, cam, o) => W.default.fetch(new Request('https://' + h + '/_tmx-admin/' + cam, o), env);
  const cab = { Authorization: 'Bearer ' + SEGREDO };
  assert.strictEqual((await adm(env.ALVO, 'ping', {})).status, 403);
  assert.strictEqual((await adm(env.ALVO, 'ping', { headers: { Authorization: 'Bearer ' + 'y'.repeat(64) } })).status, 403);
  assert.strictEqual((await adm(HOST, 'ping', { headers: cab })).status, 404, 'no domínio do cliente nem existe');
  assert.strictEqual((await adm(env.ALVO, 'ping', { headers: cab })).status, 200);
  const k = encodeURIComponent(HOST + '/c/index.html');
  const put = await adm(env.ALVO, 'objeto?k=' + k, { method: 'PUT', headers: Object.assign({ 'Content-Type': 'text/html' }, cab), body: 'oi' });
  assert.strictEqual(put.status, 200);
  assert.ok(env.PAGINAS.m.has(HOST + '/c/index.html'));
  assert.strictEqual((await adm(env.ALVO, 'objeto?k=' + encodeURIComponent('a/../b'), { method: 'PUT', headers: cab, body: 'x' })).status, 400);
  // apagar precisa de uma pasta de domínio: nunca o armazenamento inteiro
  assert.strictEqual((await adm(env.ALVO, 'pasta?p=', { method: 'DELETE', headers: cab })).status, 400);
  assert.strictEqual((await adm(env.ALVO, 'pasta?p=' + encodeURIComponent('/'), { method: 'DELETE', headers: cab })).status, 400);
  const del = await adm(env.ALVO, 'pasta?p=' + encodeURIComponent(HOST + '/'), { method: 'DELETE', headers: cab });
  assert.strictEqual(del.status, 200);
  assert.strictEqual(env.PAGINAS.m.size, 0);
});
