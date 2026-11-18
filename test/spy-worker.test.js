// Spy de anúncios (18/11/2026): os vídeos ficam no R2 da hospedagem, na pasta spy-midia/. O programa da Cloudflare
// (cloudflare/worker.mjs) entrega esses vídeos só pro servidor (com o segredo), em pedaços, e nunca pela página pública.
const { test, before } = require('node:test');
const assert = require('node:assert');

let W, env;
const SEGREDO = 's'.repeat(64);
function r2Falso() {
  const m = new Map();
  return { m,
    head: async k => (m.has(k) ? { size: m.get(k).b.length, httpMetadata: m.get(k).meta } : null),
    get: async (k, o) => {
      if (!m.has(k)) return null;
      const v = m.get(k), r = o && o.range;
      const b = r ? v.b.subarray(r.offset, r.offset + r.length) : v.b;
      return { size: v.b.length, httpMetadata: v.meta, body: new Blob([b]).stream(), text: async () => b.toString('utf8') };
    },
    put: async (k, b, o) => { m.set(k, { b: Buffer.from(b), meta: (o && o.httpMetadata) || {} }); },
    delete: async k => { [].concat(k).forEach(x => m.delete(x)); },
    list: async () => ({ objects: [], truncated: false }) };
}
const admin = (metodo, k, cab, corpo) => W.default.fetch(new Request('https://paginas.paginasnoar.com/_tmx-admin/objeto?k=' + encodeURIComponent(k), { method: metodo, headers: Object.assign({ Authorization: 'Bearer ' + SEGREDO }, cab || {}), body: corpo }), env);

before(async () => { W = await import('../cloudflare/worker.mjs'); env = { PAGINAS: r2Falso(), SEGREDO, ALVO: 'paginas.paginasnoar.com' }; });

test('o servidor guarda o vídeo e lê inteiro, em pedaços e só o tamanho', async () => {
  const video = Buffer.from(Array.from({ length: 1000 }, (_, i) => i % 256));
  assert.strictEqual((await admin('PUT', 'spy-midia/v/abc.mp4', { 'Content-Type': 'video/mp4' }, video)).status, 200);
  const r = await admin('GET', 'spy-midia/v/abc.mp4');
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.headers.get('X-TMX-Tamanho'), '1000');
  assert.deepStrictEqual(Buffer.from(await r.arrayBuffer()), video);
  const p = await admin('GET', 'spy-midia/v/abc.mp4', { Range: 'bytes=10-19' });
  assert.strictEqual(p.status, 206);
  assert.strictEqual(p.headers.get('Content-Range'), 'bytes 10-19/1000');
  assert.deepStrictEqual(Buffer.from(await p.arrayBuffer()), video.subarray(10, 20));
  const fim = await admin('GET', 'spy-midia/v/abc.mp4', { Range: 'bytes=990-' });
  assert.strictEqual(fim.headers.get('Content-Range'), 'bytes 990-999/1000');
  assert.strictEqual((await admin('GET', 'spy-midia/v/abc.mp4', { Range: 'bytes=5000-' })).status, 416);
  const h = await admin('HEAD', 'spy-midia/v/abc.mp4');
  assert.strictEqual(h.status, 200);
  assert.strictEqual((await admin('HEAD', 'spy-midia/v/nao.mp4')).status, 404);
});

test('sem o segredo não lê; fora da pasta do Spy não lê; a página pública não chega lá', async () => {
  await env.PAGINAS.put('spy-midia/v/x.mp4', Buffer.from('video'), { httpMetadata: { contentType: 'video/mp4' } });
  await env.PAGINAS.put('lp.loja.com.br/_tmx.json', Buffer.from('{"origem":"https://x"}'), { httpMetadata: { contentType: 'application/json' } });
  const semSegredo = await W.default.fetch(new Request('https://paginas.paginasnoar.com/_tmx-admin/objeto?k=spy-midia%2Fv%2Fx.mp4'), env);
  assert.strictEqual(semSegredo.status, 403);
  const config = await admin('GET', 'lp.loja.com.br/_tmx.json');
  assert.notStrictEqual(config.status, 200, 'a leitura é só da pasta do Spy');
  const publica = await W.default.fetch(new Request('https://lp.loja.com.br/spy-midia/v/x.mp4'), env);
  assert.notStrictEqual(await publica.text(), 'video');
});
