// Entrega as páginas hospedadas no TMX. Roda na Cloudflare, na rota */* da zona do sistema, e atende
// todo domínio de cliente que aponta pra cá (Cloudflare for SaaS). O TMX não fica no caminho da visita:
// se o servidor reiniciar ou cair, a página do anúncio continua no ar.
//
// No armazenamento (R2) cada domínio é uma pasta:
//   <domínio>/_tmx.json                 configuração: testes A/B, scripts globais, ícone
//   <domínio>/<página>/index.html       a página
//   <domínio>/<página>/arquivos/<hash>  imagens, CSS e scripts dela
//
// Quem instala este arquivo é o próprio servidor, ao ligar (hospedagem.js). Não editar pelo painel.

const TTL_CFG = 30000;   // quanto tempo uma mudança de teste A/B ou de script leva pra valer
const ROTAS_DO_SISTEMA = /^\/(?:r|l|q|qi)\/|^\/px\.js$|^\/api\/funil\/(?:evento|vivo)$|^\/api\/quiz\/evento$/;
// Link da Meta para multilogin: proxy que não alcança o servidor costuma alcançar a Cloudflare. Só no endereço do sistema.
const ROTAS_LINK_META = /^\/conectar-meta\/[\w-]+$|^\/api\/meta\/login\/link\/[\w-]+$/;
const CHAVE_VALIDA = /^[a-z0-9.-]+\/[A-Za-z0-9._\/-]+$/;
const PASTA_VALIDA = /^[a-z0-9-]+(\.[a-z0-9-]+)+\/([A-Za-z0-9._-]+\/)*$/;

const _cfg = new Map();
export function limparCache() { _cfg.clear(); }

async function lerCfg(env, host) {
  const c = _cfg.get(host);
  if (c && Date.now() - c.em < TTL_CFG) return c.v;
  const o = await env.PAGINAS.get(host + '/_tmx.json');
  let v = null;
  if (o) { try { v = JSON.parse(await o.text()); } catch (e) { v = null; } }
  if (_cfg.size > 3000) _cfg.clear();
  _cfg.set(host, { v, em: Date.now() });
  return v;
}

const seguranca = h => { h.set('X-Content-Type-Options', 'nosniff'); return h; };
function naoAchei() {
  return new Response('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Página não encontrada</title>' +
    '<body style="font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0;color:#334155"><p>Página não encontrada.</p></body></html>',
    { status: 404, headers: seguranca(new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })) });
}
function lerBiscoito(req, nome) {
  for (const parte of String(req.headers.get('Cookie') || '').split(';')) {
    const i = parte.indexOf('=');
    if (i > 0 && parte.slice(0, i).trim() === nome) { try { return decodeURIComponent(parte.slice(i + 1).trim()); } catch (e) { return ''; } }
  }
  return '';
}

// Quem entra por /oferta (teste A/B ou endereço sem a barra) não está na pasta da página: "arquivos/x" viraria /arquivos/x
function absolutizar(html, pagina) {
  return html.replace(/(["'(])(?:\.\/)?arquivos\//g, (m, antes) => antes + '/' + pagina + '/arquivos/');
}
// O endereço antigo do sistema sai do HTML na hora de servir (11/11/2026): as páginas publicadas antes da
// troca chamam o pixel, os links e o quiz pelo endereço novo sem precisar publicar de novo.
const ENDERECO_ANTIGO = /https:\/\/app\.centraltmx\.com(?=[\/"'?#\s]|$)/g;
export function injetar(html, cfg, ab) {
  let h = cfg.origem && !/centraltmx/.test(cfg.origem) ? html.replace(ENDERECO_ANTIGO, cfg.origem) : html;
  const cabeca = (ab ? '<script>window.TMX_AB=' + JSON.stringify(ab).replace(/</g, '\\u003c') + '</script>' : '') +
    (cfg.icone ? '<link rel="icon" href="/favicon.ico">' : '') + (cfg.head || '');
  if (cabeca) h = /<head\b[^>]*>/i.test(h) ? h.replace(/<head\b[^>]*>/i, m => m + cabeca) : cabeca + h;
  if (cfg.corpo) {
    const fim = h.toLowerCase().lastIndexOf('</body>');
    h = fim >= 0 ? h.slice(0, fim) + cfg.corpo + h.slice(fim) : h + cfg.corpo;
  }
  return h;
}

export function sortear(variantes, r = Math.random()) {
  const total = variantes.reduce((s, v) => s + (Number(v.peso) || 0), 0);
  if (total <= 0) return variantes[0];
  let x = r * total;
  for (const v of variantes) { x -= Number(v.peso) || 0; if (x < 0) return v; }
  return variantes[variantes.length - 1];
}

function respostaHtml(req, html, extra) {
  const h = seguranca(new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }));
  if (extra) for (const k of Object.keys(extra)) h.set(k, extra[k]);
  return new Response(req.method === 'HEAD' ? null : html, { status: 200, headers: h });
}

async function servirTeste(req, env, host, cfg, t) {
  const vars = Array.isArray(t.variantes) ? t.variantes.filter(v => v && v.pagina) : [];
  if (!vars.length) return naoAchei();
  const biscoito = 'tmx_ab_' + String(t.id).replace(/[^a-zA-Z0-9_-]/g, '');
  let v = null, novo = false, conta = true;
  if (t.vencedora) v = vars.find(x => x.id === t.vencedora) || vars[0];
  else if (t.ativo === false) { v = vars[0]; conta = false; }   // pausado: todo mundo vê a original e ninguém entra na conta
  else {
    const ja = lerBiscoito(req, biscoito);
    v = ja ? vars.find(x => x.id === ja) : null;
    if (!v) { v = sortear(vars); novo = true; }
  }
  const o = await env.PAGINAS.get(host + '/' + v.pagina + '/index.html');
  if (!o) return naoAchei();
  const ab = conta ? { t: t.id, v: v.id, p: (host + '/' + v.pagina + '/').toLowerCase(), n: novo ? 1 : 0 } : null;
  const html = injetar(absolutizar(await o.text(), v.pagina), cfg, ab);
  return respostaHtml(req, html, novo ? { 'Set-Cookie': biscoito + '=' + encodeURIComponent(v.id) + ';Path=/;Max-Age=7776000;SameSite=Lax;Secure' } : null);
}

async function servirArquivo(req, env, host, cfg, caminho) {
  if (caminho === '/favicon.ico') {
    const i = cfg.icone ? await env.PAGINAS.get(host + '/_icone') : null;
    if (!i) return naoAchei();
    return new Response(req.method === 'HEAD' ? null : i.body, { headers: seguranca(new Headers({
      'Content-Type': (i.httpMetadata && i.httpMetadata.contentType) || 'image/png', 'Cache-Control': 'public, max-age=3600' })) });
  }
  const pasta = !/\.[a-zA-Z0-9]{1,8}$/.test(caminho);
  const limpo = caminho.replace(/\/+$/, '');
  if (pasta) {
    if (!limpo) return naoAchei();
    const o = await env.PAGINAS.get(host + limpo + '/index.html');
    if (!o) return naoAchei();
    return respostaHtml(req, injetar(absolutizar(await o.text(), limpo.slice(1)), cfg, null));
  }
  const o = await env.PAGINAS.get(host + caminho);
  if (!o) return naoAchei();
  const meta = o.httpMetadata || {};
  const h = seguranca(new Headers({ 'Content-Type': meta.contentType || 'application/octet-stream' }));
  h.set('Cache-Control', meta.cacheControl || 'public, max-age=3600');
  return new Response(req.method === 'HEAD' ? null : o.body, { headers: h });
}

// Links curtos, teste por link, quiz e pixel continuam no servidor: aqui só passam adiante, no domínio do cliente
async function repassar(req, url, cfg, caminho) {
  const h = new Headers(req.headers);
  h.delete('Host');
  h.set('X-TMX-Dominio', url.hostname);
  const ip = req.headers.get('CF-Connecting-IP');
  if (ip) h.set('X-Forwarded-For', ip);
  return fetch(cfg.origem + (cfg.base || '') + caminho + url.search, {
    method: req.method, headers: h, redirect: 'manual',
    body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req.body
  });
}

// Só o servidor do TMX grava: o segredo nasce da chave de API, e a chave nunca sai de lá
async function admin(req, env, url) {
  const dado = String(req.headers.get('Authorization') || '').replace(/^Bearer /, '');
  if (!env.SEGREDO || dado.length !== env.SEGREDO.length) return new Response('não', { status: 403 });
  let dif = 0;
  for (let i = 0; i < dado.length; i++) dif |= dado.charCodeAt(i) ^ env.SEGREDO.charCodeAt(i);
  if (dif) return new Response('não', { status: 403 });
  const acao = url.pathname.slice('/_tmx-admin/'.length);
  const json = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: { 'Content-Type': 'application/json' } });
  if (acao === 'ping') return json({ ok: true });
  if (acao === 'objeto') {
    const k = String(url.searchParams.get('k') || '');
    if (!CHAVE_VALIDA.test(k) || k.includes('..')) return json({ ok: false, erro: 'chave inválida' }, 400);
    if (req.method === 'PUT') {
      await env.PAGINAS.put(k, await req.arrayBuffer(), { httpMetadata: {
        contentType: req.headers.get('Content-Type') || 'application/octet-stream',
        cacheControl: req.headers.get('X-TMX-Cache') || undefined } });
      _cfg.delete(k.split('/')[0]);
      return json({ ok: true });
    }
    if (req.method === 'DELETE') { await env.PAGINAS.delete(k); return json({ ok: true }); }
  }
  if (acao === 'pasta' && req.method === 'DELETE') {
    const p = String(url.searchParams.get('p') || '');
    if (!PASTA_VALIDA.test(p) || p.includes('..')) return json({ ok: false, erro: 'pasta inválida' }, 400);
    let cursor, n = 0;
    do {
      const l = await env.PAGINAS.list({ prefix: p, cursor, limit: 1000 });
      const chaves = l.objects.map(x => x.key);
      if (chaves.length) { await env.PAGINAS.delete(chaves); n += chaves.length; }
      cursor = l.truncated ? l.cursor : undefined;
    } while (cursor);
    _cfg.delete(p.split('/')[0]);
    return json({ ok: true, apagados: n });
  }
  return json({ ok: false, erro: 'ação desconhecida' }, 404);
}

async function atender(req, env) {
  const url = new URL(req.url);
  const host = url.hostname.toLowerCase();
  if (url.pathname.startsWith('/_tmx-admin/')) {
    if (env.ALVO && host !== env.ALVO) return naoAchei();
    return admin(req, env, url);
  }
  if (env.ALVO && env.ORIGEM && host === env.ALVO && ROTAS_LINK_META.test(url.pathname)) return repassar(req, url, { origem: env.ORIGEM }, url.pathname);
  // a origem gravada em cada domínio é a da hora em que ele foi configurado: a do programa é a de agora
  const cfg0 = await lerCfg(env, host);
  if (!cfg0) return naoAchei();
  const cfg = env.ORIGEM ? Object.assign({}, cfg0, { origem: env.ORIGEM }) : cfg0;
  let caminho;
  try { caminho = decodeURIComponent(url.pathname); } catch (e) { return naoAchei(); }
  if (caminho.includes('..') || /(^|\/)_/.test(caminho.replace(/^\//, ''))) {
    // nada que comece com "_" sai daqui: é onde mora a configuração
    return naoAchei();
  }
  // a página do quiz chama o servidor com o prefixo da empresa
  const semBase = cfg.base && caminho.startsWith(cfg.base + '/') ? caminho.slice(cfg.base.length) : caminho;
  if (ROTAS_DO_SISTEMA.test(semBase)) return repassar(req, url, cfg, semBase);
  if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('Método não aceito.', { status: 405 });
  const t = cfg.testes && cfg.testes[caminho.replace(/^\/+|\/+$/g, '')];
  if (t) return servirTeste(req, env, host, cfg, t);
  return servirArquivo(req, env, host, cfg, caminho);
}

export default {
  async fetch(req, env) {
    try { return await atender(req, env); }
    catch (e) { console.error('[tmx-paginas]', e && e.message); return new Response('Erro ao abrir a página. Tente de novo em instantes.', { status: 502 }); }
  }
};
