// ══════════════════════════════════════════════
// 📄 PÁGINAS · modelos, versões, conferências e publicação na hospedagem
// ══════════════════════════════════════════════
// A página nasce de um modelo (uma página da TMX que já roda tráfego) e guarda só os
// campos (VSL, atraso, checkout, preço...). Cada mudança vira uma versão; publicar
// monta o HTML da versão e envia por FTP pra hospedagem do cliente.
//
// A senha da hospedagem segue a regra das credenciais do Financeiro: só no servidor,
// cifrada (mesmo cofre, com o id do domínio como dado autenticado), nunca volta pro
// navegador, auditada, e só a Diretoria da TMX conecta. Quem digita é o Thiago.
//
// Fica num arquivo à parte pra não disputar o server.js com outras mudanças em curso.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const { Readable, Writable } = require('stream');
const ftp = require('basic-ftp');

const PASTA_MODELOS = path.join(__dirname, 'modelos-paginas');

// preco/parcela/valor: o texto exato que o modelo usa, trocado em todo lugar onde aparece.
// valor só serve pra conferir o checkout quando a página não mostra preço (ponte).
const MODELOS = {
// produto: o nome que o checkout da Payt mostra; anual de R$ 697 do Acervo num checkout do
// Foco passaria só pelo plano e pelo valor.
  'vendas-vsl':     { nome: 'Vendas com VSL',     base: 'apostilai.ai/novomvf', arquivo: 'vendas-vsl.html',
                      preco: 'R$ 697', parcela: '12x R$ 69,98', plano: 'ANUAL', produto: 'APOSTILAI FOCO' },
  'upsell-vsl':     { nome: 'Upsell com VSL',     base: 'apostilai.ai/espera',  arquivo: 'upsell-vsl.html' },
  'vendas-sem-vsl': { nome: 'Vendas sem VSL',     base: 'apostilai.ai/foco2',   arquivo: 'vendas-sem-vsl.html',
                      preco: 'R$ 697', parcela: '12x R$ 69,98', plano: 'ANUAL', produto: 'APOSTILAI FOCO' },
  'ponte':          { nome: 'Ponte pro checkout', base: 'apostilai.ai/acervo',  arquivo: 'ponte.html',
                      plano: 'ANUAL', valor: '697', produto: 'APOSTILAI ACERVO' }
};

// O que dá pra trocar em cada modelo sai do próprio HTML: o player da VTurb, o
// DELAY_SEG, os links de checkout da Payt e o pixel do TMX.
function _extrair(html) {
  const t = html.match(/<title>([^<]*)<\/title>/i);
  const pl = html.match(/scripts\.converteai\.net\/([a-f0-9-]+)\/(players|ab-test)\/([a-f0-9]{24})\//);
  const d = html.match(/var DELAY_SEG\s*=\s*(\d+)/);
  const px = html.match(/<script[^>]+centraltmx\.com\/px\.js[^>]*><\/script>/);
  return {
    titulo: t ? t[1].trim() : '',
    vsl: pl ? { conta: pl[1], tipo: pl[2], id: pl[3] } : null,
    atraso: d ? Number(d[1]) : null,
    checkouts: [...new Set(html.match(/https:\/\/checkout\.payt\.com\.br\/[a-f0-9]{32}/g) || [])],
    umClique: /multiple-oneclickbuyscript|payt_action=["']oneclick/.test(html),
    pixel: px ? px[0] : '',
    terceiros: _terceiros(html)
  };
}
let _modelosMem = null;
function _modelos() {
  if (_modelosMem) return _modelosMem;
  const m = {};
  for (const [id, cfg] of Object.entries(MODELOS)) {
    try {
      const html = fs.readFileSync(path.join(PASTA_MODELOS, cfg.arquivo), 'utf8');
      m[id] = Object.assign({ id, html, ext: _extrair(html) }, cfg);
    } catch (e) { console.error('[PAGINAS] modelo ' + id + ' não abriu:', e.message); }
  }
  return (_modelosMem = m);
}
function _modelo(id) { return _modelos()[id] || null; }

function _defs(m) {
  const x = m.ext, d = [{ k: 'titulo', rot: 'Título da aba do navegador', tipo: 'texto' }];
  if (x.vsl) d.push({ k: 'vsl', rot: 'VSL da VTurb', tipo: 'vsl',
    ajuda: 'Cole o código do player que a VTurb dá pra incorporar, ou só o id. Em teste A/B, use o código do teste (ab-…).' });
  if (x.atraso != null) d.push({ k: 'atraso', rot: 'A oferta aparece aos', tipo: 'tempo', ajuda: 'mm:ss. Tem que ser igual ao pitch da VSL.' });
  if (x.checkouts.length) {
    d.push({ k: 'checkout', rot: 'Link do checkout', tipo: 'url', ajuda: 'O link da Payt (checkout.payt.com.br/…). Vale pra todos os botões de compra.' });
    d.push({ k: 'plano', rot: 'Plano que a página vende', tipo: 'plano' });
    d.push({ k: 'produto', rot: 'Produto no checkout', tipo: 'texto', ajuda: 'Como o checkout da Payt escreve o produto, ex.: APOSTILAI FOCO. Serve pra conferir.' });
  }
  if (m.preco) d.push({ k: 'preco', rot: 'Preço', tipo: 'texto', ajuda: 'Troca o "' + m.preco + '" da página inteira.' });
  if (m.parcela) d.push({ k: 'parcela', rot: 'Parcela', tipo: 'texto', ajuda: 'Troca o "' + m.parcela + '" da página inteira.' });
  if (m.valor) d.push({ k: 'valor', rot: 'Valor do plano', tipo: 'texto', ajuda: 'Não aparece na página: serve pra conferir o checkout.' });
  d.push({ k: 'naoTem', rot: 'O que o produto não tem', tipo: 'texto',
    ajuda: 'Separado por vírgula, ex.: Professor Max. Se a página citar, a conferência avisa.' });
  return d;
}
function _camposPadrao(m) {
  const x = m.ext;
  return { titulo: x.titulo, vsl: x.vsl, atraso: x.atraso, checkout: x.checkouts[0] || '',
           plano: m.plano || '', produto: m.produto || '', preco: m.preco || '', parcela: m.parcela || '', valor: m.valor || '', naoTem: '' };
}

// ── campos que chegam da tela ──
function _lerVsl(txt, contaPadrao) {
  const s = String(txt || '').trim();
  let m = s.match(/scripts\.converteai\.net\/([a-f0-9-]+)\/(players|ab-test)\/([a-f0-9]{24})\//);
  if (m) return { conta: m[1], tipo: m[2], id: m[3] };
  m = s.match(/\b(vid|ab)[-_]([a-f0-9]{24})\b/);
  if (m && contaPadrao) return { conta: contaPadrao, tipo: m[1] === 'ab' ? 'ab-test' : 'players', id: m[2] };
  if (/^[a-f0-9]{24}$/.test(s) && contaPadrao) return { conta: contaPadrao, tipo: 'players', id: s };
  return null;
}
function _lerTempo(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'number') return Math.round(v);
  const s = String(v).trim();
  if (/^\d+$/.test(s)) return Number(s);
  const p = s.split(':').map(Number);
  if (p.some(n => !Number.isFinite(n))) return NaN;
  return p.reduce((t, n) => t * 60 + n, 0);
}
function _mmss(s) {
  if (s == null || !Number.isFinite(s)) return '—';
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
  return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(x).padStart(2, '0');
}
const CHECKOUT_OK = /^https:\/\/checkout\.payt\.com\.br\/[A-Za-z0-9]{8,64}$/;
function _validar(m, anterior, novo) {
  const c = Object.assign({}, anterior);
  const txt = (v, max) => String(v == null ? '' : v).replace(/[\r\n]+/g, ' ').trim().slice(0, max);
  if ('titulo' in novo) c.titulo = txt(novo.titulo, 120);
  if ('vsl' in novo && m.ext.vsl) {
    const v = typeof novo.vsl === 'object' && novo.vsl ? novo.vsl : _lerVsl(novo.vsl, m.ext.vsl.conta);
    if (!v || !/^[a-f0-9-]+$/.test(v.conta) || !/^(players|ab-test)$/.test(v.tipo) || !/^[a-f0-9]{24}$/.test(v.id))
      throw new Error('Não reconheci a VSL. Cole o código do player da VTurb (com scripts.converteai.net) ou o id de 24 letras e números.');
    c.vsl = { conta: v.conta, tipo: v.tipo, id: v.id };
  }
  if ('atraso' in novo && m.ext.atraso != null) {
    const s = _lerTempo(novo.atraso);
    if (!Number.isFinite(s) || s < 0 || s > 4 * 3600) throw new Error('O tempo da oferta tem que ser mm:ss, como 12:40.');
    c.atraso = s;
  }
  if ('checkout' in novo && m.ext.checkouts.length) {
    const u = txt(novo.checkout, 200).replace(/\/+$/, '');
    if (!CHECKOUT_OK.test(u)) throw new Error('O link do checkout tem que ser da Payt, como https://checkout.payt.com.br/…, sem nada depois do código.');
    c.checkout = u;
  }
  if ('plano' in novo) c.plano = /^(ANUAL|MENSAL)$/.test(novo.plano) ? novo.plano : '';
  ['preco', 'parcela', 'valor'].forEach(k => { if (k in novo) c[k] = txt(novo[k], 40); });
  if ('produto' in novo) c.produto = txt(novo.produto, 80);
  if ('naoTem' in novo) c.naoTem = txt(novo.naoTem, 300);
  return c;
}
function _resumo(m, a, b) {
  const r = [];
  if (a.titulo !== b.titulo) r.push('título');
  if (JSON.stringify(a.vsl) !== JSON.stringify(b.vsl)) r.push('VSL');
  if (a.atraso !== b.atraso) r.push('oferta aos ' + _mmss(b.atraso));
  if (a.checkout !== b.checkout) r.push('checkout');
  if (a.plano !== b.plano) r.push('plano ' + (b.plano || '—').toLowerCase());
  if (a.produto !== b.produto) r.push('produto');
  if (a.preco !== b.preco) r.push('preço ' + b.preco);
  if (a.parcela !== b.parcela) r.push('parcela ' + b.parcela);
  if (a.valor !== b.valor) r.push('valor ' + b.valor);
  if (a.naoTem !== b.naoTem) r.push('o que o produto não tem');
  return r.length ? 'Mudou ' + r.join(', ') : 'Sem mudança nos campos';
}

// ── montar o HTML de uma versão ──
const _esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const _troca = (h, de, para) => (de && de !== para) ? h.split(de).join(para) : h;
function _montar(m, pg, campos, n) {
  const x = m.ext;
  let h = m.html;
  if (campos.titulo) h = h.replace(/<title>[^<]*<\/title>/i, '<title>' + _esc(campos.titulo) + '</title>');
  if (x.vsl && campos.vsl && JSON.stringify(campos.vsl) !== JSON.stringify(x.vsl)) {
    const v = campos.vsl, pref = v.tipo === 'ab-test' ? 'ab' : 'vid';
    const caminho = v.conta + '/' + v.tipo + '/' + v.id + (v.tipo === 'players' ? '/v4/player.js' : '/player.js');
    h = h.replace(/scripts\.converteai\.net\/[a-f0-9-]+\/(players|ab-test)\/[a-f0-9]{24}\/(v4\/)?player\.js/g, 'scripts.converteai.net/' + caminho);
    h = _troca(h, x.vsl.id, v.id);
    h = h.replace(new RegExp('\\b(vid|ab)-' + v.id, 'g'), pref + '-' + v.id);
    // o preload do vídeo é do player antigo: com ele a página baixaria um vídeo à toa
    h = h.replace(/<link[^>]+\.m3u8[^>]*>\s*/gi, '');
  }
  if (x.atraso != null && Number.isFinite(campos.atraso))
    h = h.replace(/var DELAY_SEG\s*=\s*\d+;[^\n]*/, 'var DELAY_SEG = ' + campos.atraso + ';   /* ' + _mmss(campos.atraso) + ', definido no TMX */');
  if (campos.checkout && CHECKOUT_OK.test(campos.checkout)) x.checkouts.forEach(u => { h = _troca(h, u, campos.checkout); });
  if (m.preco && campos.preco) h = _troca(h, m.preco, _esc(campos.preco));
  if (m.parcela && campos.parcela) h = _troca(h, m.parcela, _esc(campos.parcela));
  // o pixel do TMX é sempre o primeiro script do <head>, com a marca da versão logo depois
  h = h.replace(/<script[^>]+centraltmx\.com\/px\.js[^>]*><\/script>\s*/g, '');
  const tagPx = x.pixel || '<script src="https://app.centraltmx.com/px.js" async></script>';
  const marca = '<meta name="tmx-pagina" content="' + pg.id + ':' + n + '">';
  let pos = h.search(/<meta charset=["']?utf-8["']?\s*\/?>/i);
  if (pos >= 0) pos = h.indexOf('>', pos) + 1; else { pos = h.search(/<head[^>]*>/i); pos = pos >= 0 ? h.indexOf('>', pos) + 1 : 0; }
  return h.slice(0, pos) + '\n' + tagPx + '\n' + marca + h.slice(pos);
}
// A prévia não pode contar visita nem view: sai o pixel, os rastreadores e o player
// (fica só a capa). A tela ainda abre num iframe sem scripts.
function _previa(html, endereco, slug) {
  let h = html.replace(/<script\b[^>]*\bsrc=["'][^"']*(centraltmx\.com\/px\.js|converteai\.net|funnelway|utmify|googletagmanager|connect\.facebook)[^"']*["'][^>]*>\s*<\/script>/gi, '');
  h = h.replace(/<link[^>]+(converteai|vturb|\.m3u8)[^>]*>/gi, '');
  h = h.replace(/<vturb-smartplayer\b[^>]*>[\s\S]*?<\/vturb-smartplayer>/gi,
    '<div style="aspect-ratio:9/16;max-width:400px;margin:0 auto;background:#0b1020;color:#cbd5e1;display:grid;place-items:center;border-radius:12px;font:600 14px system-ui;text-align:center;padding:16px">Capa da VSL<br><span style="font-weight:400;font-size:12px">a prévia não carrega o player, pra não contar view na VTurb</span></div>');
  const base = '<base href="' + _esc(new URL(slug + '/', endereco).href) + '">' +
    // sem script, o que a página mostra com animação (.rv) ou depois do atraso ficaria escondido
    '<style>html body .ap-oculto{display:revert !important}.rv,.reveal,[data-reveal]{opacity:1 !important;transform:none !important}</style>';
  const p = h.search(/<head[^>]*>/i);
  return p >= 0 ? h.slice(0, h.indexOf('>', p) + 1) + base + h.slice(h.indexOf('>', p) + 1) : base + h;
}

// ── rastreadores de terceiros na página ──
function _terceiros(html) {
  const r = new Set();
  if (/funnelway/i.test(html)) r.add('FunnelWay');
  if (/utmify/i.test(html)) r.add('UTMify');
  if (/googletagmanager\.com/i.test(html)) r.add('Google Tag Manager');
  (html.match(/fbq\(\s*["']init["']\s*,\s*["'](\d+)["']/g) || []).forEach(s => r.add('Pixel da Meta ' + s.match(/(\d{6,})/)[1]));
  if (/analytics\.tiktok\.com/i.test(html)) r.add('TikTok');
  return [...r].sort();
}

// ── rede: só endereço público, com limite de tamanho e de tempo ──
function _ipInterno(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const s = ip.toLowerCase();
  return s === '::1' || s === '::' || s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80') || s.startsWith('::ffff:127.') || s.startsWith('::ffff:10.') || s.startsWith('::ffff:192.168.');
}
async function _hostPublico(host) {
  // rodando local, o teste de ponta a ponta usa um FTP e um site na própria máquina
  if (process.env.PG_PERMITIR_LOCAL === '1') return;
  const ends = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (!ends.length || ends.some(e => _ipInterno(e.address))) throw new Error('Esse endereço é de rede interna. Use o endereço público da hospedagem.');
}
async function _baixar(url, max) {
  const u = new URL(url);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Só endereço http ou https.');
  await _hostPublico(u.hostname);
  const r = await fetch(u, { redirect: 'follow', signal: AbortSignal.timeout(12000), headers: { 'user-agent': 'CentralTMX-Paginas/1.0', 'cache-control': 'no-cache' } });
  if (!r.ok) throw new Error('respondeu ' + r.status);
  const txt = await r.text();
  return txt.length > (max || 2e6) ? txt.slice(0, max || 2e6) : txt;
}

// ── VTurb: o pitch vem da lista que o TMX já guarda; teste A/B e player fora dela, do player.js ──
const _pitchMem = {};
async function _pitchDaVsl(ctx, v) {
  if (!v) return null;
  if (v.tipo === 'players') {
    const p = (ctx.vturbPlayers() || []).find(p => String(p.id) === v.id);
    if (p && Number(p.pitch) > 0) return { s: Math.round(Number(p.pitch)), nome: p.nome || '' };
  }
  const k = v.conta + '/' + v.tipo + '/' + v.id;
  if (_pitchMem[k] && Date.now() - _pitchMem[k].em < 10 * 60000) return _pitchMem[k].r;
  let r = null;
  try {
    const js = await _baixar('https://scripts.converteai.net/' + k + (v.tipo === 'players' ? '/v4/player.js' : '/player.js'), 3e6);
    const vals = [...js.matchAll(/pitch_?[Tt]ime["']?\s*[:=]\s*["']?(\d+(?:\.\d+)?)/g)].map(x => Number(x[1])).filter(n => n > 0)
      .map(n => Math.round(n > 36000 ? n / 1000 : n));
    const unicos = [...new Set(vals)];
    if (unicos.length === 1) r = { s: unicos[0], nome: '' };
    else if (unicos.length > 1) r = { varios: unicos };
  } catch (e) { r = null; }
  _pitchMem[k] = { em: Date.now(), r };
  return r;
}

// ── Payt: o nome do plano está no <title> da página do checkout ──
const _ckMem = {};
async function _lerCheckout(url) {
  if (_ckMem[url] && Date.now() - _ckMem[url].em < 10 * 60000) return _ckMem[url].r;
  let r = null;
  try {
    const html = await _baixar(url, 2e6);
    const t = html.match(/<title>([^<]*)<\/title>/i);
    r = { titulo: t ? t[1].replace(/\s+/g, ' ').trim() : '', html };
  } catch (e) { r = null; }
  _ckMem[url] = { em: Date.now(), r };
  return r;
}
const _digitos = s => String(s || '').replace(/[^\d]/g, '');

// ── conferências: as que já pegaram erro de verdade nas páginas da TMX ──
async function _conferir(ctx, m, campos, html) {
  const x = m.ext, l = [];
  if (x.atraso != null) {
    const p = await _pitchDaVsl(ctx, campos.vsl);
    if (!campos.vsl) l.push({ r: 'Atraso da oferta igual ao pitch da VSL', st: 'falta', d: 'Falta a VSL.' });
    else if (!p) l.push({ r: 'Atraso da oferta igual ao pitch da VSL', st: 'conferir', d: 'Não consegui ler o pitch dessa VSL na VTurb. A oferta aparece aos ' + _mmss(campos.atraso) + ': confira à mão.' });
    else if (p.varios) l.push({ r: 'Atraso da oferta igual ao pitch da VSL', st: 'alerta', d: 'Os vídeos do teste A/B têm pitch diferente (' + p.varios.map(_mmss).join(', ') + '). Um atraso só não serve pra todos.' });
    else if (Math.abs(p.s - campos.atraso) <= 2) l.push({ r: 'Atraso da oferta igual ao pitch da VSL', st: 'ok', d: 'Oferta aos ' + _mmss(campos.atraso) + ', pitch aos ' + _mmss(p.s) + (p.nome ? ' ("' + p.nome + '")' : '') + '.' });
    else l.push({ r: 'Atraso da oferta igual ao pitch da VSL', st: 'alerta', d: 'A oferta aparece aos ' + _mmss(campos.atraso) + ', mas o pitch da VSL é aos ' + _mmss(p.s) + '.' });
  }
  const head = html.slice(0, Math.max(0, html.search(/<\/head>/i)));
  const primeiro = (head.match(/<script\b[^>]*>/i) || [''])[0];
  l.push(/centraltmx\.com\/px\.js/.test(primeiro)
    ? { r: 'Pixel do TMX é o primeiro script', st: 'ok', d: 'Entra sozinho em toda versão.' }
    : { r: 'Pixel do TMX é o primeiro script', st: 'alerta', d: 'O primeiro script do <head> não é o pixel do TMX.' });
  if (x.checkouts.length) {
    const rotP = 'Plano do checkout combina com a página', rotParc = 'Parcela da página igual à do checkout';
    if (!campos.checkout) { l.push({ r: rotP, st: 'falta', d: 'Falta o link do checkout.' }); }
    else {
      const ck = await _lerCheckout(campos.checkout);
      if (!ck || !ck.titulo) l.push({ r: rotP, st: 'conferir', d: 'Não consegui abrir o checkout pra ler o nome do plano.' });
      else {
        const t = ck.titulo.toUpperCase(), valor = _digitos(campos.preco || campos.valor);
        const planoOk = !campos.plano || t.includes(campos.plano), outro = campos.plano === 'ANUAL' ? 'MENSAL' : campos.plano === 'MENSAL' ? 'ANUAL' : '';
        const valorTem = /\d/.test(t), valorOk = !valor || !valorTem || _digitos(t).includes(valor);
        const produtoOk = !campos.produto || t.includes(campos.produto.toUpperCase());
        if ((outro && t.includes(outro)) || !planoOk || !valorOk || !produtoOk)
          l.push({ r: rotP, st: 'alerta', d: 'O checkout é "' + ck.titulo + '", e a página vende ' + (campos.produto ? campos.produto + ' ' : '') + (campos.plano ? campos.plano.toLowerCase() : '') + (valor ? ' de R$ ' + (campos.preco || campos.valor).replace(/^R\$\s*/, '') : '') + '.' });
        else l.push({ r: rotP, st: 'ok', d: 'Checkout: "' + ck.titulo + '".' });
        if (campos.parcela) {
          const m2 = campos.parcela.match(/(\d+)\s*x\s*(?:de\s*)?R?\$?\s*([\d.,]+)/i);
          const tem = m2 && (ck.html.includes(m2[2]) || ck.html.includes(m2[2].replace(',', '.')));
          l.push(tem ? { r: rotParc, st: 'ok', d: campos.parcela + ' aparece no checkout.' }
            : { r: rotParc, st: 'conferir', d: 'Não achei "' + campos.parcela + '" na página do checkout (ela pode montar as parcelas só depois de abrir). Confira à mão.' });
        }
      }
    }
  } else if (x.umClique) {
    l.push({ r: 'Compra com 1 clique', st: 'conferir', d: 'Os botões de 1 clique da Payt ficam iguais aos do modelo. Confira se as ofertas são as certas.' });
  }
  const naoTem = String(campos.naoTem || '').split(',').map(s => s.trim()).filter(Boolean);
  if (naoTem.length) {
    const texto = html.replace(/<[^>]+>/g, ' ').toLowerCase();
    const achados = naoTem.filter(s => texto.includes(s.toLowerCase()));
    l.push(achados.length
      ? { r: 'O que a página promete, o produto tem', st: 'alerta', d: 'A página cita ' + achados.map(s => '"' + s + '"').join(', ') + ', que o produto não tem.' }
      : { r: 'O que a página promete, o produto tem', st: 'ok', d: 'A página não cita ' + naoTem.join(', ') + '.' });
  }
  const agora = _terceiros(html), domodelo = x.terceiros;
  const novos = agora.filter(t => !domodelo.includes(t));
  l.push(novos.length
    ? { r: 'Sem rastreador de outro dono', st: 'alerta', d: 'Apareceu o que o modelo não tinha: ' + novos.join(', ') + '.' }
    : { r: 'Sem rastreador de outro dono', st: 'ok', d: agora.length ? 'Os mesmos do modelo: ' + agora.join(', ') + '.' : 'Nenhum rastreador de terceiro.' });
  l.push({ r: 'A prévia não conta view na VTurb', st: 'ok', d: 'Na prévia o vídeo mostra só a capa.' });
  return l;
}

// ── FTP ──
const TLS = {
  'tls':          { secure: true },
  'tls-sem-cert': { secure: true, secureOptions: { rejectUnauthorized: false } },
  'sem-tls':      { secure: false }
};
function _erroFtp(e) {
  const s = String((e && (e.code || '')) + ' ' + (e && e.message || ''));
  if (/530|Login|authentication|incorrect/i.test(s)) return 'O servidor recusou o usuário ou a senha.';
  if (/ENOTFOUND|EAI_AGAIN/.test(s)) return 'Não achei esse servidor. Confira o endereço.';
  if (/ECONNREFUSED/.test(s)) return 'O servidor recusou a conexão nessa porta.';
  if (/ETIMEDOUT|Timeout|timed out/i.test(s)) return 'O servidor não respondeu a tempo.';
  if (/certificate|altnames|self.signed|CERT/i.test(s)) return 'O certificado do servidor não confere com o endereço (comum quando o servidor é um IP). Tente "Com TLS, sem conferir o certificado".';
  if (/550|No such file|not found/i.test(s)) return 'Essa pasta não existe no servidor.';
  if (/rede interna/.test(s)) return e.message;
  return 'Falhou: ' + (e && e.message || 'erro desconhecido');
}
async function _comFtp(d, senha, fn) {
  await _hostPublico(d.host);
  const c = new ftp.Client(20000);
  try {
    const modo = TLS[d.tls] || TLS.tls;
    const op = { host: d.host, port: Number(d.porta) || 21, user: d.usuario, password: senha, secure: modo.secure };
    if (modo.secure) op.secureOptions = Object.assign(net.isIP(d.host) ? {} : { servername: d.host }, modo.secureOptions || {});
    await c.access(op);
    return await fn(c);
  } finally { c.close(); }
}
async function _ftpLer(c, nome) {
  const partes = [];
  const w = new Writable({ write(ch, enc, cb) { partes.push(ch); cb(); } });
  await c.downloadTo(w, nome);
  return Buffer.concat(partes).toString('utf8');
}
const _sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const _urlDe = (endereco, rel) => new URL(rel, endereco.endsWith('/') ? endereco : endereco + '/').href;

async function _testarHospedagem(d, senha) {
  const passos = [], nome = 'tmx-teste-' + crypto.randomBytes(6).toString('hex') + '.txt', marca = 'tmx-' + crypto.randomBytes(12).toString('hex');
  const url = _urlDe(d.endereco, nome);
  try {
    await _comFtp(d, senha, async c => {
      passos.push({ ok: true, t: 'Entrei no servidor ' + d.host + (d.tls === 'sem-tls' ? ' (sem TLS: a senha vai aberta)' : ' com TLS') });
      await c.cd(d.pasta || '/');
      passos.push({ ok: true, t: 'Abri a pasta ' + (d.pasta || '/') });
      await c.uploadFrom(Readable.from([Buffer.from(marca)]), nome);
      passos.push({ ok: true, t: 'Criei um arquivo de teste' });
      let abriu = false, porque = '';
      try { abriu = (await _baixar(url + '?t=' + Date.now(), 1000)).trim() === marca; if (!abriu) porque = 'O endereço abriu, mas não mostrou o arquivo de teste. A pasta pode não ser a do site.'; }
      catch (e) { porque = 'O arquivo não abriu em ' + url + ' (' + e.message + '). Confira o endereço público e a pasta.'; }
      let apagou = true; try { await c.remove(nome); } catch (e) { apagou = false; }
      passos.push({ ok: abriu, t: (abriu ? 'O arquivo abriu em ' + d.endereco : porque) + (apagou ? ' Apaguei o arquivo de teste.' : ' Não consegui apagar o arquivo de teste (' + nome + ').') });
    });
  } catch (e) { passos.push({ ok: false, t: _erroFtp(e) }); }
  return { ok: passos.length >= 4 && passos.every(p => p.ok), passos };
}

// ══════════════════════════════════════════════
module.exports = function montarPaginas(ctx) {
  const { app, express, readDB, writeDB, audit, auth, _pessoas, _q, _finCifrar, _finDecifrar } = ctx;
  let pronto = false;
  function _tabelas() {
    if (pronto) return true;
    const db = _pessoas(); if (!db) return false;
    db.exec(`
      CREATE TABLE IF NOT EXISTS pg_dominios (id TEXT PRIMARY KEY, dominio TEXT, modo TEXT, host TEXT, porta INTEGER, usuario TEXT,
        pasta TEXT, endereco TEXT, tls TEXT, cred TEXT, testado_em INTEGER, criado_em INTEGER, criado_por TEXT);
      CREATE TABLE IF NOT EXISTS pg_paginas (id TEXT PRIMARY KEY, dominio_id TEXT, slug TEXT, titulo TEXT, modelo TEXT,
        versao INTEGER, publicada INTEGER, publicada_em INTEGER, hash_ar TEXT, criado_em INTEGER, criado_por TEXT,
        UNIQUE (dominio_id, slug));
      CREATE TABLE IF NOT EXISTS pg_versoes (pagina_id TEXT, n INTEGER, campos TEXT, resumo TEXT, por TEXT, em INTEGER,
        PRIMARY KEY (pagina_id, n));
      CREATE TABLE IF NOT EXISTS pg_substituidas (pagina_id TEXT, em INTEGER, html TEXT);
    `);
    return (pronto = true);
  }
  const semBanco = res => res.status(503).json({ error: 'O banco de páginas não abriu neste servidor.' });
  const quem = req => (req.user && (req.user.nome || req.user.email)) || 'Diretoria';
  function _auditar(req, acao, alvo, meta) {
    try { const db = readDB(); audit(db, acao, alvo, meta, req.user); writeDB(db); } catch (e) { console.error('[PAGINAS] auditoria:', e.message); }
  }
  const _domPublico = d => ({ id: d.id, dominio: d.dominio, modo: d.modo, host: d.host, porta: d.porta, usuario: d.usuario,
    pasta: d.pasta, endereco: d.endereco, tls: d.tls, testado_em: d.testado_em, criado_em: d.criado_em });
  const _dom = id => _q('SELECT * FROM pg_dominios WHERE id=?').get(id);
  const _pag = id => _q('SELECT * FROM pg_paginas WHERE id=?').get(id);
  const _versao = (id, n) => { const v = _q('SELECT * FROM pg_versoes WHERE pagina_id=? AND n=?').get(id, n); return v ? Object.assign(v, { campos: JSON.parse(v.campos) }) : null; };
  function _endereco(d, slug) { return _urlDe(d.endereco, slug + '/'); }

  // o que chega da tela pra conectar uma hospedagem (a senha só vive nesta chamada)
  function _lerHospedagem(b) {
    const dominio = String(b.dominio || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(dominio)) throw new Error('Domínio inválido. Use só o endereço, como apostilai.ai.');
    const host = String(b.host || '').trim();
    if (!/^[a-zA-Z0-9.:-]+$/.test(host)) throw new Error('Servidor inválido.');
    const porta = Number(b.porta) || 21;
    if (porta < 1 || porta > 65535) throw new Error('Porta inválida.');
    const usuario = String(b.usuario || '').trim().slice(0, 120);
    if (!usuario) throw new Error('Falta o usuário do FTP.');
    let endereco = String(b.endereco || ('https://' + dominio + '/')).trim();
    if (!/^https?:\/\/[a-z0-9.-]+(:\d+)?(\/[^\s]*)?$/i.test(endereco)) throw new Error('Endereço público inválido.');
    if (!endereco.endsWith('/')) endereco += '/';
    const pasta = String(b.pasta || '/').trim().slice(0, 200) || '/';
    if (/\.\./.test(pasta)) throw new Error('Pasta inválida.');
    const tls = TLS[b.tls] ? b.tls : 'tls';
    return { dominio, modo: 'ftp', host, porta, usuario, pasta, endereco, tls };
  }

  app.get('/api/pg/estado', auth, (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const modelos = Object.values(_modelos()).map(m => ({ id: m.id, nome: m.nome, base: m.base, campos: _defs(m), padrao: _camposPadrao(m),
      tem: { vsl: !!m.ext.vsl, atraso: m.ext.atraso != null, checkout: m.ext.checkouts.length > 0, umClique: m.ext.umClique } }));
    const dominios = _q('SELECT * FROM pg_dominios ORDER BY criado_em').all().map(_domPublico);
    const paginas = _q('SELECT * FROM pg_paginas ORDER BY criado_em DESC').all().map(p => Object.assign({}, p, { hash_ar: undefined }));
    res.json({ modelos, dominios, paginas });
  });

  app.post('/api/pg/dominios/testar', auth, express.json({ limit: '20kb' }), async (req, res) => {
    let d; try { d = _lerHospedagem(req.body || {}); } catch (e) { return res.status(400).json({ error: e.message }); }
    const senha = String((req.body || {}).senha || '');
    if (!senha) return res.status(400).json({ error: 'Falta a senha do FTP.' });
    res.json(await _testarHospedagem(d, senha));
  });

  // Salvar testa de novo: só guarda a senha de uma hospedagem que acabou de funcionar
  app.post('/api/pg/dominios', auth, express.json({ limit: '20kb' }), async (req, res) => {
    if (!_tabelas()) return semBanco(res);
    let d; try { d = _lerHospedagem(req.body || {}); } catch (e) { return res.status(400).json({ error: e.message }); }
    const senha = String((req.body || {}).senha || '');
    if (!senha) return res.status(400).json({ error: 'Falta a senha do FTP.' });
    if (_q('SELECT id FROM pg_dominios WHERE dominio=?').get(d.dominio)) return res.status(409).json({ error: 'Esse domínio já está conectado. Exclua o antigo pra conectar de novo.' });
    const teste = await _testarHospedagem(d, senha);
    if (!teste.ok) return res.status(400).json(Object.assign({ error: 'O teste não passou, então não salvei.' }, teste));
    const id = 'dom_' + crypto.randomBytes(6).toString('hex'), agora = Date.now();
    _q(`INSERT INTO pg_dominios (id, dominio, modo, host, porta, usuario, pasta, endereco, tls, cred, testado_em, criado_em, criado_por)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, d.dominio, d.modo, d.host, d.porta, d.usuario, d.pasta, d.endereco, d.tls,
      JSON.stringify(_finCifrar(id, { senha })), agora, agora, quem(req));
    _auditar(req, 'pg_hospedagem_conectar', id, { dominio: d.dominio, host: d.host, usuario: d.usuario, tls: d.tls });
    res.json({ ok: true, dominio: _domPublico(_dom(id)), passos: teste.passos });
  });

  app.post('/api/pg/dominios/:id/testar', auth, async (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const d = _dom(req.params.id); if (!d) return res.status(404).json({ error: 'Domínio não encontrado.' });
    let senha; try { senha = _finDecifrar(d.id, JSON.parse(d.cred)).senha; } catch (e) { return res.status(400).json({ error: e.message }); }
    const teste = await _testarHospedagem(d, senha);
    if (teste.ok) _q('UPDATE pg_dominios SET testado_em=? WHERE id=?').run(Date.now(), d.id);
    res.json(teste);
  });

  app.post('/api/pg/dominios/:id/excluir', auth, (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const d = _dom(req.params.id); if (!d) return res.status(404).json({ error: 'Domínio não encontrado.' });
    const n = _q('SELECT COUNT(*) n FROM pg_paginas WHERE dominio_id=?').get(d.id).n;
    if (n) return res.status(409).json({ error: 'Esse domínio tem ' + n + (n === 1 ? ' página' : ' páginas') + ' no TMX. As páginas na hospedagem não são apagadas, mas tire elas do TMX antes.' });
    _q('DELETE FROM pg_dominios WHERE id=?').run(d.id);
    _auditar(req, 'pg_hospedagem_excluir', d.id, { dominio: d.dominio });
    res.json({ ok: true });
  });

  app.post('/api/pg/paginas', auth, express.json({ limit: '50kb' }), (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const b = req.body || {}, m = _modelo(b.modelo), d = _dom(b.dominio_id);
    if (!m) return res.status(400).json({ error: 'Modelo não encontrado.' });
    if (!d) return res.status(400).json({ error: 'Escolha um domínio conectado.' });
    const slug = String(b.slug || '').trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,60}$/.test(slug)) return res.status(400).json({ error: 'Endereço inválido: use letras minúsculas, números e hífen, como foco-anual.' });
    if (_q('SELECT id FROM pg_paginas WHERE dominio_id=? AND slug=?').get(d.id, slug)) return res.status(409).json({ error: 'Já existe uma página do TMX nesse endereço.' });
    let campos; try { campos = _validar(m, _camposPadrao(m), { titulo: b.titulo || m.ext.titulo }); } catch (e) { return res.status(400).json({ error: e.message }); }
    const id = 'pg_' + crypto.randomBytes(6).toString('hex'), agora = Date.now();
    _q(`INSERT INTO pg_paginas (id, dominio_id, slug, titulo, modelo, versao, publicada, criado_em, criado_por) VALUES (?,?,?,?,?,1,0,?,?)`)
      .run(id, d.id, slug, String(b.titulo || m.nome).slice(0, 120), m.id, agora, quem(req));
    _q('INSERT INTO pg_versoes (pagina_id, n, campos, resumo, por, em) VALUES (?,?,?,?,?,?)')
      .run(id, 1, JSON.stringify(campos), 'Criada a partir do modelo ' + m.nome, quem(req), agora);
    _auditar(req, 'pg_pagina_criar', id, { dominio: d.dominio, slug, modelo: m.id });
    res.json({ ok: true, id });
  });

  app.get('/api/pg/paginas/:id', auth, (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const p = _pag(req.params.id); if (!p) return res.status(404).json({ error: 'Página não encontrada.' });
    const m = _modelo(p.modelo), d = _dom(p.dominio_id);
    const versoes = _q('SELECT n, resumo, por, em FROM pg_versoes WHERE pagina_id=? ORDER BY n DESC').all(p.id);
    const v = _versao(p.id, p.versao);
    res.json({ pagina: Object.assign({}, p, { hash_ar: undefined }), dominio: d ? _domPublico(d) : null,
      endereco: d ? _endereco(d, p.slug) : '', modelo: m ? { id: m.id, nome: m.nome, base: m.base, campos: _defs(m) } : null,
      campos: v ? v.campos : null, versoes });
  });

  app.post('/api/pg/paginas/:id/versao', auth, express.json({ limit: '50kb' }), (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const p = _pag(req.params.id); if (!p) return res.status(404).json({ error: 'Página não encontrada.' });
    const m = _modelo(p.modelo), atual = _versao(p.id, p.versao);
    let campos; try { campos = _validar(m, atual.campos, (req.body || {}).campos || {}); } catch (e) { return res.status(400).json({ error: e.message }); }
    const resumo = _resumo(m, atual.campos, campos);
    if (resumo === 'Sem mudança nos campos') return res.json({ ok: true, n: p.versao, igual: true });
    const n = p.versao + 1;
    _q('INSERT INTO pg_versoes (pagina_id, n, campos, resumo, por, em) VALUES (?,?,?,?,?,?)').run(p.id, n, JSON.stringify(campos), resumo, quem(req), Date.now());
    _q('UPDATE pg_paginas SET versao=?, titulo=? WHERE id=?').run(n, campos.titulo || p.titulo, p.id);
    res.json({ ok: true, n, resumo });
  });

  // voltar cria uma versão nova com os campos da antiga: dá pra desfazer o voltar também
  app.post('/api/pg/paginas/:id/voltar/:n', auth, (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const p = _pag(req.params.id); if (!p) return res.status(404).json({ error: 'Página não encontrada.' });
    const alvo = _versao(p.id, Number(req.params.n)); if (!alvo) return res.status(404).json({ error: 'Versão não encontrada.' });
    const n = p.versao + 1;
    _q('INSERT INTO pg_versoes (pagina_id, n, campos, resumo, por, em) VALUES (?,?,?,?,?,?)').run(p.id, n, JSON.stringify(alvo.campos), 'Voltou pra versão ' + alvo.n, quem(req), Date.now());
    _q('UPDATE pg_paginas SET versao=? WHERE id=?').run(n, p.id);
    res.json({ ok: true, n });
  });

  app.get('/api/pg/paginas/:id/previa', auth, (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const p = _pag(req.params.id); if (!p) return res.status(404).json({ error: 'Página não encontrada.' });
    const n = Number(req.query.n) || p.versao, v = _versao(p.id, n), d = _dom(p.dominio_id), m = _modelo(p.modelo);
    if (!v || !d || !m) return res.status(404).json({ error: 'Versão não encontrada.' });
    res.set('Cache-Control', 'no-store').type('text/plain; charset=utf-8').send(_previa(_montar(m, p, v.campos, n), d.endereco, p.slug));
  });

  app.get('/api/pg/paginas/:id/conferencias', auth, async (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const p = _pag(req.params.id); if (!p) return res.status(404).json({ error: 'Página não encontrada.' });
    const n = Number(req.query.n) || p.versao, v = _versao(p.id, n), m = _modelo(p.modelo);
    if (!v || !m) return res.status(404).json({ error: 'Versão não encontrada.' });
    res.json({ n, conferencias: await _conferir(ctx, m, v.campos, _montar(m, p, v.campos, n)) });
  });

  app.post('/api/pg/paginas/:id/publicar', auth, express.json({ limit: '10kb' }), async (req, res) => {
    if (!_tabelas()) return semBanco(res);
    const p = _pag(req.params.id); if (!p) return res.status(404).json({ error: 'Página não encontrada.' });
    const b = req.body || {}, n = Number(b.n) || p.versao, v = _versao(p.id, n), d = _dom(p.dominio_id), m = _modelo(p.modelo);
    if (!v || !d || !m) return res.status(404).json({ error: 'Versão não encontrada.' });
    const html = _montar(m, p, v.campos, n);
    const conf = await _conferir(ctx, m, v.campos, html);
    if (conf.some(c => c.st === 'alerta' || c.st === 'falta'))
      return res.status(409).json({ codigo: 'conferencia', error: 'Tem conferência com alerta ou faltando. Resolva antes de publicar.', conferencias: conf });
    let senha; try { senha = _finDecifrar(d.id, JSON.parse(d.cred)).senha; } catch (e) { return res.status(400).json({ error: e.message }); }
    let antigo = null;
    try {
      await _comFtp(d, senha, async c => {
        await c.cd(d.pasta || '/');
        await c.ensureDir(p.slug);
        let atual = null; try { atual = await _ftpLer(c, 'index.html'); } catch (e) { atual = null; }
        // nunca escreve por cima de algo que o TMX não pôs lá sem o "sim" de quem publica
        if (atual !== null && _sha(atual) !== p.hash_ar) {
          if (!b.substituir) {
            const e = new Error(p.hash_ar ? 'A página na hospedagem mudou por fora desde a última publicação do TMX.' : 'Já existe uma página nesse endereço na hospedagem, e ela não foi publicada pelo TMX.');
            e.codigo = 'existe'; throw e;
          }
          antigo = atual;
        }
        await c.uploadFrom(Readable.from([Buffer.from(html, 'utf8')]), 'index.html');
      });
    } catch (e) {
      if (e.codigo === 'existe') return res.status(409).json({ codigo: 'existe', error: e.message + ' Se publicar mesmo assim, o TMX guarda uma cópia do arquivo de lá.' });
      return res.status(502).json({ error: _erroFtp(e) });
    }
    const agora = Date.now();
    if (antigo !== null) _q('INSERT INTO pg_substituidas (pagina_id, em, html) VALUES (?,?,?)').run(p.id, agora, antigo);
    _q('UPDATE pg_paginas SET publicada=?, publicada_em=?, hash_ar=? WHERE id=?').run(n, agora, _sha(html), p.id);
    const url = _endereco(d, p.slug);
    let noAr = false;
    try { noAr = (await _baixar(url + '?tmxv=' + n + '-' + agora, 3e6)).includes('<meta name="tmx-pagina" content="' + p.id + ':' + n + '">'); } catch (e) { noAr = false; }
    _auditar(req, 'pg_pagina_publicar', p.id, { dominio: d.dominio, slug: p.slug, versao: n, conferido_no_ar: noAr, substituiu: antigo !== null });
    res.json({ ok: true, n, url, noAr, substituiu: antigo !== null });
  });

  console.log('[PAGINAS] ' + Object.keys(_modelos()).length + ' modelos prontos');
};
// pra testar as partes que não dependem de servidor
module.exports._interno = { _extrair, _lerVsl, _lerTempo, _validar, _montar, _previa, _terceiros, _mmss, MODELOS, _modelos };
