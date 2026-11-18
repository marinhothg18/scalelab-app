// Spy de anúncios: o servidor busca o vídeo de cada anúncio na Biblioteca de Anúncios pública (18/11/2026).
// Por quê: o Claude no Chrome não repassa o link assinado do vídeo (a extensão esconde de propósito) e o Facebook
// bloqueia envio da página pra fora. Então o servidor abre https://www.facebook.com/ads/library/?id=<id> num Chromium
// headless, sem login, acha o card "Identificação da biblioteca: <id>" e lê o <video> (src e poster) dele. Quem baixa
// o arquivo e guarda no R2 é o spy.js.
// Regras: um navegador por vez, um anúncio por vez, pausa entre eles, e o navegador fecha sempre no fim.
// No Railway (Linux) o Chromium vem do @sparticuz/chromium (descompacta no /tmp, nunca no /data); no Mac, o Chrome instalado.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');

let chromium = null;
try { chromium = require('playwright-core').chromium; } catch (e) { chromium = null; }
const espera = ms => new Promise(r => setTimeout(r, ms));
const RE_LOGIN = /Entre no Facebook|Faça login para continuar|Faça login no Facebook|Log in to Facebook|You must log in|log in to continue/i;

async function abrirNavegador() {
  if (!chromium) throw new Error('playwright-core não está instalado');
  if (process.env.SPY_CHROMIUM_PATH) return chromium.launch({ executablePath: process.env.SPY_CHROMIUM_PATH, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  if (process.platform === 'linux') {
    // Chromium do sistema, se a imagem tiver (apt)
    if (fs.existsSync('/usr/bin/chromium')) return chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const sp = require('@sparticuz/chromium');
    const exe = await sp.executablePath();
    // Fora da AWS o pacote não descompacta as bibliotecas de sistema que o Chromium usa (libnss3, libnspr4, libexpat):
    // sem elas o navegador nem abre no Railway. Descompacta aqui (no /tmp) e aponta o LD_LIBRARY_PATH só pro navegador.
    const lambdafs = require('@sparticuz/chromium/build/lambdafs').default;
    const libs = await lambdafs.inflate(path.join(path.dirname(require.resolve('@sparticuz/chromium/package.json')), 'bin', 'al2023.tar.br'));
    const env = Object.assign({}, process.env, { LD_LIBRARY_PATH: [path.join(libs, 'lib'), process.env.LD_LIBRARY_PATH].filter(Boolean).join(':'),
      FONTCONFIG_PATH: process.env.FONTCONFIG_PATH || path.join(os.tmpdir(), 'fonts') });
    // --single-process é pro Lambda; o Playwright não funciona com ele
    const args = (sp.args || []).filter(a => a !== '--single-process' && a !== '--no-zygote').concat(['--disable-dev-shm-usage']);
    return chromium.launch({ executablePath: exe, args, headless: true, env });
  }
  return chromium.launch({ channel: 'chrome', headless: true });
}

// lê o card do anúncio na página aberta
async function lerCard(pg, id, ms, base) {
  await pg.goto(base + '/ads/library/?id=' + encodeURIComponent(id), { waitUntil: 'domcontentloaded', timeout: ms }).catch(() => {});
  // a verificação anti-robô do Facebook recarrega a página uma vez: espera o id e um vídeo aparecerem
  const fim = Date.now() + ms;
  let ultimo = null;
  while (Date.now() < fim) {
    try {
      ultimo = await pg.evaluate(id => {
        const txt = (document.body && document.body.innerText) || '';
        if (/\/login/.test(location.pathname)) return { login: true };
        const RE = new RegExp('(?:Identifica[çc][ãa]o da biblioteca|ID da biblioteca|Library ID)\\s*:?\\s*' + id + '(?!\\d)');
        const RE_G = /(?:Identifica[çc][ãa]o da biblioteca|ID da biblioteca|Library ID)\s*:?\s*\d{6,}/gi;
        const conta = el => ((el.textContent || '').match(RE_G) || []).length;
        let rot = null;
        for (const el of document.querySelectorAll('body *')) { if (RE.test(el.textContent || '') && ![...el.children].some(f => RE.test(f.textContent || ''))) { rot = el; break; } }
        if (!rot) return { achou: false, txt: txt.slice(0, 2000) };
        let card = rot;
        while (card.parentElement && card.parentElement !== document.body && conta(card.parentElement) <= 1) card = card.parentElement;
        const v = card.querySelector('video');
        const imgs = [...card.querySelectorAll('img')].filter(i => (i.naturalWidth || i.width) >= 160)
          .sort((a, b) => (b.naturalWidth || b.width) * (b.naturalHeight || b.height) - (a.naturalWidth || a.width) * (a.naturalHeight || a.height));
        const video = v ? (v.currentSrc || v.src || '') : '';
        return { achou: true, video: /^https?:/.test(video) ? video : '', capa: v && v.poster ? v.poster : '', imagem: !video && imgs.length ? (imgs[0].currentSrc || imgs[0].src) : '', temVideo: !!v };
      }, String(id));
    } catch (e) { ultimo = null; }   // a página recarregou no meio
    if (ultimo && (ultimo.login || (ultimo.achou && (ultimo.video || ultimo.imagem)))) break;
    if (ultimo && !ultimo.achou && RE_LOGIN.test(ultimo.txt || '')) { ultimo = { login: true }; break; }
    await espera(700);
  }
  if (!ultimo) return { erro: 'a página não carregou' };
  if (ultimo.login) return { login: true, erro: 'o Facebook pediu login' };
  if (!ultimo.achou) return { erro: 'o anúncio não apareceu na página (pode ter saído do ar)' };
  if (!ultimo.video && !ultimo.imagem) return { erro: ultimo.temVideo ? 'o vídeo deste anúncio não tem link direto' : 'o anúncio não tem vídeo nem imagem' };
  return { video: ultimo.video, capa: ultimo.capa, imagem: ultimo.imagem };
}

module.exports = function criarBuscador(opc) {
  opc = opc || {};
  const pausa = opc.pausaMs != null ? opc.pausaMs : 4000;
  const porPagina = opc.esperaMs || 30000;
  const base = opc.base || 'https://www.facebook.com';   // nos testes, uma página de mentira local
  let abertoEm = 0;
  return {
    disponivel: () => !!chromium,
    // busca uma lista de ids; aoAchar(id, resultado) é chamado a cada um. Para se o Facebook pedir login duas vezes seguidas.
    async buscar(ids, aoAchar) {
      const res = { tentados: 0, achados: 0, erros: 0, bloqueado: false, erro: '' };
      if (!ids.length) return res;
      let nav = null, logins = 0;
      // trava de segurança: se algo travar, o navegador morre em no máximo 20 min
      const trava = setTimeout(() => { try { nav && nav.close(); } catch (e) {} }, opc.limiteMs || 20 * 60000);
      try {
        nav = await abrirNavegador();
        abertoEm = Date.now();
        const ctx = await nav.newContext({ locale: 'pt-BR', viewport: { width: 1280, height: 900 } });
        const pg = await ctx.newPage();
        for (let i = 0; i < ids.length; i++) {
          const id = ids[i];
          res.tentados++;
          let r;
          try { r = await lerCard(pg, id, porPagina, base); } catch (e) { r = { erro: e.message }; }
          if (r.login) { logins++; if (logins >= 2) { res.bloqueado = true; res.erro = 'O Facebook pediu login ao servidor.'; try { aoAchar(id, r); } catch (e) {} break; } }
          else logins = 0;
          if (r.video || r.imagem) res.achados++; else res.erros++;
          try { await aoAchar(id, r); } catch (e) {}
          if (i < ids.length - 1) await espera(pausa + Math.floor(Math.random() * pausa / 2));
        }
      } catch (e) {
        res.erro = 'Não consegui abrir o navegador: ' + e.message;
      } finally {
        clearTimeout(trava);
        try { if (nav) await nav.close(); } catch (e) {}
        abertoEm = 0;
      }
      return res;
    },
    aberto: () => !!abertoEm
  };
};
