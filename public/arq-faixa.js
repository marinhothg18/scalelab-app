// Regra da faixa de ADs e leitura do nome do anúncio. É o MESMO arquivo na tela
// (ScaleLab.html, <script src>) e no servidor (server.js, require), pra formulário,
// preenchimento dos antigos e MCP nunca discordarem. Testes: npm test.
//
// Como os anúncios são nomeados (explicado pelo Thiago em 05/11/2026):
//   AD202.1                         Hook 1 do AD202 (.2 é o Hook 2, .3 é o Hook 3)
//   AD245.1 - AD216.2 + C153        anúncio novo AD245.1, com o Hook 2 do AD216 e o corpo do AD153
//   AD248.2 - AD179.1 + AD212.1 + C212   anúncio novo, com dois hooks e o corpo do AD212
//   AD94-H153                       corpo do AD94 com o hook do AD153
//   AD05-KALEB-RM                   o Kalebe gravou por conta própria: não tem roteiro
// B19 a B28 foi um erro de numeração de uma remessa só: B não é número de AD.
(function (raiz, fabrica) {
  var api = fabrica();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else raiz.ArqFaixa = api;
})(typeof self !== 'undefined' ? self : this, function () {
  var MAX_LARGURA = 100;   // "1 a 500" num título quase nunca é faixa de anúncios

  function faixaValida(a, b) {
    return a > 0 && b >= a && (b - a) <= MAX_LARGURA ? { inicio: a, fim: b } : null;
  }

  // Lê a faixa do título de um arquivo. Devolve { inicio, fim } ou null.
  function extrairFaixa(titulo) {
    var t = String(titulo || '').replace(/ /g, ' ');
    var m, f;

    // AD197 a AD206 · AD 197 ao 206 · ADs 197 até 206 · AD197-AD206 · AD197 - 206
    // O número depois do AD não pode ter ponto: "AD245.1 - AD216.2" é remontagem, não faixa.
    m = t.match(/\bADs?\s*0*(\d{1,4})(?![\d.])\s*(?:a|ao|até|ate|à|-|–|—)\s*(?:ADs?\s*)?0*(\d{1,4})(?![\d.])/i);
    if (m) { f = faixaValida(+m[1], +m[2]); if (f) return f; }

    // 197 ao 206 (sem AD). Só com palavra no meio: hífen pegaria "Remessa 04 - 10 ads".
    var re = /(^|[^\w.,\/$-])0*(\d{1,4})\s+(a|ao|até|ate|à)\s+0*(\d{1,4})(?![\d\/.,]|\s*(?:reais|min|h\b|dias))/ig;
    while ((m = re.exec(t))) {
      var antes = t.slice(0, m.index + m[1].length);
      if (/(remessa|lead|aula|m[oó]dulo|parte|hook|etapa|dia|dias|semana|p[aá]gina|cap[ií]tulo|vers[aã]o|R\$)\s*$/i.test(antes)) continue;
      if (/[BCH]\s*$/i.test(antes)) continue;
      f = faixaValida(+m[2], +m[4]);
      if (f) return f;
    }

    // Um AD só no título: "AD216 - roteiro". Mais de um sem faixa é remontagem: não dá pra saber.
    var ads = t.match(/\bAD\s*0*\d{1,4}\b/ig);
    if (ads && ads.length === 1 && !/\bC\s*\d/i.test(t)) {
      var n = +ads[0].replace(/\D/g, '');
      return faixaValida(n, n);
    }
    return null;
  }

  // Lê o que a pessoa digitou no campo "Faixa de ADs". Vazio devolve { vazio: true };
  // o que não dá pra entender devolve { erro: true }, pro formulário avisar em vez de chutar.
  function lerCampoFaixa(txt) {
    var t = String(txt == null ? '' : txt).trim();
    if (!t) return { vazio: true };
    var m = t.match(/^(?:ADs?\s*)?0*(\d{1,4})(?:\s*(?:a|ao|até|ate|à|-|–|—)\s*(?:ADs?\s*)?0*(\d{1,4}))?$/i);
    if (!m) return { erro: true };
    var a = +m[1], b = m[2] ? +m[2] : a;
    return faixaValida(a, b) || { erro: true };
  }

  // Lê o nome de um anúncio e diz de onde vem cada pedaço. Papéis:
  //   anuncio  o próprio anúncio (hook: qual hook dele, se o nome disser)
  //   hook     o hook veio de outro AD
  //   corpo    o corpo veio de outro AD
  //   semRoteiro  gravado por conta própria
  function lerAnuncio(texto) {
    var t = String(texto == null ? '' : texto).replace(/ /g, ' ').trim();
    var m;

    m = t.match(/\bAD\s*0*(\d+)[\s_-]*KALEB[A-Z]*[\s_-]*RM\b/i);
    if (m) return [{ papel: 'semRoteiro', ad: +m[1] }];

    // AD94-H153: corpo do AD94, hook do AD153 (H colado num hífen aponta outro AD)
    m = t.match(/\bAD\s*0*(\d+)(?:\.\d+)?\s*-\s*H0*(\d+)(?![\dK])/i);
    if (m) return [{ papel: 'corpo', ad: +m[1] }, { papel: 'hook', ad: +m[2] }];

    var so = t.match(/^0*(\d+)(?:\.(\d+))?$/);
    if (so) return [parte('anuncio', so[1], so[2])];

    // AD228HK.2, AD232.HK1, AD198HK1, AD237.hk2, Ad 02.h2 e AD212.3_1 são hook do próprio AD
    var re = /\b(AD|C)\s*0*(\d+)(?:\.?(?:HK?)?\.?(\d+))?/ig, toks = [];
    while ((m = re.exec(t))) toks.push({ tipo: m[1].toUpperCase(), ad: m[2], hook: m[3] });
    var ads = toks.filter(function (x) { return x.tipo === 'AD'; });
    var corpos = toks.filter(function (x) { return x.tipo === 'C'; });
    if (!ads.length && !corpos.length) return [];

    var remontagem = corpos.length > 0 || /\bAD\s*\d[\w.]*\s*-\s*AD\s*\d/i.test(t);
    if (!remontagem) return ads.map(function (x) { return parte('anuncio', x.ad, x.hook); });

    var out = [];
    ads.forEach(function (x, i) { out.push(parte(i === 0 ? 'anuncio' : 'hook', x.ad, x.hook)); });
    corpos.forEach(function (x) { out.push({ papel: 'corpo', ad: +x.ad }); });
    return out;
  }
  function parte(papel, ad, hook) {
    var p = { papel: papel, ad: +ad };
    if (hook) p.hook = +hook;
    return p;
  }

  return { extrairFaixa: extrairFaixa, lerCampoFaixa: lerCampoFaixa, lerAnuncio: lerAnuncio };
});
