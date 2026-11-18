// Spy de anúncios (fase 1, 18/11/2026): o que a tela e o servidor precisam concordar.
// É o MESMO arquivo no app (ScaleLab.html, <script src>) e no servidor (spy.js, require),
// igual ao arq-faixa.js: o formulário de "colar link" e a ferramenta do MCP leem o link do mesmo jeito.
//
// Link da Biblioteca de Anúncios da Meta:
//   ...?view_all_page_id=1140174149181447          página
//   ...?q=concursa-paginas.vercel.app              domínio (termo com ponto e sem espaço)
//   ...?q=concurso%20público                       palavra
(function (raiz, fabrica) {
  var api = fabrica();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else raiz.SpyLink = api;
})(typeof self !== 'undefined' ? self : this, function () {
  // valores fechados da especificação (seção 5, etiqueta)
  var ANGULOS = ['Notícia', 'Segmentação direta', 'Fofoca', 'Inimigo', 'Polêmica / proibido', 'Prova', 'Conselho em 1ª pessoa', 'Contrário', 'História'];
  var FORMATOS = ['Rosto / teleprompter', 'Caixinha de pergunta', 'Auto-diálogo', 'Historinha IA', 'Objeto que fala', 'Tela dividida', 'UGC / criadora', 'Inserts de IA'];
  var CAMPOS = ['angulo', 'dor', 'persona', 'formato', 'mecanismo', 'nome_chiclete', 'prova', 'cta', 'duracao'];
  var PARTES = ['gancho', 'corpo', 'cta', 'todo'];
  var DOMINIO = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

  function limparDominio(t) {
    return String(t || '').trim().toLowerCase().replace(/^"+|"+$/g, '').replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '');
  }
  function ehDominio(t) { var d = limparDominio(t); return !/\s/.test(String(t || '').trim()) && DOMINIO.test(d); }

  // Devolve { tipo: 'pagina'|'dominio'|'palavra', referencia, pais, searchType } ou null.
  // Aceita também só o número da página ou só o domínio.
  function ler(texto) {
    var v = String(texto || '').trim();
    if (!v) return null;
    if (/^\d{6,}$/.test(v)) return { tipo: 'pagina', referencia: v, pais: 'BR', searchType: '' };
    var u = null;
    if (/facebook\.com\/ads\/library|[?&](q|view_all_page_id)=/i.test(v)) {
      try { u = new URL(/^https?:\/\//i.test(v) ? v : 'https://' + v.replace(/^\/+/, '')); } catch (e) { u = null; }
    }
    if (!u) {
      if (ehDominio(v)) return { tipo: 'dominio', referencia: limparDominio(v), pais: 'BR', searchType: '' };
      return null;
    }
    var p = u.searchParams;
    var pais = String(p.get('country') || 'BR').toUpperCase();
    if (!/^([A-Z]{2}|ALL)$/.test(pais)) pais = 'BR';
    var st = String(p.get('search_type') || '');
    var pid = String(p.get('view_all_page_id') || '').trim();
    if (/^\d{5,}$/.test(pid)) return { tipo: 'pagina', referencia: pid, pais: pais, searchType: '' };
    var q = String(p.get('q') || '').trim().replace(/^"+|"+$/g, '').trim();
    if (!q) return null;
    if (ehDominio(q)) return { tipo: 'dominio', referencia: limparDominio(q), pais: pais, searchType: st };
    return { tipo: 'palavra', referencia: q.replace(/\s+/g, ' '), pais: pais, searchType: st };
  }

  // Link pra abrir na Biblioteca da Meta (o mesmo formato que o Thiago cola)
  function montar(b) {
    var base = 'https://www.facebook.com/ads/library/?active_status=active&ad_type=all&country=' + encodeURIComponent(b.pais || 'BR') + '&media_type=all';
    if (b.tipo === 'pagina') return base + '&search_type=page&view_all_page_id=' + encodeURIComponent(b.referencia);
    return base + '&q=' + encodeURIComponent(b.referencia) + '&search_type=' + encodeURIComponent(b.searchType || 'keyword_unordered');
  }

  // a mesma biblioteca não entra duas vezes: tipo + referência + país
  function chave(b) { return [b.tipo, String(b.referencia || '').toLowerCase(), String(b.pais || 'BR').toUpperCase()].join('|'); }

  function rotuloTipo(t) { return t === 'pagina' ? 'Página' : t === 'dominio' ? 'Domínio' : t === 'palavra' ? 'Palavra' : '—'; }

  return { ANGULOS: ANGULOS, FORMATOS: FORMATOS, CAMPOS: CAMPOS, PARTES: PARTES, ler: ler, montar: montar, chave: chave, rotuloTipo: rotuloTipo, limparDominio: limparDominio, ehDominio: ehDominio };
});
