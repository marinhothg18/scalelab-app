/* ════════════════════════════════════════════════════════════════════════════
   MOTOR DO QUIZ
   Desenha e conduz um quiz de funil. É o MESMO arquivo na página pública
   (/q/:slug) e na prévia do celular dentro do Central TMX: se fossem dois
   códigos, a prévia ia mostrar uma coisa e o anúncio outra, e ninguém ia
   perceber até a campanha estar rodando.

   Uma tela é uma pilha de blocos (título, imagem, opções, botão, cronômetro…).
   O CSS é todo prefixado com .qz pra não brigar com o do ScaleLab.html.

   QuizMotor.montar(raiz, quiz, opcoes) → { ir, atualizar, destruir, estado }
     opcoes.modo        'vivo' (página pública) | 'previa' (Central TMX)
     opcoes.enviar      fn(tipo, dados) — eventos pro servidor (só no vivo)
     opcoes.aoLink      fn(url, info)   — na prévia, em vez de redirecionar
     opcoes.aoTela      fn(indice)      — quando a pessoa muda de tela
     opcoes.avancarCarga fn() → bool    — na prévia, false repete o carregando
     opcoes.n           número real de quem concluiu (pra {n})
     opcoes.vid         id do visitante (vai no tmx_qid)
     opcoes.parametros  query string a repassar pro destino (as UTMs)
     opcoes.contido     true = rola dentro da caixa (prévia no celular)
   ════════════════════════════════════════════════════════════════════════════ */
(function(){
'use strict';

var CSS = [
'.qz{--q-cor:#2340B8;--q-destaque:#FFE066;--q-destaque-txt:#14172B;--q-fundo:#FFFFFF;--q-tinta:#0B1020;--q-apoio:#5B6178;--q-linha:#DCE1EC;--q-suave:#F2F4F9;--q-raio:14px;--q-alt:56px;--q-ft:"Public Sans";--q-fx:"Public Sans";',
'  --q-botao-txt:#FFFFFF;--q-alerta:#DC2626;--q-bom:#16A34A;--q-meio:#F59E0B;',
'  background:var(--q-fundo);color:var(--q-tinta);font-family:var(--q-fx),system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:flex;flex-direction:column;position:relative;',
'  box-sizing:border-box;-webkit-font-smoothing:antialiased;text-align:left;line-height:1.45;font-size:15px;min-height:100%}',
'.qz *,.qz *::before,.qz *::after{box-sizing:border-box}',
'.qz.qz-contido{height:100%;min-height:0;overflow:hidden}',
'.qz button{font:inherit;margin:0;text-transform:none;letter-spacing:normal}',
'.qz-topo{flex:0 0 auto;display:grid;grid-template-columns:30px minmax(0,1fr) 30px;align-items:center;gap:8px;padding:12px 14px 0;width:100%;max-width:520px;margin:0 auto}',
'.qz-voltar{width:30px;height:30px;border:none;background:none;border-radius:8px;color:var(--q-tinta);cursor:pointer;display:grid;place-items:center;padding:0}',
'.qz-voltar svg{width:18px;height:18px}',
'.qz-voltar.qz-oculto{visibility:hidden}',
'.qz-progresso{height:6px;border-radius:6px;background:var(--q-linha);overflow:hidden}',
'.qz-progresso i{display:block;height:100%;background:var(--q-tinta);border-radius:6px;transition:width .35s ease}',
'.qz-corpo{flex:1 1 auto;padding:18px 20px 28px;display:flex;flex-direction:column;gap:14px;width:100%;max-width:520px;margin:0 auto}',
'.qz-contido .qz-corpo{overflow-y:auto;scrollbar-width:none;min-height:0}',
'.qz-contido .qz-corpo::-webkit-scrollbar{display:none}',
'.qz-corpo.qz-centro{justify-content:center}',
'.qz-b{display:flex;flex-direction:column;gap:14px;min-width:0}',
'.qz-t{font-family:var(--q-ft),system-ui,sans-serif;font-weight:800;letter-spacing:-.02em;margin:0;padding:0;text-wrap:balance;color:var(--q-tinta);border:none;background:none}',
'.qz-t-g{font-size:25px;line-height:1.18}',
'.qz-t-m{font-size:21px;line-height:1.24}',
'.qz-t-p{font-size:17.5px;line-height:1.3;font-weight:700}',
'.qz-x{margin:0;padding:0;font-size:15px;line-height:1.5;color:var(--q-apoio);text-wrap:pretty}',
'.qz-x-italico{font-style:italic;font-size:14px}',
'.qz-x-pequeno{font-size:13px}',
'.qz mark{background:var(--q-destaque);color:var(--q-destaque-txt);padding:0 .16em;border-radius:4px;-webkit-box-decoration-break:clone;box-decoration-break:clone}',
'.qz-img{width:100%;height:auto;border-radius:var(--q-raio);display:block;margin:0}',
'.qz-ops{display:flex;flex-direction:column;gap:9px}',
'.qz-ops.qz-grade{display:grid;grid-template-columns:1fr 1fr}',
'.qz-op{min-height:var(--q-alt);display:flex;align-items:center;gap:11px;width:100%;text-align:left;cursor:pointer;background:var(--q-fundo);border:1.5px solid var(--q-linha);',
'  border-radius:var(--q-raio);padding:9px 13px;font-size:15px;font-weight:500;line-height:1.3;color:var(--q-tinta);transition:border-color .15s,background .15s;-webkit-tap-highlight-color:transparent}',
'.qz-op:hover{border-color:color-mix(in srgb,var(--q-cor) 40%,var(--q-linha))}',
'.qz-op.qz-marcada{border-color:var(--q-cor);background:color-mix(in srgb,var(--q-cor) 8%,var(--q-fundo))}',
'.qz-mk{flex:0 0 auto;display:grid;place-items:center;transition:background .15s,border-color .15s,color .15s}',
'.qz-mk-letra{width:28px;height:28px;border-radius:50%;border:1.5px solid color-mix(in srgb,var(--q-apoio) 55%,transparent);font-family:"IBM Plex Mono",ui-monospace,Menlo,monospace;font-size:12px;font-weight:600;color:var(--q-apoio)}',
'.qz-mk-bolinha{width:22px;height:22px;border-radius:50%;border:1.5px solid color-mix(in srgb,var(--q-apoio) 55%,transparent)}',
'.qz-mk-caixinha{width:22px;height:22px;border-radius:6px;border:1.5px solid color-mix(in srgb,var(--q-apoio) 55%,transparent);color:#fff;font-size:13px;font-weight:700}',
'.qz-mk-emoji{font-size:22px;line-height:1;width:28px}',
'.qz-marcada .qz-mk-letra{background:var(--q-cor);border-color:var(--q-cor);color:#fff}',
'.qz-marcada .qz-mk-bolinha{border-color:var(--q-cor);box-shadow:inset 0 0 0 4px var(--q-fundo);background:var(--q-cor)}',
'.qz-marcada .qz-mk-caixinha{background:var(--q-cor);border-color:var(--q-cor)}',
'.qz-botao{min-height:var(--q-alt);width:100%;border:none;border-radius:var(--q-raio);padding:12px 16px;font-size:16px;font-weight:700;letter-spacing:.01em;',
'  background:var(--q-cor);color:var(--q-botao-txt);cursor:pointer;font-family:var(--q-ft),system-ui,sans-serif;box-shadow:inset 0 -3px 0 rgba(0,0,0,.14);-webkit-tap-highlight-color:transparent}',
'.qz-botao:disabled{background:color-mix(in srgb,var(--q-apoio) 35%,var(--q-fundo));box-shadow:none;cursor:not-allowed}',
'.qz-prova{margin:0;text-align:center;font-size:14px;line-height:1.45;color:var(--q-apoio)}',
'.qz-num{display:flex;flex-direction:column;align-items:center;gap:16px;margin:4px 0}',
'.qz-num-valor{font-size:54px;font-weight:800;letter-spacing:-.04em;line-height:1;font-variant-numeric:tabular-nums;font-family:var(--q-ft),system-ui,sans-serif}',
'.qz-num-valor small{font-size:15px;font-weight:600;color:var(--q-apoio);letter-spacing:0;margin-left:6px}',
'.qz-passo{display:flex;align-items:center;gap:12px;width:100%}',
'.qz-passo button{width:44px;height:44px;border-radius:50%;border:1.5px solid var(--q-linha);background:var(--q-fundo);font-size:22px;font-weight:600;color:var(--q-tinta);cursor:pointer;flex:0 0 auto;padding:0}',
'.qz-passo input[type=range]{flex:1;accent-color:var(--q-cor);min-width:0;margin:0}',
'.qz-campo{width:100%;min-height:var(--q-alt);border:1.5px solid var(--q-linha);border-radius:var(--q-raio);padding:12px 14px;font-size:17px;font-family:inherit;outline:none;color:var(--q-tinta);background:var(--q-fundo);margin:0}',
'.qz-campo:focus{border-color:var(--q-cor)}',
'.qz-privado{font-size:12.5px;color:var(--q-apoio);margin:-6px 0 0}',
'.qz-crono{display:flex;flex-direction:column;align-items:center;gap:8px}',
'.qz-crono-rot{font-size:13px;color:var(--q-apoio);text-align:center}',
'.qz-crono-cx{display:flex;align-items:center;gap:6px}',
'.qz-crono-cx span{min-width:62px;padding:8px 6px 6px;border-radius:12px;background:color-mix(in srgb,var(--q-alerta) 9%,var(--q-fundo));border:1px solid color-mix(in srgb,var(--q-alerta) 22%,transparent);text-align:center}',
'.qz-crono-cx b{display:block;font-size:27px;font-weight:800;color:var(--q-alerta);font-variant-numeric:tabular-nums;line-height:1.05;font-family:var(--q-ft),system-ui,sans-serif}',
'.qz-crono-cx small{font-size:11px;color:color-mix(in srgb,var(--q-alerta) 62%,var(--q-apoio));font-weight:600}',
'.qz-crono-cx i{font-style:normal;font-weight:800;color:var(--q-alerta)}',
'.qz-graf svg{width:100%;height:auto;display:block;overflow:visible}',
'.qz-med{display:grid;grid-template-columns:1fr 1fr;gap:10px}',
'.qz-med>div{border:1px solid var(--q-linha);border-radius:var(--q-raio);padding:14px 10px 12px;display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center}',
'.qz-tubo{width:40px;height:100px;border-radius:10px;background:var(--q-suave);position:relative;overflow:hidden}',
'.qz-tubo i{position:absolute;left:0;right:0;bottom:0;border-radius:10px}',
'.qz-tubo em{position:absolute;top:6px;left:0;right:0;font-style:normal;font-size:11px;font-weight:700}',
'.qz-med p{margin:0;font-size:13px;line-height:1.4;color:var(--q-apoio)}',
'.qz-carga{display:flex;flex-direction:column;gap:10px}',
'.qz-carga-topo{display:flex;justify-content:space-between;font-weight:700;font-size:15px;font-family:var(--q-ft),system-ui,sans-serif}',
'.qz-carga-topo span:last-child{font-variant-numeric:tabular-nums}',
'.qz-carga-barra{height:8px;border-radius:8px;background:var(--q-linha);overflow:hidden;margin-bottom:6px}',
'.qz-carga-barra i{display:block;height:100%;width:0;background:var(--q-tinta);border-radius:8px}',
'.qz-carga-item{position:relative;overflow:hidden;border-radius:var(--q-raio);background:var(--q-suave);padding:14px;font-weight:600;font-size:14.5px;color:var(--q-apoio)}',
'.qz-carga-item i{position:absolute;left:0;top:0;bottom:0;width:0;background:var(--q-cor)}',
'.qz-carga-item span{position:relative}',
'.qz-carga-item.qz-cheio span{color:#fff}',
'.qz-rodape{margin-top:6px;padding-top:12px;border-top:1px solid var(--q-linha);font-size:11px;line-height:1.5;color:var(--q-apoio);text-align:center;display:flex;flex-direction:column;gap:4px}',
'.qz-entra{animation:qz-entra .22s ease both}',
'@keyframes qz-entra{from{opacity:.001;transform:translateY(6px)}to{opacity:1;transform:none}}',
'@media (prefers-reduced-motion:reduce){.qz *,.qz *::before,.qz *::after{animation-duration:.001ms!important;transition-duration:.001ms!important}}'
].join('\n');

var FONTES = { 'Public Sans':1, 'Inter':1, 'Montserrat':1, 'Poppins':1 };

function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
  });
}
function dec(n){ return (Math.round((Number(n) || 0) * 10) / 10).toLocaleString('pt-BR'); }
function num(n){ return Math.round(Number(n) || 0).toLocaleString('pt-BR'); }
function letra(i){ return String.fromCharCode(65 + i); }
function lum(hex){
  var c = String(hex || '#ffffff').replace('#', '');
  if (c.length === 3) c = c[0] + c[0] + c[1] + c[1] + c[2] + c[2];
  var v = [0, 2, 4].map(function(i){ return parseInt(c.substr(i, 2), 16) / 255; })
    .map(function(x){ return isNaN(x) ? 1 : (x <= .03928 ? x / 12.92 : Math.pow((x + .055) / 1.055, 2.4)); });
  return .2126 * v[0] + .7152 * v[1] + .0722 * v[2];
}
function corValida(c, padrao){ return /^#[0-9a-f]{3}([0-9a-f]{3})?$/i.test(String(c || '')) ? c : padrao; }

/* Cores de um bloco só. Cada nome vira uma variável dentro da caixa do bloco,
   então mudar a cor do cronômetro não mexe no resto da tela. O que ele não
   escolher continua vindo do tema (aba Aparência). */
var CORES_BLOCO = {
  titulo:     { texto:'--q-tinta', destaque:'--q-destaque' },
  texto:      { texto:'--q-apoio', destaque:'--q-destaque' },
  prova:      { texto:'--q-apoio', destaque:'--q-destaque' },
  imagem:     {},
  botao:      { fundo:'--q-cor', texto:'--q-botao-txt' },
  opcoes:     { fundo:'--q-fundo', borda:'--q-linha', texto:'--q-tinta', marcada:'--q-cor' },
  numero:     { numero:'--q-tinta', barra:'--q-cor' },
  campo:      { borda:'--q-linha', foco:'--q-cor' },
  cronometro: { numeros:'--q-alerta', rotulo:'--q-apoio' },
  grafico:    { linha:'--q-cor', inicio:'--q-alerta', meio:'--q-meio', fim:'--q-bom' },
  medidores:  { antes:'--q-alerta', depois:'--q-bom', linha:'--q-cor' },
  carregando: { titulo:'--q-tinta', barra:'--q-cor' }
};
function estiloBloco(b){
  var mapa = CORES_BLOCO[b.tipo] || {}, c = b.cor || {}, fora = [];
  Object.keys(mapa).forEach(function(k){
    var v = corValida(c[k], ''); if (v) fora.push(mapa[k] + ':' + v);
  });
  // texto do botão e do marca-texto: se ele não escolher, o motor põe claro ou
  // escuro conforme o fundo — senão sai branco no amarelo
  if (b.tipo === 'botao' && corValida(c.fundo, '') && !corValida(c.texto, '')) fora.push('--q-botao-txt:' + (lum(c.fundo) > .55 ? '#14172B' : '#FFFFFF'));
  if (corValida(c.destaque, '')) fora.push('--q-destaque-txt:' + (lum(c.destaque) > .45 ? '#14172B' : '#FFFFFF'));
  var raio = { reto:'6px', suave:'14px', redondo:'24px' }[b.raio];   // 'tema' e vazio seguem o tema
  if (raio) fora.push('--q-raio:' + raio);
  return fora.length ? ' style="' + fora.join(';') + '"' : '';
}

function injetarCss(doc){
  if (doc.getElementById('qz-css')) return;
  var s = doc.createElement('style'); s.id = 'qz-css'; s.textContent = CSS;
  (doc.head || doc.documentElement).appendChild(s);
}
function carregarFontes(doc, tema){
  var nomes = [tema.fonteTitulo, tema.fonteTexto, 'IBM Plex Mono'].filter(function(f, i, a){ return FONTES[f] || f === 'IBM Plex Mono' ? a.indexOf(f) === i : false; });
  var id = 'qz-fontes-' + nomes.join('-').replace(/\s/g, '');
  if (doc.getElementById(id)) return;
  var l = doc.createElement('link'); l.id = id; l.rel = 'stylesheet';
  l.href = 'https://fonts.googleapis.com/css2?' + nomes.map(function(f){
    return 'family=' + f.replace(/ /g, '+') + (f === 'IBM Plex Mono' ? ':wght@500;600' : ':wght@400;500;600;700;800');
  }).join('&') + '&display=swap';
  (doc.head || doc.documentElement).appendChild(l);
}

function montar(raiz, quiz, op){
  op = op || {};
  var doc = raiz.ownerDocument || document;
  var vivo = op.modo === 'vivo';
  var semMovimento = !!(doc.defaultView && doc.defaultView.matchMedia && doc.defaultView.matchMedia('(prefers-reduced-motion: reduce)').matches);
  var st = { i:0, hist:[], resp:{}, nums:{}, nome:'', timers:[], raf:0, cronoFim:0, vistas:{}, fimEnviado:false };
  var tick = 0, destruido = false;

  injetarCss(doc);
  raiz.classList.add('qz');
  raiz.classList.toggle('qz-contido', !!op.contido);
  raiz.innerHTML = '<div class="qz-topo"></div><div class="qz-corpo"></div>';
  var topo = raiz.querySelector('.qz-topo'), corpo = raiz.querySelector('.qz-corpo');

  function telas(){ return (quiz && quiz.telas) || []; }
  function perfis(){ return (quiz && quiz.perfis) || []; }
  function emitir(tipo, dados){ if (vivo && typeof op.enviar === 'function'){ try { op.enviar(tipo, dados || {}); } catch (e) {} } }
  function limparTimers(){ st.timers.forEach(clearTimeout); st.timers = []; if (st.raf) cancelAnimationFrame(st.raf); st.raf = 0; }
  function acharBloco(id){
    var ts = telas();
    for (var i = 0; i < ts.length; i++){ var b = (ts[i].blocos || []).filter(function(x){ return x.id === id; })[0]; if (b) return b; }
    return null;
  }
  function blocoDe(tipo){
    var ts = telas();
    for (var i = 0; i < ts.length; i++){ var b = (ts[i].blocos || []).filter(function(x){ return x.tipo === tipo; })[0]; if (b) return b; }
    return null;
  }
  function valorHoras(){ var b = blocoDe('numero'); return b ? (st.nums[b.id] != null ? st.nums[b.id] : b.valor) : 0; }
  function perfilCalculado(){
    var soma = {};
    telas().forEach(function(t){ (t.blocos || []).forEach(function(b){
      if (b.tipo !== 'opcoes') return;
      (st.resp[b.id] || []).forEach(function(id){
        var o = (b.ops || []).filter(function(x){ return x.id === id; })[0];
        if (o && o.perfil) soma[o.perfil] = (soma[o.perfil] || 0) + (Number(o.peso) || 1);
      });
    }); });
    var ps = perfis(), melhor = ps[0] || null, maior = 0;
    ps.forEach(function(p){ if ((soma[p.id] || 0) > maior){ maior = soma[p.id]; melhor = p; } });
    return melhor;
  }
  function variaveis(){
    var g = blocoDe('grafico'), dias = g ? (Number(g.dias) || 90) : 90, horas = valorHoras(), p = perfilCalculado();
    return { nome: st.nome.trim() || 'Você', horas: dec(horas), dias: dias, total: num(horas * dias),
             perfil: p ? p.nome : '', n: op.n != null ? num(op.n) : '—' };
  }
  function rico(s){
    var v = variaveis();
    return esc(s).replace(/\{(\w+)\}/g, function(m, k){ return v[k] != null ? esc(String(v[k])) : m; })
                 .replace(/\*([^*]+)\*/g, '<mark>$1</mark>');
  }

  function aplicarTema(){
    var t = (quiz && quiz.tema) || {}, s = raiz.style;
    var fundo = corValida(t.fundo, '#FFFFFF'), destaque = corValida(t.destaque, '#FFE066');
    var escuro = lum(fundo) < .2;
    s.setProperty('--q-cor', corValida(t.cor, '#2340B8'));
    s.setProperty('--q-destaque', destaque);
    s.setProperty('--q-destaque-txt', lum(destaque) > .45 ? '#14172B' : '#FFFFFF');
    s.setProperty('--q-fundo', fundo);
    s.setProperty('--q-tinta', escuro ? '#F3F5FB' : '#0B1020');
    s.setProperty('--q-apoio', escuro ? '#A9B0C6' : '#5B6178');
    s.setProperty('--q-linha', escuro ? 'rgba(255,255,255,.14)' : '#DCE1EC');
    s.setProperty('--q-suave', escuro ? 'rgba(255,255,255,.06)' : '#F2F4F9');
    s.setProperty('--q-raio', { reto:'6px', suave:'14px', redondo:'24px' }[t.raio] || '14px');
    s.setProperty('--q-alt', (Number(t.altura) || 56) + 'px');
    s.setProperty('--q-ft', '"' + (FONTES[t.fonteTitulo] ? t.fonteTitulo : 'Public Sans') + '"');
    s.setProperty('--q-fx', '"' + (FONTES[t.fonteTexto] ? t.fonteTexto : 'Public Sans') + '"');
    carregarFontes(doc, { fonteTitulo: FONTES[t.fonteTitulo] ? t.fonteTitulo : 'Public Sans', fonteTexto: FONTES[t.fonteTexto] ? t.fonteTexto : 'Public Sans' });
  }

  // ── desenho ─────────────────────────────────────────────────────────────
  function pintar(animar){
    if (destruido) return;
    limparTimers();
    aplicarTema();
    var ts = telas(), n = ts.length;
    if (!n){ topo.innerHTML = ''; corpo.innerHTML = '<p class="qz-x" style="text-align:center">Este quiz ainda não tem telas.</p>'; return; }
    if (st.i >= n) st.i = n - 1;
    var tela = ts[st.i], tema = quiz.tema || {};
    var prog = n > 1 ? st.i / (n - 1) : 1;
    topo.innerHTML =
      '<button class="qz-voltar' + (tema.voltar !== false && st.hist.length ? '' : ' qz-oculto') + '" type="button" data-qz="voltar" aria-label="Voltar">' +
        '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.5 4.5 7 10l5.5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></button>' +
      (tema.progresso !== false ? '<div class="qz-progresso" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + Math.round(prog * 100) + '"><i style="width:' + (prog * 100).toFixed(1) + '%"></i></div>' : '<div></div>') +
      '<div></div>';

    var blocos = tela.blocos || [];
    corpo.classList.toggle('qz-centro', blocos.some(function(b){ return b.tipo === 'carregando'; }));
    corpo.innerHTML = blocos.map(function(b){
      var h = bloco(b, tela);
      return h ? '<div class="qz-b"' + estiloBloco(b) + '>' + h + '</div>' : '';
    }).join('') +
      (st.i === 0 && (tema.aviso || tema.empresa) ? '<div class="qz-rodape">' + (tema.aviso ? '<span>' + esc(tema.aviso) + '</span>' : '') + (tema.empresa ? '<span>' + esc(tema.empresa) + '</span>' : '') + '</div>' : '');
    if (animar && !semMovimento){ corpo.classList.remove('qz-entra'); void corpo.offsetWidth; corpo.classList.add('qz-entra'); }
    if (animar){ corpo.scrollTop = 0; if (vivo && doc.defaultView) doc.defaultView.scrollTo(0, 0); }

    var cr = blocos.filter(function(b){ return b.tipo === 'cronometro'; })[0];
    if (cr && !st.cronoFim) st.cronoFim = inicioCrono(cr);
    tickCrono();
    var cg = blocos.filter(function(b){ return b.tipo === 'carregando'; })[0];
    if (cg) rodarCarga(cg);

    if (!st.vistas[st.i]){
      st.vistas[st.i] = 1;
      emitir('tela', { t: tela.id, i: st.i });
      if (st.i === n - 1 && !st.fimEnviado){ st.fimEnviado = true; var p = perfilCalculado(); emitir('fim', { p: p ? p.id : '' }); }
    }
  }

  function bloco(b, tela){
    var al = ' style="text-align:' + (b.alinhar === 'esquerda' ? 'left' : 'center') + '"';
    switch (b.tipo){
      case 'titulo': return '<h2 class="qz-t qz-t-' + (b.tam || 'm') + '"' + al + '>' + rico(b.txt) + '</h2>';
      case 'texto':  return '<p class="qz-x qz-x-' + (b.estilo || 'normal') + '"' + al + '>' + rico(b.txt) + '</p>';
      case 'imagem': return b.src ? '<img class="qz-img" src="' + esc(b.src) + '" alt="' + esc(b.alt || '') + '" loading="lazy" decoding="async">' : '';
      case 'espaco': return '<div style="height:' + Math.max(0, Math.min(200, Number(b.alt) || 16)) + 'px" aria-hidden="true"></div>';
      case 'prova':
        // Número real e baixo espanta mais do que convence: "0 pessoas fizeram"
        // é pior que nada. No ar, some até passar do mínimo; na prévia aparece.
        if (vivo && b.real && (op.n == null || op.n < (Number(b.minimo) || 20))) return '';
        return '<p class="qz-prova">' + esc(b.emoji || '') + ' ' + rico(b.txt) + '</p>';
      case 'botao': {
        var travado = (tela.blocos || []).some(function(x){ return x.tipo === 'campo'; }) && !st.nome.trim();
        return '<button class="qz-botao" type="button" data-qz="botao" data-bloco="' + esc(b.id) + '"' + (travado ? ' disabled' : '') + '>' + esc(b.txt) + '</button>';
      }
      case 'opcoes': {
        var marc = st.resp[b.id] || [];
        var html = (b.ops || []).map(function(o, i){
          var on = marc.indexOf(o.id) >= 0, mk = '';
          if (b.marcador === 'letra') mk = '<span class="qz-mk qz-mk-letra">' + letra(i) + '</span>';
          if (b.marcador === 'bolinha') mk = '<span class="qz-mk qz-mk-bolinha"></span>';
          if (b.marcador === 'caixinha') mk = '<span class="qz-mk qz-mk-caixinha">' + (on ? '✓' : '') + '</span>';
          if (b.marcador === 'emoji') mk = '<span class="qz-mk qz-mk-emoji" aria-hidden="true">' + esc(o.emoji || '•') + '</span>';
          return '<button type="button" class="qz-op' + (on ? ' qz-marcada' : '') + '" data-qz="op" data-bloco="' + esc(b.id) + '" data-op="' + esc(o.id) + '" aria-pressed="' + on + '">' + mk + '<span>' + esc(o.t) + '</span></button>';
        }).join('');
        return '<div class="qz-ops' + (b.layout === 'grade' ? ' qz-grade' : '') + '" role="group">' + html + '</div>' +
          (b.modo === 'varias' ? '<button class="qz-botao" type="button" data-qz="seguir" data-bloco="' + esc(b.id) + '"' + (marc.length ? '' : ' disabled') + '>' + esc(b.botao || 'Continuar') + '</button>' : '');
      }
      case 'numero': {
        var v = st.nums[b.id] != null ? st.nums[b.id] : b.valor;
        return '<div class="qz-num"><div class="qz-num-valor"><span data-num-v="' + esc(b.id) + '">' + dec(v) + '</span><small>' + esc(b.unidade) + '</small></div>' +
          '<div class="qz-passo"><button type="button" data-qz="menos" data-bloco="' + esc(b.id) + '" aria-label="Menos">−</button>' +
          '<input type="range" data-qz-range="' + esc(b.id) + '" min="' + (Number(b.min) || 0) + '" max="' + (Number(b.max) || 10) + '" step="' + (Number(b.passo) || 1) + '" value="' + v + '" aria-label="Valor">' +
          '<button type="button" data-qz="mais" data-bloco="' + esc(b.id) + '" aria-label="Mais">+</button></div></div>';
      }
      case 'campo':
        return '<input class="qz-campo" data-qz-nome autocomplete="given-name" placeholder="' + esc(b.placeholder) + '" value="' + esc(st.nome) + '" aria-label="' + esc(b.placeholder) + '">' +
          '<p class="qz-privado">Usamos só pra personalizar seu resultado.</p>';
      case 'cronometro':
        return '<div class="qz-crono"><div class="qz-crono-rot">' + rico(b.rotulo) + '</div><div class="qz-crono-cx">' +
          '<span><b data-qz-crono="mm">00</b><small>min</small></span><i>:</i><span><b data-qz-crono="ss">00</b><small>seg</small></span></div></div>';
      case 'grafico':   return '<div class="qz-graf">' + grafico(b) + '</div>';
      case 'medidores': return medidores(b);
      case 'carregando':
        return '<div class="qz-carga"><div class="qz-carga-topo"><span>' + esc(b.titulo) + '</span><span data-qz-pct>0%</span></div>' +
          '<div class="qz-carga-barra"><i data-qz-barra></i></div>' +
          (b.itens || []).map(function(it){ return '<div class="qz-carga-item"><i></i><span>' + esc(it) + '</span></div>'; }).join('') + '</div>';
    }
    return '';
  }

  function grafico(b){
    var v = variaveis(), W = 400, H = 232, x0 = 30, x1 = 370, yb = 188, yt = 46;
    var gid = 'qzg' + String(b.id).replace(/[^a-z0-9]/gi, ''), grad = b.estilo !== 'tema';
    var cor = 'var(--q-cor)';
    var stops = grad ? '<stop offset="0" style="stop-color:var(--q-alerta)"/><stop offset=".5" style="stop-color:var(--q-meio)"/><stop offset="1" style="stop-color:var(--q-bom)"/>'
                     : '<stop offset="0" stop-color="' + cor + '"/><stop offset="1" stop-color="' + cor + '"/>';
    var grade = '';
    for (var k = 0; k <= 4; k++){ var y = yb - (yb - yt) * k / 4; grade += '<line x1="' + x0 + '" x2="' + x1 + '" y1="' + y + '" y2="' + y + '" style="stroke:var(--q-linha)" stroke-width="1"/>'; }
    var rotDe = esc(String(b.de || '').replace('{dias}', v.dias)), rotAte = esc(String(b.ate || '').replace('{dias}', v.dias));
    var w1 = rotDe.length * 7.4 + 18, w2 = rotAte.length * 7.4 + 18;
    function pilula(x, y, w, txt){ return txt ? '<g transform="translate(' + x + ' ' + y + ')"><rect width="' + w + '" height="24" rx="7" style="fill:var(--q-fundo);stroke:var(--q-linha)"/><text x="' + (w / 2) + '" y="16" text-anchor="middle" font-size="11.5" font-weight="700" style="fill:var(--q-tinta)">' + txt + '</text></g>' : ''; }
    return '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="De 0 hoje até ' + esc(v.total) + ' em ' + v.dias + ' dias">' +
      '<defs><linearGradient id="' + gid + '" gradientUnits="userSpaceOnUse" x1="' + x0 + '" y1="0" x2="' + x1 + '" y2="0">' + stops + '</linearGradient></defs>' + grade +
      '<path d="M' + x0 + ' ' + yb + ' L' + x1 + ' ' + yt + ' L' + x1 + ' ' + yb + ' Z" fill="url(#' + gid + ')" opacity="' + (grad ? .26 : .12) + '"/>' +
      '<path d="M' + x0 + ' ' + yb + ' L' + x1 + ' ' + yt + '" stroke="url(#' + gid + ')" stroke-width="3" fill="none" stroke-linecap="round"/>' +
      '<circle cx="' + x0 + '" cy="' + yb + '" r="6" style="fill:' + (grad ? 'var(--q-alerta)' : cor) + ';stroke:var(--q-fundo)" stroke-width="2.5"/>' +
      '<circle cx="' + x1 + '" cy="' + yt + '" r="6" style="fill:' + (grad ? 'var(--q-bom)' : cor) + ';stroke:var(--q-fundo)" stroke-width="2.5"/>' +
      pilula(x0 - 6, yb - 38, w1, rotDe) + pilula(x1 - w2 + 6, yt - 38, w2, rotAte) +
      '<text x="' + x0 + '" y="' + (H - 16) + '" font-size="11.5" style="fill:var(--q-apoio)">0 h</text>' +
      '<text x="' + x1 + '" y="' + (H - 16) + '" font-size="11.5" text-anchor="end" style="fill:var(--q-apoio)">' + esc(v.total) + ' h</text></svg>';
  }
  function medidores(b){
    var sem = b.estilo !== 'tema';
    function card(p, cor, txt){ return '<div><div class="qz-tubo"><i style="height:' + p + '%;background:' + cor + '"></i><em style="color:' + (p >= 30 ? '#fff' : 'var(--q-apoio)') + '">' + p + '%</em></div><p>' + rico(txt) + '</p></div>'; }
    return '<div class="qz-med">' + card(10, sem ? 'var(--q-alerta)' : 'color-mix(in srgb,var(--q-cor) 40%,transparent)', b.antes) + card(100, sem ? 'var(--q-bom)' : 'var(--q-cor)', b.depois) + '</div>';
  }

  // Cronômetro que não reinicia ao recarregar: guarda a hora de fim no navegador
  function inicioCrono(b){
    var dur = (Number(b.min) || 10) * 60000;
    if (!vivo || !b.fixo) return Date.now() + dur;
    var chave = 'qz_crono_' + (quiz.id || quiz.slug || '') + '_' + b.id;
    try {
      var salvo = Number(localStorage.getItem(chave));
      if (salvo && salvo > Date.now() - 86400000) return salvo;
      var fim = Date.now() + dur; localStorage.setItem(chave, String(fim)); return fim;
    } catch (e) { return Date.now() + dur; }
  }
  function tickCrono(){
    var mm = raiz.querySelectorAll('[data-qz-crono="mm"]'); if (!mm.length) return;
    var resta = Math.max(0, st.cronoFim - Date.now());
    var m = String(Math.floor(resta / 60000)).padStart(2, '0'), s = String(Math.floor(resta / 1000) % 60).padStart(2, '0');
    Array.prototype.forEach.call(mm, function(e){ e.textContent = m; });
    Array.prototype.forEach.call(raiz.querySelectorAll('[data-qz-crono="ss"]'), function(e){ e.textContent = s; });
  }
  tick = setInterval(tickCrono, 250);

  function rodarCarga(b){
    var ms = (Number(b.seg) || 4) * 1000, t0 = performance.now();
    var itens = raiz.querySelectorAll('.qz-carga-item'), n = itens.length || 1;
    var pctEl = raiz.querySelector('[data-qz-pct]'), barra = raiz.querySelector('[data-qz-barra]');
    function passo(agora){
      if (destruido) return;
      var p = Math.min(1, (agora - t0) / ms);
      if (pctEl) pctEl.textContent = Math.round(p * 100) + '%';
      if (barra) barra.style.width = (p * 100) + '%';
      Array.prototype.forEach.call(itens, function(it, k){
        var q = Math.max(0, Math.min(1, (p - k / n) * n));
        it.querySelector('i').style.width = (q * 100) + '%';
        it.classList.toggle('qz-cheio', q >= 1);
      });
      if (p < 1){ st.raf = requestAnimationFrame(passo); return; }
      var avanca = typeof op.avancarCarga === 'function' ? op.avancarCarga() : true;
      if (avanca) st.timers.push(setTimeout(function(){ ir(st.i + 1); }, 350));
      else st.timers.push(setTimeout(function(){ pintar(false); }, 1200));
    }
    st.raf = requestAnimationFrame(passo);
  }

  // ── navegação ───────────────────────────────────────────────────────────
  function ir(i, voltando){
    var n = telas().length; if (!n) return;
    var alvo = Math.max(0, Math.min(i, n - 1));
    if (!voltando && alvo !== st.i) st.hist.push(st.i);
    st.i = alvo;
    pintar(true);
    if (typeof op.aoTela === 'function') op.aoTela(st.i);
  }
  function proximaDe(b, opId){
    var o = b && opId && (b.ops || []).filter(function(x){ return x.id === opId; })[0];
    if (o && o.pular){
      var j = -1; telas().forEach(function(t, k){ if (t.id === o.pular) j = k; });
      if (j >= 0) return j;
    }
    return st.i + 1;
  }
  // Ao sair de uma tela, registra os números que a pessoa escolheu nela
  function registrarNumeros(){
    var tela = telas()[st.i]; if (!tela) return;
    (tela.blocos || []).forEach(function(b){
      if (b.tipo !== 'numero') return;
      var v = st.nums[b.id] != null ? st.nums[b.id] : b.valor;
      st.nums[b.id] = v;
      emitir('resp', { t: tela.id, b: b.id, valor: v });
    });
  }

  function urlDestino(b){
    var p = perfilCalculado();
    var destino = String(b.porPerfil ? (p && p.url) || '' : (b.url || '')).trim();
    if (!destino) return '';
    if (!/^https?:\/\//i.test(destino)) destino = 'https://' + destino;
    var u; try { u = new URL(destino); } catch (e) { return ''; }
    new URLSearchParams(op.parametros || '').forEach(function(v, k){
      if (/^tmx_(qid|quiz|perfil)$/.test(k)) return;
      if (!u.searchParams.has(k)) u.searchParams.set(k, v);
    });
    if (op.vid) u.searchParams.set('tmx_qid', op.vid);
    if (quiz.slug) u.searchParams.set('tmx_quiz', quiz.slug);
    if (b.porPerfil && p) u.searchParams.set('tmx_perfil', p.id);
    return u.toString();
  }

  function aoClicar(e){
    var el = e.target.closest('[data-qz]'); if (!el || !raiz.contains(el)) return;
    var acao = el.getAttribute('data-qz'), b = acharBloco(el.getAttribute('data-bloco')), tela = telas()[st.i];
    if (acao === 'voltar'){ if (st.hist.length) ir(st.hist.pop(), true); return; }
    if (acao === 'op' && b){
      var id = el.getAttribute('data-op');
      if (b.modo === 'varias'){
        var marc = st.resp[b.id] = st.resp[b.id] || [];
        var k = marc.indexOf(id);
        if (k >= 0) marc.splice(k, 1); else marc.push(id);
        el.classList.toggle('qz-marcada', k < 0); el.setAttribute('aria-pressed', k < 0);
        var cx = el.querySelector('.qz-mk-caixinha'); if (cx) cx.textContent = k < 0 ? '✓' : '';
        var seg = el.parentElement.nextElementSibling;
        if (seg && seg.getAttribute('data-qz') === 'seguir') seg.disabled = !marc.length;
      } else {
        st.resp[b.id] = [id];
        Array.prototype.forEach.call(el.parentElement.querySelectorAll('.qz-op'), function(x){
          var on = x === el; x.classList.toggle('qz-marcada', on); x.setAttribute('aria-pressed', on);
        });
        emitir('resp', { t: tela.id, b: b.id, ops: [id] });
        st.timers.push(setTimeout(function(){ ir(proximaDe(b, id)); }, semMovimento ? 120 : 320));
      }
      return;
    }
    if (acao === 'seguir' && b){
      emitir('resp', { t: tela.id, b: b.id, ops: (st.resp[b.id] || []).slice() });
      ir(st.i + 1); return;
    }
    if ((acao === 'mais' || acao === 'menos') && b){
      var atual = st.nums[b.id] != null ? st.nums[b.id] : b.valor;
      var passo = Number(b.passo) || 1;
      var v = Math.max(Number(b.min) || 0, Math.min(Number(b.max) || 10, atual + (acao === 'mais' ? passo : -passo)));
      st.nums[b.id] = Math.round(v * 100) / 100;
      var r = raiz.querySelector('[data-qz-range="' + b.id + '"]'); if (r) r.value = st.nums[b.id];
      var t = raiz.querySelector('[data-num-v="' + b.id + '"]'); if (t) t.textContent = dec(st.nums[b.id]);
      return;
    }
    if (acao === 'botao' && b){
      registrarNumeros();
      if (b.acao !== 'link'){ ir(st.i + 1); return; }
      var url = urlDestino(b), p = perfilCalculado();
      if (!vivo){ if (typeof op.aoLink === 'function') op.aoLink(url, { perfil: p, bloco: b }); return; }
      if (!url) return;   // sem link configurado: no ar não há pra onde ir
      emitir('clique', { t: tela.id, b: b.id, p: p ? p.id : '' });
      setTimeout(function(){ doc.defaultView.location.href = url; }, 80);
    }
  }
  function aoDigitar(e){
    var r = e.target.closest && e.target.closest('[data-qz-range]');
    if (r){ var id = r.getAttribute('data-qz-range'); st.nums[id] = Number(r.value); var t = raiz.querySelector('[data-num-v="' + id + '"]'); if (t) t.textContent = dec(st.nums[id]); }
    if (e.target.hasAttribute && e.target.hasAttribute('data-qz-nome')){
      st.nome = e.target.value;
      Array.prototype.forEach.call(corpo.querySelectorAll('[data-qz="botao"]'), function(x){ x.disabled = !st.nome.trim(); });
    }
  }
  function aoTeclar(e){
    if (e.target.hasAttribute && e.target.hasAttribute('data-qz-nome') && e.key === 'Enter' && st.nome.trim()){
      var bt = corpo.querySelector('[data-qz="botao"]'); if (bt) bt.click();
    }
  }
  raiz.addEventListener('click', aoClicar);
  raiz.addEventListener('input', aoDigitar);
  raiz.addEventListener('keydown', aoTeclar);

  emitir('ver', {});
  pintar(false);

  return {
    estado: st,
    ir: function(i, limparHistorico){ if (limparHistorico) st.hist = i > 0 ? [i - 1] : []; ir(i, !!limparHistorico); },
    atualizar: function(novo){ quiz = novo; pintar(false); },
    reiniciar: function(){ st.i = 0; st.hist = []; st.resp = {}; st.nums = {}; st.nome = ''; st.cronoFim = 0; st.vistas = {}; st.fimEnviado = false; pintar(true); if (typeof op.aoTela === 'function') op.aoTela(0); },
    perfil: perfilCalculado,
    urlDestino: urlDestino,
    destruir: function(){
      destruido = true; limparTimers(); clearInterval(tick);
      raiz.removeEventListener('click', aoClicar); raiz.removeEventListener('input', aoDigitar); raiz.removeEventListener('keydown', aoTeclar);
    }
  };
}

window.QuizMotor = { montar: montar, versao: '1' };
})();
