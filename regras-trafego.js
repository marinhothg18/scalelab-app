// ══════════════════════════════════════════════
// ⚡ REGRAS DE TRÁFEGO (10/11/2026)
// "Nestes itens, se estas condições baterem, faça isto, neste horário." Esboço aprovado pelo Thiago em
// claude.ai/artifact/Csxm9xpGTg1Uu2C2Engmus, com os 7 extras (mudar orçamento, só avisar, religar à meia-noite,
// números que só o TMX tem, simular dias passados, modelos prontos e nunca mexer nas fixadas).
//
// De onde vêm os números:
//   Meta: a puxada de 15 em 15 min grava campanha (meta_camp_dia) e anúncio (meta_ad_dia); conjunto é a soma dos
//         anúncios dele. meta_puxado diz quais dias de cada conta já vieram: sem a linha, o número é "sem dado",
//         não zero.
//   TMX:  vendas e faturamento (pedidos) e visitas, pitch, checkout e vídeo (sessoes), ligados à campanha e ao
//         anúncio pelo id no fim do utm_campaign e do utm_content (ou pelo nome do anúncio, sem o id).
// Pausar, ativar e orçamento passam pelo mesmo _metaMudarStatus/_metaMudarOrcamento da tela, com "Regra · <nome>"
// em Quem mexeu. A execução automática nasce desligada: até o Dono ligar, a regra só avalia e registra ("seria
// pausado"). "Só avisar" funciona sempre. As regras antigas (Projetos › Jornada › Regras e alertas) continuam lá.
// ══════════════════════════════════════════════
'use strict';

const KEY = 'sl_regras_trafego';
const METRICAS = ['gasto', 'vendas', 'fat', 'cpa', 'roas', 'lucro', 'checkouts', 'pitch', 'ret1', 'compras', 'ctr', 'cpm'];
const NOME_METRICA = { gasto: 'Gasto', vendas: 'Vendas', fat: 'Faturamento', cpa: 'CPA', roas: 'ROAS', lucro: 'Lucro', checkouts: 'Checkouts',
  pitch: 'Chegam ao pitch', ret1: 'Retenção 1 min', compras: 'Compras na Meta', ctr: 'CTR', cpm: 'CPM' };
const OPS = ['>=', '>', '<=', '<', '='];
const ALVOS = ['campanha', 'conjunto', 'anuncio'];
const ACOES = ['pausar', 'ativar', 'orcamento', 'avisar'];
const PERIODOS = ['hoje', 'ontem', '3d', '7d'];
const NIVEL_TXT = { campanha: ['campanha', 'campanhas'], conjunto: ['conjunto', 'conjuntos'], anuncio: ['anúncio', 'anúncios'] };
const TZ = 3 * 3600000;
const diaBR = ms => new Date(ms - TZ).toISOString().slice(0, 10);
const hmBR = ms => new Date(ms - TZ).toISOString().slice(11, 16);
const inicioDia = dia => Date.parse(dia + 'T00:00:00-03:00');
const somaDia = (dia, n) => diaBR(inicioDia(dia) + n * 86400000);
const r2 = v => v == null ? null : Math.round(v * 100) / 100;
const brl = v => 'R$ ' + Number(v || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// O pedaço de tempo dos números. ref = agora (ou o fim de um dia passado, na simulação); "ontem" e os dias passados vão até o fim do dia.
function periodo(per, ref, diaInteiro) {
  const d = diaBR(ref);
  const de = per === 'ontem' ? somaDia(d, -1) : per === '3d' ? somaDia(d, -2) : per === '7d' ? somaDia(d, -6) : d;
  const ate = per === 'ontem' ? somaDia(d, -1) : d;
  const dias = []; for (let x = de; x <= ate; x = somaDia(x, 1)) dias.push(x);
  return { per, de, ate, dias, ini: inicioDia(de), fim: (per === 'ontem' || diaInteiro) ? inicioDia(ate) + 86400000 - 1 : ref };
}
function dentroDaJanela(hm, de, ate) { return de <= ate ? (hm >= de && hm <= ate) : (hm >= de || hm <= ate); }

module.exports = function (ctx) {
  const { app, readDB, writeDB, audit, authMeta, authDiretoria, _q, _pessoas } = ctx;
  const nrm = ctx._nrm, idUtm = ctx._idDaCampUtm;

  // ── guardar ──
  function cfg(db) {
    const c = (db || readDB()).store[KEY];
    return { lista: c && Array.isArray(c.lista) ? c.lista : [], auto: !!(c && c.auto) };
  }
  function gravar(db, c) {
    db.store[KEY] = { lista: c.lista, auto: !!c.auto, _updatedAt: Date.now() };
    if (!db.timestamps) db.timestamps = {};
    db.timestamps[KEY] = Math.floor(Date.now() / 1000);
  }
  const num = (v, min, max, pad) => { const n = Number(String(v == null ? '' : v).replace(',', '.')); return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : pad; };
  const hm = v => /^([01]\d|2[0-3]):[0-5]\d$/.test(String(v || '')) ? String(v) : null;

  // Confere e limpa o que veio da tela. Devolve { regra } ou { erro }.
  function normalizar(b, antiga) {
    b = b || {};
    const a = antiga || {};
    const r = {
      id: a.id || ('rg' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)),
      nome: String(b.nome || '').trim().slice(0, 80),
      sit: ['rascunho', 'ativa', 'pausada'].includes(b.sit) ? b.sit : (a.sit || 'rascunho'),
      projeto: String(b.projeto || '').slice(0, 60),
      contas: (Array.isArray(b.contas) ? b.contas : []).map(x => String(x).replace(/\D/g, '')).filter(Boolean).slice(0, 50),
      campanhas: (Array.isArray(b.campanhas) ? b.campanhas : []).map(x => String(x).replace(/\D/g, '')).filter(Boolean).slice(0, 20),
      alvo: ALVOS.includes(b.alvo) ? b.alvo : 'anuncio',
      statusItem: ['ativos', 'pausados', 'todos'].includes(b.statusItem) ? b.statusItem : 'ativos',
      nomeOp: ['tem', 'nao', ''].includes(b.nomeOp) ? b.nomeOp : '',
      termo: String(b.termo || '').trim().slice(0, 80),
      fixas: b.fixas !== false,
      junta: b.junta === 'qualquer' ? 'qualquer' : 'todas',
      conds: [],
      acao: ACOES.includes(b.acao) ? b.acao : 'pausar',
      religar: !!b.religar,
      orcDir: b.orcDir === 'baixar' ? 'baixar' : 'subir',
      orcPct: Math.round(num(b.orcPct, 1, 50, 20)),
      orcLimite: num(b.orcLimite, 0, 1000000, 0),
      per: PERIODOS.includes(b.per) ? b.per : 'hoje',
      freq: [15, 30, 60].includes(Number(b.freq)) ? Number(b.freq) : 15,
      de: hm(b.de) || '00:00', ate: hm(b.ate) || '23:59',
      lim: Math.round(num(b.lim, 1, 100, 10)),
      esp: [0, 6, 24].includes(Number(b.esp)) ? Number(b.esp) : 6,
      novoH: [0, 6, 24].includes(Number(b.novoH)) ? Number(b.novoH) : 24,
      zap: b.zap !== false,
      criadoPor: a.criadoPor || null, criadoEm: a.criadoEm || Date.now(),
      ultima: a.ultima || null, ultimaRodada: a.ultimaRodada || 0, ultimoReligar: a.ultimoReligar || '',
      _updatedAt: Date.now()
    };
    (Array.isArray(b.conds) ? b.conds : []).slice(0, 8).forEach(c => {
      if (!c || !METRICAS.includes(c.m)) return;
      const v = Number(String(c.v).replace(',', '.'));
      if (!Number.isFinite(v)) return;
      r.conds.push({ m: c.m, de: c.de === 'campanha' && r.alvo !== 'campanha' ? 'campanha' : 'item', op: OPS.includes(c.op) ? c.op : '>=', v });
    });
    if (!r.nome) return { erro: 'Dê um nome para a regra.' };
    if (!r.conds.length) return { erro: 'Ponha pelo menos uma condição.' };
    if (r.acao === 'orcamento' && r.alvo === 'anuncio') return { erro: 'Anúncio não tem orçamento: para mudar orçamento, aplique em campanhas ou conjuntos.' };
    if (r.acao === 'orcamento' && !r.orcLimite) return { erro: 'Diga o ' + (r.orcDir === 'subir' ? 'máximo' : 'mínimo') + ' por dia do orçamento.' };
    if (r.acao !== 'pausar') r.religar = false;
    return { regra: r };
  }

  // ── a situação de agora de cada campanha, conjunto e anúncio ──
  function estado() {
    const recente = Date.now() - 2 * 86400000;
    const camps = {}, conjs = {}, ads = {};
    _q('SELECT * FROM meta_camp WHERE em>=?').all(recente).forEach(x => {
      camps[x.id] = { nivel: 'campanha', id: x.id, conta: x.conta, nome: x.nome || '', status: x.status, efetivo: x.efetivo, orc: x.orc, orcVida: x.orc_vida, criado: x.criado, camp: x.id, campNome: x.nome || '' };
    });
    _q('SELECT * FROM meta_conj WHERE em>=?').all(recente).forEach(x => {
      conjs[x.id] = { nivel: 'conjunto', id: x.id, conta: x.conta, nome: x.nome || '', status: x.status, efetivo: x.efetivo, orc: x.orc, orcVida: x.orc_vida, criado: x.criado, camp: x.camp, campNome: (camps[x.camp] || {}).nome || '' };
    });
    _q('SELECT * FROM meta_ad WHERE em>=?').all(recente).forEach(x => {
      ads[x.id] = { nivel: 'anuncio', id: x.id, conta: x.conta, nome: x.nome || '', status: x.status, efetivo: x.efetivo, criado: x.criado, camp: x.camp, conj: x.conj, campNome: (camps[x.camp] || {}).nome || '' };
    });
    return { camps, conjs, ads };
  }

  // ── os números de um período, de todos os itens de uma vez ──
  function numeros(P, E) {
    const cobre = {};
    _q('SELECT conta, nivel, COUNT(*) n FROM meta_puxado WHERE dia BETWEEN ? AND ? GROUP BY conta, nivel').all(P.de, P.ate).forEach(x => { cobre[x.conta + '|' + x.nivel] = x.n; });
    const mCamp = {}, mAd = {}, mConj = {};
    _q('SELECT id, SUM(gasto) g, SUM(imp) i, SUM(link_cliques) c, SUM(compras) v FROM meta_camp_dia WHERE dia BETWEEN ? AND ? GROUP BY id').all(P.de, P.ate).forEach(x => { mCamp[x.id] = x; });
    _q('SELECT id, conj, SUM(gasto) g, SUM(imp) i, SUM(link_cliques) c, SUM(compras) v FROM meta_ad_dia WHERE dia BETWEEN ? AND ? GROUP BY id').all(P.de, P.ate).forEach(x => {
      mAd[x.id] = x;
      const s = mConj[x.conj] || (mConj[x.conj] = { g: 0, i: 0, c: 0, v: 0 });
      s.g += x.g || 0; s.i += x.i || 0; s.c += x.c || 0; s.v += x.v || 0;
    });
    // TMX: venda e visita ligadas à campanha e ao anúncio
    const adPorNome = {};
    Object.values(E.ads).forEach(a => { adPorNome[a.camp + '|' + nrm(a.nome)] = a.id; });
    const adDe = (camp, cont) => {
      const id = idUtm(cont); if (id) return id;
      const nome = String(cont || '').replace(/\|\s*\d{10,}\s*$/, '').trim();
      return nome ? (adPorNome[camp + '|' + nrm(nome)] || '') : '';
    };
    const tCamp = {}, tAd = {};
    const novo = () => ({ vendas: 0, fat: 0, vis: new Set(), pitch: new Set(), ck: new Set(), tocou: new Set(), min1: new Set() });
    const pega = (m, k) => m[k] || (m[k] = novo());
    _q('SELECT valor, cred_camp, camp, cred_cont, cont FROM pedidos WHERE em BETWEEN ? AND ? AND pago=1 AND estorno=0 AND renovacao=0').all(P.ini, P.fim).forEach(p => {
      const c = idUtm(p.cred_camp) || idUtm(p.camp); if (!c) return;
      const a = adDe(c, p.cred_camp ? p.cred_cont : p.cont), v = Number(p.valor) || 0;
      const alvos = [pega(tCamp, c)]; if (a) alvos.push(pega(tAd, a));
      alvos.forEach(x => { x.vendas++; x.fat += v; });
    });
    _q('SELECT visitante, camp, cont, pitch, checkout, video FROM sessoes WHERE inicio BETWEEN ? AND ? AND interno=0').all(P.ini, P.fim).forEach(s => {
      const c = idUtm(s.camp); if (!c) return;
      const a = adDe(c, s.cont);
      const alvos = [pega(tCamp, c)]; if (a) alvos.push(pega(tAd, a));
      alvos.forEach(x => { x.vis.add(s.visitante); if (s.pitch) x.pitch.add(s.visitante); if (s.checkout) x.ck.add(s.visitante); if (s.video > 0) x.tocou.add(s.visitante); if (s.video >= 60) x.min1.add(s.visitante); });
    });
    const tConj = {};
    Object.keys(tAd).forEach(id => {
      const a = E.ads[id]; if (!a || !a.conj) return;
      const d = pega(tConj, a.conj), o = tAd[id];
      d.vendas += o.vendas; d.fat += o.fat;
      ['vis', 'pitch', 'ck', 'tocou', 'min1'].forEach(k => o[k].forEach(v => d[k].add(v)));
    });
    return { P, cobre, mCamp, mAd, mConj, tCamp, tAd, tConj };
  }

  // Os números de um item. null = não há o número (com o motivo em faltas[métrica]).
  function valoresDe(nivel, item, N) {
    const meta = (nivel === 'campanha' ? N.mCamp : nivel === 'anuncio' ? N.mAd : N.mConj)[item.id] || null;
    const coberto = (N.cobre[item.conta + '|' + (nivel === 'campanha' ? 'camp' : 'ad')] || 0) >= N.P.dias.length;
    const t = (nivel === 'campanha' ? N.tCamp : nivel === 'anuncio' ? N.tAd : N.tConj)[item.id] || null;
    const g = coberto ? ((meta && meta.g) || 0) : null, imp = coberto ? ((meta && meta.i) || 0) : null;
    const cl = coberto ? ((meta && meta.c) || 0) : null, cp = coberto ? ((meta && meta.v) || 0) : null;
    const vendas = t ? t.vendas : 0, fat = t ? t.fat : 0, vis = t ? t.vis.size : 0, tocou = t ? t.tocou.size : 0;
    const v = {
      gasto: r2(g), compras: cp, ctr: imp ? r2(cl / imp * 100) : null, cpm: imp ? r2(g / imp * 1000) : null,
      vendas, fat: r2(fat), cpa: g != null && vendas > 0 ? r2(g / vendas) : null, roas: g ? r2(fat / g) : null, lucro: g != null ? r2(fat - g) : null,
      checkouts: t ? t.ck.size : 0, pitch: vis ? r2(t.pitch.size / vis * 100) : null, ret1: tocou ? r2(t.min1.size / tocou * 100) : null
    };
    const semMeta = 'os números da Meta deste período ainda não chegaram por ' + NIVEL_TXT[nivel][0];
    const faltas = {
      gasto: semMeta, compras: semMeta, lucro: semMeta,
      ctr: coberto ? 'sem impressão no período' : semMeta, cpm: coberto ? 'sem impressão no período' : semMeta,
      cpa: g == null ? semMeta : 'sem venda, não há CPA', roas: g == null ? semMeta : 'sem gasto, não há ROAS',
      pitch: 'ninguém chegou à página por este item', ret1: 'ninguém deu play na VSL por este item'
    };
    return { v, faltas };
  }

  const pausado = it => it.status === 'PAUSED';
  function fmt(m, v) {
    if (v == null) return '—';
    if (['gasto', 'fat', 'cpa', 'lucro', 'cpm'].includes(m)) return brl(v);
    if (['pitch', 'ret1', 'ctr'].includes(m)) return String(v).replace('.', ',') + '%';
    if (m === 'roas') return String(v).replace('.', ',') + 'x';
    return String(v);
  }
  const compara = (a, op, b) => op === '>=' ? a >= b : op === '>' ? a > b : op === '<=' ? a <= b : op === '<' ? a < b : Math.abs(a - b) < 1e-9;

  // Avalia uma regra: quem está no escopo, o que bateu e o que faria. Não mexe em nada.
  function avaliar(r, E, N, extra) {
    const agora = extra.agora || Date.now(), marcas = extra.marcas || {}, projDe = extra.projDe;
    const fixa = it => { const m = marcas[it.camp] || marcas['n:' + nrm(it.campNome)]; return !!(m && m.fixa); };
    const base = r.alvo === 'campanha' ? E.camps : r.alvo === 'conjunto' ? E.conjs : E.ads;
    const termo = nrm(r.termo);
    const fora = [], itens = [];
    Object.values(base).forEach(it => {
      if (r.contas.length && !r.contas.includes(String(it.conta))) return;
      if (r.campanhas.length && !r.campanhas.includes(String(it.camp))) return;
      if (r.projeto && projDe && projDe(it.conta, it.campNome) !== r.projeto) return;
      if (r.statusItem === 'ativos' && it.efetivo !== 'ACTIVE') return;
      if (r.statusItem === 'pausados' && !pausado(it)) return;
      if (r.nomeOp && termo) { const tem = nrm(it.nome).includes(termo); if (r.nomeOp === 'tem' ? !tem : tem) return; }
      if (r.fixas && fixa(it)) { fora.push({ id: it.id, nome: it.nome, campNome: it.campNome, motivo: 'campanha fixada no topo' }); return; }
      if (r.novoH && it.criado && agora - it.criado < r.novoH * 3600000) { fora.push({ id: it.id, nome: it.nome, campNome: it.campNome, motivo: 'criado há menos de ' + r.novoH + ' h' }); return; }
      const proprio = valoresDe(r.alvo, it, N);
      const daCamp = r.alvo !== 'campanha' && r.conds.some(c => c.de === 'campanha') ? valoresDe('campanha', E.camps[it.camp] || { id: it.camp, conta: it.conta }, N) : null;
      const valores = {}, faltou = [];
      const bateu = r.conds.map(c => {
        const fonte = c.de === 'campanha' && daCamp ? daCamp : proprio, v = fonte.v[c.m];
        const rot = NOME_METRICA[c.m] + (c.de === 'campanha' && r.alvo !== 'campanha' ? ' da campanha' : '');
        if (v == null) { faltou.push(rot + ': ' + fonte.faltas[c.m]); return null; }
        valores[rot] = fmt(c.m, v);
        return compara(v, c.op, c.v);
      });
      let res;
      if (r.junta === 'todas') res = bateu.includes(false) ? 'nao' : bateu.includes(null) ? 'sem_dado' : 'bateu';
      else res = bateu.includes(true) ? 'bateu' : bateu.includes(null) ? 'sem_dado' : 'nao';
      const x = { id: it.id, nivel: r.alvo, nome: it.nome, camp: it.camp, campNome: it.campNome, conta: it.conta, status: it.status, efetivo: it.efetivo, orc: it.orc, valores, resultado: res, motivo: faltou.join('; ') };
      if (res === 'bateu') {
        if (r.acao === 'pausar' && pausado(it)) { x.resultado = 'ja'; x.motivo = 'já está pausado'; }
        else if (r.acao === 'ativar' && !pausado(it)) { x.resultado = 'ja'; x.motivo = 'já está ativo'; }
        else if (r.acao === 'orcamento') {
          if (!it.orc) { x.resultado = 'ja'; x.motivo = 'o orçamento não fica aqui' + (r.alvo === 'campanha' ? ' (fica nos conjuntos)' : ' (fica na campanha)'); }
          else {
            let novo = it.orc * (1 + (r.orcDir === 'subir' ? 1 : -1) * r.orcPct / 100);
            novo = r.orcDir === 'subir' ? Math.min(novo, r.orcLimite) : Math.max(novo, r.orcLimite);
            novo = r2(novo);
            if (Math.abs(novo - it.orc) < 0.01) { x.resultado = 'ja'; x.motivo = 'já está no ' + (r.orcDir === 'subir' ? 'teto' : 'piso'); }
            else x.orcamento = { de: r2(it.orc), para: novo };
          }
        }
      }
      itens.push(x);
    });
    return { itens, fora };
  }

  // ── o registro ──
  function registrar(r, x, resultado, detalhe, agora) {
    try {
      _q('INSERT INTO regras_log(regra, em, dia, nivel, item, nome, camp, valores, resultado, acao, detalhe) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
        .run(r.id, agora, diaBR(agora), x.nivel || r.alvo, String(x.id || ''), String(x.nome || '').slice(0, 160), String(x.campNome || '').slice(0, 160),
             JSON.stringify(x.valores || {}), resultado, r.acao, String(detalhe || '').slice(0, 400));
    } catch (e) { console.error('[REGRAS] registro:', e.message); }
  }
  const jaRegistrouHoje = (r, item, resultado, agora) => !!_q('SELECT 1 FROM regras_log WHERE regra=? AND item=? AND resultado=? AND dia=? LIMIT 1').get(r.id, String(item), resultado, diaBR(agora));
  const quem = r => ({ id: 'regra-' + r.id, nome: 'Regra · ' + r.nome, cargo: 'Regra' });
  const verbo = { pausar: 'pausou', ativar: 'ativou', orcamento: 'mudou o orçamento de', avisar: 'avisou sobre' };

  // Faz o que a avaliação pediu, respeitando a chave geral, o limite do dia e o "não mexer de novo por".
  async function executar(r, av, auto, agora) {
    const conta = { avaliados: av.itens.length, bateram: 0, agiu: 0, seria: 0, avisou: 0, ja: 0, sem_dado: 0, erros: 0, limite: 0, esperando: 0, fora: av.fora.length };
    let feitosHoje = _q("SELECT COUNT(*) n FROM regras_log WHERE regra=? AND dia=? AND resultado IN ('agiu','avisou')").get(r.id, diaBR(agora)).n;
    const avisos = [], feitos = [];
    for (const x of av.itens) {
      if (x.resultado === 'sem_dado') { conta.sem_dado++; if (!jaRegistrouHoje(r, x.id, 'sem_dado', agora)) registrar(r, x, 'sem_dado', x.motivo, agora); continue; }
      if (x.resultado === 'nao') continue;
      conta.bateram++;
      if (x.resultado === 'ja') { conta.ja++; continue; }
      if (r.esp && _q("SELECT 1 FROM regras_log WHERE regra=? AND item=? AND resultado IN ('agiu','avisou') AND em>? LIMIT 1").get(r.id, String(x.id), agora - r.esp * 3600000)) { conta.esperando++; continue; }
      if (feitosHoje >= r.lim) { conta.limite++; if (!jaRegistrouHoje(r, x.id, 'limite', agora)) registrar(r, x, 'limite', 'chegou ao máximo de ' + r.lim + ' por dia', agora); continue; }
      if (r.acao === 'avisar') { avisos.push(x); registrar(r, x, 'avisou', '', agora); conta.avisou++; feitosHoje++; continue; }
      if (!auto) { conta.seria++; if (!jaRegistrouHoje(r, x.id, 'seria', agora)) registrar(r, x, 'seria', 'execução automática desligada', agora); continue; }
      try {
        if (r.acao === 'orcamento') {
          const ok = await ctx._metaMudarOrcamento({ nivel: r.alvo, id: x.id, pct: (r.orcDir === 'subir' ? 1 : -1) * r.orcPct, limite: r.orcLimite, camp: x.camp, nome: x.nome }, quem(r));
          x.orcamento = { de: x.orc, para: ok.valor };
        } else {
          await ctx._metaMudarStatus({ nivel: r.alvo, id: x.id, ativo: r.acao === 'ativar', camp: x.camp, nome: x.nome }, quem(r));
        }
        registrar(r, x, 'agiu', x.orcamento ? brl(x.orcamento.de) + ' → ' + brl(x.orcamento.para) : '', agora);
        conta.agiu++; feitosHoje++; feitos.push(x);
      } catch (e) {
        if (e.semMudanca) { conta.ja++; continue; }
        conta.erros++;
        registrar(r, x, 'erro', e.httpTela ? e.message : ctx._metaErroTxt(e), agora);
      }
    }
    const dono = r.criadoPor && r.criadoPor.id;
    const linha = x => '• ' + x.nome + (x.nivel !== 'campanha' && x.campNome ? ' (' + x.campNome + ')' : '') + ': ' + Object.keys(x.valores).map(k => k + ' ' + x.valores[k]).join(', ') +
      (x.orcamento ? ' · orçamento ' + brl(x.orcamento.de) + ' → ' + brl(x.orcamento.para) : '');
    if (dono && avisos.length) ctx.notificar(dono, '⚡ Regra: ' + r.nome, avisos.length + ' ' + NIVEL_TXT[r.alvo][avisos.length === 1 ? 0 : 1] + ' bateram:\n' + avisos.slice(0, 8).map(linha).join('\n'));
    if (dono && r.zap && feitos.length) ctx.notificar(dono, '⚡ Regra: ' + r.nome, 'A regra ' + verbo[r.acao] + ' ' + feitos.length + ' ' + NIVEL_TXT[r.alvo][feitos.length === 1 ? 0 : 1] + ':\n' + feitos.slice(0, 8).map(linha).join('\n'));
    return conta;
  }

  // À meia-noite: o que a regra pausou ontem volta, se ainda está pausado e ninguém mexeu nele depois.
  async function religar(r, auto, agora) {
    const ontem = somaDia(diaBR(agora), -1);
    const rows = _q("SELECT * FROM regras_log WHERE regra=? AND dia=? AND resultado='agiu' AND acao='pausar' ORDER BY em").all(r.id, ontem);
    if (!rows.length) return 0;
    const E = estado(), base = r.alvo === 'campanha' ? E.camps : r.alvo === 'conjunto' ? E.conjs : E.ads;
    const audits = (readDB().store.sl_auditlog || []);
    let n = 0;
    for (const row of rows) {
      const it = base[row.item];
      const x = { id: row.item, nivel: row.nivel, nome: row.nome, campNome: row.camp, valores: {} };
      if (!it || !pausado(it)) continue;
      const mexeram = audits.some(a => a && String(a.target) === row.item && a.ts > row.em && a.userNome !== quem(r).nome);
      if (mexeram) { registrar(r, x, 'religar_nao', 'alguém mexeu nele depois da regra', agora); continue; }
      if (!auto) { registrar(r, x, 'seria_religado', 'execução automática desligada', agora); continue; }
      try { await ctx._metaMudarStatus({ nivel: row.nivel, id: row.item, ativo: true, camp: it.camp, nome: it.nome }, quem(r)); registrar(r, x, 'religou', '', agora); n++; }
      catch (e) { registrar(r, x, 'erro', 'ao religar: ' + (e.httpTela ? e.message : ctx._metaErroTxt(e)), agora); }
    }
    return n;
  }

  // ── a rotina: de minuto em minuto vê quais regras estão na hora ──
  let rodando = false;
  async function rodar(forcar) {
    if (rodando || !_pessoas()) return null;
    rodando = true;
    const resumo = [];
    try {
      const db0 = readDB(), c = cfg(db0), agora = Date.now(), hmAgora = hmBR(agora), hoje = diaBR(agora);
      const ativas = c.lista.filter(r => r.sit === 'ativa');
      const marcaReligar = {};
      for (const r of ativas) {
        if (r.acao === 'pausar' && r.religar && r.ultimoReligar !== hoje && (forcar === 'religar' || hmAgora < '06:00')) {
          await religar(r, c.auto, agora); marcaReligar[r.id] = hoje;
        }
      }
      const devidas = forcar === 'religar' ? [] : ativas.filter(r => forcar === true || ((agora - (r.ultimaRodada || 0)) >= r.freq * 60000 - 30000 && dentroDaJanela(hmAgora, r.de, r.ate)));
      const ultimas = {};
      if (devidas.length) {
        const E = estado(), cache = {}, marcas = ctx.marcas(), projDe = ctx.projetoDaCampanha();
        for (const r of devidas) {
          const N = cache[r.per] || (cache[r.per] = numeros(periodo(r.per, agora), E));
          const av = avaliar(r, E, N, { agora, marcas, projDe });
          const conta = await executar(r, av, c.auto, agora);
          ultimas[r.id] = Object.assign({ em: agora, auto: c.auto }, conta);
          resumo.push(Object.assign({ regra: r.id, nome: r.nome }, conta));
        }
      }
      if (devidas.length || Object.keys(marcaReligar).length) {
        const db = readDB(), c2 = cfg(db);
        c2.lista.forEach(r => {
          if (ultimas[r.id]) { r.ultima = ultimas[r.id]; r.ultimaRodada = agora; }
          if (marcaReligar[r.id]) r.ultimoReligar = marcaReligar[r.id];
        });
        gravar(db, c2); writeDB(db);
      }
    } catch (e) { console.error('[REGRAS]', e.message); }
    finally { rodando = false; }
    return resumo;
  }
  setInterval(() => { rodar(false).catch(() => {}); }, 60 * 1000);

  // ── simulação: o que a regra faria agora, ontem ou em cada um dos últimos 7 dias. Não mexe em nada. ──
  function simular(r, modo) {
    const E = estado(), marcas = ctx.marcas(), projDe = ctx.projetoDaCampanha(), agora = Date.now(), hoje = diaBR(agora);
    if (modo === '7d') {
      const dias = [];
      for (let k = 6; k >= 0; k--) {
        const dia = somaDia(hoje, -k), ref = k ? inicioDia(dia) + 86400000 - 1 : agora;
        const av = avaliar(r, E, numeros(periodo(r.per, ref, !!k), E), { agora: ref, marcas, projDe });
        dias.push({ dia, n: av.itens.filter(x => x.resultado === 'bateu').length, semDado: av.itens.filter(x => x.resultado === 'sem_dado').length });
      }
      return { modo, dias };
    }
    const ref = modo === 'ontem' ? inicioDia(hoje) - 1 : agora;
    const av = avaliar(r, E, numeros(periodo(r.per, ref, modo === 'ontem'), E), { agora: ref, marcas, projDe });
    const ordem = { bateu: 0, sem_dado: 1, ja: 2, nao: 3 };
    av.itens.sort((a, b) => (ordem[a.resultado] - ordem[b.resultado]) || String(a.nome).localeCompare(String(b.nome)));
    return { modo, itens: av.itens.slice(0, 300).map(x => ({ id: x.id, nome: x.nome, campNome: x.campNome, resultado: x.resultado, motivo: x.motivo, valores: x.valores, orcamento: x.orcamento || null })),
      total: av.itens.length, fora: av.fora.slice(0, 50) };
  }

  // ── rotas ──
  const publica = r => Object.assign({}, r);
  app.get('/api/regras-trafego', authMeta, (req, res) => {
    try {
      const c = cfg(), E = _pessoas() ? estado() : { camps: {} }, marcas = ctx.marcas();
      const fixadas = Object.keys(marcas).filter(k => marcas[k] && marcas[k].fixa).map(k => ({ id: k, nome: (E.camps[k] && E.camps[k].nome) || k.replace(/^n:/, '') }));
      const mc = ctx._metaCfg() || {}, nomes = ctx.contaNomes();
      const contas = (mc.contas || []).filter(x => [1, 201, 9].includes(x.status)).map(x => ({ conta: String(x.conta), nome: nomes[x.conta] || x.nome || x.conta }));
      let desde = null; try { desde = (_q("SELECT MIN(dia) d FROM meta_puxado WHERE nivel='ad'").get() || {}).d || null; } catch (e) {}
      // o nome das campanhas escolhidas uma a uma (o botão ⚡ da tabela), pra tela não mostrar só o id
      const campNomes = {};
      c.lista.forEach(r => (r.campanhas || []).forEach(id => { if (E.camps[id]) campNomes[id] = E.camps[id].nome; }));
      res.json({ ok: true, auto: c.auto, podeLigar: ctx.ehDiretoria(req), metaLigada: !!(mc.accessToken && mc.tipo === 'sistema'),
        regras: c.lista.map(publica), opcoes: { projetos: ctx.projetos(), contas, fixadas, porAnuncioDesde: desde, campNomes } });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.post('/api/regras-trafego', authMeta, (req, res) => {
    try {
      const b = (req.body && req.body.regra) || {}, db = readDB(), c = cfg(db);
      const antiga = b.id ? c.lista.find(x => x.id === b.id) : null;
      if (b.id && !antiga) return res.status(404).json({ error: 'Regra não encontrada.' });
      const n = normalizar(b, antiga);
      if (n.erro) return res.status(400).json({ error: n.erro });
      if (!antiga) n.regra.criadoPor = { id: req.user.id, nome: req.user.nome || '' };
      c.lista = antiga ? c.lista.map(x => x.id === antiga.id ? n.regra : x) : c.lista.concat([n.regra]);
      gravar(db, c);
      audit(db, 'regra_trafego_salva', n.regra.id, { nome: n.regra.nome, sit: n.regra.sit, acao: n.regra.acao }, req.user);
      writeDB(db);
      res.json({ ok: true, regra: n.regra });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.post('/api/regras-trafego/simular', authMeta, (req, res) => {
    try {
      if (!_pessoas()) return res.status(503).json({ error: 'A base de dados não abriu neste servidor.' });
      const n = normalizar(Object.assign({ nome: 'Simulação' }, (req.body && req.body.regra) || {}));
      if (n.erro) return res.status(400).json({ error: n.erro });
      const modo = ['agora', 'ontem', '7d'].includes(req.body.modo) ? req.body.modo : 'agora';
      res.json(Object.assign({ ok: true, auto: cfg().auto }, simular(n.regra, modo)));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.post('/api/regras-trafego/:id/situacao', authMeta, (req, res) => {
    try {
      const sit = (req.body || {}).sit;
      if (!['ativa', 'pausada'].includes(sit)) return res.status(400).json({ error: 'Situação desconhecida.' });
      const db = readDB(), c = cfg(db), r = c.lista.find(x => x.id === req.params.id);
      if (!r) return res.status(404).json({ error: 'Regra não encontrada.' });
      r.sit = sit; r._updatedAt = Date.now();
      gravar(db, c);
      audit(db, sit === 'ativa' ? 'regra_trafego_ativada' : 'regra_trafego_pausada', r.id, { nome: r.nome }, req.user);
      writeDB(db);
      res.json({ ok: true, regra: r });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.post('/api/regras-trafego/:id/duplicar', authMeta, (req, res) => {
    try {
      const db = readDB(), c = cfg(db), r = c.lista.find(x => x.id === req.params.id);
      if (!r) return res.status(404).json({ error: 'Regra não encontrada.' });
      const n = normalizar(Object.assign({}, r, { id: null, nome: (r.nome + ' (cópia)').slice(0, 80), sit: 'rascunho' }));
      n.regra.criadoPor = { id: req.user.id, nome: req.user.nome || '' }; n.regra.ultima = null; n.regra.ultimaRodada = 0; n.regra.ultimoReligar = '';
      c.lista.push(n.regra);
      gravar(db, c);
      audit(db, 'regra_trafego_duplicada', n.regra.id, { de: r.id, nome: n.regra.nome }, req.user);
      writeDB(db);
      res.json({ ok: true, regra: n.regra });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.get('/api/regras-trafego/:id/historico', authMeta, (req, res) => {
    try {
      const r = cfg().lista.find(x => x.id === req.params.id);
      if (!r) return res.status(404).json({ error: 'Regra não encontrada.' });
      const itens = _pessoas() ? _q('SELECT em, nivel, item, nome, camp, valores, resultado, acao, detalhe FROM regras_log WHERE regra=? ORDER BY n DESC LIMIT 300').all(r.id)
        .map(x => { let v = {}; try { v = JSON.parse(x.valores || '{}'); } catch (e) {} return Object.assign(x, { valores: v }); }) : [];
      res.json({ ok: true, regra: { id: r.id, nome: r.nome }, itens });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  // a chave geral: só o Dono liga a execução automática
  app.post('/api/regras-trafego/auto', authDiretoria, (req, res) => {
    try {
      const ligado = !!(req.body && req.body.ligado === true), db = readDB(), c = cfg(db);
      c.auto = ligado; gravar(db, c);
      audit(db, ligado ? 'regras_trafego_auto_ligada' : 'regras_trafego_auto_desligada', KEY, null, req.user);
      writeDB(db);
      res.json({ ok: true, auto: ligado });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  // verifica agora todas as regras ativas, fora do horário delas (botão "Verificar agora" e os testes)
  app.post('/api/regras-trafego/rodar', authDiretoria, async (req, res) => {
    try {
      const r = await rodar(req.body && req.body.religar ? 'religar' : true);
      if (r === null) return res.status(409).json({ error: 'Já está verificando. Tente de novo em instantes.' });
      res.json({ ok: true, resumo: r });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  return { rodar, simular, avaliar, periodo };
};
